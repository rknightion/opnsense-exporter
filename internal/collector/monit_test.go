package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// monitRunningCollectorFixture is the full monit status body used for collector
// tests. Two services: $HOST (type 5 = system, status 0 = ok) and nginx
// (type 3 = process, status 512 = error).
const monitRunningCollectorFixture = `{
  "result": "ok",
  "status": {
    "@attributes": {"id": "abc123", "incarnation": "1700000000", "version": "5.33.0"},
    "service": [
      {"@attributes": {"type": "5"}, "name": "$HOST",
       "status": "0", "monitor": "1", "monitormode": "0", "pendingaction": "0"},
      {"@attributes": {"type": "3"}, "name": "nginx",
       "status": "512", "monitor": "1", "monitormode": "0", "pendingaction": "0"}
    ]
  }
}`

// monitDownCollectorFixture matches the live-validated "monit not running" response.
const monitDownCollectorFixture = `{"result": "failed",
 "status": "\nEither the file /var/run/monit.sock does not exists or it is not a unix socket.\nPlease check if the Monit service is running.\n\nIf you have started Monit recently, wait for StartDelay seconds and refresh this page."}`

func monitCollectorMux(t *testing.T, statusBody, serviceStatus string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(statusBody))
	})
	mux.HandleFunc("/api/monit/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(serviceStatus))
	})
	return mux
}

func TestMonitCollector_Update_Running(t *testing.T) {
	server := httptest.NewServer(monitCollectorMux(t,
		monitRunningCollectorFixture, `{"status":"running"}`))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &monitCollector{subsystem: MonitSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected:
	//   1  service_running
	//   1  status_ok
	//   1  checks_total
	//   2× check_status  (one per service)
	//   2× check_monitored (one per service)
	// Total = 7
	if len(metrics) != 7 {
		t.Errorf("expected 7 metrics, got %d", len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "monit_service_running"):
			if val != 1 {
				t.Errorf("service_running: expected 1, got %v", val)
			}
		case strings.Contains(desc, "monit_status_ok"):
			if val != 1 {
				t.Errorf("status_ok: expected 1, got %v", val)
			}
		case strings.Contains(desc, "monit_checks_total"):
			if val != 2 {
				t.Errorf("checks_total: expected 2, got %v", val)
			}
		case strings.Contains(desc, "monit_check_status"):
			switch labels["name"] {
			case "$HOST":
				if val != 1 {
					t.Errorf("check_status $HOST: expected 1 (ok), got %v", val)
				}
				if labels["type"] != "system" {
					t.Errorf("check_status $HOST: expected type=system, got %q", labels["type"])
				}
			case "nginx":
				if val != 0 {
					t.Errorf("check_status nginx: expected 0 (error, status=512), got %v", val)
				}
				if labels["type"] != "process" {
					t.Errorf("check_status nginx: expected type=process, got %q", labels["type"])
				}
			default:
				t.Errorf("unexpected check_status label name=%q", labels["name"])
			}
		}
	}
}

func TestMonitCollector_Update_MonitStopped(t *testing.T) {
	// monit is installed but not running: status endpoint returns "failed" envelope.
	// The OPNsense service/status endpoint reports "stopped".
	server := httptest.NewServer(monitCollectorMux(t,
		monitDownCollectorFixture, `{"status":"stopped"}`))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &monitCollector{subsystem: MonitSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected:
	//   1 service_running (=0, stopped)
	//   1 status_ok (=0, monit not reachable)
	// No per-check metrics.
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics when monit stopped, got %d", len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "monit_service_running"):
			if val != 0 {
				t.Errorf("service_running: expected 0 (stopped), got %v", val)
			}
		case strings.Contains(desc, "monit_status_ok"):
			if val != 0 {
				t.Errorf("status_ok: expected 0, got %v", val)
			}
		}
	}
}

func TestMonitCollector_Name(t *testing.T) {
	c := &monitCollector{subsystem: MonitSubsystem}
	if c.Name() != MonitSubsystem {
		t.Errorf("expected %s, got %s", MonitSubsystem, c.Name())
	}
}

// monitResourceCollectorFixture is the RAW capture from a live OPNsense
// 26.7-devel box (2026-07-13) with one check of each of the four
// resource-bearing types provisioned: type 5 system
// ("opnsense-devel.internal"), type 0 filesystem ("RootFs"), type 4 host
// ("TestLxcHost", icmp + one port test), type 3 process ("ConfigdProcess",
// whose cpu.percent reads monit's "-1" not-yet-computed sentinel). See
// scratchpad captures/monit/status_get_xml.json for provenance; identical to
// opnsense.monitResourceFixture.
const monitResourceCollectorFixture = `{"result":"ok","status":{"server":{"id":"562352efdd23b9523497e6d7fee623c8","incarnation":"1783962711","version":"5.35.2","uptime":"27","poll":"120","startdelay":"120","localhostname":"opnsense-devel.internal","controlfile":"/usr/local/etc/monitrc","httpd":{"unixsocket":"/var/run/monit.sock"}},"platform":{"name":"FreeBSD","release":"15.1-RELEASE-p1","version":"FreeBSD 15.1-RELEASE-p1 stable/26.7-n283669-9664a203d589 SMP","machine":"amd64","cpu":"4","memory":"8345052","swap":"8388608"},"service":[{"@attributes":{"type":"5"},"name":"opnsense-devel.internal","collected_sec":"1783962711","collected_usec":"270742","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","uptime":"82799","boottime":"1783879939","filedescriptors":{"allocated":"826","unused":"0","maximum":"260782"},"system":{"load":{"avg01":"0.06","avg05":"0.16","avg15":"0.15"},"cpu":{"user":"1.7","system":"0.6","nice":"0.0","hardirq":"0.0"},"memory":{"percent":"17.7","kilobyte":"1479740"},"swap":{"percent":"0.0","kilobyte":"0"}}},{"@attributes":{"type":"0"},"name":"RootFs","collected_sec":"1783962711","collected_usec":"270844","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","fstype":"ufs","fsflags":"journaled soft updates, soft updates, local, rootfs","mode":"755","uid":"0","gid":"0","block":{"percent":"8.4","usage":"4492.3","total":"53292.2"},"inode":{"percent":"1.6","usage":"112539","total":"7051262"},"read":{"bytes":{"count":"0","total":"2418515456"},"operations":{"count":"0","total":"99232"}},"write":{"bytes":{"count":"0","total":"17453239296"},"operations":{"count":"0","total":"565679"}},"servicetime":{"read":"0.000","write":"0.000"}},{"@attributes":{"type":"4"},"name":"TestLxcHost","collected_sec":"1783962711","collected_usec":"283984","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","icmp":{"type":"Ping","responsetime":"0.000160"},"port":{"hostname":"172.16.20.117","portnumber":"22","request":{},"protocol":"SSH","type":"TCP","responsetime":"0.012940"}},{"@attributes":{"type":"3"},"name":"ConfigdProcess","collected_sec":"1783962711","collected_usec":"284014","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","pid":"552","ppid":"1","uid":"0","euid":"0","gid":"0","uptime":"143","threads":"1","children":"2","memory":{"percent":"0.2","percenttotal":"0.9","kilobyte":"17648","kilobytetotal":"76796"},"cpu":{"percent":"-1.0","percenttotal":"-1.0"},"filedescriptors":{"open":"0","opentotal":"0","limit":{"soft":"0","hard":"0"}},"read":{"operations":{"count":"0","total":"0"}},"write":{"operations":{"count":"0","total":"0"}}}]}}`

func TestMonitCollector_Update_ResourceTelemetry(t *testing.T) {
	server := httptest.NewServer(monitCollectorMux(t,
		monitResourceCollectorFixture, `{"status":"running"}`))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &monitCollector{subsystem: MonitSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected:
	//   1  service_running
	//   1  status_ok
	//   1  checks_total
	//   4× check_status + 4× check_monitored  (one per check)          =  8
	//   filesystem: usage_percent + inode_usage_percent                =  2
	//   process: memory_bytes + uptime_seconds + threads               =  3
	//     (cpu_percent skipped: monit's -1 not-yet-computed sentinel)
	//   host: icmp_response_seconds + port_response_seconds (1 port)    =  2
	//   system: load×3 (1m/5m/15m) + memory_percent + swap_percent
	//     + cpu_percent×4 (user/system/nice/hardirq)                   =  9
	// Total = 1+1+1+8+2+3+2+9 = 27
	const want = 27
	if len(metrics) != want {
		t.Errorf("expected %d metrics, got %d", want, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s %v", m.Desc().String(), getMetricLabels(m))
		}
	}

	var sawProcessCPU, sawPort, sawSystemCPU bool
	var portCount, systemCPUCount int

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "monit_process_cpu_percent"):
			sawProcessCPU = true

		case strings.Contains(desc, "monit_filesystem_usage_percent"):
			if labels["name"] != "RootFs" || val != 8.4 {
				t.Errorf("filesystem_usage_percent: unexpected name/val %q/%v", labels["name"], val)
			}
		case strings.Contains(desc, "monit_filesystem_inode_usage_percent"):
			if val != 1.6 {
				t.Errorf("filesystem_inode_usage_percent: expected 1.6, got %v", val)
			}

		case strings.Contains(desc, "monit_process_memory_bytes"):
			if val != 17648*1024 {
				t.Errorf("process_memory_bytes: expected %v, got %v", 17648*1024, val)
			}
		case strings.Contains(desc, "monit_process_uptime_seconds"):
			if val != 143 {
				t.Errorf("process_uptime_seconds: expected 143, got %v", val)
			}
		case strings.Contains(desc, "monit_process_threads"):
			if val != 1 {
				t.Errorf("process_threads: expected 1, got %v", val)
			}

		case strings.Contains(desc, "monit_host_icmp_response_seconds"):
			if val != 0.000160 {
				t.Errorf("host_icmp_response_seconds: expected 0.000160, got %v", val)
			}
		case strings.Contains(desc, "monit_port_response_seconds"):
			sawPort = true
			portCount++
			if labels["port"] != "22" || labels["protocol"] != "SSH" {
				t.Errorf("port_response_seconds: unexpected labels %v", labels)
			}
			if val != 0.012940 {
				t.Errorf("port_response_seconds: expected 0.012940, got %v", val)
			}

		case strings.Contains(desc, "monit_system_load"):
			switch labels["period"] {
			case "1m":
				if val != 0.06 {
					t.Errorf("system_load 1m: expected 0.06, got %v", val)
				}
			case "5m":
				if val != 0.16 {
					t.Errorf("system_load 5m: expected 0.16, got %v", val)
				}
			case "15m":
				if val != 0.15 {
					t.Errorf("system_load 15m: expected 0.15, got %v", val)
				}
			default:
				t.Errorf("system_load: unexpected period label %q", labels["period"])
			}
		case strings.Contains(desc, "monit_system_memory_percent"):
			if val != 17.7 {
				t.Errorf("system_memory_percent: expected 17.7, got %v", val)
			}
		case strings.Contains(desc, "monit_system_swap_percent"):
			if val != 0.0 {
				t.Errorf("system_swap_percent: expected 0.0, got %v", val)
			}
		case strings.Contains(desc, "monit_system_cpu_percent"):
			sawSystemCPU = true
			systemCPUCount++
			if labels["mode"] == "wait" {
				t.Error("did not expect a Linux-only 'wait' cpu mode from a FreeBSD box")
			}
		}
	}

	if sawProcessCPU {
		t.Error("did not expect a process_cpu_percent series: monit's -1 sentinel means not-yet-computed")
	}
	if !sawPort || portCount != 1 {
		t.Errorf("expected exactly 1 port_response_seconds series, got %d (saw=%v)", portCount, sawPort)
	}
	if !sawSystemCPU || systemCPUCount != 4 {
		t.Errorf("expected exactly 4 system_cpu_percent series (user/system/nice/hardirq), got %d", systemCPUCount)
	}
}
