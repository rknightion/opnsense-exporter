package opnsense

import (
	"net/http"
	"testing"
)

// monitRunningFixture is derived from core Monit/Api/StatusController.php +
// monit 5.x _status?format=xml schema as serialised by PHP simplexml_load_string
// + json_encode. The overall envelope/service-list shape is live-validated
// (see monitResourceFixture below for the per-check resource fields).
const monitRunningFixture = `{
  "result": "ok",
  "status": {
    "@attributes": {"id": "abc123", "incarnation": "1700000000", "version": "5.33.0"},
    "server": {"uptime": "3600", "poll": "120", "startdelay": "0",
               "localhostname": "fw1", "controlfile": "/usr/local/etc/monitrc"},
    "platform": {"name": "FreeBSD", "release": "14.1", "cpu": "4", "memory": "8388608"},
    "service": [
      {"@attributes": {"type": "5"}, "name": "$HOST", "collected_sec": "1700000060",
       "status": "0", "status_hint": "0", "monitor": "1", "monitormode": "0",
       "onreboot": "0", "pendingaction": "0"},
      {"@attributes": {"type": "3"}, "name": "nginx", "collected_sec": "1700000060",
       "status": "512", "status_hint": "0", "monitor": "1", "monitormode": "0",
       "onreboot": "0", "pendingaction": "0"}
    ]
  }
}`

// monitDownFixture is the live-validated shape returned by api/monit/status/get/xml
// on OPNsense 26.1 when monit is installed but not running (validated 2026-06-09).
// The exact wording of the message is preserved here so the fixture matches the box.
const monitDownFixture = `{"result": "failed",
 "status": "\nEither the file /var/run/monit.sock does not exists or it is not a unix socket.\nPlease check if the Monit service is running.\n\nIf you have started Monit recently, wait for StartDelay seconds and refresh this page."}`

// monitSingleServiceFixture exercises the simplexml single-child-as-object quirk:
// when there is exactly one service, it is serialised as a JSON object, not an array.
const monitSingleServiceFixture = `{
  "result": "ok",
  "status": {
    "service": {"@attributes": {"type": "5"}, "name": "$HOST",
                "status": "0", "monitor": "1", "monitormode": "0",
                "pendingaction": "0"}
  }
}`

func TestFetchMonitStatus_Running(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitRunningFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.StatusOK {
		t.Fatal("expected StatusOK=true for running monit")
	}
	if len(data.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(data.Checks))
	}

	// Find checks by name.
	checks := map[string]MonitCheck{}
	for _, c := range data.Checks {
		checks[c.Name] = c
	}

	host, ok := checks["$HOST"]
	if !ok {
		t.Fatal("expected $HOST check")
	}
	if host.Type != "system" {
		t.Errorf("expected $HOST type=system, got %q", host.Type)
	}
	if host.StatusOK != 1 {
		t.Errorf("expected $HOST StatusOK=1, got %v", host.StatusOK)
	}
	if host.Monitored != 1 {
		t.Errorf("expected $HOST Monitored=1, got %v", host.Monitored)
	}

	nginx, ok := checks["nginx"]
	if !ok {
		t.Fatal("expected nginx check")
	}
	if nginx.Type != "process" {
		t.Errorf("expected nginx type=process, got %q", nginx.Type)
	}
	if nginx.StatusOK != 0 {
		t.Errorf("expected nginx StatusOK=0 (status=512), got %v", nginx.StatusOK)
	}
	if nginx.Monitored != 1 {
		t.Errorf("expected nginx Monitored=1, got %v", nginx.Monitored)
	}
}

func TestFetchMonitStatus_SingleServiceObject(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitSingleServiceFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.StatusOK {
		t.Fatal("expected StatusOK=true")
	}
	if len(data.Checks) != 1 {
		t.Fatalf("expected 1 check (single object, not array), got %d", len(data.Checks))
	}
	c := data.Checks[0]
	if c.Name != "$HOST" {
		t.Errorf("expected name=$HOST, got %q", c.Name)
	}
	if c.Type != "system" {
		t.Errorf("expected type=system, got %q", c.Type)
	}
	if c.StatusOK != 1 {
		t.Errorf("expected StatusOK=1, got %v", c.StatusOK)
	}
}

func TestFetchMonitStatus_Down(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitDownFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("expected nil error when monit is down, got: %v", err)
	}
	if data.StatusOK {
		t.Error("expected StatusOK=false when result=failed")
	}
	if len(data.Checks) != 0 {
		t.Errorf("expected 0 checks when monit is down, got %d", len(data.Checks))
	}
}

func TestFetchMonitStatus_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.StatusOK {
		t.Error("expected StatusOK=false on 404")
	}
	if len(data.Checks) != 0 {
		t.Errorf("expected 0 checks on 404, got %d", len(data.Checks))
	}
}

// monitResourceFixture is the RAW capture from a live OPNsense 26.7-devel box
// (2026-07-13) with one check of each of the four resource-bearing types
// provisioned in a single status/get/xml payload: type 5 system
// ("opnsense-devel.internal"), type 0 filesystem ("RootFs"), type 4 host
// ("TestLxcHost", icmp + one port test), and type 3 process
// ("ConfigdProcess"). See scratchpad captures/monit/status_get_xml.json for
// provenance. The process check's cpu.percent reads "-1.0" — monit's
// not-yet-computed sentinel before its second poll cycle — preserved as-is.
const monitResourceFixture = `{"result":"ok","status":{"server":{"id":"562352efdd23b9523497e6d7fee623c8","incarnation":"1783962711","version":"5.35.2","uptime":"27","poll":"120","startdelay":"120","localhostname":"opnsense-devel.internal","controlfile":"/usr/local/etc/monitrc","httpd":{"unixsocket":"/var/run/monit.sock"}},"platform":{"name":"FreeBSD","release":"15.1-RELEASE-p1","version":"FreeBSD 15.1-RELEASE-p1 stable/26.7-n283669-9664a203d589 SMP","machine":"amd64","cpu":"4","memory":"8345052","swap":"8388608"},"service":[{"@attributes":{"type":"5"},"name":"opnsense-devel.internal","collected_sec":"1783962711","collected_usec":"270742","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","uptime":"82799","boottime":"1783879939","filedescriptors":{"allocated":"826","unused":"0","maximum":"260782"},"system":{"load":{"avg01":"0.06","avg05":"0.16","avg15":"0.15"},"cpu":{"user":"1.7","system":"0.6","nice":"0.0","hardirq":"0.0"},"memory":{"percent":"17.7","kilobyte":"1479740"},"swap":{"percent":"0.0","kilobyte":"0"}}},{"@attributes":{"type":"0"},"name":"RootFs","collected_sec":"1783962711","collected_usec":"270844","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","fstype":"ufs","fsflags":"journaled soft updates, soft updates, local, rootfs","mode":"755","uid":"0","gid":"0","block":{"percent":"8.4","usage":"4492.3","total":"53292.2"},"inode":{"percent":"1.6","usage":"112539","total":"7051262"},"read":{"bytes":{"count":"0","total":"2418515456"},"operations":{"count":"0","total":"99232"}},"write":{"bytes":{"count":"0","total":"17453239296"},"operations":{"count":"0","total":"565679"}},"servicetime":{"read":"0.000","write":"0.000"}},{"@attributes":{"type":"4"},"name":"TestLxcHost","collected_sec":"1783962711","collected_usec":"283984","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","icmp":{"type":"Ping","responsetime":"0.000160"},"port":{"hostname":"172.16.20.117","portnumber":"22","request":{},"protocol":"SSH","type":"TCP","responsetime":"0.012940"}},{"@attributes":{"type":"3"},"name":"ConfigdProcess","collected_sec":"1783962711","collected_usec":"284014","status":"0","status_hint":"0","monitor":"1","monitormode":"0","onreboot":"0","pendingaction":"0","pid":"552","ppid":"1","uid":"0","euid":"0","gid":"0","uptime":"143","threads":"1","children":"2","memory":{"percent":"0.2","percenttotal":"0.9","kilobyte":"17648","kilobytetotal":"76796"},"cpu":{"percent":"-1.0","percenttotal":"-1.0"},"filedescriptors":{"open":"0","opentotal":"0","limit":{"soft":"0","hard":"0"}},"read":{"operations":{"count":"0","total":"0"}},"write":{"operations":{"count":"0","total":"0"}}}]}}`

func fetchMonitResourceFixtureChecks(t *testing.T) map[string]MonitCheck {
	t.Helper()
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/monit/status/get/xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(monitResourceFixture))
	})

	data, err := client.FetchMonitStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.StatusOK {
		t.Fatal("expected StatusOK=true")
	}
	if len(data.Checks) != 4 {
		t.Fatalf("expected 4 checks, got %d", len(data.Checks))
	}

	checks := map[string]MonitCheck{}
	for _, c := range data.Checks {
		checks[c.Name] = c
	}
	return checks
}

func TestFetchMonitStatus_FilesystemResource(t *testing.T) {
	checks := fetchMonitResourceFixtureChecks(t)

	fs, ok := checks["RootFs"]
	if !ok {
		t.Fatal("expected RootFs check")
	}
	if fs.Type != "filesystem" {
		t.Fatalf("expected type=filesystem, got %q", fs.Type)
	}
	if fs.FilesystemUsagePercent == nil {
		t.Fatal("expected FilesystemUsagePercent to be set")
	}
	if *fs.FilesystemUsagePercent != 8.4 {
		t.Errorf("expected FilesystemUsagePercent=8.4, got %v", *fs.FilesystemUsagePercent)
	}
	if fs.FilesystemInodeUsagePercent == nil {
		t.Fatal("expected FilesystemInodeUsagePercent to be set")
	}
	if *fs.FilesystemInodeUsagePercent != 1.6 {
		t.Errorf("expected FilesystemInodeUsagePercent=1.6, got %v", *fs.FilesystemInodeUsagePercent)
	}

	// Fields that only apply to other check types must stay unset.
	if fs.ProcessCPUPercent != nil || fs.ICMPResponseSeconds != nil || fs.SystemLoad1 != nil {
		t.Error("expected non-filesystem resource fields to be nil on a filesystem check")
	}
}

func TestFetchMonitStatus_ProcessResource(t *testing.T) {
	checks := fetchMonitResourceFixtureChecks(t)

	proc, ok := checks["ConfigdProcess"]
	if !ok {
		t.Fatal("expected ConfigdProcess check")
	}
	if proc.Type != "process" {
		t.Fatalf("expected type=process, got %q", proc.Type)
	}

	// cpu.percent is monit's "-1" not-yet-computed sentinel in this capture:
	// must be treated as absent, not a real (negative) reading.
	if proc.ProcessCPUPercent != nil {
		t.Errorf("expected ProcessCPUPercent nil for -1 sentinel, got %v", *proc.ProcessCPUPercent)
	}

	if proc.ProcessMemoryBytes == nil {
		t.Fatal("expected ProcessMemoryBytes to be set")
	}
	if want := 17648.0 * 1024; *proc.ProcessMemoryBytes != want {
		t.Errorf("expected ProcessMemoryBytes=%v, got %v", want, *proc.ProcessMemoryBytes)
	}

	if proc.ProcessUptimeSeconds == nil || *proc.ProcessUptimeSeconds != 143 {
		t.Errorf("expected ProcessUptimeSeconds=143, got %v", proc.ProcessUptimeSeconds)
	}
	if proc.ProcessThreads == nil || *proc.ProcessThreads != 1 {
		t.Errorf("expected ProcessThreads=1, got %v", proc.ProcessThreads)
	}
}

func TestFetchMonitStatus_HostResource(t *testing.T) {
	checks := fetchMonitResourceFixtureChecks(t)

	host, ok := checks["TestLxcHost"]
	if !ok {
		t.Fatal("expected TestLxcHost check")
	}
	if host.Type != "host" {
		t.Fatalf("expected type=host, got %q", host.Type)
	}

	if host.ICMPResponseSeconds == nil {
		t.Fatal("expected ICMPResponseSeconds to be set")
	}
	if *host.ICMPResponseSeconds != 0.000160 {
		t.Errorf("expected ICMPResponseSeconds=0.000160, got %v", *host.ICMPResponseSeconds)
	}

	if len(host.Ports) != 1 {
		t.Fatalf("expected 1 port check, got %d", len(host.Ports))
	}
	port := host.Ports[0]
	if port.Port != "22" {
		t.Errorf("expected port=22, got %q", port.Port)
	}
	if port.Protocol != "SSH" {
		t.Errorf("expected protocol=SSH, got %q", port.Protocol)
	}
	if port.ResponseSeconds != 0.012940 {
		t.Errorf("expected port ResponseSeconds=0.012940, got %v", port.ResponseSeconds)
	}
}

func TestFetchMonitStatus_SystemResource(t *testing.T) {
	checks := fetchMonitResourceFixtureChecks(t)

	sys, ok := checks["opnsense-devel.internal"]
	if !ok {
		t.Fatal("expected opnsense-devel.internal check")
	}
	if sys.Type != "system" {
		t.Fatalf("expected type=system, got %q", sys.Type)
	}

	for name, got := range map[string]*float64{
		"SystemLoad1":  sys.SystemLoad1,
		"SystemLoad5":  sys.SystemLoad5,
		"SystemLoad15": sys.SystemLoad15,
	} {
		if got == nil {
			t.Fatalf("expected %s to be set", name)
		}
	}
	if *sys.SystemLoad1 != 0.06 {
		t.Errorf("expected SystemLoad1=0.06, got %v", *sys.SystemLoad1)
	}
	if *sys.SystemLoad5 != 0.16 {
		t.Errorf("expected SystemLoad5=0.16, got %v", *sys.SystemLoad5)
	}
	if *sys.SystemLoad15 != 0.15 {
		t.Errorf("expected SystemLoad15=0.15, got %v", *sys.SystemLoad15)
	}

	if sys.SystemMemoryPercent == nil || *sys.SystemMemoryPercent != 17.7 {
		t.Errorf("expected SystemMemoryPercent=17.7, got %v", sys.SystemMemoryPercent)
	}
	if sys.SystemSwapPercent == nil || *sys.SystemSwapPercent != 0.0 {
		t.Errorf("expected SystemSwapPercent=0.0, got %v", sys.SystemSwapPercent)
	}

	// FreeBSD monit reports user/system/nice/hardirq modes (no "wait" —
	// that's Linux-only); the map must reflect exactly what was present,
	// not a hardcoded mode set.
	wantModes := map[string]float64{"user": 1.7, "system": 0.6, "nice": 0.0, "hardirq": 0.0}
	if len(sys.SystemCPU) != len(wantModes) {
		t.Fatalf("expected %d cpu modes, got %d: %v", len(wantModes), len(sys.SystemCPU), sys.SystemCPU)
	}
	for mode, want := range wantModes {
		got, ok := sys.SystemCPU[mode]
		if !ok {
			t.Errorf("expected cpu mode %q to be present", mode)
			continue
		}
		if got != want {
			t.Errorf("cpu mode %q: expected %v, got %v", mode, want, got)
		}
	}
	if _, ok := sys.SystemCPU["wait"]; ok {
		t.Error("did not expect a Linux-only 'wait' cpu mode from a FreeBSD box")
	}
}
