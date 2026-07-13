package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

const haproxyCollectorCountersFixture = `[
  {"pxname":"web_frontend","svname":"FRONTEND","scur":"3","stot":"5000","bin":"123456","bout":"654321","dreq":"7","ereq":"42","status":"OPEN","type":"0","hrsp_1xx":"0","hrsp_2xx":"4800","hrsp_3xx":"100","hrsp_4xx":"80","hrsp_5xx":"20","hrsp_other":"0","id":"web_frontend/FRONTEND"},
  {"pxname":"web_backend","svname":"srv1","qcur":"0","scur":"2","stot":"3000","bin":"100000","bout":"500000","econ":"3","eresp":"5","wretr":"9","wredis":"1","status":"DOWN","weight":"100","act":"1","bck":"0","chkfail":"2","downtime":"120","type":"2","id":"web_backend/srv1"},
  {"pxname":"web_backend","svname":"BACKEND","qcur":"1","scur":"2","stot":"3000","bin":"100000","bout":"500000","econ":"3","eresp":"5","wretr":"9","wredis":"1","status":"UP","act":"1","bck":"0","type":"1","hrsp_1xx":"0","hrsp_2xx":"2900","hrsp_3xx":"50","hrsp_4xx":"40","hrsp_5xx":"10","hrsp_other":"0","id":"web_backend/BACKEND"}
]`

func haproxyCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/haproxy/statistics/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(haproxyCollectorCountersFixture))
	})
	mux.HandleFunc("/api/haproxy/statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Name":"HAProxy","Version":"2.8.3","Uptime_sec":"86400","CurrConns":"4","CumConns":"9876","CumReq":"55555","Idle_pct":"99"}`))
	})
	mux.HandleFunc("/api/haproxy/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

func TestHAProxyCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(haproxyCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &haproxyCollector{subsystem: HAProxySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// process: uptime + currconns + conns_total + reqs_total + idle = 5
	// frontend: status + scur + stot + bin + bout + ereq + dreq + 6 codes = 13
	// backend:  status + scur + stot + bin + bout + qcur + econ + eresp +
	//           wretr + wredis + act + bck + 6 codes = 18
	// server:   status + scur + stot + bin + bout + qcur + econ + eresp +
	//           chkfail + downtime + weight = 11
	// service_running = 1
	expected := 5 + 13 + 18 + 11 + 1
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "haproxy_frontend_status"):
			if labels["frontend"] != "web_frontend" || val != 1 {
				t.Errorf("frontend_status wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "haproxy_server_status"):
			if labels["backend"] != "web_backend" || labels["server"] != "srv1" || val != 0 {
				t.Errorf("server_status wrong: labels=%v val=%v", labels, val)
			}
		case strings.Contains(desc, "haproxy_backend_http_responses_total"):
			if labels["code"] == "2xx" && val != 2900 {
				t.Errorf("backend 2xx wrong: %v", val)
			}
		case strings.Contains(desc, "haproxy_service_running"):
			if val != 1 {
				t.Errorf("service_running wrong: %v", val)
			}
		}
	}
}

func TestHAProxyCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers → all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &haproxyCollector{subsystem: HAProxySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

// TestHAProxyCollector_Update_TCPModeNoResponseCodes guards #164: a tcp-mode
// proxy (empty hrsp_* cells) must not emit any http_responses_total series.
func TestHAProxyCollector_Update_TCPModeNoResponseCodes(t *testing.T) {
	const fixture = `[
	  {"pxname":"smtp_frontend","svname":"FRONTEND","scur":"3","stot":"5000","bin":"1","bout":"2","dreq":"0","ereq":"0","status":"OPEN","type":"0","hrsp_1xx":"","hrsp_2xx":"","hrsp_3xx":"","hrsp_4xx":"","hrsp_5xx":"","hrsp_other":"","id":"smtp_frontend/FRONTEND"},
	  {"pxname":"smtp_backend","svname":"BACKEND","scur":"2","stot":"3000","bin":"1","bout":"2","econ":"0","eresp":"0","wretr":"0","wredis":"0","status":"UP","act":"1","bck":"0","type":"1","hrsp_1xx":"","hrsp_2xx":"","hrsp_3xx":"","hrsp_4xx":"","hrsp_5xx":"","hrsp_other":"","id":"smtp_backend/BACKEND"}
	]`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/haproxy/statistics/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	})
	mux.HandleFunc("/api/haproxy/statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Name":"HAProxy","Version":"2.8.3","Uptime_sec":"1","CurrConns":"0","CumConns":"0","CumReq":"0","Idle_pct":"100"}`))
	})
	mux.HandleFunc("/api/haproxy/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &haproxyCollector{subsystem: HAProxySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "http_responses_total") {
			t.Errorf("no http_responses_total series should be emitted for a tcp-mode proxy, got %s with labels %v", m.Desc().String(), getMetricLabels(m))
		}
	}
}

func TestHAProxyCollector_Name(t *testing.T) {
	c := &haproxyCollector{subsystem: HAProxySubsystem}
	if c.Name() != HAProxySubsystem {
		t.Errorf("expected %s, got %s", HAProxySubsystem, c.Name())
	}
}

// haproxyExtendedFieldsFixture is a trimmed replica of a real dev-box capture
// (issue #201, captures/haproxy/stats_counters_populated.json): a frontend +
// a 2-server HTTP backend, carrying qtime/ctime/rtime/ttime, slim, req_tot,
// lbtot and cli_abrt/srv_abrt.
const haproxyExtendedFieldsFixture = `[
  {"pxname":"ft-heavy","svname":"FRONTEND","scur":"0","stot":"179","slim":"117337","dreq":"0","ereq":"0","req_tot":"179","status":"OPEN","type":"0","hrsp_2xx":"179","id":"ft-heavy/FRONTEND"},
  {"pxname":"bk-heavy","svname":"heavy-1","qcur":"0","scur":"0","stot":"179","bin":"14678","bout":"34368","status":"UP","weight":"1","act":"1","bck":"0","chkfail":"0","chkdown":"0","lastchg":"54","downtime":"0","type":"2","qtime":"0","ctime":"0","rtime":"1","ttime":"1","lbtot":"1","id":"bk-heavy/heavy-1"},
  {"pxname":"bk-heavy","svname":"BACKEND","qcur":"0","scur":"0","stot":"179","bin":"14678","bout":"34368","slim":"11734","status":"UP","weight":"2","act":"2","bck":"0","type":"1","qtime":"0","ctime":"0","rtime":"1","ttime":"1","lbtot":"1","cli_abrt":"0","srv_abrt":"0","hrsp_2xx":"179","id":"bk-heavy/BACKEND"}
]`

func haproxyExtendedMux(t *testing.T, tablesFixture string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/haproxy/statistics/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(haproxyExtendedFieldsFixture))
	})
	mux.HandleFunc("/api/haproxy/statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Name":"HAProxy","Version":"3.2.21","Uptime_sec":"53","CurrConns":"0","CumConns":"232","CumReq":"232","Idle_pct":"100","Maxconn":"117337","CurrSslConns":"0"}`))
	})
	mux.HandleFunc("/api/haproxy/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	if tablesFixture != "" {
		mux.HandleFunc("/api/haproxy/statistics/tables", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(tablesFixture))
		})
	}
	return mux
}

// metricsByName indexes collected metrics by their fq metric name (the part
// of Desc().String() between the first pair of quotes) for easy lookup.
func metricsByName(t *testing.T, metrics []prometheus.Metric) map[string][]prometheus.Metric {
	t.Helper()
	out := map[string][]prometheus.Metric{}
	for _, m := range metrics {
		desc := m.Desc().String()
		start := strings.Index(desc, `"`)
		end := strings.Index(desc[start+1:], `"`)
		name := desc[start+1 : start+1+end]
		out[name] = append(out[name], m)
	}
	return out
}

// TestHAProxyCollector_Update_ExtendedFieldsAndStickTables guards issue #201:
// the show-stat latency/health-transition/capacity fields and stick-table
// occupancy metrics, using a trimmed replica of a real dev-box capture.
func TestHAProxyCollector_Update_ExtendedFieldsAndStickTables(t *testing.T) {
	const tablesFixture = `[{"table":"bk-heavy","type":"ip","size":"51200","used":"1"},{"table":"ft-heavy","type":"ip","size":"102400","used":"0"}]`
	server := httptest.NewServer(haproxyExtendedMux(t, tablesFixture))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &haproxyCollector{subsystem: HAProxySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	byName := metricsByName(t, metrics)

	assertGauge := func(name string, wantLabels map[string]string, wantValue float64) {
		t.Helper()
		found := byName[name]
		if len(found) == 0 {
			t.Fatalf("expected at least one %s series, got none", name)
		}
		for _, m := range found {
			labels := getMetricLabels(m)
			match := true
			for k, v := range wantLabels {
				if labels[k] != v {
					match = false
					break
				}
			}
			if match {
				if got := getMetricValue(m); got != wantValue {
					t.Errorf("%s{%v} = %v, want %v", name, wantLabels, got, wantValue)
				}
				return
			}
		}
		t.Errorf("no %s series matched labels %v (have %d series)", name, wantLabels, len(found))
	}

	assertGauge("opnsense_haproxy_connection_limit", nil, 117337)
	assertGauge("opnsense_haproxy_ssl_current_connections", nil, 0)
	assertGauge("opnsense_haproxy_frontend_requests_total", map[string]string{"frontend": "ft-heavy"}, 179)
	assertGauge("opnsense_haproxy_frontend_session_limit", map[string]string{"frontend": "ft-heavy"}, 117337)
	assertGauge("opnsense_haproxy_backend_response_time_avg_seconds", map[string]string{"backend": "bk-heavy"}, 0.001)
	assertGauge("opnsense_haproxy_backend_selected_total", map[string]string{"backend": "bk-heavy"}, 1)
	assertGauge("opnsense_haproxy_backend_aborts_total", map[string]string{"backend": "bk-heavy", "side": "client"}, 0)
	assertGauge("opnsense_haproxy_backend_aborts_total", map[string]string{"backend": "bk-heavy", "side": "server"}, 0)
	assertGauge("opnsense_haproxy_server_response_time_avg_seconds", map[string]string{"backend": "bk-heavy", "server": "heavy-1"}, 0.001)
	assertGauge("opnsense_haproxy_server_check_downs_total", map[string]string{"backend": "bk-heavy", "server": "heavy-1"}, 0)
	assertGauge("opnsense_haproxy_server_last_state_change_seconds", map[string]string{"backend": "bk-heavy", "server": "heavy-1"}, 54)
	assertGauge("opnsense_haproxy_stick_table_size", map[string]string{"table": "bk-heavy", "type": "ip"}, 51200)
	assertGauge("opnsense_haproxy_stick_table_used", map[string]string{"table": "bk-heavy", "type": "ip"}, 1)
	assertGauge("opnsense_haproxy_stick_table_used", map[string]string{"table": "ft-heavy", "type": "ip"}, 0)
}

// TestHAProxyCollector_Update_CheckDownTransition guards the live DOWN
// transition captured for #201 (stats_counters_chkdown.json).
func TestHAProxyCollector_Update_CheckDownTransition(t *testing.T) {
	const fixture = `[
	  {"pxname":"bk-heavy","svname":"heavy-2","qcur":"0","scur":"0","stot":"0","bin":"0","bout":"0","status":"DOWN","weight":"1","act":"1","bck":"0","chkfail":"1","chkdown":"1","lastchg":"12","downtime":"12","type":"2","qtime":"0","ctime":"0","rtime":"0","ttime":"0","lbtot":"0","id":"bk-heavy/heavy-2"}
	]`
	mux := http.NewServeMux()
	mux.HandleFunc("/api/haproxy/statistics/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	})
	mux.HandleFunc("/api/haproxy/statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Name":"HAProxy","Version":"3.2.21","Uptime_sec":"1","CurrConns":"0","CumConns":"0","CumReq":"0","Idle_pct":"100"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &haproxyCollector{subsystem: HAProxySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	byName := metricsByName(t, metrics)

	for _, m := range byName["opnsense_haproxy_server_status"] {
		if getMetricValue(m) != 0 {
			t.Errorf("expected server_status=0 for DOWN, got %v", getMetricValue(m))
		}
	}
	for _, m := range byName["opnsense_haproxy_server_check_downs_total"] {
		if getMetricValue(m) != 1 {
			t.Errorf("expected server_check_downs_total=1, got %v", getMetricValue(m))
		}
	}
	for _, m := range byName["opnsense_haproxy_server_last_state_change_seconds"] {
		if getMetricValue(m) != 12 {
			t.Errorf("expected server_last_state_change_seconds=12, got %v", getMetricValue(m))
		}
	}
}
