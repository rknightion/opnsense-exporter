package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestHAProxyCollector_Name(t *testing.T) {
	c := &haproxyCollector{subsystem: HAProxySubsystem}
	if c.Name() != HAProxySubsystem {
		t.Errorf("expected %s, got %s", HAProxySubsystem, c.Name())
	}
}
