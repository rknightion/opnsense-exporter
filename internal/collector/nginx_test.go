package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

const nginxCollectorVtsFixture = `{
  "hostName": "fw1",
  "nginxVersion": "1.26.0",
  "loadMsec": 1700000000000,
  "nowMsec": 1700000060000,
  "connections": {"active": 2, "reading": 0, "writing": 1, "waiting": 1,
                  "accepted": 1000, "handled": 1000, "requests": 5000},
  "sharedZones": {"name": "ngx_http_vhost_traffic_status",
                  "maxSize": 1048575, "usedSize": 4096, "usedNode": 3},
  "serverZones": {
    "*": {"requestCounter": 5000, "inBytes": 1, "outBytes": 1,
          "responses": {"1xx":0,"2xx":1,"3xx":0,"4xx":0,"5xx":0}},
    "example.com": {"requestCounter": 4000, "inBytes": 123456, "outBytes": 654321,
          "responses": {"1xx":0,"2xx":3800,"3xx":100,"4xx":80,"5xx":20}}
  },
  "upstreamZones": {
    "backend_pool": [
      {"server": "10.0.0.10:8080", "requestCounter": 2000,
       "inBytes": 60000, "outBytes": 300000,
       "responses": {"1xx":0,"2xx":1900,"3xx":50,"4xx":40,"5xx":10},
       "responseMsec": 35, "requestMsec": 36,
       "weight": 1, "maxFails": 1, "failTimeout": 10,
       "backup": false, "down": false}
    ]
  }
}`

func nginxCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nginxCollectorVtsFixture))
	})
	mux.HandleFunc("/api/nginx/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	return mux
}

func TestNginxCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(nginxCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nginxCollector{subsystem: NginxSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected metric count breakdown:
	//   4 connection gauges:  active, reading, writing, waiting
	//   3 connection counters: accepted_total, handled_total, requests_total
	//   3 shared memory gauges: max_bytes, used_bytes, used_nodes
	//   per server zone "example.com":
	//     3 counters (requests_total, bytes_in_total, bytes_out_total)
	//     5 code counters (1xx..5xx)
	//   per upstream server "backend_pool / 10.0.0.10:8080":
	//     3 counters (requests_total, bytes_in_total, bytes_out_total)
	//     5 code counters (1xx..5xx)
	//     1 gauge (down)
	//     1 gauge (response_time_seconds)
	//   1 service_running gauge
	// total = 4+3+3+8+10+1 = 29
	expected := 29
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
		for _, m := range metrics {
			t.Logf("  %s", m.Desc().String())
		}
	}

	// Spot-check key values
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "nginx_server_zone_requests_total"):
			if labels["zone"] == "example.com" && val != 4000 {
				t.Errorf("server_zone_requests_total{zone=example.com}: want 4000, got %v", val)
			}
		case strings.Contains(desc, "nginx_upstream_server_down"):
			if labels["upstream"] == "backend_pool" && labels["server"] == "10.0.0.10:8080" && val != 0 {
				t.Errorf("upstream_server_down: want 0, got %v", val)
			}
		case strings.Contains(desc, "nginx_upstream_server_response_time_seconds"):
			if val < 0.034 || val > 0.036 {
				t.Errorf("upstream_server_response_time_seconds: want ~0.035, got %v", val)
			}
		case strings.Contains(desc, "nginx_service_running"):
			if val != 1 {
				t.Errorf("nginx_service_running: want 1, got %v", val)
			}
		case strings.Contains(desc, "nginx_connections_active"):
			if val != 2 {
				t.Errorf("nginx_connections_active: want 2, got %v", val)
			}
		case strings.Contains(desc, "nginx_server_zone_responses_total"):
			if labels["zone"] == "example.com" && labels["code"] == "2xx" && val != 3800 {
				t.Errorf("server_zone_responses_total{zone=example.com,code=2xx}: want 3800, got %v", val)
			}
		}
	}
}

func TestNginxCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers → all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nginxCollector{subsystem: NginxSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}

func TestNginxCollector_Name(t *testing.T) {
	c := &nginxCollector{subsystem: NginxSubsystem}
	if c.Name() != NginxSubsystem {
		t.Errorf("expected %s, got %s", NginxSubsystem, c.Name())
	}
}
