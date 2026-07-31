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
          "requestMsecCounter": 90000,
          "responses": {"1xx":0,"2xx":1,"3xx":0,"4xx":0,"5xx":0,
                        "miss":0,"bypass":0,"expired":0,"stale":0,
                        "updating":0,"revalidated":0,"hit":0,"scarce":0}},
    "example.com": {"requestCounter": 4000, "inBytes": 123456, "outBytes": 654321,
          "requestMsecCounter": 80000,
          "responses": {"1xx":0,"2xx":3800,"3xx":100,"4xx":80,"5xx":20,
                        "miss":5,"bypass":0,"expired":0,"stale":0,
                        "updating":0,"revalidated":0,"hit":20,"scarce":0}}
  },
  "upstreamZones": {
    "backend_pool": [
      {"server": "10.0.0.10:8080", "requestCounter": 2000,
       "inBytes": 60000, "outBytes": 300000,
       "responses": {"1xx":0,"2xx":1900,"3xx":50,"4xx":40,"5xx":10},
       "responseMsec": 35, "requestMsec": 36,
       "requestMsecCounter": 70000, "responseMsecCounter": 65000,
       "weight": 1, "maxFails": 1, "failTimeout": 10,
       "backup": false, "down": false}
    ]
  },
  "cacheZones": {
    "abc123cachezoneuuid": {
      "maxSize": 53687091200, "usedSize": 4096, "inBytes": 1909, "outBytes": 4158,
      "responses": {"miss":3,"bypass":0,"expired":0,"stale":0,
                    "updating":0,"revalidated":0,"hit":20,"scarce":0}
    }
  }
}`

const nginxCollectorBansFixture = `{
  "rows": [{"uuid":"74ee3555-68fd-4cd9-98c6-0b5fe63ff2b2","ip":"172.16.9.99","time":"1700000030"}],
  "rowCount": 1, "total": 1, "current": 1
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
	mux.HandleFunc("/api/nginx/bans/searchban", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nginxCollectorBansFixture))
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
	//     1 counter (request_seconds_total)
	//     8 cache-status counters (hit/miss/bypass/expired/stale/updating/revalidated/scarce)
	//   per upstream server "backend_pool / 10.0.0.10:8080":
	//     3 counters (requests_total, bytes_in_total, bytes_out_total)
	//     5 code counters (1xx..5xx)
	//     1 gauge (down)
	//     1 gauge (response_time_seconds)
	//     2 counters (request_seconds_total, response_seconds_total)
	//   per cache zone "abc123cachezoneuuid":
	//     2 gauges (max_bytes, used_bytes)
	//     2 counters (bytes_in_total, bytes_out_total)
	//     8 cache-status counters
	//   1 config_load_timestamp_seconds gauge
	//   1 service_running gauge
	//   2 ban gauges (bans, ban_last_timestamp_seconds)
	//   2 counter_wraps_total counters (#584): 1 per server zone, 1 per upstream server
	// total = 4+3+3 + (8+1+8) + (10+2) + (12) + 1 + 1 + 2 + 2 = 57
	expected := 57
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
		case strings.Contains(desc, "nginx_server_zone_request_seconds_total"):
			if labels["zone"] == "example.com" && val != 80 {
				t.Errorf("server_zone_request_seconds_total{zone=example.com}: want 80, got %v", val)
			}
		case strings.Contains(desc, "nginx_server_zone_cache_responses_total"):
			if labels["zone"] == "example.com" && labels["cache_status"] == "hit" && val != 20 {
				t.Errorf("server_zone_cache_responses_total{zone=example.com,cache_status=hit}: want 20, got %v", val)
			}
		case strings.Contains(desc, "nginx_upstream_server_down"):
			if labels["upstream"] == "backend_pool" && labels["server"] == "10.0.0.10:8080" && val != 0 {
				t.Errorf("upstream_server_down: want 0, got %v", val)
			}
		case strings.Contains(desc, "nginx_upstream_server_response_time_seconds"):
			if val < 0.034 || val > 0.036 {
				t.Errorf("upstream_server_response_time_seconds: want ~0.035, got %v", val)
			}
		case strings.Contains(desc, "nginx_upstream_server_request_seconds_total"):
			if val != 70 {
				t.Errorf("upstream_server_request_seconds_total: want 70, got %v", val)
			}
		case strings.Contains(desc, "nginx_upstream_server_response_seconds_total"):
			if val != 65 {
				t.Errorf("upstream_server_response_seconds_total: want 65, got %v", val)
			}
		case strings.Contains(desc, "nginx_cache_zone_used_bytes"):
			if labels["zone"] != "abc123cachezoneuuid" || val != 4096 {
				t.Errorf("cache_zone_used_bytes: want zone=abc123cachezoneuuid val=4096, got zone=%s val=%v",
					labels["zone"], val)
			}
		case strings.Contains(desc, "nginx_cache_zone_responses_total"):
			if labels["cache_status"] == "miss" && val != 3 {
				t.Errorf("cache_zone_responses_total{cache_status=miss}: want 3, got %v", val)
			}
		case strings.Contains(desc, "nginx_config_load_timestamp_seconds"):
			if val != 1700000000 {
				t.Errorf("config_load_timestamp_seconds: want 1700000000, got %v", val)
			}
		case strings.Contains(desc, "nginx_bans\""):
			if val != 1 {
				t.Errorf("bans: want 1, got %v", val)
			}
		case strings.Contains(desc, "nginx_ban_last_timestamp_seconds"):
			if val != 1700000030 {
				t.Errorf("ban_last_timestamp_seconds: want 1700000030, got %v", val)
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
		case strings.Contains(desc, "nginx_server_zone_counter_wraps_total"),
			strings.Contains(desc, "nginx_upstream_server_counter_wraps_total"):
			// #584: fixture carries no overCounts key -- zero is the correct
			// "never wrapped" reading, emitted unconditionally like every
			// other zone/upstream counter in this collector.
			if val != 0 {
				t.Errorf("%s: want 0 (absent overCounts in fixture), got %v (labels=%v)", desc, val, labels)
			}
		}
	}
}

func TestNginxCollector_Update_NoCacheNoBans(t *testing.T) {
	// Fresh install / no proxy_cache_path configured and no active bans:
	// cacheZones absent from the vts payload, bans endpoint answers 200 with
	// an empty rowset (matches the real dev-box baseline capture, not a 404).
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
		  "loadMsec": 1700000000000,
		  "connections": {"active": 0, "reading": 0, "writing": 0, "waiting": 0,
		                  "accepted": 0, "handled": 0, "requests": 0},
		  "sharedZones": {"name": "vts", "maxSize": 1048575, "usedSize": 0, "usedNode": 0},
		  "serverZones": {
		    "*": {"requestCounter": 0, "inBytes": 0, "outBytes": 0,
		          "responses": {"1xx":0,"2xx":0,"3xx":0,"4xx":0,"5xx":0}}
		  },
		  "upstreamZones": {}
		}`))
	})
	mux.HandleFunc("/api/nginx/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	mux.HandleFunc("/api/nginx/bans/searchban", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nginxCollector{subsystem: NginxSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "nginx_cache_zone_"):
			t.Errorf("expected no cache_zone metrics with no cacheZones configured, got %s", desc)
		case strings.Contains(desc, "nginx_server_zone_cache_responses_total"):
			t.Errorf("expected no server_zone_cache_responses_total with cache-status extension absent, got %s", desc)
		case strings.Contains(desc, "nginx_ban_last_timestamp_seconds"):
			t.Errorf("expected no ban_last_timestamp_seconds when there are no active bans, got %s", desc)
		case strings.Contains(desc, "nginx_bans\""):
			if val != 0 {
				t.Errorf("bans: want 0 (present, zero count), got %v", val)
			}
		}
	}
}

func TestNginxCollector_Update_BansEndpointAbsentWhileVTSPresent(t *testing.T) {
	// Independent controllers: a 404 on bans/searchban while VTS answers fine
	// must not drop the whole scrape — just the ban metrics.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nginxCollectorVtsFixture))
	})
	mux.HandleFunc("/api/nginx/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	// no bans handler registered -> 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nginxCollector{subsystem: NginxSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) == 0 {
		t.Fatal("expected VTS metrics even though bans endpoint 404s")
	}
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "nginx_bans\"") || strings.Contains(desc, "nginx_ban_last_timestamp_seconds") {
			t.Errorf("expected no ban metrics when bans endpoint is absent, got %s", desc)
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

// TestNginxCollector_CounterWraps guards #584: overCounts must surface as a
// COUNTER (nginx-module-vts's ngx_http_vhost_traffic_status_add_oc()
// increments it, itself monotonically increasing -- never a gauge), split
// into server_zone_counter_wraps_total / upstream_server_counter_wraps_total
// to match this collector's existing server_zone_* / upstream_server_*
// naming split for every other stat, rather than one shared metric that
// cannot cleanly label both a zone name and an (upstream, server) pair.
func TestNginxCollector_CounterWraps(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
		  "connections": {"active": 1, "reading": 0, "writing": 0, "waiting": 0,
		                  "accepted": 1, "handled": 1, "requests": 1},
		  "sharedZones": {"maxSize": 1, "usedSize": 1, "usedNode": 1},
		  "serverZones": {
		    "example.com": {"requestCounter": 1, "inBytes": 1, "outBytes": 1,
		          "overCounts": 3,
		          "responses": {"1xx":0,"2xx":1,"3xx":0,"4xx":0,"5xx":0}}
		  },
		  "upstreamZones": {
		    "backend_pool": [
		      {"server": "10.0.0.10:8080", "requestCounter": 1, "inBytes": 1, "outBytes": 1,
		       "responses": {"1xx":0,"2xx":1,"3xx":0,"4xx":0,"5xx":0},
		       "overCounts": 7, "down": false}
		    ]
		  }
		}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &nginxCollector{subsystem: NginxSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var sawServerZone, sawUpstream bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if strings.Contains(desc, `fqName: "opnsense_nginx_server_zone_counter_wraps_total"`) {
			sawServerZone = true
			if labels["zone"] != "example.com" {
				t.Errorf("expected zone=example.com, got %q", labels["zone"])
			}
			if v := getMetricValue(m); v != 3 {
				t.Errorf("expected server_zone_counter_wraps_total=3, got %v", v)
			}
		}
		if strings.Contains(desc, `fqName: "opnsense_nginx_upstream_server_counter_wraps_total"`) {
			sawUpstream = true
			if labels["upstream"] != "backend_pool" || labels["server"] != "10.0.0.10:8080" {
				t.Errorf("expected upstream=backend_pool server=10.0.0.10:8080, got %+v", labels)
			}
			if v := getMetricValue(m); v != 7 {
				t.Errorf("expected upstream_server_counter_wraps_total=7, got %v", v)
			}
		}
	}
	if !sawServerZone {
		t.Error("expected opnsense_nginx_server_zone_counter_wraps_total to be emitted")
	}
	if !sawUpstream {
		t.Error("expected opnsense_nginx_upstream_server_counter_wraps_total to be emitted")
	}
}

func TestNginxCollector_Name(t *testing.T) {
	c := &nginxCollector{subsystem: NginxSubsystem}
	if c.Name() != NginxSubsystem {
		t.Errorf("expected %s, got %s", NginxSubsystem, c.Name())
	}
}
