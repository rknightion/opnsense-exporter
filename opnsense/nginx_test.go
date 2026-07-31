package opnsense

import (
	"net/http"
	"testing"
)

const nginxVtsFixture = `{
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
          "responses": {"1xx":0,"2xx":1,"3xx":0,"4xx":0,"5xx":0,
                        "miss":0,"bypass":0,"expired":0,"stale":0,
                        "updating":0,"revalidated":0,"hit":0,"scarce":0}},
    "example.com": {"requestCounter": 4000, "inBytes": 123456, "outBytes": 654321,
          "requestMsecCounter": 800000,
          "responses": {"1xx":0,"2xx":3800,"3xx":100,"4xx":80,"5xx":20,
                        "miss":0,"bypass":0,"expired":0,"stale":0,
                        "updating":0,"revalidated":0,"hit":0,"scarce":0}}
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

func TestFetchNginxVTS_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nginxVtsFixture))
	})

	data, err := client.FetchNginxVTS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true when vts endpoint responds")
	}

	// connections
	if data.ConnectionsActive != 2 {
		t.Errorf("ConnectionsActive: want 2, got %v", data.ConnectionsActive)
	}
	if data.ConnectionsWaiting != 1 {
		t.Errorf("ConnectionsWaiting: want 1, got %v", data.ConnectionsWaiting)
	}
	if data.ConnectionsAccepted != 1000 {
		t.Errorf("ConnectionsAccepted: want 1000, got %v", data.ConnectionsAccepted)
	}
	if data.RequestsTotal != 5000 {
		t.Errorf("RequestsTotal: want 5000, got %v", data.RequestsTotal)
	}

	// shared zones
	if data.SharedMaxBytes != 1048575 {
		t.Errorf("SharedMaxBytes: want 1048575, got %v", data.SharedMaxBytes)
	}
	if data.SharedUsedBytes != 4096 {
		t.Errorf("SharedUsedBytes: want 4096, got %v", data.SharedUsedBytes)
	}
	if data.SharedUsedNodes != 3 {
		t.Errorf("SharedUsedNodes: want 3, got %v", data.SharedUsedNodes)
	}

	// server zones: "*" excluded, only "example.com"
	if len(data.ServerZones) != 1 {
		t.Fatalf("expected 1 server zone (\"*\" excluded), got %d", len(data.ServerZones))
	}
	sz := data.ServerZones[0]
	if sz.Zone != "example.com" {
		t.Errorf("server zone name: want example.com, got %q", sz.Zone)
	}
	if sz.Requests != 4000 {
		t.Errorf("server zone Requests: want 4000, got %v", sz.Requests)
	}
	if sz.BytesIn != 123456 {
		t.Errorf("server zone BytesIn: want 123456, got %v", sz.BytesIn)
	}
	if sz.BytesOut != 654321 {
		t.Errorf("server zone BytesOut: want 654321, got %v", sz.BytesOut)
	}
	if sz.ResponsesByCode["2xx"] != 3800 {
		t.Errorf("server zone 2xx: want 3800, got %v", sz.ResponsesByCode["2xx"])
	}
	if sz.ResponsesByCode["5xx"] != 20 {
		t.Errorf("server zone 5xx: want 20, got %v", sz.ResponsesByCode["5xx"])
	}
	// #584: this fixture carries no overCounts key for "example.com" -- Go's
	// zero value (0) is the correct "never wrapped" reading, same convention
	// as every other vts counter here.
	if sz.CounterWraps != 0 {
		t.Errorf("server zone CounterWraps: want 0 (absent in fixture), got %v", sz.CounterWraps)
	}

	// upstream servers
	if len(data.UpstreamServers) != 1 {
		t.Fatalf("expected 1 upstream server, got %d", len(data.UpstreamServers))
	}
	us := data.UpstreamServers[0]
	if us.Upstream != "backend_pool" {
		t.Errorf("upstream name: want backend_pool, got %q", us.Upstream)
	}
	if us.Server != "10.0.0.10:8080" {
		t.Errorf("upstream server: want 10.0.0.10:8080, got %q", us.Server)
	}
	if us.Requests != 2000 {
		t.Errorf("upstream Requests: want 2000, got %v", us.Requests)
	}
	if us.ResponseTimeSeconds != 0.035 {
		t.Errorf("upstream ResponseTimeSeconds: want 0.035, got %v", us.ResponseTimeSeconds)
	}
	if us.Down {
		t.Error("upstream Down: want false, got true")
	}
	if us.ResponsesByCode["2xx"] != 1900 {
		t.Errorf("upstream 2xx: want 1900, got %v", us.ResponsesByCode["2xx"])
	}
	if us.CounterWraps != 0 {
		t.Errorf("upstream CounterWraps: want 0 (absent in fixture), got %v", us.CounterWraps)
	}
}

// TestFetchNginxVTS_OverCounts guards #584: serverZones.*.overCounts and
// upstreamZones.*[].overCounts are vhost-traffic-status's own wrap-detection
// counters (nginx-module-vts ngx_http_vhost_traffic_status_add_oc(): each
// incremented once whenever a shard's counter is found to have wrapped past
// its own accumulated value -- itself monotonically increasing, i.e. a
// COUNTER, never a gauge). A non-zero value here means the underlying
// request/byte/response counters it accompanies wrapped and their rate()
// series has a discontinuity -- correctness-relevant for series already shipped.
func TestFetchNginxVTS_OverCounts(t *testing.T) {
	const fixture = `{
	  "connections": {"active": 1, "reading": 0, "writing": 0, "waiting": 0,
	                  "accepted": 1, "handled": 1, "requests": 1},
	  "sharedZones": {"maxSize": 1, "usedSize": 1, "usedNode": 1},
	  "serverZones": {
	    "example.com": {"requestCounter": 5000000000, "inBytes": 1, "outBytes": 1,
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
	}`

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	})

	data, err := client.FetchNginxVTS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.ServerZones) != 1 {
		t.Fatalf("expected 1 server zone, got %d", len(data.ServerZones))
	}
	if data.ServerZones[0].CounterWraps != 3 {
		t.Errorf("server zone CounterWraps: want 3, got %v", data.ServerZones[0].CounterWraps)
	}
	if len(data.UpstreamServers) != 1 {
		t.Fatalf("expected 1 upstream server, got %d", len(data.UpstreamServers))
	}
	if data.UpstreamServers[0].CounterWraps != 7 {
		t.Errorf("upstream CounterWraps: want 7, got %v", data.UpstreamServers[0].CounterWraps)
	}
}

// nginxVtsHeavyFixture is a trimmed, faithful reproduction of the real
// heavy-topology dev-box capture for issue #200 (2026-07-13,
// captures/nginx/vts_populated.json): a vhost with a proxy_cache zone
// (hit=20/miss=3), a 2-server upstream with per-server requestMsecCounter /
// responseMsecCounter, and a top-level loadMsec. The verbose requestMsecs/
// requestBuckets/overCounts fields the real payload carries are dropped —
// they decode to nothing our structs read, and Go's decoder ignores unknown
// fields — keeping this fixture readable while remaining shape-accurate.
const nginxVtsHeavyFixture = `{
  "hostName": "opnsense-devel.internal",
  "moduleVersion": "v0.2.1",
  "nginxVersion": "1.30.3",
  "loadMsec": 1783965615789,
  "nowMsec": 1783966062574,
  "connections": {"active": 1, "reading": 0, "writing": 1, "waiting": 0,
                  "accepted": 27, "handled": 27, "requests": 27},
  "sharedZones": {"name": "vhost_traffic_status",
                  "maxSize": 20971520, "usedSize": 14225, "usedNode": 4},
  "serverZones": {
    "heavy.exporter.test": {
      "requestCounter": 25, "inBytes": 2075, "outBytes": 20066,
      "requestMsecCounter": 78133,
      "responses": {"1xx":0,"2xx":21,"3xx":0,"4xx":2,"5xx":2,
                    "miss":5,"bypass":0,"expired":0,"stale":0,
                    "updating":0,"revalidated":0,"hit":20,"scarce":0}
    },
    "*": {
      "requestCounter": 25, "inBytes": 2075, "outBytes": 20066,
      "requestMsecCounter": 78133,
      "responses": {"1xx":0,"2xx":21,"3xx":0,"4xx":2,"5xx":2,
                    "miss":5,"bypass":0,"expired":0,"stale":0,
                    "updating":0,"revalidated":0,"hit":20,"scarce":0}
    }
  },
  "upstreamZones": {
    "upstream9c728a822c7c4e908b876344b0283d63": [
      {"server": "172.16.9.99:8081", "requestCounter": 2, "inBytes": 166, "outBytes": 198,
       "responses": {"1xx":0,"2xx":1,"3xx":0,"4xx":1,"5xx":0},
       "requestMsecCounter": 18095, "responseMsecCounter": 0,
       "weight": 1, "maxFails": 1, "failTimeout": 10, "backup": false, "down": false},
      {"server": "172.16.9.99:8082", "requestCounter": 1, "inBytes": 83, "outBytes": 0,
       "responses": {"1xx":0,"2xx":0,"3xx":0,"4xx":1,"5xx":0},
       "requestMsecCounter": 60038, "responseMsecCounter": 0,
       "weight": 1, "maxFails": 1, "failTimeout": 10, "backup": false, "down": false}
    ]
  },
  "cacheZones": {
    "e875b648feaa4e4fbdffd06de04c3eaa": {
      "maxSize": 53687091200, "usedSize": 4096, "inBytes": 1909, "outBytes": 4158,
      "responses": {"miss":3,"bypass":0,"expired":0,"stale":0,
                    "updating":0,"revalidated":0,"hit":20,"scarce":0}
    }
  }
}`

func TestFetchNginxVTS_CacheZonesAndLatencyCounters(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nginxVtsHeavyFixture))
	})

	data, err := client.FetchNginxVTS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}

	// config load timestamp
	if data.ConfigLoadTimestampSeconds != 1783965615.789 {
		t.Errorf("ConfigLoadTimestampSeconds: want 1783965615.789, got %v", data.ConfigLoadTimestampSeconds)
	}

	// cache-status extension present (top-level cacheZones key present)
	if !data.CacheStatusPresent {
		t.Error("expected CacheStatusPresent=true when cacheZones key is present")
	}

	// server zone: "*" excluded, only "heavy.exporter.test"
	if len(data.ServerZones) != 1 {
		t.Fatalf("expected 1 server zone, got %d", len(data.ServerZones))
	}
	sz := data.ServerZones[0]
	if sz.Zone != "heavy.exporter.test" {
		t.Errorf("server zone name: want heavy.exporter.test, got %q", sz.Zone)
	}
	if sz.RequestSecondsTotal != 78.133 {
		t.Errorf("server zone RequestSecondsTotal: want 78.133, got %v", sz.RequestSecondsTotal)
	}
	if sz.CacheResponsesByCode["hit"] != 20 {
		t.Errorf("server zone cache hit: want 20, got %v", sz.CacheResponsesByCode["hit"])
	}
	if sz.CacheResponsesByCode["miss"] != 5 {
		t.Errorf("server zone cache miss: want 5, got %v", sz.CacheResponsesByCode["miss"])
	}

	// upstream servers: 2, with cumulative request latency counters
	if len(data.UpstreamServers) != 2 {
		t.Fatalf("expected 2 upstream servers, got %d", len(data.UpstreamServers))
	}
	var found8081, found8082 bool
	for _, us := range data.UpstreamServers {
		if us.Upstream != "upstream9c728a822c7c4e908b876344b0283d63" {
			t.Errorf("upstream name: want upstream9c728a822c7c4e908b876344b0283d63, got %q", us.Upstream)
		}
		switch us.Server {
		case "172.16.9.99:8081":
			found8081 = true
			if us.RequestSecondsTotal != 18.095 {
				t.Errorf("upstream 8081 RequestSecondsTotal: want 18.095, got %v", us.RequestSecondsTotal)
			}
			if us.ResponseSecondsTotal != 0 {
				t.Errorf("upstream 8081 ResponseSecondsTotal: want 0, got %v", us.ResponseSecondsTotal)
			}
		case "172.16.9.99:8082":
			found8082 = true
			if us.RequestSecondsTotal != 60.038 {
				t.Errorf("upstream 8082 RequestSecondsTotal: want 60.038, got %v", us.RequestSecondsTotal)
			}
		}
	}
	if !found8081 || !found8082 {
		t.Errorf("expected both upstream servers present, found8081=%v found8082=%v", found8081, found8082)
	}

	// cache zones: one, keyed by the raw cache_path uuid (dashes stripped)
	if len(data.CacheZones) != 1 {
		t.Fatalf("expected 1 cache zone, got %d", len(data.CacheZones))
	}
	cz := data.CacheZones[0]
	if cz.Zone != "e875b648feaa4e4fbdffd06de04c3eaa" {
		t.Errorf("cache zone name: want raw uuid (no dashes), got %q", cz.Zone)
	}
	if cz.MaxBytes != 53687091200 {
		t.Errorf("cache zone MaxBytes: want 53687091200, got %v", cz.MaxBytes)
	}
	if cz.UsedBytes != 4096 {
		t.Errorf("cache zone UsedBytes: want 4096, got %v", cz.UsedBytes)
	}
	if cz.BytesIn != 1909 || cz.BytesOut != 4158 {
		t.Errorf("cache zone bytes in/out: want 1909/4158, got %v/%v", cz.BytesIn, cz.BytesOut)
	}
	if cz.ResponsesByCode["hit"] != 20 {
		t.Errorf("cache zone hit: want 20, got %v", cz.ResponsesByCode["hit"])
	}
	if cz.ResponsesByCode["miss"] != 3 {
		t.Errorf("cache zone miss: want 3, got %v", cz.ResponsesByCode["miss"])
	}
}

func TestFetchNginxVTS_NoCacheConfigured(t *testing.T) {
	// A fresh install / no proxy_cache_path configured: cacheZones is either
	// absent or an empty object, and serverZones responses carry no cache-
	// status keys (older vts module without the cache-status extension). The
	// existing nginxVtsFixture (no cacheZones key, no cache-status fields in
	// responses) already models this; assert the zero-value behaviour here.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(nginxVtsFixture))
	})

	data, err := client.FetchNginxVTS()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.CacheStatusPresent {
		t.Error("expected CacheStatusPresent=false when cacheZones key is absent")
	}
	if len(data.CacheZones) != 0 {
		t.Errorf("expected no cache zones, got %d", len(data.CacheZones))
	}
	// loadMsec IS present in nginxVtsFixture (1700000000000) — reload
	// detection should still work independently of the cache extension.
	if data.ConfigLoadTimestampSeconds != 1700000000 {
		t.Errorf("ConfigLoadTimestampSeconds: want 1700000000, got %v", data.ConfigLoadTimestampSeconds)
	}
}

func TestFetchNginxBans_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/bans/searchban", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"74ee3555-68fd-4cd9-98c6-0b5fe63ff2b2","ip":"172.16.9.99","time":"1783966140"}],"rowCount":1,"total":1,"current":1}`))
	})

	data, err := client.FetchNginxBans()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.Count != 1 {
		t.Errorf("Count: want 1, got %d", data.Count)
	}
	if data.LastBanTimestampSeconds != 1783966140 {
		t.Errorf("LastBanTimestampSeconds: want 1783966140, got %v", data.LastBanTimestampSeconds)
	}
}

func TestFetchNginxBans_Empty(t *testing.T) {
	// Fresh install / no active bans: real captured baseline shape.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/bans/searchban", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})

	data, err := client.FetchNginxBans()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (endpoint answers 200 with empty rows, not 404)")
	}
	if data.Count != 0 {
		t.Errorf("Count: want 0, got %d", data.Count)
	}
	if data.LastBanTimestampSeconds != 0 {
		t.Errorf("LastBanTimestampSeconds: want 0, got %v", data.LastBanTimestampSeconds)
	}
}

func TestFetchNginxBans_MultipleRows_TracksMostRecent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/bans/searchban", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"uuid":"a","ip":"10.0.0.1","time":"100"},
			{"uuid":"b","ip":"10.0.0.2","time":"300"},
			{"uuid":"c","ip":"10.0.0.3","time":"200"}
		],"rowCount":3,"total":3,"current":1}`))
	})

	data, err := client.FetchNginxBans()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Count != 3 {
		t.Errorf("Count: want 3, got %d", data.Count)
	}
	if data.LastBanTimestampSeconds != 300 {
		t.Errorf("LastBanTimestampSeconds: want 300 (most recent), got %v", data.LastBanTimestampSeconds)
	}
}

func TestFetchNginxBans_PluginAbsent404(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/bans/searchban", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	})

	data, err := client.FetchNginxBans()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
	if data.Count != 0 {
		t.Errorf("expected Count=0 on 404, got %d", data.Count)
	}
}

func TestFetchNginxVTS_PluginAbsent404(t *testing.T) {
	// The nginx VTS controller returns HTTP 404 with body "[]" when nginx is
	// stopped or VTS yields nothing — treat as plugin absent.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/nginx/service/vts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`[]`))
	})

	data, err := client.FetchNginxVTS()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
	if len(data.ServerZones)+len(data.UpstreamServers) != 0 {
		t.Errorf("expected empty data on 404, got %d zones %d upstreams",
			len(data.ServerZones), len(data.UpstreamServers))
	}
}
