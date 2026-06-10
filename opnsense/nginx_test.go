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
