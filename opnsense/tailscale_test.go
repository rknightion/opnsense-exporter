package opnsense

import (
	"net/http"
	"testing"
)

const tailscaleStatusFixture = `{
	"Version": "1.96.4",
	"TUN": true,
	"BackendState": "Running",
	"Self": {
		"ID": "selfid1",
		"PublicKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
		"HostName": "opnsense",
		"DNSName": "opnsense.example-tailnet.ts.net.",
		"OS": "freebsd",
		"Relay": "lhr",
		"RxBytes": 0,
		"TxBytes": 0,
		"Online": true,
		"CurAddr": "",
		"LastHandshake": "0001-01-01T00:00:00Z"
	},
	"Peer": {
		"nodekey:1111111111111111111111111111111111111111111111111111111111111111": {
			"ID": "peerid1",
			"HostName": "server-a",
			"DNSName": "server-a.example-tailnet.ts.net.",
			"OS": "linux",
			"Relay": "lhr",
			"RxBytes": 123456,
			"TxBytes": 654321,
			"Online": true,
			"CurAddr": "192.0.2.10:41641",
			"LastHandshake": "2026-06-09T22:30:00Z"
		},
		"nodekey:2222222222222222222222222222222222222222222222222222222222222222": {
			"ID": "peerid2",
			"HostName": "laptop-b",
			"DNSName": "laptop-b.example-tailnet.ts.net.",
			"OS": "macOS",
			"Relay": "lhr",
			"RxBytes": 0,
			"TxBytes": 0,
			"Online": false,
			"CurAddr": "",
			"LastHandshake": "0001-01-01T00:00:00Z"
		},
		"nodekey:3333333333333333333333333333333333333333333333333333333333333333": {
			"ID": "peerid3",
			"HostName": "idle-c",
			"DNSName": "idle-c.example-tailnet.ts.net.",
			"OS": "linux",
			"Relay": "lhr",
			"RxBytes": 0,
			"TxBytes": 0,
			"Online": true,
			"CurAddr": "",
			"LastHandshake": "0001-01-01T00:00:00Z"
		}
	}
}`

func TestFetchTailscaleStatus_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/tailscale/status/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(tailscaleStatusFixture))
	})

	data, err := client.FetchTailscaleStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.Version != "1.96.4" || data.BackendState != "Running" || data.SelfRelay != "lhr" {
		t.Errorf("unexpected self data: %+v", data)
	}
	if data.PeersTotal != 3 || data.PeersWithActiveSession != 1 {
		t.Errorf("expected 3 peers / 1 with active session, got %d / %d",
			data.PeersTotal, data.PeersWithActiveSession)
	}
	if len(data.Peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(data.Peers))
	}
	byName := map[string]TailscalePeer{}
	for _, p := range data.Peers {
		byName[p.Name] = p
	}
	a, ok := byName["server-a"] // first DNS label, not raw key
	if !ok {
		t.Fatalf("peer server-a missing; got %v", byName)
	}
	if !a.Direct || a.RxBytes != 123456 || a.TxBytes != 654321 {
		t.Errorf("unexpected server-a: %+v", a)
	}
	if !a.HasHandshake || a.LastHandshakeSeconds != 1781044200 { // 2026-06-09T22:30:00Z
		t.Errorf("unexpected handshake: %+v", a)
	}
	b := byName["laptop-b"]
	if b.Direct || b.HasHandshake {
		t.Errorf("expected laptop-b no-direct/no-handshake: %+v", b)
	}
	// Online:true in the JSON must NOT translate into session activity.
	c2 := byName["idle-c"]
	if c2.Direct || c2.HasHandshake {
		t.Errorf("expected idle-c (coordination-online, no handshake) to be inactive: %+v", c2)
	}
}

// TestFetchTailscaleStatus_HealthWarnings covers #237: the Health array of live
// client warning strings is counted, never exported as label text.
func TestFetchTailscaleStatus_HealthWarnings(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{
			name: "no Health key (healthy client, older tailscaled)",
			body: `{"Version": "1.96.4", "BackendState": "Running", "Self": {}, "Peer": {}}`,
			want: 0,
		},
		{
			name: "empty Health array (healthy)",
			body: `{"Version": "1.96.4", "BackendState": "Running", "Health": [], "Self": {}, "Peer": {}}`,
			want: 0,
		},
		{
			name: "two warnings",
			body: `{"Version": "1.96.4", "BackendState": "Running", "Health": [
				"update available: 1.98.0",
				"some peers are advertising routes but --accept-routes is false"
			], "Self": {}, "Peer": {}}`,
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(tt.body))
			})
			defer server.Close()

			data, err := client.FetchTailscaleStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data.HealthWarnings != tt.want {
				t.Errorf("HealthWarnings = %d, want %d", data.HealthWarnings, tt.want)
			}
		})
	}
}

func TestFetchTailscaleStatus_PluginAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchTailscaleStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}
