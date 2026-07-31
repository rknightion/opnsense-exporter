package opnsense

import (
	"fmt"
	"net/http"
	"strings"
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

// TestFetchTailscaleStatus_ReauthAndKeyExpiry pins the #583 node-local posture
// decode: the two signals that say "this tunnel is about to stop working".
//
// Wire evidence, tailscale ipn/ipnstate/ipnstate.go:
//   - `AuthURL string` (line 47) has NO omitempty, so the key is always present
//     and empty means "not waiting for interactive reauth".
//   - `KeyExpiry *time.Time \`json:",omitempty"\“ (line 338) is a POINTER with
//     omitempty, so the key is ABSENT whenever the node key does not expire
//     (key expiry disabled on the node). Absent must produce no series.
func TestFetchTailscaleStatus_ReauthAndKeyExpiry(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantReauth    bool
		wantExpiry    float64
		wantHasExpiry bool
	}{
		{
			name: "awaiting reauth with a key expiry",
			body: `{"Version":"1.2.3","BackendState":"NeedsLogin",
			        "AuthURL":"https://login.tailscale.com/a/SECRETSECRET",
			        "Self":{"HostName":"fw","KeyExpiry":"2026-09-01T00:00:00Z"},"Peer":{}}`,
			wantReauth:    true,
			wantExpiry:    1788220800,
			wantHasExpiry: true,
		},
		{
			name: "healthy, empty AuthURL, key expiry disabled (KeyExpiry omitted)",
			body: `{"Version":"1.2.3","BackendState":"Running","AuthURL":"",
			        "Self":{"HostName":"fw"},"Peer":{}}`,
			wantReauth:    false,
			wantHasExpiry: false,
		},
		{
			name: "AuthURL key absent entirely (older tailscaled)",
			body: `{"Version":"1.2.3","BackendState":"Running",
			        "Self":{"HostName":"fw"},"Peer":{}}`,
			wantReauth:    false,
			wantHasExpiry: false,
		},
		{
			name: "unparseable KeyExpiry emits nothing rather than epoch 0",
			body: `{"Version":"1.2.3","BackendState":"Running","AuthURL":"",
			        "Self":{"HostName":"fw","KeyExpiry":"soon"},"Peer":{}}`,
			wantReauth:    false,
			wantHasExpiry: false,
		},
		{
			name: "a PEER key expiry must never leak into the Self-only metric",
			body: `{"Version":"1.2.3","BackendState":"Running","AuthURL":"",
			        "Self":{"HostName":"fw"},
			        "Peer":{"nodekey":{"HostName":"other","KeyExpiry":"2026-09-01T00:00:00Z"}}}`,
			wantReauth:    false,
			wantHasExpiry: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			})
			defer server.Close()

			data, err := client.FetchTailscaleStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data.ReauthRequired != tc.wantReauth {
				t.Errorf("ReauthRequired = %v, want %v", data.ReauthRequired, tc.wantReauth)
			}
			if data.HasSelfKeyExpiry != tc.wantHasExpiry {
				t.Errorf("HasSelfKeyExpiry = %v, want %v", data.HasSelfKeyExpiry, tc.wantHasExpiry)
			}
			if tc.wantHasExpiry && data.SelfKeyExpiry != tc.wantExpiry {
				t.Errorf("SelfKeyExpiry = %v, want %v", data.SelfKeyExpiry, tc.wantExpiry)
			}
		})
	}
}

// TestFetchTailscaleStatus_AuthURLNeverRetained is the standing privacy guard
// for #583: the AuthURL is a one-click credential (anyone who reads it can
// authorise the tailnet node). Only its PRESENCE may ever leave this package.
// This asserts on the whole decoded struct so a future field that stashes the
// URL fails here rather than in review.
func TestFetchTailscaleStatus_AuthURLNeverRetained(t *testing.T) {
	const secret = "https://login.tailscale.com/a/DEADBEEFCAFE"
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"1.2.3","BackendState":"NeedsLogin","AuthURL":"` + secret +
			`","Self":{"HostName":"fw"},"Peer":{}}`))
	})
	defer server.Close()

	data, err := client.FetchTailscaleStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.ReauthRequired {
		t.Fatal("expected ReauthRequired=true")
	}
	if rendered := fmt.Sprintf("%+v", data); strings.Contains(rendered, "login.tailscale.com") ||
		strings.Contains(rendered, "DEADBEEFCAFE") {
		t.Fatalf("AuthURL leaked into TailscaleStatus: %s", rendered)
	}
}
