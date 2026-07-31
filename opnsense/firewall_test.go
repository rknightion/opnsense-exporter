package opnsense

import (
	"net/http"
	"testing"
	"time"
)

func TestFetchPFStatsByInterface_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"references": 100,
					"in4_pass_packets": 1000,
					"in4_block_packets": 50,
					"out4_pass_packets": 2000,
					"out4_block_packets": 10,
					"in6_pass_packets": 500,
					"in6_block_packets": 25,
					"out6_pass_packets": 1000,
					"out6_block_packets": 5,
					"in4_pass_bytes": 100000,
					"in4_block_bytes": 5000,
					"out4_pass_bytes": 200000,
					"out4_block_bytes": 1000,
					"in6_pass_bytes": 50000,
					"in6_block_bytes": 2500,
					"out6_pass_bytes": 100000,
					"out6_block_bytes": 500
				},
				"lo0": {
					"references": 50,
					"in4_pass_packets": 100,
					"in4_block_packets": 0,
					"out4_pass_packets": 100,
					"out4_block_packets": 0,
					"in6_pass_packets": 0,
					"in6_block_packets": 0,
					"out6_pass_packets": 0,
					"out6_block_packets": 0,
					"in4_pass_bytes": 10000,
					"in4_block_bytes": 0,
					"out4_pass_bytes": 10000,
					"out4_block_bytes": 0,
					"in6_pass_bytes": 0,
					"in6_block_bytes": 0,
					"out6_pass_bytes": 0,
					"out6_block_bytes": 0
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchPFStatsByInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(data.Interfaces))
	}

	// Find igb0
	var igb0 *FirewallPFStat
	for i := range data.Interfaces {
		if data.Interfaces[i].InterfaceName == "igb0" {
			igb0 = &data.Interfaces[i]
		}
	}

	if igb0 == nil {
		t.Fatal("igb0 interface not found")
	}

	// Verify InterfaceName is set from the map key
	if igb0.InterfaceName != "igb0" {
		t.Errorf("expected InterfaceName 'igb0', got %q", igb0.InterfaceName)
	}
	if igb0.References != 100 {
		t.Errorf("expected References=100, got %d", igb0.References)
	}
	if igb0.In4PassPackets != 1000 {
		t.Errorf("expected In4PassPackets=1000, got %d", igb0.In4PassPackets)
	}
	if igb0.In4BlockPackets != 50 {
		t.Errorf("expected In4BlockPackets=50, got %d", igb0.In4BlockPackets)
	}
	if igb0.Out4PassBytes != 200000 {
		t.Errorf("expected Out4PassBytes=200000, got %d", igb0.Out4PassBytes)
	}
	if igb0.In6PassPackets != 500 {
		t.Errorf("expected In6PassPackets=500, got %d", igb0.In6PassPackets)
	}
}

// TestFetchPFStatsByInterface_FiltersPseudoEntries guards #105: the pfctl
// interfaces map mixes the "all" aggregate and pf interface-group rows in with
// real devices, and appends " (skip)" to devices with pf skip enabled. Only real
// devices should survive, with a stable (skip-suffix-free) name.
func TestFetchPFStatsByInterface_FiltersPseudoEntries(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces": {
			"all": {"in4_pass_packets": 100},
			"enc": {"in4_pass_packets": 1},
			"vlan": {"in4_pass_packets": 1},
			"zenvpngroup": {"in4_pass_packets": 1},
			"igb0": {"in4_pass_packets": 10},
			"lo0 (skip)": {"in4_pass_packets": 5},
			"pfsync0 (skip)": {"in4_pass_packets": 3},
			"tailscale0": {"in4_pass_packets": 7}
		}}`))
	})
	defer server.Close()

	data, err := client.FetchPFStatsByInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[string]bool{}
	for _, iface := range data.Interfaces {
		got[iface.InterfaceName] = true
	}

	// Real devices survive, with the " (skip)" suffix stripped.
	for _, want := range []string{"igb0", "lo0", "pfsync0", "tailscale0"} {
		if !got[want] {
			t.Errorf("expected device %q to be present, got keys %v", want, got)
		}
	}
	// Aggregate + group pseudo-entries are excluded.
	for _, banned := range []string{"all", "enc", "vlan", "zenvpngroup", "lo0 (skip)", "pfsync0 (skip)"} {
		if got[banned] {
			t.Errorf("pseudo-entry/unstable name %q must not appear as an interface", banned)
		}
	}
}

// TestFetchPFStatsByInterface_SkipToggleStableLabel guards #105 AC4: toggling pf
// "skip on interface" must not change the interface label between scrapes.
func TestFetchPFStatsByInterface_SkipToggleStableLabel(t *testing.T) {
	fetch := func(key string) string {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"interfaces": {"` + key + `": {"in4_pass_packets": 1}}}`))
		})
		defer server.Close()
		data, err := client.FetchPFStatsByInterface()
		if err != nil || len(data.Interfaces) != 1 {
			t.Fatalf("fetch %q: err=%v len=%d", key, err, len(data.Interfaces))
		}
		return data.Interfaces[0].InterfaceName
	}
	if a, b := fetch("lo0"), fetch("lo0 (skip)"); a != b {
		t.Errorf("interface label changed on skip toggle: %q vs %q", a, b)
	}
}

// TestFetchPFStatsByInterface_ClearedTimestamp guards #580: pf's own
// "counters reset at" field must be decoded into Unix seconds when present and
// parseable, and must NEVER fabricate epoch 0 when absent or malformed — a
// fabricated 0 would misreport a healthy interface's counter history as reset
// at 1970 instead of simply "unknown".
//
// The fixture value "2026-07-31T09:15:23" is the exact shape produced by
// OPNsense's pfstatistics.py: datetime.datetime.strptime(line, "%b %d %H:%M:%S
// %Y").isoformat() — whole seconds, no fractional part, and NO timezone marker
// at all (verified against upstream source, not guessed).
func TestFetchPFStatsByInterface_ClearedTimestamp(t *testing.T) {
	tests := []struct {
		name       string
		clearedRaw string // raw JSON value for the "cleared" key, or "" to omit the key entirely
		wantHas    bool
		wantUnix   int64
	}{
		{
			name:       "present and parseable",
			clearedRaw: `"2026-07-31T09:15:23"`,
			wantHas:    true,
			wantUnix:   time.Date(2026, 7, 31, 9, 15, 23, 0, time.UTC).Unix(),
		},
		{
			name:       "key absent entirely (box has never reset this interface's counters)",
			clearedRaw: "",
			wantHas:    false,
		},
		{
			name:       "empty string",
			clearedRaw: `""`,
			wantHas:    false,
		},
		{
			name:       "JSON null",
			clearedRaw: `null`,
			wantHas:    false,
		},
		{
			name:       "JSON empty array (the flexString PHP-quirk shape)",
			clearedRaw: `[]`,
			wantHas:    false,
		},
		{
			name:       "unparseable garbage must not panic and must not synthesize a timestamp",
			clearedRaw: `"not-a-date"`,
			wantHas:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"interfaces": {"igb0": {"references": 1`
			if tt.clearedRaw != "" {
				body += `, "cleared": ` + tt.clearedRaw
			}
			body += `}}}`

			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(body))
			})
			defer server.Close()

			data, err := client.FetchPFStatsByInterface()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(data.Interfaces) != 1 {
				t.Fatalf("expected 1 interface, got %d", len(data.Interfaces))
			}
			got := data.Interfaces[0]

			if got.HasClearedTimestamp != tt.wantHas {
				t.Errorf("HasClearedTimestamp = %v, want %v (ClearedTimestamp=%v)",
					got.HasClearedTimestamp, tt.wantHas, got.ClearedTimestamp)
			}
			if tt.wantHas && int64(got.ClearedTimestamp) != tt.wantUnix {
				t.Errorf("ClearedTimestamp = %v, want %v", got.ClearedTimestamp, tt.wantUnix)
			}
			if !tt.wantHas && got.ClearedTimestamp != 0 {
				// Not itself a bug (0 is a valid zero-value float), but a non-zero
				// value here alongside HasClearedTimestamp=false would indicate the
				// gating logic disagreed with itself.
				t.Errorf("expected ClearedTimestamp=0 when HasClearedTimestamp=false, got %v", got.ClearedTimestamp)
			}
		})
	}
}

func TestFetchPFStatsByInterface_EmptyInterfaces(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces": {}}`))
	})
	defer server.Close()

	data, err := client.FetchPFStatsByInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Interfaces) != 0 {
		t.Errorf("expected 0 interfaces, got %d", len(data.Interfaces))
	}
}

func TestFetchPFStatsByInterface_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchPFStatsByInterface()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchFirewallStats_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`[
			{"label": "igb0", "value": 12345},
			{"label": "igb1", "value": 6789},
			{"label": "lo0", "value": 100}
		]`))
	})
	defer server.Close()

	hits, err := client.FetchFirewallStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(hits))
	}

	// Find igb0
	var found bool
	for _, h := range hits {
		if h.Label == "igb0" {
			found = true
			if h.Value != 12345 {
				t.Errorf("expected igb0 value=12345, got %d", h.Value)
			}
		}
	}
	if !found {
		t.Error("igb0 not found in results")
	}
}

func TestFetchFirewallStats_EmptyArray(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	defer server.Close()

	hits, err := client.FetchFirewallStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("expected 0 hits, got %d", len(hits))
	}
}

func TestFetchFirewallStats_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchFirewallStats()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchPFStatsByInterface_SkippedFlag covers #542: pfctl appends a literal
// " (skip)" suffix to any device with pf "skip on interface" enabled. The suffix
// is stripped out of the interface name (so toggling the pf option does not rename
// the series, #105) but the skip state itself is real information — pf is not
// filtering that interface at all — so it must be carried on the parsed row rather
// than thrown away.
//
// The fixture is the real prod key set and shape captured from
// api/diagnostics/firewall/pf_statistics/interfaces on 10.0.0.254 (OPNsense 26.1):
// two skipped devices, one ordinary populated device, one all-zero device, and the
// "all" aggregate row.
func TestFetchPFStatsByInterface_SkippedFlag(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"pppoe0":       {"references": 486, "in4_pass_packets": 10},
				"igb0":         {"references": 0},
				"lo0 (skip)":   {"references": 28},
				"pfsync0 (skip)": {"references": 0},
				"all":          {"references": 42}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchPFStatsByInterface()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byName := make(map[string]FirewallPFStat, len(data.Interfaces))
	for _, iface := range data.Interfaces {
		byName[iface.InterfaceName] = iface
	}

	if _, ok := byName["all"]; ok {
		t.Error(`the "all" aggregate row must never be returned as an interface: it is a sum of the others, so emitting it would double every total in any panel that aggregates the family`)
	}

	tests := []struct {
		name           string
		wantReferences int
		wantSkipped    bool
	}{
		{name: "pppoe0", wantReferences: 486, wantSkipped: false},
		{name: "igb0", wantReferences: 0, wantSkipped: false},
		{name: "lo0", wantReferences: 28, wantSkipped: true},
		{name: "pfsync0", wantReferences: 0, wantSkipped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := byName[tt.name]
			if !ok {
				t.Fatalf("expected an interface named %q, got %v", tt.name, byName)
			}
			if got.References != tt.wantReferences {
				t.Errorf("References = %d, want %d", got.References, tt.wantReferences)
			}
			if got.Skipped != tt.wantSkipped {
				t.Errorf("Skipped = %v, want %v", got.Skipped, tt.wantSkipped)
			}
		})
	}
}
