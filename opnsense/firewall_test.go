package opnsense

import (
	"net/http"
	"testing"
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
