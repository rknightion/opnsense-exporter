package opnsense

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestFetchArpTable_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Verify the POST body matches the expected payload
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}
		if payload["resolve"] != "no" {
			t.Errorf("expected resolve=no, got %v", payload["resolve"])
		}

		resp := arpSearchResponse{
			Rows: []struct {
				Mac             string `json:"mac"`
				IP              string `json:"ip"`
				Intf            string `json:"intf"`
				Type            string `json:"type"`
				Manufacturer    string `json:"manufacturer"`
				Hostname        string `json:"hostname"`
				IntfDescription string `json:"intf_description"`
				Permanent       bool   `json:"permanent"`
				Expired         bool   `json:"expired"`
				Expires         int    `json:"expires"`
			}{
				{
					Mac:             "aa:bb:cc:dd:ee:ff",
					IP:              "192.168.1.100",
					Intf:            "em0",
					Type:            "ethernet",
					Manufacturer:    "Dell Inc.",
					Hostname:        "workstation1",
					IntfDescription: "LAN",
					Permanent:       true,
					Expired:         false,
					Expires:         1200,
				},
				{
					Mac:             "11:22:33:44:55:66",
					IP:              "192.168.1.200",
					Intf:            "em0",
					Type:            "ethernet",
					Manufacturer:    "Apple Inc.",
					Hostname:        "macbook",
					IntfDescription: "LAN",
					Permanent:       false,
					Expired:         true,
					Expires:         0,
				},
			},
			Total:    2,
			RowCount: 2,
			Current:  1,
		}
		w.Write(mustMarshal(t, resp))
	})
	defer server.Close()

	arpTable, err := client.FetchArpTable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if arpTable.TotalEntries != 2 {
		t.Errorf("expected TotalEntries=2, got %d", arpTable.TotalEntries)
	}
	if len(arpTable.Arp) != 2 {
		t.Fatalf("expected 2 ARP entries, got %d", len(arpTable.Arp))
	}

	// Check first entry: permanent, not expired
	a1 := arpTable.Arp[0]
	if a1.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected mac 'aa:bb:cc:dd:ee:ff', got %q", a1.Mac)
	}
	if a1.IP != "192.168.1.100" {
		t.Errorf("expected ip '192.168.1.100', got %q", a1.IP)
	}
	if !a1.Permanent {
		t.Error("expected Permanent=true")
	}
	if a1.Expired {
		t.Error("expected Expired=false")
	}
	if a1.Expires != 1200 {
		t.Errorf("expected Expires=1200, got %d", a1.Expires)
	}
	if a1.IntfDescription != "LAN" {
		t.Errorf("expected IntfDescription='LAN', got %q", a1.IntfDescription)
	}

	// Check second entry: not permanent, expired
	a2 := arpTable.Arp[1]
	if a2.Permanent {
		t.Error("expected Permanent=false for second entry")
	}
	if !a2.Expired {
		t.Error("expected Expired=true for second entry")
	}
}

func TestFetchArpTable_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})
	defer server.Close()

	_, err := client.FetchArpTable()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
