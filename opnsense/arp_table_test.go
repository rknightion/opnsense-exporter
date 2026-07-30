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

		// Raw JSON literal mirroring a real /api/diagnostics/interface/search_arp
		// payload, so a wrong json tag or field type in arpSearchResponse is caught
		// rather than round-tripped away (#155). Live shape: permanent/expired are
		// native JSON bools, expires a native int.
		w.Write([]byte(`{
			"rows": [
				{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100", "intf": "em0", "type": "ethernet", "manufacturer": "Dell Inc.", "hostname": "workstation1", "intf_description": "LAN", "permanent": true, "expired": false, "expires": 1200},
				{"mac": "11:22:33:44:55:66", "ip": "192.168.1.200", "intf": "em0", "type": "ethernet", "manufacturer": "Apple Inc.", "hostname": "macbook", "intf_description": "LAN", "permanent": false, "expired": true, "expires": 0}
			],
			"total": 2,
			"rowCount": 2,
			"current": 1
		}`))
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

// liveArpManufacturerFixture is trimmed verbatim from the prod box (OPNsense
// 26.1, api/diagnostics/interface/search_arp). Every one of the 101 rows on that
// box has an empty hostname while 88 carry a manufacturer, so the populated-
// manufacturer/empty-hostname row is the normal case, not the exception. The
// VLAN row is the one where intf and intf_description genuinely diverge.
const liveArpManufacturerFixture = `{"total":3,"rowCount":3,"current":1,"rows":[
 {"mac":"48:25:67:13:97:33","ip":"10.0.0.139","intf":"ixl0","expired":false,"expires":1192,"permanent":false,"type":"ethernet","manufacturer":"Poly","hostname":"","intf_description":"LAN"},
 {"mac":"00:11:32:aa:bb:cc","ip":"10.0.50.10","intf":"ixl0_vlan50","expired":false,"expires":900,"permanent":false,"type":"ethernet","manufacturer":"Synology Incorporated","hostname":"","intf_description":"IOT"},
 {"mac":"de:ad:be:ef:00:01","ip":"10.0.0.200","intf":"ixl0","expired":true,"expires":0,"permanent":false,"type":"ethernet","manufacturer":"","hostname":"","intf_description":"LAN"}
]}`

func TestFetchArpTable_CarriesManufacturerAndDevice(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(liveArpManufacturerFixture))
	})
	defer server.Close()

	table, err := client.FetchArpTable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(table.Arp) != 3 {
		t.Fatalf("got %d entries, want 3", len(table.Arp))
	}

	byIP := make(map[string]Arp, len(table.Arp))
	for _, a := range table.Arp {
		byIP[a.IP] = a
	}
	if got := byIP["10.0.0.139"].Manufacturer; got != "Poly" {
		t.Errorf("manufacturer = %q, want %q", got, "Poly")
	}
	// The raw device is what joins against the interface metrics; on a VLAN it
	// is not the description.
	if got := byIP["10.0.50.10"].Device; got != "ixl0_vlan50" {
		t.Errorf("device = %q, want %q", got, "ixl0_vlan50")
	}
	if got := byIP["10.0.50.10"].IntfDescription; got != "IOT" {
		t.Errorf("intf description = %q, want %q", got, "IOT")
	}
	// An unresolved OUI is normal (13 of 101 on the reference box) and must
	// stay empty rather than being invented.
	if got := byIP["10.0.0.200"].Manufacturer; got != "" {
		t.Errorf("manufacturer for an unresolved OUI = %q, want empty", got)
	}
}
