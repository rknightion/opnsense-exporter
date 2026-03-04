package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchNDPTable_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`[
			{
				"mac": "00:11:22:33:44:55",
				"ip": "fe80::1",
				"intf": "igb0",
				"intf_description": "LAN",
				"manufacturer": "Vendor Name",
				"expire": "23h59m50s",
				"type": "dynamic"
			},
			{
				"mac": "aa:bb:cc:dd:ee:ff",
				"ip": "2001:db8::1",
				"intf": "igb1",
				"intf_description": "WAN",
				"manufacturer": "Other Vendor",
				"expire": "permanent",
				"type": "static"
			}
		]`))
	})
	defer server.Close()

	data, err := client.FetchNDPTable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalEntries != 2 {
		t.Errorf("expected TotalEntries=2, got %d", data.TotalEntries)
	}
	if len(data.Entries) != 2 {
		t.Fatalf("expected 2 NDP entries, got %d", len(data.Entries))
	}

	e1 := data.Entries[0]
	if e1.Mac != "00:11:22:33:44:55" {
		t.Errorf("expected mac '00:11:22:33:44:55', got %q", e1.Mac)
	}
	if e1.IP != "fe80::1" {
		t.Errorf("expected ip 'fe80::1', got %q", e1.IP)
	}
	if e1.IntfDescription != "LAN" {
		t.Errorf("expected IntfDescription 'LAN', got %q", e1.IntfDescription)
	}
	if e1.Type != "dynamic" {
		t.Errorf("expected Type 'dynamic', got %q", e1.Type)
	}

	e2 := data.Entries[1]
	if e2.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected mac 'aa:bb:cc:dd:ee:ff', got %q", e2.Mac)
	}
	if e2.IP != "2001:db8::1" {
		t.Errorf("expected ip '2001:db8::1', got %q", e2.IP)
	}
	if e2.IntfDescription != "WAN" {
		t.Errorf("expected IntfDescription 'WAN', got %q", e2.IntfDescription)
	}
	if e2.Type != "static" {
		t.Errorf("expected Type 'static', got %q", e2.Type)
	}
}

func TestFetchNDPTable_EmptyArray(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	defer server.Close()

	data, err := client.FetchNDPTable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalEntries != 0 {
		t.Errorf("expected TotalEntries=0, got %d", data.TotalEntries)
	}
	if len(data.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(data.Entries))
	}
}

func TestFetchNDPTable_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})
	defer server.Close()

	_, err := client.FetchNDPTable()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
