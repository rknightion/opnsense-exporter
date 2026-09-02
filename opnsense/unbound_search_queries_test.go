package opnsense

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestFetchUnboundSearchQueries_ParsesRowsAndTolerateNullUUID(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.PostForm.Get("current"); got != "1" {
			t.Errorf("current = %q, want 1", got)
		}
		if got := r.PostForm.Get("rowCount"); got != "1000" {
			t.Errorf("rowCount = %q, want 1000 (the backend's own cap, #233)", got)
		}

		body := `{"total":1000,"rowCount":2,"current":1,"rows":[` +
			`{"uuid":null,"time":1783970520,"client":"172.16.9.99","family":"ip4","type":"A","domain":"github.com.","action":"Pass","source":"Cache","blocklist":"","rcode":"NOERROR","resolve_time_ms":0,"dnssec_status":"Unchecked","ttl":601,"policy":"","status":1},` +
			`{"uuid":null,"time":1783970461,"client":"localhost","family":"ip4","type":"A","domain":"enc0.","action":"Drop","source":"Local","blocklist":"badlist","rcode":"SERVFAIL","resolve_time_ms":0,"dnssec_status":"Unchecked","ttl":0,"policy":"strict","status":4}` +
			`]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	defer server.Close()

	rows, err := client.FetchUnboundSearchQueries()
	if err != nil {
		t.Fatalf("FetchUnboundSearchQueries returned error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	first := rows[0]
	if first.UUID.String() != "" {
		t.Errorf("expected null uuid to decode as empty string, got %q", first.UUID.String())
	}
	if first.Time.Int() != 1783970520 {
		t.Errorf("Time = %d, want 1783970520", first.Time.Int())
	}
	if first.Client.String() != "172.16.9.99" {
		t.Errorf("Client = %q", first.Client.String())
	}
	if first.Domain.String() != "github.com." {
		t.Errorf("Domain = %q", first.Domain.String())
	}
	if first.Action.String() != "Pass" {
		t.Errorf("Action = %q", first.Action.String())
	}
	if first.Source.String() != "Cache" {
		t.Errorf("Source = %q", first.Source.String())
	}

	second := rows[1]
	if second.Action.String() != "Drop" {
		t.Errorf("second Action = %q", second.Action.String())
	}
	if second.Blocklist.String() != "badlist" {
		t.Errorf("second Blocklist = %q", second.Blocklist.String())
	}
	if second.Policy.String() != "strict" {
		t.Errorf("second Policy = %q", second.Policy.String())
	}
}

func TestFetchUnboundSearchQueries_EmptyRows(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	defer server.Close()

	rows, err := client.FetchUnboundSearchQueries()
	if err != nil {
		t.Fatalf("FetchUnboundSearchQueries returned error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(rows))
	}
}

func TestFetchUnboundSearchQueries_UUIDPresent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[` +
			`{"uuid":"abc-123","time":1,"client":"c","family":"ip4","type":"A","domain":"d.","action":"Pass","source":"Cache","blocklist":"","rcode":"NOERROR","resolve_time_ms":0,"dnssec_status":"Unchecked","ttl":1,"policy":"","status":1}` +
			`]}`))
	})
	defer server.Close()

	rows, err := client.FetchUnboundSearchQueries()
	if err != nil {
		t.Fatalf("FetchUnboundSearchQueries returned error: %v", err)
	}
	if len(rows) != 1 || rows[0].UUID.String() != "abc-123" {
		t.Fatalf("expected uuid abc-123 to survive decoding, got %+v", rows)
	}
}

func TestFetchUnboundSearchQueries_CategoryMarksLowercaseDisplayValue(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[` +
			`{"time":1,"client":"10.0.0.5","domain":"x.test.","type":"A",` +
			`"action":"Block","source":"Cache","blocklist":"easylist",` +
			`"category":"General Blocklists","rcode":"NOERROR"}` +
			`]}`))
	})
	defer server.Close()

	rows, err := client.FetchUnboundSearchQueries()
	if err != nil {
		t.Fatalf("FetchUnboundSearchQueries returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if got, present := rows[0].BlocklistIdentity(); present {
		t.Fatalf("BlocklistIdentity() = %q, %t; category marks the value as display-only", got, present)
	}
}

// TestUnboundSearchQueryRow_BlocklistIdentityByResponseShape pins the source
// seam used by the log shipper. Legacy search_queries rows retain the backend
// short code. OPNsense 26.7 adds category while replacing that code with a
// display value, which cannot be used as a stable identity.
func TestUnboundSearchQueryRow_BlocklistIdentityByResponseShape(t *testing.T) {
	for _, tc := range []struct {
		name         string
		payload      string
		wantIdentity string
		wantPresent  bool
	}{
		{
			name:         "legacy short code",
			payload:      `{"blocklist":"ag"}`,
			wantIdentity: "ag",
			wantPresent:  true,
		},
		{
			name:        "26.7 display value with category",
			payload:     `{"blocklist":"AdGuard List","category":"General Blocklists"}`,
			wantPresent: false,
		},
		{
			name:        "empty blocklist",
			payload:     `{"blocklist":""}`,
			wantPresent: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var row UnboundSearchQueryRow
			if err := json.Unmarshal([]byte(tc.payload), &row); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got, present := row.BlocklistIdentity()
			if present != tc.wantPresent || got != tc.wantIdentity {
				t.Fatalf("BlocklistIdentity() = %q, %t; want %q, %t", got, present, tc.wantIdentity, tc.wantPresent)
			}
		})
	}
}

func TestFetchUnboundSearchQueries_MissingEndpoint(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no request should be made when the endpoint is missing")
	})
	defer server.Close()
	delete(client.endpoints, "unboundSearchQueries")

	_, err := client.FetchUnboundSearchQueries()
	if err == nil {
		t.Fatal("expected an error when the endpoint is not registered")
	}
}

// TestUnboundSearchQueriesRowCapIsBackendCeiling pins the constant to the value
// documented in FetchUnboundSearchQueries (the backend's own accessible-window
// ceiling, #233) so a drift here is caught rather than silently changing what
// the exporter requests.
func TestUnboundSearchQueriesRowCapIsBackendCeiling(t *testing.T) {
	if UnboundSearchQueriesRowCap != 1000 {
		t.Fatalf("UnboundSearchQueriesRowCap drifted: %d", UnboundSearchQueriesRowCap)
	}
}
