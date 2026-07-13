package opnsense

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestFetchSiproxdRegistrations_Absent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errorMessage":"Endpoint not found"}`, http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchSiproxdRegistrations()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404 (os-siproxd plugin absent)")
	}
}

// TestFetchSiproxdRegistrations_Empty covers a freshly-installed plugin whose
// registration file doesn't exist yet: cat's stdout is empty, so the
// configd script_output wraps "" (verified against actions_siproxd.conf:
// `command:/bin/cat /var/lib/siproxd/siproxd_registrations`, which prints
// nothing on stdout when the file is missing).
func TestFetchSiproxdRegistrations_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"response":""}`))
	})
	defer server.Close()

	data, err := client.FetchSiproxdRegistrations()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (plugin installed, 200 response)")
	}
	if data.Active != 0 {
		t.Errorf("expected Active=0 for an empty registrations file, got %d", data.Active)
	}
}

// TestFetchSiproxdRegistrations_Populated mirrors the four-line-per-entry
// format the pfSense siproxd package's siproxd_registered_phones.php parses
// from the identical /var/lib/siproxd/siproxd_registrations file: a
// "stars:active:expires" header line followed by real/nat/registered
// "type:user@host:port;tags" lines. Two entries: one active, one not.
func TestFetchSiproxdRegistrations_Populated(t *testing.T) {
	raw := "" +
		"*:1:1234567890\n" +
		"udp:alice@10.0.0.5:5060;tag=abc\n" +
		"udp:alice@203.0.113.5:5060;tag=abc\n" +
		"udp:alice@203.0.113.5:5060;tag=abc\n" +
		"*:0:0\n" +
		"udp:bob@10.0.0.6:5060;tag=def\n" +
		"udp:bob@203.0.113.6:5060;tag=def\n" +
		"udp:bob@203.0.113.6:5060;tag=def"

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := json.Marshal(map[string]string{"response": raw})
		if err != nil {
			t.Fatalf("failed to marshal fixture: %v", err)
		}
		w.Write(body)
	})
	defer server.Close()

	data, err := client.FetchSiproxdRegistrations()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.Active != 1 {
		t.Errorf("expected Active=1 (one entry has active=1), got %d", data.Active)
	}
}

// TestFetchSiproxdRegistrations_Garbage guards against a corrupt/binary-ish
// file wedging the exporter: malformed header lines must never crash the
// scrape or produce a false count, only be skipped (#224 — validated-infeasible
// fallback if this ever needs to be stricter).
func TestFetchSiproxdRegistrations_Garbage(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"response":"garbage-not-a-real-registration-file"}`))
	})
	defer server.Close()

	data, err := client.FetchSiproxdRegistrations()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true (200 response)")
	}
	if data.Active != 0 {
		t.Errorf("expected Active=0 for unparseable content, got %d", data.Active)
	}
}

func TestFetchSiproxdRegistrations_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchSiproxdRegistrations()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
