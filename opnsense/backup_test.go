package opnsense

import (
	"bytes"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

func TestFetchConfigBackupHistory_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		// Sanitised prod shapes (2026-07-13 capture): time is a quoted decimal
		// epoch string, filesize a JSON int. Items are newest-first.
		w.Write([]byte(`{
			"items": [
				{
					"time": "1783886416.55",
					"time_iso": "2026-07-12T21:00:16+01:00",
					"description": "/api/example/config change made changes",
					"username": "root@10.0.0.1",
					"filesize": 417639,
					"id": "config-1783886416.5486.xml"
				},
				{
					"time": "1783886406.03",
					"time_iso": "2026-07-12T21:00:06+01:00",
					"description": "/api/example/other change made changes",
					"username": "root@10.0.0.1",
					"filesize": 417637,
					"id": "config-1783886406.0265.xml"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Count != 2 {
		t.Errorf("expected Count=2, got %d", data.Count)
	}
	if data.LastTimestamp != 1783886416.55 {
		t.Errorf("expected LastTimestamp=1783886416.55, got %v", data.LastTimestamp)
	}
	if data.LastSizeBytes != 417639 {
		t.Errorf("expected LastSizeBytes=417639, got %v", data.LastSizeBytes)
	}
}

func TestFetchConfigBackupRevisions(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"id":"config-1783886416.5486.xml","time":"1783886416.55","username":"operator","description":"/api/firewall/filter/savepoint made changes","filesize":417639}]}`))
	})
	defer server.Close()

	revisions, err := client.FetchConfigBackupRevisions()
	if err != nil {
		t.Fatalf("FetchConfigBackupRevisions: %v", err)
	}
	if len(revisions) != 1 {
		t.Fatalf("got %d revisions, want 1", len(revisions))
	}
	wantTime := time.Unix(1783886416, 550000000).UTC()
	if got := revisions[0]; got.ID != "config-1783886416.5486.xml" || got.Timestamp.Sub(wantTime).Abs() > time.Microsecond || got.User != "operator" || !strings.HasPrefix(got.Description, "/api/firewall/filter/savepoint") {
		t.Fatalf("revision = %+v, want identity, timestamp, user and description", got)
	}
}

func TestFetchConfigBackupDiff(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		// BackupController::diffAction executes diff(backup2, backup1) on
		// both stable/26.7 and stable/26.1. Model those operands rather
		// than returning a forward diff regardless of the request path.
		switch r.URL.EscapedPath() {
		case "/api/core/backup/diff/this/config-new.xml/config-old.xml":
			_, _ = w.Write([]byte(`{"items":["--- old","+++ new","+&lt;rule/&gt;"]}`))
		case "/api/core/backup/diff/this/config-old.xml/config-new.xml":
			_, _ = w.Write([]byte(`{"items":["--- new","+++ old","-&lt;rule/&gt;"]}`))
		default:
			t.Errorf("unexpected diff path %q", r.URL.EscapedPath())
			http.Error(w, "unexpected diff operands", http.StatusBadRequest)
		}
	})
	defer server.Close()

	diff, err := client.FetchConfigBackupDiff("this", "config-old.xml", "config-new.xml")
	if err != nil {
		t.Fatalf("FetchConfigBackupDiff: %v", err)
	}
	if diff != "--- old\n+++ new\n+&lt;rule/&gt;" {
		t.Fatalf("diff = %q", diff)
	}
}

func TestBoundConfigBackupDiffLines_CutAtLineBoundaryWithMarker(t *testing.T) {
	items := []string{"aaaa", "bbbb", "cccc", "dddd"}
	// "aaaa\nbbbb" is exactly 9 bytes; adding "\ncccc" would push it to 14. The
	// bound includes the marker line, so it is 9 plus the marker and its newline.
	max := 9 + 1 + len(configBackupDiffTruncationMarker)
	got, truncated := boundConfigBackupDiffLines(items, max)
	if !truncated {
		t.Fatalf("expected truncated=true")
	}
	want := "aaaa\nbbbb\n" + configBackupDiffTruncationMarker
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if len(got) > max {
		t.Fatalf("bounded diff is %d bytes, over the %d byte bound including the marker", len(got), max)
	}
	if !strings.HasSuffix(got, configBackupDiffTruncationMarker) {
		t.Fatalf("marker is not the final line: %q", got)
	}
	if !strings.Contains(got, "aaaa") || !strings.Contains(got, "bbbb") {
		t.Fatalf("kept lines are not intact: %q", got)
	}
	if strings.Contains(got, "cccc") || strings.Contains(got, "dddd") {
		t.Fatalf("dropped lines leaked into output: %q", got)
	}
}

func TestBoundConfigBackupDiffLines_UnderBoundUnchanged(t *testing.T) {
	items := []string{"line one", "line two", "line three"}
	got, truncated := boundConfigBackupDiffLines(items, 1<<20)
	if truncated {
		t.Fatalf("expected truncated=false for a diff under the bound")
	}
	want := strings.Join(items, "\n")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if strings.Contains(got, configBackupDiffTruncationMarker) {
		t.Fatalf("marker present on an unbounded diff: %q", got)
	}
}

func TestFetchConfigBackupDiff_UsesStableObserverEndpoint(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	defer server.Close()

	observer := &fakeResultObserver{}
	client.SetRequestObserver(observer)
	if _, err := client.FetchConfigBackupDiff("this", "config-old.xml", "config-new.xml"); err != nil {
		t.Fatalf("FetchConfigBackupDiff: %v", err)
	}
	calls := observer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("observer calls = %#v, want one", calls)
	}
	if got, want := calls[0].endpoint, "api/core/backup/diff"; got != want {
		t.Fatalf("observer endpoint = %q, want static route %q", got, want)
	}
}

// TestFetchConfigBackupHistory_OutOfOrder covers the defensive max(time) scan:
// even if a response were not newest-first, the newest backup must still win.
func TestFetchConfigBackupHistory_OutOfOrder(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"items": [
				{"time": "1000", "filesize": 100},
				{"time": "3000", "filesize": 300},
				{"time": "2000", "filesize": 200}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Count != 3 {
		t.Errorf("expected Count=3, got %d", data.Count)
	}
	if data.LastTimestamp != 3000 {
		t.Errorf("expected LastTimestamp=3000, got %v", data.LastTimestamp)
	}
	if data.LastSizeBytes != 300 {
		t.Errorf("expected LastSizeBytes=300, got %v", data.LastSizeBytes)
	}
}

func TestFetchConfigBackupHistory_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items": []}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Count != 0 {
		t.Errorf("expected Count=0, got %d", data.Count)
	}
	if data.LastTimestamp != 0 {
		t.Errorf("expected LastTimestamp=0, got %v", data.LastTimestamp)
	}
	if data.LastSizeBytes != 0 {
		t.Errorf("expected LastSizeBytes=0, got %v", data.LastSizeBytes)
	}
}

func TestFetchConfigBackupHistory_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchConfigBackupHistory()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchConfigBackupHistory_NaNTimestamp is the #323 regression test.
// backup.go seeds its newest-timestamp scan from Items[0]; strconv.ParseFloat
// accepts "NaN" WITHOUT an error, and every comparison against NaN is false,
// so a NaN seed could never be displaced by a later, larger timestamp. The
// resulting NaN opnsense_backup_last_timestamp_seconds makes a
// `time() - metric > X` staleness alert silently never fire.
func TestFetchConfigBackupHistory_NaNTimestamp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"items": [
				{"time": "NaN", "filesize": 100},
				{"time": "1783886416.55", "filesize": 417639}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.IsNaN(data.LastTimestamp) || math.IsInf(data.LastTimestamp, 0) {
		t.Fatalf("LastTimestamp is non-finite (%v); a NaN gauge defeats staleness alerting", data.LastTimestamp)
	}
	if data.LastTimestamp != 1783886416.55 {
		t.Errorf("expected LastTimestamp=1783886416.55 (the real entry must win over the NaN seed), got %v", data.LastTimestamp)
	}
}

// TestFetchConfigBackupHistory_InfTimestamp covers the ±Inf half of #323:
// +Inf DOES compare greater than every real timestamp, so it wins the scan
// outright and pins the gauge at infinity.
func TestFetchConfigBackupHistory_InfTimestamp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"items": [
				{"time": "+Inf", "filesize": 100},
				{"time": "1783886416.55", "filesize": 417639}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchConfigBackupHistory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if math.IsInf(data.LastTimestamp, 0) || math.IsNaN(data.LastTimestamp) {
		t.Fatalf("LastTimestamp is non-finite (%v)", data.LastTimestamp)
	}
	if data.LastTimestamp != 1783886416.55 {
		t.Errorf("expected LastTimestamp=1783886416.55, got %v", data.LastTimestamp)
	}
}

func TestFetchConfigBackupDiff_RefusesOversizedResponseBeforeDecoding(t *testing.T) {
	// A body past configBackupDiffMaxResponseBytes must be refused while it is
	// still bytes, never decoded into a []string only to be trimmed afterwards.
	oversized := configBackupDiffMaxResponseBytes + 1024
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":["`))
		filler := bytes.Repeat([]byte("x"), 64*1024)
		for written := 0; written < oversized; written += len(filler) {
			_, _ = w.Write(filler)
		}
		_, _ = w.Write([]byte(`"]}`))
	}))
	defer server.Close()

	client, err := NewClient(options.OPNSenseConfig{
		Protocol:  "http",
		Host:      strings.TrimPrefix(server.URL, "http://"),
		APIKey:    "test-key",
		APISecret: "test-secret",
	}, "test", slog.Default())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	diff, apiErr := client.FetchConfigBackupDiff("this", "config-old.xml", "config-new.xml")
	if apiErr == nil {
		t.Fatalf("expected an API error for an oversized body, got %d bytes of diff", len(diff))
	}
	if !strings.Contains(apiErr.Message, "exceeds") {
		t.Fatalf("expected the body-limit error, got %q", apiErr.Message)
	}
}
