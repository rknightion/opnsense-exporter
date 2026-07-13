package opnsense

import (
	"net/http"
	"sync/atomic"
	"testing"
)

// baseMbufFields is the shared systemMbuf JSON body (without the extended
// jumbo9/jumbo16/sendfile keys) used to compose the mbuf test responses.
const baseMbufFields = `"mbuf-current": 1024, "mbuf-cache": 512, "mbuf-total": 2048, "mbuf-max": 4096,
	"cluster-current": 256, "cluster-cache": 128, "cluster-total": 512, "cluster-max": 1024,
	"mbuf-failures": 3, "cluster-failures": 1, "packet-failures": 0,
	"mbuf-sleeps": 5, "cluster-sleeps": 2, "packet-sleeps": 0,
	"jumbop-current": 10, "jumbop-cache": 5, "jumbop-total": 20, "jumbop-max": 50,
	"jumbop-failures": 7, "jumbop-sleeps": 4,
	"bytes-in-use": 65536, "bytes-total": 131072, "percentage": 50, "mbuf-and-cluster": 100`

// modernMbufFields is the FULL systemMbuf `mbuf-statistics` key set as served by
// OPNsense 26.1.11 (values are synthetic). Compared with baseMbufFields it drops
// mbuf-max / percentage / mbuf-and-cluster, renames jumbop-current/-cache/-total/-max
// to jumbo-count/-cache/-total/-max (jumbop-failures / jumbop-sleeps survive under
// their old names), and adds the jumbo9/jumbo16/packet/sendfile/sfbufs families.
const modernMbufFields = `"bytes-in-cache": 3000, "bytes-in-use": 65536, "bytes-total": 131072,
	"cluster-cache": 128, "cluster-current": 256, "cluster-failures": 1, "cluster-max": 1024,
	"cluster-sleeps": 2, "cluster-total": 512,
	"jumbo-cache": 5, "jumbo-count": 10, "jumbo-max": 50, "jumbo-page-size": 4096, "jumbo-total": 20,
	"jumbo16-cache": 0, "jumbo16-count": 0, "jumbo16-failures": 22, "jumbo16-limit": 6,
	"jumbo16-sleeps": 11, "jumbo16-total": 0,
	"jumbo9-cache": 0, "jumbo9-count": 0, "jumbo9-failures": 15, "jumbo9-max": 9,
	"jumbo9-sleeps": 8, "jumbo9-total": 0,
	"jumbop-failures": 7, "jumbop-sleeps": 4,
	"mbuf-cache": 512, "mbuf-current": 1024, "mbuf-failures": 3, "mbuf-sleeps": 5, "mbuf-total": 2048,
	"packet-count": 12, "packet-failures": 0, "packet-free": 13, "packet-sleeps": 0,
	"sendfile-busy-encounters": 0, "sendfile-io-count": 100, "sendfile-no-io": 0,
	"sendfile-pages-bogus": 0, "sendfile-pages-sent": 500, "sendfile-pages-valid": 0,
	"sendfile-readahead": 0, "sendfile-requested-readahead": 0, "sendfile-syscalls": 42,
	"sfbufs-alloc-failed": 0, "sfbufs-alloc-wait": 0`

// TestFetchMbufStatistics_JumboPageKeyRename pins the tolerant read of the jumbo-page
// pool across the 26.1.11 key rename (jumbop-current/-cache/-total/-max ->
// jumbo-count/-cache/-total/-max): the new keys win when present, the legacy keys are
// used when they are not, and a box sending both is read from the new keys.
func TestFetchMbufStatistics_JumboPageKeyRename(t *testing.T) {
	tests := []struct {
		name                                string
		jumboKeys                           string
		wantCurrent, wantCache, wantTotal   int
		wantMax                             int
		wantJumbopFailures, wantJumbopSleep int
	}{
		{
			name:               "legacy jumbop keys only (<=26.1.x)",
			jumboKeys:          `"jumbop-current": 10, "jumbop-cache": 5, "jumbop-total": 20, "jumbop-max": 50, "jumbop-failures": 7, "jumbop-sleeps": 4`,
			wantCurrent:        10,
			wantCache:          5,
			wantTotal:          20,
			wantMax:            50,
			wantJumbopFailures: 7,
			wantJumbopSleep:    4,
		},
		{
			name:               "modern jumbo keys only (>=26.1.11)",
			jumboKeys:          `"jumbo-count": 11, "jumbo-cache": 6, "jumbo-total": 21, "jumbo-max": 51, "jumbop-failures": 7, "jumbop-sleeps": 4`,
			wantCurrent:        11,
			wantCache:          6,
			wantTotal:          21,
			wantMax:            51,
			wantJumbopFailures: 7,
			wantJumbopSleep:    4,
		},
		{
			name:               "both key sets present, new wins",
			jumboKeys:          `"jumbop-current": 10, "jumbop-cache": 5, "jumbop-total": 20, "jumbop-max": 50, "jumbo-count": 11, "jumbo-cache": 6, "jumbo-total": 21, "jumbo-max": 51, "jumbop-failures": 7, "jumbop-sleeps": 4`,
			wantCurrent:        11,
			wantCache:          6,
			wantTotal:          21,
			wantMax:            51,
			wantJumbopFailures: 7,
			wantJumbopSleep:    4,
		},
		{
			name:        "neither key set present",
			jumboKeys:   `"mbuf-current": 1024`,
			wantCurrent: 0, wantCache: 0, wantTotal: 0, wantMax: 0,
			wantJumbopFailures: 0,
			wantJumbopSleep:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"mbuf-statistics": {` + tt.jumboKeys + `}}`))
			})
			defer server.Close()

			data, err := client.FetchMbufStatistics()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data.JumboPageCurrent != tt.wantCurrent {
				t.Errorf("JumboPageCurrent = %d, want %d", data.JumboPageCurrent, tt.wantCurrent)
			}
			if data.JumboPageCache != tt.wantCache {
				t.Errorf("JumboPageCache = %d, want %d", data.JumboPageCache, tt.wantCache)
			}
			if data.JumboPageTotal != tt.wantTotal {
				t.Errorf("JumboPageTotal = %d, want %d", data.JumboPageTotal, tt.wantTotal)
			}
			if data.JumboPageMax != tt.wantMax {
				t.Errorf("JumboPageMax = %d, want %d", data.JumboPageMax, tt.wantMax)
			}
			// jumbop-failures / jumbop-sleeps were NOT renamed: they must keep reading
			// from their old keys on every release.
			if got := data.FailuresByType["jumbop"]; got != tt.wantJumbopFailures {
				t.Errorf("FailuresByType[jumbop] = %d, want %d", got, tt.wantJumbopFailures)
			}
			if got := data.SleepsByType["jumbop"]; got != tt.wantJumbopSleep {
				t.Errorf("SleepsByType[jumbop] = %d, want %d", got, tt.wantJumbopSleep)
			}
		})
	}
}

// TestFetchMbufStatistics_ModernPayload feeds the real 26.1.11 systemMbuf key set
// (synthetic values) and asserts every value that backs a metric still resolves — i.e.
// no metric silently reads zero on a current-stable box.
func TestFetchMbufStatistics_ModernPayload(t *testing.T) {
	var memStatsCalls atomic.Int32
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/system/systemMbuf", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"mbuf-statistics": {` + modernMbufFields + `}}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_memory_statistics", func(w http.ResponseWriter, _ *http.Request) {
		memStatsCalls.Add(1)
		w.Write([]byte(`{"mbuf-statistics": {}}`))
	})

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.MbufCurrent != 1024 || data.MbufCache != 512 || data.MbufTotal != 2048 {
		t.Errorf("mbuf pool = %d/%d/%d, want 1024/512/2048", data.MbufCurrent, data.MbufCache, data.MbufTotal)
	}
	if data.ClusterCurrent != 256 || data.ClusterCache != 128 || data.ClusterTotal != 512 || data.ClusterMax != 1024 {
		t.Errorf("cluster pool = %d/%d/%d/%d, want 256/128/512/1024",
			data.ClusterCurrent, data.ClusterCache, data.ClusterTotal, data.ClusterMax)
	}
	if data.BytesInUse != 65536*1024 || data.BytesTotal != 131072*1024 {
		t.Errorf("bytes = %d/%d, want %d/%d", data.BytesInUse, data.BytesTotal, 65536*1024, 131072*1024)
	}
	// Jumbo-page pool resolves from the renamed keys.
	if data.JumboPageCurrent != 10 || data.JumboPageCache != 5 || data.JumboPageTotal != 20 || data.JumboPageMax != 50 {
		t.Errorf("jumbo page pool = %d/%d/%d/%d, want 10/5/20/50",
			data.JumboPageCurrent, data.JumboPageCache, data.JumboPageTotal, data.JumboPageMax)
	}
	wantFailures := map[string]int{"mbuf": 3, "cluster": 1, "packet": 0, "jumbop": 7, "jumbo9": 15, "jumbo16": 22}
	for k, want := range wantFailures {
		if got := data.FailuresByType[k]; got != want {
			t.Errorf("FailuresByType[%q] = %d, want %d", k, got, want)
		}
	}
	wantSleeps := map[string]int{"mbuf": 5, "cluster": 2, "packet": 0, "jumbop": 4, "jumbo9": 8, "jumbo16": 11}
	for k, want := range wantSleeps {
		if got := data.SleepsByType[k]; got != want {
			t.Errorf("SleepsByType[%q] = %d, want %d", k, got, want)
		}
	}
	if data.SendfileSyscalls != 42 || data.SendfileIOCount != 100 || data.SendfilePagesSent != 500 {
		t.Errorf("sendfile = %d/%d/%d, want 42/100/500",
			data.SendfileSyscalls, data.SendfileIOCount, data.SendfilePagesSent)
	}
	if got := memStatsCalls.Load(); got != 0 {
		t.Errorf("memoryStatistics calls = %d, want 0 (26.1.11 systemMbuf is self-sufficient)", got)
	}
}

// TestFetchMbufStatistics_ExtendedFromSystemMbuf covers #137: when systemMbuf already
// carries the jumbo9/jumbo16/sendfile keys (OPNsense 26.1+), they are read from that
// single response and the redundant memoryStatistics call is NOT made.
func TestFetchMbufStatistics_ExtendedFromSystemMbuf(t *testing.T) {
	var systemMbufCalls, memStatsCalls atomic.Int32
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/system/systemMbuf", func(w http.ResponseWriter, _ *http.Request) {
		systemMbufCalls.Add(1)
		w.Write([]byte(`{"mbuf-statistics": {` + baseMbufFields + `,
			"jumbo9-failures": 15, "jumbo16-failures": 22,
			"jumbo9-sleeps": 8, "jumbo16-sleeps": 11,
			"sendfile-syscalls": 42, "sendfile-io-count": 100, "sendfile-pages-sent": 500}}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_memory_statistics", func(w http.ResponseWriter, _ *http.Request) {
		memStatsCalls.Add(1)
		w.Write([]byte(`{"mbuf-statistics": {}}`))
	})

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.FailuresByType["jumbo9"] != 15 || data.FailuresByType["jumbo16"] != 22 {
		t.Errorf("jumbo failures = %v, want jumbo9=15 jumbo16=22", data.FailuresByType)
	}
	if data.SleepsByType["jumbo9"] != 8 || data.SleepsByType["jumbo16"] != 11 {
		t.Errorf("jumbo sleeps = %v, want jumbo9=8 jumbo16=11", data.SleepsByType)
	}
	if data.SendfileSyscalls != 42 || data.SendfileIOCount != 100 || data.SendfilePagesSent != 500 {
		t.Errorf("sendfile = %d/%d/%d, want 42/100/500", data.SendfileSyscalls, data.SendfileIOCount, data.SendfilePagesSent)
	}
	// Steady-state: exactly one call to systemMbuf, zero to memoryStatistics.
	if got := systemMbufCalls.Load(); got != 1 {
		t.Errorf("systemMbuf calls = %d, want 1", got)
	}
	if got := memStatsCalls.Load(); got != 0 {
		t.Errorf("memoryStatistics calls = %d, want 0 (redundant call must be skipped)", got)
	}
}

// TestFetchMbufStatistics_FallsBackWhenExtendedAbsent covers #137 acceptance #3: an
// older-release systemMbuf without the extended keys still uses the memoryStatistics
// fallback exactly once.
func TestFetchMbufStatistics_FallsBackWhenExtendedAbsent(t *testing.T) {
	var systemMbufCalls, memStatsCalls atomic.Int32
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/system/systemMbuf", func(w http.ResponseWriter, _ *http.Request) {
		systemMbufCalls.Add(1)
		w.Write([]byte(`{"mbuf-statistics": {` + baseMbufFields + `}}`)) // no extended keys
	})
	mux.HandleFunc("/api/diagnostics/interface/get_memory_statistics", func(w http.ResponseWriter, _ *http.Request) {
		memStatsCalls.Add(1)
		w.Write([]byte(`{"mbuf-statistics": {"jumbo9-failures": 15, "jumbo16-failures": 22,
			"jumbo9-sleeps": 8, "jumbo16-sleeps": 11, "sendfile-syscalls": 42,
			"sendfile-io-count": 100, "sendfile-pages-sent": 500}}`))
	})

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.FailuresByType["jumbo9"] != 15 || data.SendfileSyscalls != 42 {
		t.Errorf("fallback did not populate extended fields: %v sendfile=%d", data.FailuresByType, data.SendfileSyscalls)
	}
	if got := memStatsCalls.Load(); got != 1 {
		t.Errorf("memoryStatistics calls = %d, want 1 (fallback for older release)", got)
	}
}

func TestFetchMbufStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"mbuf-statistics": {
				"mbuf-current": 1024,
				"mbuf-cache": 512,
				"mbuf-total": 2048,
				"mbuf-max": 4096,
				"cluster-current": 256,
				"cluster-cache": 128,
				"cluster-total": 512,
				"cluster-max": 1024,
				"mbuf-failures": 3,
				"cluster-failures": 1,
				"packet-failures": 0,
				"mbuf-sleeps": 5,
				"cluster-sleeps": 2,
				"packet-sleeps": 0,
				"jumbop-current": 10,
				"jumbop-cache": 5,
				"jumbop-total": 20,
				"jumbop-max": 50,
				"jumbop-failures": 7,
				"jumbop-sleeps": 4,
				"bytes-in-use": 65536,
				"bytes-total": 131072,
				"percentage": 50,
				"mbuf-and-cluster": 100
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check scalar fields
	if data.MbufCurrent != 1024 {
		t.Errorf("expected MbufCurrent=1024, got %d", data.MbufCurrent)
	}
	if data.MbufCache != 512 {
		t.Errorf("expected MbufCache=512, got %d", data.MbufCache)
	}
	if data.MbufTotal != 2048 {
		t.Errorf("expected MbufTotal=2048, got %d", data.MbufTotal)
	}
	if data.ClusterCurrent != 256 {
		t.Errorf("expected ClusterCurrent=256, got %d", data.ClusterCurrent)
	}
	if data.ClusterCache != 128 {
		t.Errorf("expected ClusterCache=128, got %d", data.ClusterCache)
	}
	if data.ClusterTotal != 512 {
		t.Errorf("expected ClusterTotal=512, got %d", data.ClusterTotal)
	}
	if data.ClusterMax != 1024 {
		t.Errorf("expected ClusterMax=1024, got %d", data.ClusterMax)
	}
	// API reports KB; FetchMbufStatistics converts to bytes (×1024).
	if data.BytesInUse != 65536*1024 {
		t.Errorf("expected BytesInUse=%d, got %d", 65536*1024, data.BytesInUse)
	}
	if data.BytesTotal != 131072*1024 {
		t.Errorf("expected BytesTotal=%d, got %d", 131072*1024, data.BytesTotal)
	}

	// Check FailuresByType map
	expectedFailures := map[string]int{
		"mbuf":    3,
		"cluster": 1,
		"packet":  0,
		"jumbop":  7,
	}
	for k, want := range expectedFailures {
		if got := data.FailuresByType[k]; got != want {
			t.Errorf("FailuresByType[%q] = %d; want %d", k, got, want)
		}
	}

	// Check SleepsByType map
	expectedSleeps := map[string]int{
		"mbuf":    5,
		"cluster": 2,
		"packet":  0,
		"jumbop":  4,
	}
	for k, want := range expectedSleeps {
		if got := data.SleepsByType[k]; got != want {
			t.Errorf("SleepsByType[%q] = %d; want %d", k, got, want)
		}
	}
}

func TestFetchMbufStatistics_WithMemoryStatistics(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/system/systemMbuf", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"mbuf-statistics": {
				"mbuf-current": 1024,
				"mbuf-cache": 512,
				"mbuf-total": 2048,
				"mbuf-max": 4096,
				"cluster-current": 256,
				"cluster-cache": 128,
				"cluster-total": 512,
				"cluster-max": 1024,
				"mbuf-failures": 3,
				"cluster-failures": 1,
				"packet-failures": 0,
				"mbuf-sleeps": 5,
				"cluster-sleeps": 2,
				"packet-sleeps": 0,
				"jumbop-current": 10,
				"jumbop-cache": 5,
				"jumbop-total": 20,
				"jumbop-max": 50,
				"jumbop-failures": 7,
				"jumbop-sleeps": 4,
				"bytes-in-use": 65536,
				"bytes-total": 131072,
				"percentage": 50,
				"mbuf-and-cluster": 100
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/interface/get_memory_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"mbuf-statistics": {
				"jumbo9-failures": 15,
				"jumbo16-failures": 22,
				"jumbo9-sleeps": 8,
				"jumbo16-sleeps": 11,
				"sendfile-syscalls": 42,
				"sendfile-io-count": 100,
				"sendfile-pages-sent": 500
			}
		}`))
	})

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check scalar fields from primary endpoint
	if data.MbufCurrent != 1024 {
		t.Errorf("expected MbufCurrent=1024, got %d", data.MbufCurrent)
	}
	if data.BytesInUse != 65536*1024 {
		t.Errorf("expected BytesInUse=%d, got %d", 65536*1024, data.BytesInUse)
	}

	// Check FailuresByType map includes jumbo9 and jumbo16
	expectedFailures := map[string]int{
		"mbuf":    3,
		"cluster": 1,
		"packet":  0,
		"jumbop":  7,
		"jumbo9":  15,
		"jumbo16": 22,
	}
	for k, want := range expectedFailures {
		if got := data.FailuresByType[k]; got != want {
			t.Errorf("FailuresByType[%q] = %d; want %d", k, got, want)
		}
	}

	// Check SleepsByType map includes jumbo9 and jumbo16
	expectedSleeps := map[string]int{
		"mbuf":    5,
		"cluster": 2,
		"packet":  0,
		"jumbop":  4,
		"jumbo9":  8,
		"jumbo16": 11,
	}
	for k, want := range expectedSleeps {
		if got := data.SleepsByType[k]; got != want {
			t.Errorf("SleepsByType[%q] = %d; want %d", k, got, want)
		}
	}

	// Check sendfile fields
	if data.SendfileSyscalls != 42 {
		t.Errorf("expected SendfileSyscalls=42, got %d", data.SendfileSyscalls)
	}
	if data.SendfileIOCount != 100 {
		t.Errorf("expected SendfileIOCount=100, got %d", data.SendfileIOCount)
	}
	if data.SendfilePagesSent != 500 {
		t.Errorf("expected SendfilePagesSent=500, got %d", data.SendfilePagesSent)
	}
}

func TestFetchMbufStatistics_MemoryStatisticsFails(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/system/systemMbuf", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"mbuf-statistics": {
				"mbuf-current": 512,
				"mbuf-cache": 256,
				"mbuf-total": 1024,
				"mbuf-max": 2048,
				"cluster-current": 128,
				"cluster-cache": 64,
				"cluster-total": 256,
				"cluster-max": 512,
				"mbuf-failures": 0,
				"cluster-failures": 0,
				"packet-failures": 0,
				"mbuf-sleeps": 0,
				"cluster-sleeps": 0,
				"packet-sleeps": 0,
				"jumbop-current": 0,
				"jumbop-cache": 0,
				"jumbop-total": 0,
				"jumbop-max": 0,
				"jumbop-failures": 0,
				"jumbop-sleeps": 0,
				"bytes-in-use": 4096,
				"bytes-total": 8192,
				"percentage": 50,
				"mbuf-and-cluster": 0
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/interface/get_memory_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	data, err := client.FetchMbufStatistics()
	if err != nil {
		t.Fatalf("expected no error when memoryStatistics fails, got: %v", err)
	}

	// Primary data should still be present
	if data.MbufCurrent != 512 {
		t.Errorf("expected MbufCurrent=512, got %d", data.MbufCurrent)
	}

	// jumbo9/jumbo16 should not be in the maps
	if _, ok := data.FailuresByType["jumbo9"]; ok {
		t.Error("expected jumbo9 not to be in FailuresByType when memoryStatistics fails")
	}

	// sendfile fields should be 0
	if data.SendfileSyscalls != 0 {
		t.Errorf("expected SendfileSyscalls=0, got %d", data.SendfileSyscalls)
	}
}

func TestFetchMbufStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchMbufStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
