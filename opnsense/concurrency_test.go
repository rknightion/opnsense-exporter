package opnsense

import (
	"net/http"
	"testing"
	"time"
)

// The timing tests below prove the multi-endpoint fetchers fan their independent
// sub-calls out concurrently (#129): with a per-endpoint artificial delay, total wall
// time must be far closer to the slowest single call than to the sum of all calls. A
// regression to sequential execution would blow past the (generous) thresholds.

const fetchDelay = 60 * time.Millisecond

func delayHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(fetchDelay)
		_, _ = w.Write([]byte(body))
	}
}

func TestFetchSystemResources_Concurrent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	for _, p := range []string{
		"/api/diagnostics/system/systemResources",
		"/api/diagnostics/system/systemTime",
		"/api/diagnostics/system/systemDisk",
		"/api/diagnostics/system/systemSwap",
		"/api/diagnostics/system/system_information",
	} {
		mux.HandleFunc(p, delayHandler(`{}`))
	}
	mux.HandleFunc("/api/diagnostics/cpu_usage/getCPUType", delayHandler(`[]`))

	start := time.Now()
	client.FetchSystemResources()
	elapsed := time.Since(start)
	// Sequential would be ~6*60ms = 360ms; concurrent ~60ms.
	if elapsed > 250*time.Millisecond {
		t.Errorf("FetchSystemResources took %v; expected ~max(delay), not the sum — concurrency regressed", elapsed)
	}
}

func TestFetchPFStatistics_Concurrent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	for _, p := range []string{
		"/api/diagnostics/firewall/pf_statistics/info",
		"/api/diagnostics/firewall/pf_statistics/memory",
		"/api/diagnostics/firewall/pf_statistics/timeouts",
	} {
		mux.HandleFunc(p, delayHandler(`{}`))
	}
	start := time.Now()
	client.FetchPFStatistics()
	elapsed := time.Since(start)
	// Sequential ~3*60ms = 180ms; concurrent ~60ms.
	if elapsed > 140*time.Millisecond {
		t.Errorf("FetchPFStatistics took %v; expected ~max(delay), not the sum", elapsed)
	}
}

func TestFetchChronyStatus_Concurrent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	// tracking gates Present and runs first; sources + sourcestats then run concurrently.
	mux.HandleFunc("/api/chrony/service/chronytracking", delayHandler(`{"response":""}`))
	mux.HandleFunc("/api/chrony/service/chronysources", delayHandler(`{"response":""}`))
	mux.HandleFunc("/api/chrony/service/chronysourcestats", delayHandler(`{"response":""}`))

	start := time.Now()
	client.FetchChronyStatus()
	elapsed := time.Since(start)
	// Fully sequential = 3*60 = 180ms; with the two secondaries overlapped = ~120ms.
	if elapsed > 160*time.Millisecond {
		t.Errorf("FetchChronyStatus took %v; the sources/sourcestats calls did not overlap", elapsed)
	}
}

func TestFetchHAProxyStats_Concurrent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/haproxy/statistics/counters", delayHandler(`[]`))
	mux.HandleFunc("/api/haproxy/statistics/info", delayHandler(`{}`))

	start := time.Now()
	client.FetchHAProxyStats()
	elapsed := time.Since(start)
	// Sequential = 2*60 = 120ms; concurrent = ~60ms.
	if elapsed > 100*time.Millisecond {
		t.Errorf("FetchHAProxyStats took %v; counters and info did not overlap", elapsed)
	}
}
