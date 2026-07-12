package opnsense

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const firmwareStatusBody = `{
	"last_check": "2024-01-15T10:30:00Z",
	"needs_reboot": "0",
	"os_version": "24.1",
	"product_id": "opnsense",
	"product_version": "24.1.1",
	"product_abi": "24.1:amd64",
	"upgrade_packages": [
		{"name": "pkg2", "repository": "OPNsense", "current_version": "1.0", "new_version": "2.0"}
	],
	"product": {"product_check": {"upgrade_needs_reboot": "0"}},
	"status": "ok"
}`

// fakeClock drives the cache's TTL expiry without sleeping in tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// withFakeClock installs a controllable clock on the client's cache and returns it.
func withFakeClock(t *testing.T, c *Client) *fakeClock {
	t.Helper()
	if c.cache == nil {
		t.Fatal("client has no cache; call SetEndpointCacheTTL first")
	}
	clock := &fakeClock{now: time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)}
	c.cache.now = clock.Now
	return clock
}

func TestClient_CacheServesRepeatedGETsWithinTTL(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	for i := range 5 {
		data, err := client.FetchFirmwareStatus()
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		// Every scrape must still see the full data, not an empty struct.
		if data.ProductVersion != "24.1.1" || data.UpgradePackages != 1 {
			t.Fatalf("call %d: cached data not returned: %+v", i, data)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("expected 1 upstream request for 5 cached calls, got %d", got)
	}
}

func TestClient_CacheRefetchesAfterTTLExpiry(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	clock := withFakeClock(t, client)

	if _, err := client.FetchFirmwareStatus(); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Just inside the TTL: still served from cache.
	clock.Advance(12*time.Hour - time.Second)
	if _, err := client.FetchFirmwareStatus(); err != nil {
		t.Fatalf("call inside TTL: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected entry still cached just inside TTL, got %d requests", got)
	}

	// Past the TTL: refetched.
	clock.Advance(2 * time.Second)
	if _, err := client.FetchFirmwareStatus(); err != nil {
		t.Fatalf("call after TTL: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("expected refetch after TTL expiry, got %d requests", got)
	}
}

func TestClient_NoCachingWithoutConfiguredTTL(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	// No SetEndpointCacheTTL call: caching is off by default for every endpoint.
	for range 3 {
		if _, err := client.FetchFirmwareStatus(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 upstream requests with caching off, got %d", got)
	}
}

func TestClient_ZeroTTLDisablesCaching(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 0)

	for range 3 {
		if _, err := client.FetchFirmwareStatus(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 upstream requests with a zero TTL, got %d", got)
	}
}

func TestClient_CacheDoesNotStoreFailedResponses(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := requests.Add(1)
		// The client retries 5xx on GET, so fail with a non-retryable status.
		if n == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":"denied"}`))
			return
		}
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	if _, err := client.FetchFirmwareStatus(); err == nil {
		t.Fatal("expected an error from the first (403) call")
	}

	// The failure must not be cached: the next scrape retries and succeeds.
	data, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("second call should have refetched: %v", err)
	}
	if data.ProductVersion != "24.1.1" {
		t.Errorf("expected fresh data after the failed call, got %+v", data)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("expected 2 upstream requests (error not cached), got %d", got)
	}
}

func TestClient_CacheSharedAcrossWithContextClones(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	// Each scrape clones the client via WithContext; the cache must survive that,
	// otherwise every scrape starts with an empty cache and nothing is ever cached.
	for range 4 {
		scrapeClient := client.WithContext(context.Background())
		if _, err := scrapeClient.FetchFirmwareStatus(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("expected the cache to be shared across WithContext clones (1 request), got %d", got)
	}
}

func TestClient_CacheSkipsPOSTEndpoints(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	defer server.Close()

	// Even with a TTL configured, a POST must never be served from cache: POSTs
	// are actions on the box, not idempotent reads.
	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	path := client.endpoints["firmware"]
	for range 3 {
		var resp struct {
			Status string `json:"status"`
		}
		if err := client.doWithContentType("POST", path, nil, "application/json", &resp); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("expected POSTs to bypass the cache (3 requests), got %d", got)
	}
}

func TestClient_CacheIsPerEndpoint(t *testing.T) {
	var statusRequests, infoRequests atomic.Int64
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/core/firmware/status", func(w http.ResponseWriter, _ *http.Request) {
		statusRequests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	mux.HandleFunc("/api/core/firmware/info", func(w http.ResponseWriter, _ *http.Request) {
		infoRequests.Add(1)
		_, _ = w.Write([]byte(`{"product_id":"opnsense","product_version":"24.1.1","plugin":[{"name":"os-acme-client","version":"3.0","installed":"1"}]}`))
	})

	// Only the status endpoint is cached; info has no TTL and must still be fetched.
	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	for range 3 {
		if _, err := client.FetchFirmwareStatus(); err != nil {
			t.Fatalf("status: %v", err)
		}
		if _, err := client.FetchFirmwareInfo(); err != nil {
			t.Fatalf("info: %v", err)
		}
	}

	if got := statusRequests.Load(); got != 1 {
		t.Errorf("expected the cached status endpoint to be fetched once, got %d", got)
	}
	if got := infoRequests.Load(); got != 3 {
		t.Errorf("expected the uncached info endpoint to be fetched every call, got %d", got)
	}
}

func TestClient_CacheIsConcurrencySafe(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	// Sub-collectors run concurrently and share one client clone; the cache must
	// not race (this test is meaningful under -race).
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := client.WithContext(context.Background()).FetchFirmwareStatus(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
}
