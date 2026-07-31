package opnsense

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newBoundedTestClient builds a Client pointed at server whose upstream fan-out is
// capped at limit in-flight requests (limit <= 0 leaves it unbounded).
func newBoundedTestClient(server *httptest.Server, limit int) *Client {
	c := &Client{
		httpClient:       server.Client(),
		baseURL:          server.URL,
		key:              "test-key",
		secret:           "test-secret",
		log:              slog.Default(),
		gatewayLossRegex: regexp.MustCompile(`\d\.\d %`),
		gatewayRTTRegex:  regexp.MustCompile(`\d+\.\d+ ms`),
		headers: map[string]string{
			"Accept":     "application/json",
			"User-Agent": "prometheus-opnsense2otel/test",
		},
		endpoints:  defaultEndpoints(),
		maxRetries: 1,
	}
	if limit > 0 {
		c.sem = make(chan struct{}, limit)
	}
	return c
}

// TestClientBoundsConcurrentRequests drives many logical calls through one shared
// client (as a scrape's WithContext clones do) and asserts the test server never sees
// more than `limit` requests in flight at once. It records peak concurrency and
// wall-clock duration per limit, covering #294's deterministic-peak + benchmark bullets.
func TestClientBoundsConcurrentRequests(t *testing.T) {
	const callers = 40
	for _, limit := range []int{1, 4, 16} {
		t.Run("limit="+strconv.Itoa(limit), func(t *testing.T) {
			var inflight, peak int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n := atomic.AddInt64(&inflight, 1)
				for {
					p := atomic.LoadInt64(&peak)
					if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
						break
					}
				}
				// Hold the slot long enough that real overlap would occur if unbounded.
				time.Sleep(15 * time.Millisecond)
				atomic.AddInt64(&inflight, -1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))

			client := newBoundedTestClient(server, limit)
			start := time.Now()
			var wg sync.WaitGroup
			wg.Add(callers)
			for range callers {
				go func() {
					defer wg.Done()
					var out map[string]any
					_ = client.WithContext(context.Background()).do("GET", EndpointPath("api/test"), nil, &out)
				}()
			}
			wg.Wait()
			dur := time.Since(start)
			server.Close()

			if peak > int64(limit) {
				t.Fatalf("peak concurrent upstream requests = %d, want <= %d", peak, limit)
			}
			if peak == 0 {
				t.Fatalf("test observed no requests; peak=0")
			}
			t.Logf("limit=%d peak=%d duration=%s", limit, peak, dur)
		})
	}
}

// TestAcquireSlotRespectsCancellation proves a caller waiting on a saturated budget is
// released by scrape cancellation rather than blocking indefinitely — the property that
// keeps nested runConcurrentFetches from deadlocking under a low limit.
func TestAcquireSlotRespectsCancellation(t *testing.T) {
	c := &Client{sem: make(chan struct{}, 1)}
	c.sem <- struct{}{} // saturate the only slot

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	release, err := c.acquireSlot(ctx)
	if err == nil {
		release()
		t.Fatal("acquireSlot returned no error despite a saturated budget and a cancelled context")
	}
}

// TestAcquireSlotUnboundedNoop confirms a client with no configured limit acquires
// without blocking and hands back a no-op release.
func TestAcquireSlotUnboundedNoop(t *testing.T) {
	c := &Client{}
	release, err := c.acquireSlot(context.Background())
	if err != nil {
		t.Fatalf("unbounded acquireSlot errored: %v", err)
	}
	release() // must not panic
}
