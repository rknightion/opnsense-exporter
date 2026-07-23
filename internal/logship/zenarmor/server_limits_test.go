package zenarmor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// oneBulkPair is a minimal, real-shaped action/source pair: one document.
const oneBulkPair = `{"index":{"_index":"zenarmor_0000000000_abc_conn_write"}}` + "\n" +
	`{"app_name":"SSDP"}` + "\n"

// blockingBulk builds an onBulk callback that parks every document on gate while
// recording the high-water mark of concurrent handlers. That mark is the whole point:
// the per-request body limit bounds ONE request, so what has to be proven is that N
// requests cannot each buffer that allowance at once (#315).
func blockingBulk(gate <-chan struct{}, inFlight, high *atomic.Int64) func(string, []byte, netip.Addr) {
	return func(string, []byte, netip.Addr) {
		cur := inFlight.Add(1)
		for {
			h := high.Load()
			if cur <= h || high.CompareAndSwap(h, cur) {
				break
			}
		}
		<-gate
		inFlight.Add(-1)
	}
}

// postBulk fires one bulk write and reports its status code on out.
func postBulk(t *testing.T, url string, out chan<- int, wg *sync.WaitGroup) {
	t.Helper()
	go func() {
		defer wg.Done()
		resp, err := http.Post(url+"/_bulk", "application/x-ndjson", strings.NewReader(oneBulkPair)) //nolint:noctx // test client
		if err != nil {
			out <- 0
			return
		}
		_ = resp.Body.Close()
		out <- resp.StatusCode
	}()
}

func awaitStatus(t *testing.T, ch <-chan int, what string) int {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return 0
	}
}

// #315: without an aggregate cap, N concurrent bulk requests each buffer the full
// per-request allowance. Past MaxConcurrentRequests the excess must be refused BEFORE
// a body is read, and no more than the limit may ever be in flight at once.
func TestBulkConcurrencyLimitRefusesExcess(t *testing.T) {
	const limit = 2
	const callers = 6

	reg := prometheus.NewRegistry()
	gate := make(chan struct{})
	var inFlight, high atomic.Int64

	srv := httptest.NewServer(newServer(
		Config{MaxConcurrentRequests: limit},
		blockingBulk(gate, &inFlight, &high),
		newMetrics(reg, nil), discardLogger()))
	// LIFO, and the opener is idempotent: httptest's Close blocks until every in-flight
	// request finishes, so a parked handler must be released first — including on the
	// failure path, where the test bails out before it opens the gate itself.
	var once sync.Once
	open := func() { once.Do(func() { close(gate) }) }
	defer srv.Close()
	defer open()

	statuses := make(chan int, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		postBulk(t, srv.URL, statuses, &wg)
	}

	// The blocked handlers hold every slot, so exactly callers-limit requests must come
	// back refused while the gate is still shut.
	refused := 0
	for range callers - limit {
		if got := awaitStatus(t, statuses, "a refused bulk request"); got != http.StatusServiceUnavailable {
			t.Errorf("over-limit request status = %d, want 503", got)
		} else {
			refused++
		}
	}

	open()
	wg.Wait()
	for range limit {
		if got := awaitStatus(t, statuses, "an accepted bulk request"); got != http.StatusOK {
			t.Errorf("in-limit request status = %d, want 200", got)
		}
	}

	if got := high.Load(); got > limit {
		t.Errorf("peak concurrent bulk handlers = %d, want <= %d", got, limit)
	}
	if got := rejectCount(t, reg, "overloaded"); got != float64(refused) {
		t.Errorf("overloaded reject count = %v, want %d", got, refused)
	}
}

// The refusal must never make the receiver look like something other than
// Elasticsearch: the product header is what the official client checks before it will
// speak to us at all.
func TestBulkConcurrencyRefusalCarriesProductHeader(t *testing.T) {
	gate := make(chan struct{})
	var inFlight, high atomic.Int64

	srv := httptest.NewServer(newServer(
		Config{MaxConcurrentRequests: 1},
		blockingBulk(gate, &inFlight, &high),
		nil, discardLogger()))
	// LIFO: the gate is opened BEFORE Close, which blocks until every in-flight
	// request has finished — a parked handler would otherwise deadlock the test.
	defer srv.Close()
	defer close(gate)

	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	postBulk(t, srv.URL, statuses, &wg)
	postBulk(t, srv.URL, statuses, &wg)

	if got := awaitStatus(t, statuses, "the refused request"); got != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", got)
	}
	// Re-issue one synchronously to read the headers of a refusal.
	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader(oneBulkPair)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Elastic-Product"); got != "Elasticsearch" {
		t.Errorf("X-Elastic-Product = %q on a refusal, want Elasticsearch", got)
	}
}

// Zero disables the limit — the zero-value Config used throughout the rest of the
// package's tests (and by an operator who sets 0 deliberately) must not silently
// refuse everything.
func TestBulkConcurrencyLimitZeroIsUnlimited(t *testing.T) {
	const callers = 4

	gate := make(chan struct{})
	var inFlight, high atomic.Int64

	srv := httptest.NewServer(newServer(
		Config{MaxConcurrentRequests: 0},
		blockingBulk(gate, &inFlight, &high),
		nil, discardLogger()))
	var once sync.Once
	open := func() { once.Do(func() { close(gate) }) }
	defer srv.Close()
	defer open()

	statuses := make(chan int, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		postBulk(t, srv.URL, statuses, &wg)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && inFlight.Load() < callers {
		time.Sleep(10 * time.Millisecond)
	}
	if got := inFlight.Load(); got != callers {
		t.Errorf("in-flight handlers = %d, want %d (0 must not cap concurrency)", got, callers)
	}

	open()
	wg.Wait()
	for range callers {
		if got := awaitStatus(t, statuses, "a bulk response"); got != http.StatusOK {
			t.Errorf("status = %d, want 200", got)
		}
	}
}

// #316: a PUT inserts the WIRE-CHOSEN index name into a map held for the process
// lifetime. A hostile peer walking distinct names must hit a ceiling, and the
// over-cap PUT must be refused outright rather than accepted-and-dropped (which would
// leave the exists probe lying about an index we never recorded).
func TestIndexRegistryIsCapped(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := newServer(Config{}, nil, newMetrics(reg, nil), discardLogger())
	srv := httptest.NewServer(s)
	defer srv.Close()

	put := func(name string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, srv.URL+"/"+name, strings.NewReader(`{"mappings":{}}`)) //nolint:noctx // test client
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// A real family name first, so the legitimate case can be re-checked once the
	// registry is full.
	const family = "zenarmor_0000000000_abc_conn_write"
	if got := put(family); got != http.StatusOK {
		t.Fatalf("PUT %s = %d, want 200", family, got)
	}
	for i := range maxIndices - 1 {
		if got := put(fmt.Sprintf("hostile-%d", i)); got != http.StatusOK {
			t.Fatalf("PUT #%d = %d, want 200 (below the cap)", i, got)
		}
	}

	if got := put("one-too-many"); got != http.StatusTooManyRequests {
		t.Errorf("over-cap PUT = %d, want 429", got)
	}
	s.mu.RLock()
	n := len(s.indices)
	s.mu.RUnlock()
	if n != maxIndices {
		t.Errorf("registry holds %d entries, want it pinned at %d", n, maxIndices)
	}
	// The refused name must NOT be readable back: refusal, not accept-and-drop.
	resp, err := http.Head(srv.URL + "/one-too-many") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("HEAD of a refused index = %d, want 404", resp.StatusCode)
	}

	// A name already in the registry does not grow it, so re-creating a legitimate
	// family keeps working even at the ceiling.
	if got := put(family); got != http.StatusOK {
		t.Errorf("re-PUT of an existing index at the cap = %d, want 200", got)
	}
	// And freeing a slot lets a new index in again.
	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/hostile-0", nil) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	del, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = del.Body.Close()
	if got := put("after-a-delete"); got != http.StatusOK {
		t.Errorf("PUT after a DELETE freed a slot = %d, want 200", got)
	}
	if got := rejectCount(t, reg, "index_limit"); got != 1 {
		t.Errorf("index_limit reject count = %v, want 1", got)
	}
}

// #325b: handleBulk appends a fully-populated nested response map per action line, so
// a body of minimal action lines amplifies ~100x into the heap. Past the item cap the
// request is refused on the same path as an oversized body, BEFORE any document is
// handed to onBulk.
func TestBulkItemCapRejectsOversizedBatch(t *testing.T) {
	reg := prometheus.NewRegistry()
	var called atomic.Int64
	srv := httptest.NewServer(newServer(Config{},
		func(string, []byte, netip.Addr) { called.Add(1) },
		newMetrics(reg, nil), discardLogger()))
	defer srv.Close()

	// Action/source pairs, so a cap enforced mid-loop rather than up front would show
	// up as documents already delivered for a request we then answer 400.
	body := strings.Repeat(oneBulkPair, maxBulkItems/2+1)
	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an over-cap batch", resp.StatusCode)
	}
	if got := called.Load(); got != 0 {
		t.Errorf("onBulk ran %d times on an over-cap batch, want 0", got)
	}
	if got := rejectCount(t, reg, "body"); got != 1 {
		t.Errorf("body reject count = %v, want 1", got)
	}
}

// The mirror: a batch far larger than anything Zenarmor sends is still accepted, so
// the cap cannot clip real traffic.
func TestBulkUnderItemCapIsAccepted(t *testing.T) {
	var called atomic.Int64
	srv := httptest.NewServer(newServer(Config{},
		func(string, []byte, netip.Addr) { called.Add(1) },
		nil, discardLogger()))
	defer srv.Close()

	const docs = 2000 // live batches run a few hundred
	body := strings.Repeat(oneBulkPair, docs)
	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := called.Load(); got != docs {
		t.Errorf("onBulk ran %d times, want %d", got, docs)
	}
}

// #314 (runtime half): a configured username with an EMPTY password must REFUSE, not
// authenticate anyone who sends the username and nothing else. The options layer
// refuses the config at startup; this is the defence-in-depth guard at the server.
func TestAuthRefusesConfiguredEmptyPassword(t *testing.T) {
	cases := []struct {
		name       string
		cfg        Config
		setAuth    bool
		user, pass string
		want       int
	}{
		{
			name:    "user set, password empty, client sends an empty password",
			cfg:     Config{AuthUser: "admin", AuthPassword: ""},
			setAuth: true, user: "admin", pass: "",
			want: http.StatusUnauthorized,
		},
		{
			name: "user set, password empty, client sends nothing",
			cfg:  Config{AuthUser: "admin", AuthPassword: ""},
			want: http.StatusUnauthorized,
		},
		{
			name:    "user set, password empty, client guesses a password",
			cfg:     Config{AuthUser: "admin", AuthPassword: ""},
			setAuth: true, user: "admin", pass: "anything",
			want: http.StatusUnauthorized,
		},
		{
			name:    "password set with no user is equally unauthenticatable",
			cfg:     Config{AuthUser: "", AuthPassword: "s3cret"},
			setAuth: true, user: "", pass: "s3cret",
			want: http.StatusUnauthorized,
		},
		{
			name: "both empty: auth is off, unchanged",
			cfg:  Config{},
			want: http.StatusOK,
		},
		{
			name:    "both set: correct credentials still work, unchanged",
			cfg:     Config{AuthUser: "zen", AuthPassword: "s3cret"},
			setAuth: true, user: "zen", pass: "s3cret",
			want: http.StatusOK,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(newServer(c.cfg, nil, nil, discardLogger()))
			defer srv.Close()
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil) //nolint:noctx // test client
			if err != nil {
				t.Fatal(err)
			}
			if c.setAuth {
				req.SetBasicAuth(c.user, c.pass)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, c.want)
			}
		})
	}
}
