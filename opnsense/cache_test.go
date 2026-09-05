package opnsense

import (
	"context"
	"fmt"
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

func TestResponseCacheBoundsPerEntryAndAggregateBytes(t *testing.T) {
	rc := newResponseCache()
	for i := 0; i < maxResponseCacheBytes/maxResponseCacheEntryBytes+4; i++ {
		path := EndpointPath(fmt.Sprintf("api/test/%d", i))
		rc.setTTL(path, time.Hour)
		if !rc.put(path, http.StatusOK, make([]byte, maxResponseCacheEntryBytes)) {
			t.Fatalf("entry %d was not cached", i)
		}
	}
	if rc.bytes > maxResponseCacheBytes {
		t.Fatalf("cache bytes = %d, max %d", rc.bytes, maxResponseCacheBytes)
	}
	tooLarge := EndpointPath("api/test/too-large")
	rc.setTTL(tooLarge, time.Hour)
	if rc.put(tooLarge, http.StatusOK, make([]byte, maxResponseCacheEntryBytes+1)) {
		t.Fatal("oversized cache entry was stored")
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

func TestCacheSnapshot(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 30*time.Second)
	clock := withFakeClock(t, client)

	if _, err := client.FetchFirmwareStatus(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	snap := client.CacheSnapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 cache entry, got %d: %+v", len(snap), snap)
	}
	got := snap[0]
	if got.StatusCode != http.StatusOK {
		t.Errorf("expected StatusCode 200, got %d", got.StatusCode)
	}
	if !got.StoredAt.Equal(clock.Now()) {
		t.Errorf("expected StoredAt to be the fetch time %v, got %v", clock.Now(), got.StoredAt)
	}
	if got.TTL != 30*time.Second {
		t.Errorf("expected TTL 30s, got %v", got.TTL)
	}
	if got.Remaining <= 0 || got.Remaining > 30*time.Second {
		t.Errorf("expected 0 < Remaining <= 30s, got %v", got.Remaining)
	}
	if got.Endpoint == "" {
		t.Errorf("expected a resolved endpoint name, got empty string")
	}
	if got.Path != string(client.endpoints["firmware"]) {
		t.Errorf("expected path %q, got %q", client.endpoints["firmware"], got.Path)
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

// TestPluginGatedIncludesVnstatGetJsonData pins the semantic set against the
// negative-cacheable one (#495). vnstatGetJsonData is an os-vnstat route and
// 404s exactly when the plugin is absent, so a 404 there is NOT a vanished core
// route — but it must stay OUT of the cacheable set, because the cache keys on
// the registered query-less path while the real request always carries
// "?iface=", so a TTL on it would never match.
//
// The canary (cmd/apidrift) and acl.go ask the semantic question; only main.go's
// TTL wiring asks the cacheable one. Conflating them made a box WITHOUT os-vnstat
// report the endpoint in the report's highest-signal "core route vanished
// upstream" section - found on the first canary run against the production
// release box, and invisible on the nightly testbed, which has the plugin.
func TestPluginGatedIncludesVnstatGetJsonData(t *testing.T) {
	gated := map[EndpointName]bool{}
	for _, n := range PluginGatedEndpoints() {
		gated[n] = true
	}
	if !gated["vnstatGetJsonData"] {
		t.Error("vnstatGetJsonData must be in PluginGatedEndpoints: its 404 means os-vnstat is absent")
	}

	cacheable := map[EndpointName]bool{}
	for _, n := range NegativeCacheable404Endpoints() {
		cacheable[n] = true
	}
	if cacheable["vnstatGetJsonData"] {
		t.Error("vnstatGetJsonData must NOT be negative-cacheable: the cache key omits its ?iface= query string")
	}

	// The cacheable set must stay a SUBSET of the gated set, or the two lists can
	// drift into contradicting each other about what a 404 on an endpoint means.
	for n := range cacheable {
		if !gated[n] {
			t.Errorf("%s is negative-cacheable but not plugin-gated; cacheable must be a subset of gated", n)
		}
	}
}

// TestClient_CacheRefusesFirmwareStatusWithoutLastCheck pins the fix for GitHub
// issue 724 (OPN-0095): api/core/firmware/status answers 200 with an empty
// last_check while a check is running or right after the stored status was
// cleared. Such a body carries no check result, so caching it would make every
// check-dependent series absent for the whole --exporter.firmware-cache-ttl
// (12h by default) even though the box finishes its check seconds later. The
// cache must refuse it and the next poll must fetch live; a body WITH a
// last_check is still cached for the TTL as before.
func TestClient_CacheRefusesFirmwareStatusWithoutLastCheck(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := requests.Add(1)
		if n == 1 {
			_, _ = w.Write([]byte(`{"last_check":"","product_id":"opnsense","product_version":"24.1.1","status":"none"}`))
			return
		}
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	client.SetEndpointCacheTTL("firmware", 12*time.Hour)
	withFakeClock(t, client)

	first, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if first.CheckPresent {
		t.Fatalf("fixture error: the first body must carry no check result, got %+v", first)
	}
	if snap := client.CacheSnapshot(); len(snap) != 0 {
		t.Fatalf("a firmware body with an empty last_check must not be cached, got %+v", snap)
	}

	second, err := client.FetchFirmwareStatus()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("second call must go to the firewall, got %d upstream requests", got)
	}
	if !second.CheckPresent || second.UpgradePackages != 1 {
		t.Fatalf("second call must decode the live body, got %+v", second)
	}

	if _, err := client.FetchFirmwareStatus(); err != nil {
		t.Fatalf("third call: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("a body with a last_check must still be cached, got %d upstream requests", got)
	}
}

// TestCacheAdmissionRulesRefuseInterimBodies pins the sweep that followed GitHub
// issue 724 (OPN-0095): every body-cached endpoint whose 200 can carry "no result
// right now" instead of a result has an admission rule, and the rule refuses
// exactly that interim body while admitting a real one. The interim shapes are
// taken from upstream: Unbound's DiagnosticsController answers {"status":"failed"}
// with no data key when unbound-control is unreachable (Unbound stopped or
// mid-reload); FirmwareController::infoAction builds package[] from `firmware
// local`, so an empty package list means pkg answered nothing (the base system is
// itself a package); IDS SettingsController::listRulesetsAction returns empty rows
// when `ids list installablerulesets` decoded to null, and the installable
// catalogue ships with the core package so it is never legitimately empty.
func TestCacheAdmissionRulesRefuseInterimBodies(t *testing.T) {
	cases := []struct {
		endpoint EndpointName
		interim  string
		real     string
	}{
		{"firmware", `{"last_check":"","product_id":"opnsense"}`, `{"last_check":"2024-01-15T10:30:00Z","product_id":"opnsense"}`},
		{"firmwareInfo", `{"product_id":"opnsense","product_version":"24.1.1","package":[],"plugin":[]}`,
			`{"product_id":"opnsense","product_version":"24.1.1","package":[{"name":"opnsense"}],"plugin":[]}`},
		{"unboundLocalZones", `{"status":"failed"}`, `{"status":"ok","data":[]}`},
		{"unboundLocalData", `{"status":"failed"}`, `{"status":"ok","data":[]}`},
		{"unboundInsecureDomains", `{"status":"failed"}`, `{"status":"ok","data":[]}`},
		{"idsRulesets", `{"rows":[],"rowCount":0,"total":0,"current":1}`,
			`{"rows":[{"filename":"a.rules","enabled":"1","modified_local":null}],"rowCount":1,"total":1,"current":1}`},
	}
	for _, tc := range cases {
		rule := cacheAdmissionRules[tc.endpoint]
		if rule == nil {
			t.Errorf("%s: no admission rule registered", tc.endpoint)
			continue
		}
		if rule([]byte(tc.interim)) {
			t.Errorf("%s: interim body must be refused: %s", tc.endpoint, tc.interim)
		}
		if !rule([]byte(tc.real)) {
			t.Errorf("%s: real body must be admitted: %s", tc.endpoint, tc.real)
		}
		if rule([]byte(`not json`)) {
			t.Errorf("%s: an undecodable body must be refused", tc.endpoint)
		}
	}

	// Every body-cached endpoint that shells out to a daemon or pkg has a rule.
	// Config reads (MVC model gets, certificate inventory, NAT/auth tables) do not
	// need one: their 200 is always the current configuration.
	for _, name := range []EndpointName{"firmware", "firmwareInfo", "unboundLocalZones", "unboundLocalData", "unboundInsecureDomains", "idsRulesets"} {
		if _, ok := cacheAdmissionRules[name]; !ok {
			t.Errorf("%s: expected an admission rule", name)
		}
	}
}

// TestClient_CacheRefusesFailedUnboundDiagnostics is the end-to-end form for the
// most likely live occurrence: Unbound reloads on every DNS config edit, and a
// poll landing inside that window sees {"status":"failed"}. Caching it would
// report zero local zones for --exporter.cache-ttl after Unbound is back.
func TestClient_CacheRefusesFailedUnboundDiagnostics(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"status":"failed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":[{"zone":"home.arpa.","type":"static"}]}`))
	})
	defer server.Close()
	client.endpoints = map[EndpointName]EndpointPath{"unboundLocalZones": "api/unbound/diagnostics/listlocalzones"}
	client.SetEndpointCacheTTL("unboundLocalZones", 30*time.Minute)
	withFakeClock(t, client)

	var resp unboundLocalZonesResponse
	if err := client.do("GET", client.endpoints["unboundLocalZones"], nil, &resp); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if snap := client.CacheSnapshot(); len(snap) != 0 {
		t.Fatalf("a failed diagnostics body must not be cached, got %+v", snap)
	}
	resp = unboundLocalZonesResponse{}
	if err := client.do("GET", client.endpoints["unboundLocalZones"], nil, &resp); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := requests.Load(); got != 2 || len(resp.Data) != 1 {
		t.Fatalf("second call must fetch live, got %d requests and %d zones", got, len(resp.Data))
	}
	if err := client.do("GET", client.endpoints["unboundLocalZones"], nil, &resp); err != nil {
		t.Fatalf("third call: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("the ok body must be cached, got %d requests", got)
	}
}
