package opnsense

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

type recordedLookup struct {
	endpoint string
	kind     string // "body", "absent" or "miss"
}

type fakeCacheObserver struct {
	mu      sync.Mutex
	lookups []recordedLookup
}

func (f *fakeCacheObserver) ObserveCacheHit(endpoint, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, recordedLookup{endpoint: endpoint, kind: kind})
}

func (f *fakeCacheObserver) ObserveCacheMiss(endpoint string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, recordedLookup{endpoint: endpoint, kind: "miss"})
}

func (f *fakeCacheObserver) kinds() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.lookups))
	for _, l := range f.lookups {
		out = append(out, l.kind)
	}
	return out
}

func equalKinds(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestCacheObserver_RecordsMissThenBodyHits(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	obs := &fakeCacheObserver{}
	client.SetCacheObserver(obs)
	client.SetEndpointCacheTTL("firmware", time.Hour)
	withFakeClock(t, client)

	for range 3 {
		if _, err := client.FetchFirmwareStatus(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// First call populates the cache (miss), the next two are served from it.
	want := []string{"miss", "body", "body"}
	if got := obs.kinds(); !equalKinds(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCacheObserver_RecordsAbsentHitsSeparatelyFromBodyHits(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	obs := &fakeCacheObserver{}
	client.SetCacheObserver(obs)
	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)
	withFakeClock(t, client)

	for range 3 {
		if _, _, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// A replayed 404 is reported as "absent", not "body": the two mean different
	// things (a plugin that isn't installed vs a payload replayed to save a fetch).
	want := []string{"miss", "absent", "absent"}
	if got := obs.kinds(); !equalKinds(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A POST to a plugin-gated endpoint can hit the absent cache, so it must be observed.
func TestCacheObserver_RecordsPOSTAbsentHits(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	})
	defer server.Close()

	obs := &fakeCacheObserver{}
	client.SetCacheObserver(obs)
	client.SetEndpointAbsentTTL("crowdsecAlerts", time.Hour)
	withFakeClock(t, client)

	path := client.endpoints["crowdsecAlerts"]
	for range 3 {
		var resp struct{}
		_ = client.doForm(path, url.Values{}, &resp)
	}

	want := []string{"miss", "absent", "absent"}
	if got := obs.kinds(); !equalKinds(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Endpoints with no TTL are not cacheable, so they must produce NO lookups at all.
// Counting them as misses would bury the real hit/miss signal under ~90 endpoints
// that were never candidates for caching, making the miss counter meaningless.
func TestCacheObserver_IgnoresEndpointsWithNoTTL(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(firmwareStatusBody))
	})
	defer server.Close()

	obs := &fakeCacheObserver{}
	client.SetCacheObserver(obs)
	// No TTL configured for "firmware".

	for range 3 {
		if _, err := client.FetchFirmwareStatus(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := obs.kinds(); len(got) != 0 {
		t.Errorf("expected no cache lookups for an endpoint with no TTL, got %v", got)
	}
}

// A POST to an endpoint that only has a POSITIVE TTL is never cache-eligible (a POST
// body is never replayed), so it must not be recorded as a miss on every call.
func TestCacheObserver_IgnoresPOSTWithOnlyAPositiveTTL(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	defer server.Close()

	obs := &fakeCacheObserver{}
	client.SetCacheObserver(obs)
	client.SetEndpointCacheTTL("smartInfo", time.Hour) // positive only, no absent TTL
	withFakeClock(t, client)

	path := client.endpoints["smartInfo"]
	for range 3 {
		var resp struct{}
		_ = client.doForm(path, url.Values{"device": {"ada0"}}, &resp)
	}

	if got := obs.kinds(); len(got) != 0 {
		t.Errorf("expected no cache lookups for a POST with only a positive TTL, got %v", got)
	}
}

// Regression: a plugin-gated endpoint whose plugin IS installed answers 200 on every
// scrape, and that live payload is never cacheable (only its 404 would be). It must
// therefore record NO miss — an earlier version counted a miss per scrape here, which
// made every healthy plugin look like a permanent cache miss and dragged the hit rate
// toward zero while the cache was working perfectly.
func TestCacheObserver_PresentPluginOnAbsentListRecordsNoMiss(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"running"}`))
	})
	defer server.Close()

	obs := &fakeCacheObserver{}
	client.SetCacheObserver(obs)
	client.SetEndpointAbsentTTL("tailscaleServiceStatus", time.Hour)
	withFakeClock(t, client)

	for range 4 {
		status, present, err := client.FetchServiceStatusOptional("tailscaleServiceStatus")
		if err != nil || !present || status != "running" {
			t.Fatalf("unexpected: status=%q present=%v err=%v", status, present, err)
		}
	}

	if got := obs.kinds(); len(got) != 0 {
		t.Errorf("a present plugin's live 200 is not a cache miss; got %v", got)
	}
}
