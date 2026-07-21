package opnsense

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// A plugin-gated endpoint answers 404 on a box without the plugin. The exporter
// treats that as "feature absent" and stays silent — but re-asks on every single
// scrape, forever. These tests cover caching that 404 (negative caching), which is
// distinct from caching a successful body: a *ServiceStatus endpoint's 200 payload
// is live data ({"status":"running"}) and must never be cached, while its 404 is a
// routing fact that only changes when an admin installs the plugin.

func TestClient_AbsentEndpoint404IsCached(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)
	withFakeClock(t, client)

	for i := range 5 {
		status, present, err := client.FetchServiceStatusOptional("haproxyServiceStatus")
		if err != nil {
			t.Fatalf("call %d: a cached 404 must still read as feature-absent, not an error: %v", i, err)
		}
		if present || status != "" {
			t.Fatalf("call %d: expected feature-absent, got status=%q present=%v", i, status, present)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("expected 1 upstream request for 5 calls to an absent endpoint, got %d", got)
	}
}

func TestClient_Absent404NotCachedWithoutAbsentTTL(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	// No absent TTL configured: today's behaviour, re-asked every scrape.
	for range 3 {
		if _, _, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("expected 3 upstream requests with no absent TTL, got %d", got)
	}
}

func TestClient_Absent404ExpiresAndPluginIsPickedUp(t *testing.T) {
	var requests atomic.Int64
	var pluginInstalled atomic.Bool
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if !pluginInstalled.Load() {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"status":"running"}`))
	})
	defer server.Close()

	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)
	clock := withFakeClock(t, client)

	if _, present, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err != nil || present {
		t.Fatalf("expected feature-absent, got present=%v err=%v", present, err)
	}

	// The admin installs the plugin. Until the absent TTL expires we still say absent
	// (the documented staleness cost); after it expires the plugin must be picked up.
	pluginInstalled.Store(true)

	if _, present, _ := client.FetchServiceStatusOptional("haproxyServiceStatus"); present {
		t.Error("expected the cached 404 to still be served inside the absent TTL")
	}

	clock.Advance(time.Hour + time.Second)

	status, present, err := client.FetchServiceStatusOptional("haproxyServiceStatus")
	if err != nil {
		t.Fatalf("after absent TTL expiry: %v", err)
	}
	if !present || status != "running" {
		t.Errorf("expected the plugin to be picked up after the absent TTL expired, got status=%q present=%v", status, present)
	}
}

// A live 200 from a *ServiceStatus endpoint must never be cached: the running/stopped
// state is exactly what the metric reports. Only its 404 may be.
func TestClient_AbsentTTLDoesNotCacheSuccessfulResponses(t *testing.T) {
	var requests atomic.Int64
	statuses := []string{"running", "stopped", "running"}
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := requests.Add(1)
		_, _ = w.Write([]byte(`{"status":"` + statuses[n-1] + `"}`))
	})
	defer server.Close()

	// An absent TTL alone must NOT turn on positive caching for the endpoint.
	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)
	withFakeClock(t, client)

	for i, want := range statuses {
		status, present, err := client.FetchServiceStatusOptional("haproxyServiceStatus")
		if err != nil || !present {
			t.Fatalf("call %d: unexpected err=%v present=%v", i, err, present)
		}
		if status != want {
			t.Fatalf("call %d: live service state was cached: got %q, want %q", i, status, want)
		}
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("expected every successful service-status call to hit the box, got %d requests", got)
	}
}

// Only 404 is treated as "absent". A 500 is a fault, not a routing fact, and caching
// it would suppress a real error for an hour.
func TestClient_AbsentTTLDoesNotCacheServerErrors(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer server.Close()

	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)
	withFakeClock(t, client)

	// The client retries 5xx on GET (maxRetries attempts per call), so count calls, not
	// raw requests: the point is that the second call re-attempts rather than replaying
	// a cached 500.
	if _, _, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err == nil {
		t.Fatal("expected an error from a 500")
	}
	first := requests.Load()

	if _, _, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err == nil {
		t.Fatal("expected an error from a 500 on the second call too")
	}
	if requests.Load() <= first {
		t.Error("expected the second call to re-request rather than serve a cached 500")
	}
}

// The plugin-gated allowlist is what protects core endpoints from negative caching.
// A cached 404 on the health check would pin opnsense_up=0 for the whole TTL after
// the box came back, so it must never be on the list.
func TestPluginGatedEndpoints_ExcludesCoreEndpoints(t *testing.T) {
	endpoints := defaultEndpoints()

	for _, name := range PluginGatedEndpoints() {
		if _, ok := endpoints[name]; !ok {
			t.Errorf("plugin-gated endpoint %q is not a registered endpoint", name)
		}
	}

	// Core endpoints whose absence must always be observed live. A cached 404 on the
	// health check would keep reporting a recovered firewall as down.
	for _, forbidden := range []EndpointName{"healthCheck", "services", "systemResources", "firmware"} {
		for _, name := range PluginGatedEndpoints() {
			if name == forbidden {
				t.Errorf("core endpoint %q must never be negative-cached", forbidden)
			}
		}
	}
}

// The list is hand-maintained and grew through several union merges (#227), which
// is exactly how an entry gets written twice and a missing one gets overlooked: a
// list with duplicates cannot be reviewed by eye. Callers build a set from it, so a
// duplicate is harmless at runtime and would otherwise never be noticed.
func TestPluginGatedEndpoints_HasNoDuplicates(t *testing.T) {
	seen := make(map[EndpointName]int, len(PluginGatedEndpoints()))
	for _, name := range PluginGatedEndpoints() {
		seen[name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("plugin-gated endpoint %q is listed %d times; keep the list unique so it stays reviewable", name, count)
		}
	}
}

// POST endpoints are allowed on the plugin-gated list (only their 404 is cached),
// but they must never receive a POSITIVE TTL: a POST's response body depends on what
// was posted, so replaying it would serve one request's data for another.
func TestCache_NeverServesACachedBodyForAPOST(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"device":"ada0"}`))
	})
	defer server.Close()

	path := client.endpoints["smartInfo"]

	// Force the pathological case: a positive entry present for a POST endpoint.
	client.SetEndpointCacheTTL("smartInfo", time.Hour)
	withFakeClock(t, client)
	client.cache.put(path, http.StatusOK, []byte(`{"device":"ada0"}`))

	if _, ok := client.cache.get(path); !ok {
		t.Fatal("test setup: expected the entry to be cached")
	}

	// Even so, a POST must go to the box rather than replay that body.
	var requests atomic.Int64
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = r.ParseForm()
		_, _ = w.Write([]byte(`{"device":"` + r.FormValue("device") + `"}`))
	})

	var resp struct {
		Device string `json:"device"`
	}
	if err := client.doForm(path, url.Values{"device": {"ada1"}}, &resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Device != "ada1" {
		t.Errorf("a POST was served a cached body: asked for ada1, got %q", resp.Device)
	}
	if requests.Load() != 1 {
		t.Errorf("expected the POST to reach the box, got %d requests", requests.Load())
	}
}
