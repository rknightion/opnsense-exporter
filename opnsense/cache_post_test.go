package opnsense

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// A 404 is a property of the ROUTE, not of the request body: OPNsense answers
// "Endpoint not found" when a plugin is not installed, whatever you POST at it.
// Verified against a live OPNsense 26.1: a POST to an absent plugin's endpoint
// returns 404 {"errorMessage":"Endpoint not found"}, while a POST carrying a bogus
// resource (api/smart/service/info with device=BOGUS, os-smart installed) returns
// 200 {"message":"Invalid device name"} — NOT a 404.
//
// That is what makes negative caching safe for POST with a path-only key, even
// though positive caching of a POST is not: smartInfo is POSTed once per device,
// so replaying one device's BODY for another would be wrong — but replaying
// "this route does not exist" is correct for every device.

func TestClient_AbsentPOSTEndpoint404IsCached(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	})
	defer server.Close()

	client.SetEndpointAbsentTTL("crowdsecAlerts", time.Hour)
	withFakeClock(t, client)

	path := client.endpoints["crowdsecAlerts"]
	for i := range 5 {
		var resp struct{}
		err := client.doForm(path, url.Values{"current": {"1"}}, &resp)
		if err == nil || err.StatusCode != http.StatusNotFound {
			t.Fatalf("call %d: expected the cached 404 to be replayed, got %v", i, err)
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("expected 1 upstream POST for 5 calls to an absent plugin endpoint, got %d", got)
	}
}

// The counterpart: a SUCCESSFUL POST must never be cached, because the response
// depends on the request body. smartInfo is POSTed once per disk; replaying disk
// ada0's body for disk ada1 would report the wrong device's health.
func TestClient_SuccessfulPOSTIsNeverCached(t *testing.T) {
	var requests atomic.Int64
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = r.ParseForm()
		// Echo the requested device back, so a body-blind cache would be caught.
		_, _ = w.Write([]byte(`{"device":"` + r.FormValue("device") + `"}`))
	})
	defer server.Close()

	// Both TTLs set: even so, a 200 from a POST must go to the box every time.
	client.SetEndpointAbsentTTL("smartInfo", time.Hour)
	client.SetEndpointCacheTTL("smartInfo", time.Hour)
	withFakeClock(t, client)

	path := client.endpoints["smartInfo"]
	for _, device := range []string{"ada0", "ada1", "ada2"} {
		var resp struct {
			Device string `json:"device"`
		}
		if err := client.doForm(path, url.Values{"device": {device}}, &resp); err != nil {
			t.Fatalf("device %s: %v", device, err)
		}
		if resp.Device != device {
			t.Fatalf("per-device POST body was served from cache: asked for %q, got %q", device, resp.Device)
		}
	}

	if got := requests.Load(); got != 3 {
		t.Errorf("expected every successful POST to reach the box (3), got %d", got)
	}
}

// A cached POST 404 must expire, so installing the plugin is picked up.
func TestClient_AbsentPOST404ExpiresAndPluginIsPickedUp(t *testing.T) {
	var installed atomic.Bool
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if !installed.Load() {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"rows":[]}`))
	})
	defer server.Close()

	client.SetEndpointAbsentTTL("crowdsecAlerts", time.Hour)
	clock := withFakeClock(t, client)
	path := client.endpoints["crowdsecAlerts"]

	var resp struct{}
	if err := client.doForm(path, url.Values{}, &resp); err == nil {
		t.Fatal("expected 404 while the plugin is absent")
	}

	installed.Store(true)
	if err := client.doForm(path, url.Values{}, &resp); err == nil {
		t.Error("expected the cached 404 to still be replayed inside the absent TTL")
	}

	clock.Advance(time.Hour + time.Second)
	if err := client.doForm(path, url.Values{}, &resp); err != nil {
		t.Errorf("expected the installed plugin to be picked up after the absent TTL expired: %v", err)
	}
}
