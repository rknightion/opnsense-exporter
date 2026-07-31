package opnsense

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

func probeClient(t *testing.T, h http.Handler) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(srv.URL, "http://"),
		APIKey: "k", APISecret: "s", MaxRetries: 1,
	}
	c, err := NewClient(cfg, "t", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// The three outcomes are three, not two. "absent" and "could not tell" must not
// collapse into one answer: a firewall that is briefly unreachable would
// otherwise read as every plugin having been uninstalled at once.
func TestProbeEndpoint_DistinguishesAbsentFromUnanswerable(t *testing.T) {
	t.Run("route answers: available", func(t *testing.T) {
		c := probeClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"rows":[]}`))
		}))
		got, err := c.ProbeEndpoint("crowdsecServiceStatus")
		if err != nil || !got {
			t.Fatalf("got (%v, %v), want (true, nil) — an empty payload still proves the route exists", got, err)
		}
	})

	t.Run("404: absent, and NOT an error", func(t *testing.T) {
		c := probeClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
		}))
		got, err := c.ProbeEndpoint("crowdsecServiceStatus")
		if got || err != nil {
			t.Fatalf("got (%v, %v), want (false, nil) — a 404 is the plugin being absent, not a fault", got, err)
		}
	})

	t.Run("500: unanswerable, reported as an error", func(t *testing.T) {
		c := probeClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		got, err := c.ProbeEndpoint("crowdsecServiceStatus")
		if got || err == nil {
			t.Fatalf("got (%v, %v), want (false, non-nil) — the question could not be answered "+
				"and must never be recorded as absence", got, err)
		}
	})

	t.Run("unknown endpoint name is a programming error, not absence", func(t *testing.T) {
		c := probeClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		if _, err := c.ProbeEndpoint("thisEndpointDoesNotExist"); err == nil {
			t.Fatal("want an error for an endpoint the client does not know")
		}
	})
}

// smartList is POST-only. Probing it with a GET would 400/405 and read as
// "unanswerable" forever, so the method has to come from postEndpoints rather
// than being assumed.
func TestProbeEndpoint_UsesPostForPostOnlyEndpoints(t *testing.T) {
	var gotMethod string
	c := probeClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		_, _ = w.Write([]byte(`{}`))
	}))
	if _, err := c.ProbeEndpoint("smartList"); err != nil {
		t.Fatalf("ProbeEndpoint: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST — smartList is in postEndpoints", gotMethod)
	}
}
