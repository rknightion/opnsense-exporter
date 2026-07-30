package annotations

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// redirectTarget is the server a malicious or misconfigured redirect points at.
// It records whether it ever received a request, and if so, whether that
// request carried the bearer token or the annotation body — either would mean
// a secret or a write payload crossed a scheme/host/port boundary the caller
// never intended.
type redirectTarget struct {
	server      *httptest.Server
	hit         atomic.Bool
	sawBearer   atomic.Bool
	sawBodyText atomic.Bool
}

func newRedirectTarget(t *testing.T) *redirectTarget {
	t.Helper()
	rt := &redirectTarget{}
	rt.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.hit.Store(true)
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			rt.sawBearer.Store(true)
		}
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		if strings.Contains(string(buf[:n]), "canary-text") {
			rt.sawBodyText.Store(true)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"message":"Annotation added"}`))
	}))
	t.Cleanup(rt.server.Close)
	return rt
}

// newRedirectOrigin builds a server that answers every request with the given
// redirect status and Location, whatever the request is — mirroring an
// annotation POST (or the reconciliation GET) being bounced elsewhere. tlsServer
// exercises the HTTPS-endpoint case; the redirect Location itself always points
// at a plain-HTTP target, which is what makes the downgrade test meaningful.
func newRedirectOrigin(t *testing.T, tlsServer bool, status int, location string) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	})
	var srv *httptest.Server
	if tlsServer {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	t.Cleanup(srv.Close)
	return srv
}

// clientFor builds an annotations client pointed at origin. When origin is a
// TLS test server, it borrows origin.Client()'s transport (which trusts
// exactly that server's self-signed cert) so the test exercises the redirect
// policy rather than tripping over an unrelated cert-verification failure.
// This never extends trust to the redirect target: the whole point of the
// test is that the target is never dialed at all.
func clientFor(origin *httptest.Server) *client {
	c := newClient(Config{URL: origin.URL, Token: "test-token"})
	c.http.Transport = origin.Client().Transport
	return c
}

func assertRedirectRejected(t *testing.T, origin *httptest.Server, target *redirectTarget) {
	t.Helper()
	c := clientFor(origin)
	err := c.post(context.Background(), Event{Kind: "test", Text: "canary-text"})
	if err == nil {
		t.Fatal("expected the redirect to surface as an error, got nil")
	}
	var httpErr *httpError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected an *httpError (the redirect response itself, unfollowed), got %T: %v", err, err)
	}
	if httpErr.StatusCode < 300 || httpErr.StatusCode >= 400 {
		t.Fatalf("expected the unfollowed redirect's own 3xx status, got %d", httpErr.StatusCode)
	}
	if target.hit.Load() {
		t.Fatal("redirect target received a request; the client must never follow a redirect")
	}
	if target.sawBearer.Load() {
		t.Fatal("redirect target saw the bearer token")
	}
	if target.sawBodyText.Load() {
		t.Fatal("redirect target saw the annotation body")
	}
}

func TestPostRejectsRedirectToAlternatePortOnSameHost(t *testing.T) {
	// httptest servers already bind distinct ports on 127.0.0.1, so pointing
	// the Location at another such server IS the same-host-alternate-port case.
	target := newRedirectTarget(t)
	origin := newRedirectOrigin(t, false, http.StatusFound, target.server.URL)
	assertRedirectRejected(t, origin, target)
}

func TestPostRejectsRedirectToSubdomain(t *testing.T) {
	target := newRedirectTarget(t)
	// nip.io resolves any "<label>.<ip>.nip.io" to <ip>, so this is a real
	// subdomain-of-nothing-in-particular relative to origin's own address.
	subdomainLocation := strings.Replace(target.server.URL, "127.0.0.1", "sub.127.0.0.1.nip.io", 1)
	origin := newRedirectOrigin(t, false, http.StatusFound, subdomainLocation)
	assertRedirectRejected(t, origin, target)
}

func TestPostRejectsRedirectToDifferentHost(t *testing.T) {
	target := newRedirectTarget(t)
	origin := newRedirectOrigin(t, false, http.StatusFound, target.server.URL)
	assertRedirectRejected(t, origin, target)
}

func TestPostRejectsHTTPSToHTTPDowngradeRedirect(t *testing.T) {
	target := newRedirectTarget(t) // plain HTTP target
	origin := newRedirectOrigin(t, true, http.StatusFound, target.server.URL)
	assertRedirectRejected(t, origin, target)
}

func TestPostRejects307RedirectWithoutReplayingBody(t *testing.T) {
	target := newRedirectTarget(t)
	origin := newRedirectOrigin(t, false, http.StatusTemporaryRedirect, target.server.URL)
	assertRedirectRejected(t, origin, target)
}

func TestPostRejects308RedirectWithoutReplayingBody(t *testing.T) {
	target := newRedirectTarget(t)
	origin := newRedirectOrigin(t, false, http.StatusPermanentRedirect, target.server.URL)
	assertRedirectRejected(t, origin, target)
}

func TestExistingAlsoRejectsRedirects(t *testing.T) {
	target := newRedirectTarget(t)
	origin := newRedirectOrigin(t, false, http.StatusFound, target.server.URL)
	c := clientFor(origin)
	_, err := c.existing(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected the GET redirect to surface as an error, got nil")
	}
	var httpErr *httpError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected an *httpError, got %T: %v", err, err)
	}
	if target.hit.Load() {
		t.Fatal("redirect target received the GET request")
	}
}
