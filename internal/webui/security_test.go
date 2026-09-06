package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var (
	consoleTagRE = regexp.MustCompile(`(?s)<(script|style)\b([^>]*)>`)
	nonceAttrRE  = regexp.MustCompile(`\bnonce="([^"]+)"`)
	onAttrRE     = regexp.MustCompile(`(?i)\bon[a-z][a-z0-9_-]*\s*=`)
	styleAttrRE  = regexp.MustCompile(`(?i)\bstyle\s*=`)
	jsURLRE      = regexp.MustCompile(`(?i)javascript\s*:`)
)

func TestSecurityHeadersCoverConsoleRoutes(t *testing.T) {
	srv := NewServer(testDeps())
	routes := []struct {
		path   string
		status int
		cache  string
		json   bool
		lazy   bool
	}{
		{path: "/", status: http.StatusOK, cache: "no-store"},
		{path: "/api/status.json", status: http.StatusOK, cache: "no-store", json: true},
		{path: "/api/devices.json", status: http.StatusOK, cache: "no-store", json: true, lazy: true},
		{path: "/api/ifindex.json", status: http.StatusNotFound, cache: "no-store", json: true, lazy: true},
	}

	var pageNonce string
	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route.path, nil))
			if rec.Code != route.status {
				t.Fatalf("status = %d, want %d", rec.Code, route.status)
			}
			assertSecurityHeaders(t, rec, route.cache)
			if route.json && !strings.Contains(rec.Header().Get("Content-Type"), "application/json") && rec.Code != http.StatusNotFound {
				t.Errorf("Content-Type = %q, want JSON", rec.Header().Get("Content-Type"))
			}
			if route.lazy && rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("lazy route has no Content-Security-Policy")
			}

			if route.path != "/" {
				return
			}
			pageNonce = assertRenderedConsole(t, rec.Body.String(), rec.Header().Get("Content-Security-Policy"))
		})
	}

	if pageNonce == "" {
		t.Fatal("status page did not yield a CSP nonce")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	secondNonce := assertRenderedConsole(t, rec.Body.String(), rec.Header().Get("Content-Security-Policy"))
	if secondNonce == pageNonce {
		t.Fatal("two status requests reused the same CSP nonce")
	}
}

func TestSecurityHeadersKeepFontCachePolicy(t *testing.T) {
	srv := NewServer(testDeps())
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_static/fonts/hanken-grotesk-latin.woff2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("font status = %d, want 200", rec.Code)
	}
	assertSecurityHeaders(t, rec, "public, max-age=31536000, immutable")
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("font response unexpectedly sets HSTS: %q", got)
	}
}

func assertSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder, cache string) {
	t.Helper()
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != cache {
		t.Errorf("Cache-Control = %q, want %q", got, cache)
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("response unexpectedly sets HSTS: %q", got)
	}
	policy := rec.Header().Get("Content-Security-Policy")
	if policy == "" {
		t.Fatal("Content-Security-Policy is missing")
	}
	if strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "unsafe-hashes") {
		t.Fatalf("CSP contains an unsafe inline allowance: %q", policy)
	}
}

func assertRenderedConsole(t *testing.T, body, policy string) string {
	t.Helper()
	nonce := extractPolicyNonce(t, policy, "script-src")
	if styleNonce := extractPolicyNonce(t, policy, "style-src"); styleNonce != nonce {
		t.Fatalf("script/style CSP nonces differ: %q/%q", nonce, styleNonce)
	}
	wantPolicy := "default-src 'none'; " +
		"script-src 'nonce-" + nonce + "'; " +
		"style-src 'nonce-" + nonce + "'; " +
		"font-src 'self'; " +
		"img-src data:; " +
		"connect-src 'self'; " +
		"base-uri 'none'; " +
		"form-action 'none'; " +
		"frame-ancestors 'none'"
	if policy != wantPolicy {
		t.Fatalf("CSP = %q, want exactly %q", policy, wantPolicy)
	}
	tags := consoleTagRE.FindAllStringSubmatch(body, -1)
	if len(tags) != 5 {
		t.Fatalf("found %d script/style blocks, want 5", len(tags))
	}
	for _, tag := range tags {
		match := nonceAttrRE.FindStringSubmatch(tag[2])
		if len(match) != 2 {
			t.Fatalf("%s block has no nonce: %q", tag[1], tag[0])
		}
		if match[1] != nonce {
			t.Fatalf("%s nonce %q does not match CSP nonce %q", tag[1], match[1], nonce)
		}
	}
	if onAttrRE.MatchString(body) {
		t.Fatal("rendered console contains an inline event-handler attribute")
	}
	if styleAttrRE.MatchString(body) {
		t.Fatal("rendered console contains an inline style attribute")
	}
	if jsURLRE.MatchString(body) {
		t.Fatal("rendered console contains a javascript: URL")
	}
	if !strings.Contains(body, `href="data:image/svg+xml,`) {
		t.Fatal("rendered console lost the data favicon covered by img-src data:")
	}
	return nonce
}

func extractPolicyNonce(t *testing.T, policy, directive string) string {
	t.Helper()
	want := fmt.Sprintf(`%s 'nonce-`, directive)
	start := strings.Index(policy, want)
	if start < 0 {
		t.Fatalf("CSP has no %s nonce source: %q", directive, policy)
	}
	start += len(want)
	end := strings.IndexByte(policy[start:], '\'')
	if end < 0 {
		t.Fatalf("CSP %s nonce source is unterminated: %q", directive, policy)
	}
	return policy[start : start+end]
}
