package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const consoleNonceBytes = 16

// nonceContextKey keeps the request's CSP nonce private to this package. The
// page handler copies it into the view so every inline block receives the
// nonce that the middleware published in the response policy.
type nonceContextKey struct{}

// securityHeaders wraps the complete console handler. A new nonce is generated
// for every request, including JSON, lazy data, fonts, and error responses.
// Font responses replace the default no-store cache directive in their route
// handler with the immutable policy appropriate for bundled assets.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := requestNonce()
		if err != nil {
			setSecurityHeaders(w, "")
			http.Error(w, "unable to create response nonce", http.StatusInternalServerError)
			return
		}

		setSecurityHeaders(w, nonce)
		ctx := context.WithValue(r.Context(), nonceContextKey{}, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestNonce() (string, error) {
	var raw [consoleNonceBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func nonceFromContext(ctx context.Context) string {
	nonce, _ := ctx.Value(nonceContextKey{}).(string)
	return nonce
}

func consoleCSP(nonce string) string {
	if nonce == "" {
		return "default-src 'none'; " +
			"script-src 'none'; " +
			"style-src 'none'; " +
			"font-src 'self'; " +
			"img-src data:; " +
			"connect-src 'self'; " +
			"base-uri 'none'; " +
			"form-action 'none'; " +
			"frame-ancestors 'none'"
	}
	return "default-src 'none'; " +
		"script-src 'nonce-" + nonce + "'; " +
		"style-src 'nonce-" + nonce + "'; " +
		"font-src 'self'; " +
		"img-src data:; " +
		"connect-src 'self'; " +
		"base-uri 'none'; " +
		"form-action 'none'; " +
		"frame-ancestors 'none'"
}

func setSecurityHeaders(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Security-Policy", consoleCSP(nonce))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	// The console listener is plaintext. Deliberately do not emit HSTS: a
	// browser that receives it would force HTTPS on this HTTP-only endpoint.
}
