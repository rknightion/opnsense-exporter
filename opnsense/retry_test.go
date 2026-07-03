package opnsense

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRetryBackoffIncreases covers #127: repeated transport errors must wait increasing
// intervals, not a constant 25ms.
func TestRetryBackoffIncreases(t *testing.T) {
	b1, b2, b3 := retryBackoff(1), retryBackoff(2), retryBackoff(3)
	if b1 >= b2 || b2 >= b3 {
		t.Errorf("backoff not strictly increasing: %v, %v, %v", b1, b2, b3)
	}
	if b1 == 25*time.Millisecond {
		t.Error("backoff is still the old fixed 25ms")
	}
}

// TestGetRetriedOnGatewayError covers #127: an idempotent GET receiving 503 must be
// retried (previously it returned immediately without retry).
func TestGetRetriedOnGatewayError(t *testing.T) {
	var attempts atomic.Int32
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer server.Close()

	var out map[string]any
	if err := client.do("GET", "api/test/x", nil, &out); err == nil {
		t.Fatal("expected an error for a persistent 503")
	}
	if got := attempts.Load(); got < 2 {
		t.Errorf("expected the GET to be retried at least once on 503 (>=2 attempts), got %d", got)
	}
}

// TestNonGetNotRetriedOnGatewayError guards the scope: only idempotent GETs are retried
// on 5xx, so a POST 503 is a single attempt.
func TestNonGetNotRetriedOnGatewayError(t *testing.T) {
	var attempts atomic.Int32
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer server.Close()

	var out map[string]any
	_ = client.doForm("api/test/x", nil, &out)
	if got := attempts.Load(); got != 1 {
		t.Errorf("POST must not be retried on 503, got %d attempts", got)
	}
}

// TestExhaustedRetriesIncludeCause covers #127: when all retries are exhausted on a
// transport error, the returned APICallError must include the underlying cause, not
// just the generic "max retries ..." string.
func TestExhaustedRetriesIncludeCause(t *testing.T) {
	server, client := newTestClientWithServer(t, func(http.ResponseWriter, *http.Request) {})
	server.Close() // every dial now refused -> transport error, retries exhausted

	var out map[string]any
	err := client.do("GET", "api/test/x", nil, &out)
	if err == nil {
		t.Fatal("expected an error dialing a closed server")
	}
	if err.StatusCode != 0 {
		t.Errorf("transport failure should have StatusCode 0, got %d", err.StatusCode)
	}
	if !strings.Contains(err.Message, "max retries") {
		t.Errorf("expected retries-exhausted message, got %q", err.Message)
	}
	// The real cause (a dial/connection error) must be preserved, not discarded.
	low := strings.ToLower(err.Message)
	if !strings.Contains(low, "refused") && !strings.Contains(low, "connect") && !strings.Contains(low, "dial") {
		t.Errorf("final error should include the underlying transport cause, got %q", err.Message)
	}
}
