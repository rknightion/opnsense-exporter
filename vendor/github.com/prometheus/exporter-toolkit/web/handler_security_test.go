package web

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestBasicAuthCredentialsAreBoundedBeforeHashing(t *testing.T) {
	if !credentialsWithinLimits(strings.Repeat("u", maxBasicAuthUsernameBytes), strings.Repeat("p", maxBasicAuthPasswordBytes)) {
		t.Fatal("credentials at the limits were rejected")
	}
	if credentialsWithinLimits(strings.Repeat("u", maxBasicAuthUsernameBytes+1), "p") {
		t.Fatal("oversized username was accepted")
	}
	if credentialsWithinLimits("u", strings.Repeat("p", maxBasicAuthPasswordBytes+1)) {
		t.Fatal("oversized password was accepted")
	}
}

func TestBasicAuthCacheKeyHasFixedSizeAndFraming(t *testing.T) {
	a := authCacheKey("a", "bc", "d")
	b := authCacheKey("ab", "c", "d")
	if len(a) != sha256.Size*2 {
		t.Fatalf("cache key length = %d, want %d", len(a), sha256.Size*2)
	}
	if a == b {
		t.Fatal("length-framed credentials produced the same cache key")
	}
}

func TestBasicAuthMissesAreRateLimitedPerPeer(t *testing.T) {
	limiters := newAuthAttemptLimiters()
	for i := 0; i < authAttemptBurst; i++ {
		if !limiters.allow("peer-a.invalid:1234") {
			t.Fatalf("attempt %d unexpectedly rejected", i+1)
		}
	}
	if limiters.allow("peer-a.invalid:9999") {
		t.Fatal("same peer bypassed rate limit by changing source port")
	}
	if !limiters.allow("peer-b.invalid:1234") {
		t.Fatal("one peer's failures rate-limited another peer")
	}
}
