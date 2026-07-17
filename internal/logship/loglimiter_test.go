package logship

import (
	"strconv"
	"testing"
	"time"
)

func TestLogLimiterSuppressesRepeatsPerKey(t *testing.T) {
	l := NewLogLimiter(time.Hour, 16)

	if !l.Allow("a") {
		t.Fatal("first Allow(a) = false, want true")
	}
	if l.Allow("a") {
		t.Error("second Allow(a) = true, want false (within the interval)")
	}
	// A distinct key must be reported promptly rather than inherit a's suppression.
	if !l.Allow("b") {
		t.Error("Allow(b) = false, want true (a distinct key is not suppressed by a)")
	}
}

func TestLogLimiterAllowsAgainAfterInterval(t *testing.T) {
	l := NewLogLimiter(time.Millisecond, 16)

	if !l.Allow("a") {
		t.Fatal("first Allow(a) = false, want true")
	}
	time.Sleep(5 * time.Millisecond)
	if !l.Allow("a") {
		t.Error("Allow(a) after the interval = false, want true")
	}
}

// The key map is what the key set costs in memory. Every key today is code-defined
// and bounded ("poll:"+name, "ship"), but a key can now carry a wire-sourced value —
// an unhandled request's method+path (#285) — and an unbounded map is then a
// peer-controlled leak: the same hazard #280 forbids for metric labels, merely
// relocated from a label into a map. So the key set is capped.
func TestLogLimiterBoundsItsKeySet(t *testing.T) {
	const maxKeys = 8
	l := NewLogLimiter(time.Hour, maxKeys)

	for i := range 1000 {
		l.Allow("key-" + strconv.Itoa(i))
	}

	l.mu.Lock()
	got := len(l.last)
	l.mu.Unlock()
	if got > maxKeys {
		t.Errorf("tracked keys = %d, want <= %d (a flood of distinct keys must not grow the map)", got, maxKeys)
	}
}

// A full key set must not silence new keys for the life of the process: expired
// entries are purged on insert, so the cap bounds keys held per interval rather than
// forever.
func TestLogLimiterPurgesExpiredKeysWhenFull(t *testing.T) {
	l := NewLogLimiter(20*time.Millisecond, 2)

	l.Allow("a")
	l.Allow("b")
	if l.Allow("c") {
		t.Error("Allow(c) = true with a full key set, want false")
	}

	time.Sleep(40 * time.Millisecond)
	if !l.Allow("c") {
		t.Error("Allow(c) = false once the held keys expired, want true")
	}
}
