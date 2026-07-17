//go:build !race

package syslog

import "testing"

// TestEnrichMessageAllocations pins the zero-allocation invariant of the common
// enrichment path. It is deliberately isolated in this `//go:build !race` file so that
// `go test -race ./...` can be a clean CI gate (#295).
//
// Why the constraint: the race detector instruments every memory access and allocates
// its own shadow state, so testing.AllocsPerRun would never observe 0 under `-race` —
// the assertion would fail for a reason that has nothing to do with the code under test.
// Excluding ONLY this test from race builds (rather than a hand-maintained command-line
// `-skip`) means every OTHER test in the package — and every new test added later — is
// covered by the race detector automatically. If you add a test that must also run under
// `-race`, put it in a normally-tagged file, not here; keep this file to the alloc
// assertion alone.
//
// The machine-independent half of the budget, and the only part worth gating.
//
// The no-match path — the one multiplied by every line the box sends — allocates
// NOTHING today. That is not luck: `seen` and `devSeen` never escape enrichMessage, so
// escape analysis stacks them, and both regexes return nil rather than a slice when
// they find no match. Pinning it at zero is therefore a REGRESSION TRIPWIRE, not a
// target: it fires the moment a change makes the common path allocate per line (a
// wider regex, a match slice that escapes, a lookup that boxes into an interface),
// which is exactly how a nanosecond budget gets eaten silently.
//
// AllocsPerRun, not ns/op: allocation counts are deterministic across machines, so
// this lives in CI without flaking. If a Go release changes escape analysis and this
// starts failing honestly, raise the constant deliberately and say why — do not delete
// the test.
func TestEnrichMessageAllocations(t *testing.T) {
	snap := enrichSnap()
	set := func(k, v string) { sinkK, sinkV = k, v }

	if got := testing.AllocsPerRun(100, func() {
		enrichMessage("Poll UPS [ups@localhost] failed - Protocol error", snap, set)
	}); got != 0 {
		t.Errorf("no-match enrichment allocates %.0f times per line, want 0 — this path runs "+
			"on the receiver goroutine for every line the box sends (~5M/day on camden)", got)
	}

	// A nil snapshot must not allocate either: it returns before the regexes.
	if got := testing.AllocsPerRun(100, func() {
		enrichMessage("Accepted publickey for root from 10.0.0.6", nil, set)
	}); got != 0 {
		t.Errorf("nil-snapshot enrichment allocates %.0f times, want 0 (it must return before the regexes)", got)
	}
}
