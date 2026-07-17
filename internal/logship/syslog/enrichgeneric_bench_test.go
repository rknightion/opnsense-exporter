package syslog

import "testing"

// Benchmarks for the universal enrichment path (#286, the criterion #250 promised and
// never delivered).
//
// Why this path and not another: enrichMessage runs SYNCHRONOUSLY on the receiver
// goroutine, before the record reaches the pipeline queue — the same constraint that
// makes Deps.Miss documented MUST-NOT-block and MUST-NOT-do-I/O (logship/source.go).
// Time spent here stalls the socket read loop, and UDP syslog offers no backpressure,
// so an over-budget path drops datagrams with no error and no counter. The failure is
// silent, which is exactly why it needs a number. camden pushes ~5M lines/day through it.
//
// These are a recorded BASELINE, not a CI gate: ns/op is machine-dependent and pinning
// it would flake. Compare runs with benchstat. The allocation counts are the stable,
// machine-independent half — b.ReportAllocs prints them, and TestEnrichMessageAllocations
// below pins the one that actually matters.
//
// The cases are ordered by how often the real box produces them, not by cost.

// sink defeats dead-code elimination without pretending the caller is free. The real
// caller writes each pair into the record's attribute map; this measures enrichMessage
// itself, so a map write is deliberately not included.
var sinkK, sinkV string

// benchCases are real shapes, not synthetic ones. Every message here is the kind of
// line the receiver actually sees.
var benchCases = []struct{ name, msg string }{
	// THE dominant case. Most non-filterlog lines mention no address at all, so this
	// is the one whose cost is multiplied by ~5M/day. Both regexes still run.
	{"no_match", "Poll UPS [ups@localhost] failed - Protocol error"},
	// The case #250 exists for: an address our tables can resolve.
	{"one_resolvable_ip", "Accepted publickey for root from 10.0.0.6 port 51000 ssh2: RSA SHA256:abc"},
	// Just as common and deliberately cheap: every internet-facing line carries an
	// address we cannot resolve, and enrichMessage must bail without emitting.
	{"unresolvable_ip", "Connection closed by authenticating user root 203.0.113.45 port 40222"},
	// Interface resolution only — the deviceRe half of the path.
	{"interface_only", "vtnet0: link state changed to DOWN"},
	// The pathological line maxEnrichedIPs exists to bound: a traceroute-style dump
	// with far more addresses than the cap.
	//
	// Measured ~8x the no_match line, and that is CORRECT, not a bug to chase. The cap
	// bounds the ATTRIBUTE SET, which is what its comment claims; it cannot bound the
	// scan, because FindAllString must find every match before the loop can know which
	// three resolve. Capping the regex itself (FindAllString(msg, 3)) would silently
	// change behaviour: a line whose first three addresses are unresolvable would stop
	// enriching the resolvable fourth. Cost here scales with line length, which is
	// bounded upstream, not with anything a peer chooses.
	{"many_addresses_capped", "traceroute to 10.0.0.6: 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 " +
		"10.0.0.5 10.0.0.6 10.0.0.7 10.0.0.8 10.0.0.9 10.0.0.10 10.0.0.11 10.0.0.12 " +
		"10.0.0.13 10.0.0.14 10.0.0.15 10.0.0.16 10.0.0.17 10.0.0.18 10.0.0.19 10.0.0.20"},
}

func BenchmarkEnrichMessage(b *testing.B) {
	snap := enrichSnap()
	set := func(k, v string) { sinkK, sinkV = k, v }

	for _, tc := range benchCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enrichMessage(tc.msg, snap, set)
			}
		})
	}
}

// A cold snapshot is the startup case and the enrichment-disabled case. It must be
// nearly free: enrichMessage bails on a nil snapshot before touching either regex.
func BenchmarkEnrichMessage_NilSnapshot(b *testing.B) {
	set := func(k, v string) { sinkK, sinkV = k, v }
	b.ReportAllocs()
	for b.Loop() {
		enrichMessage(benchCases[1].msg, nil, set)
	}
}

// TestEnrichMessageAllocations lives in enrichgeneric_allocs_test.go, gated `//go:build
// !race`. The zero-alloc assertion cannot survive `-race`: race instrumentation adds its
// own allocations, so AllocsPerRun would never read 0 under it (#295). The build
// constraint scopes the exception to that one test — the rest of this file, and every
// other test in the package, builds and runs under both `go test` and `go test -race`.
