package syslog

import (
	"testing"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// OpenVPN names one syslog program PER CONFIGURED INSTANCE — openvpn_server40,
// openvpn_client2 — so the exact-match registry cannot reach any of them. These
// tests pin the prefix table's contract: exact match always wins, the longest
// matching prefix wins among prefixes (so dispatch is deterministic regardless of
// Go's random map iteration order), and a duplicate or empty prefix panics at
// startup exactly as a duplicate exact registration does.
func TestParserForPrefersExactMatchOverPrefix(t *testing.T) {
	prefixHit := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{Body: "prefix"}, true
	})
	exactHit := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{Body: "exact"}, true
	})

	restore := swapParserTables(t)
	defer restore()

	RegisterParserPrefix(prefixHit, "testprog")
	RegisterParser(exactHit, "testprog_one")

	got, ok := parserFor("testprog_one")
	if !ok {
		t.Fatal("parserFor(testprog_one) ok = false, want true")
	}
	rec, _ := got(Envelope{}, nil, nil)
	if rec.Body != "exact" {
		t.Errorf("dispatched to %q, want the exact-match parser", rec.Body)
	}

	got, ok = parserFor("testprog_two")
	if !ok {
		t.Fatal("parserFor(testprog_two) ok = false, want true from the prefix table")
	}
	rec, _ = got(Envelope{}, nil, nil)
	if rec.Body != "prefix" {
		t.Errorf("dispatched to %q, want the prefix parser", rec.Body)
	}
}

func TestParserForPrefixLongestWins(t *testing.T) {
	short := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{Body: "short"}, true
	})
	long := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{Body: "long"}, true
	})

	restore := swapParserTables(t)
	defer restore()

	RegisterParserPrefix(short, "testprog")
	RegisterParserPrefix(long, "testprog_server")

	// Run it repeatedly: a map-order-dependent implementation passes this once and
	// then fails, which is worse than failing outright.
	for i := 0; i < 50; i++ {
		got, ok := parserFor("testprog_server40")
		if !ok {
			t.Fatal("parserFor(testprog_server40) ok = false, want true")
		}
		rec, _ := got(Envelope{}, nil, nil)
		if rec.Body != "long" {
			t.Fatalf("dispatched to %q, want the longest matching prefix", rec.Body)
		}
	}
}

func TestParserForUnknownProgramHasNoParser(t *testing.T) {
	restore := swapParserTables(t)
	defer restore()

	RegisterParserPrefix(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{}, true
	}, "testprog")

	if _, ok := parserFor("something_else"); ok {
		t.Error("parserFor(something_else) ok = true, want false")
	}
	// A program that only CONTAINS the prefix is not a prefix match.
	if _, ok := parserFor("x_testprog"); ok {
		t.Error("parserFor(x_testprog) ok = true, want false — prefix means prefix")
	}
}

func TestRegisterParserPrefixPanicsOnDuplicate(t *testing.T) {
	restore := swapParserTables(t)
	defer restore()

	noop := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{}, false
	})
	RegisterParserPrefix(noop, "testprog")

	defer func() {
		if recover() == nil {
			t.Error("RegisterParserPrefix did not panic on a duplicate prefix")
		}
	}()
	RegisterParserPrefix(noop, "testprog")
}

func TestRegisterParserPrefixPanicsOnEmptyPrefix(t *testing.T) {
	restore := swapParserTables(t)
	defer restore()

	defer func() {
		if recover() == nil {
			t.Error("RegisterParserPrefix did not panic on an empty prefix")
		}
	}()
	RegisterParserPrefix(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{}, false
	}, "")
}

// Body enrichment is OPT-IN per parser: a plain RegisterParser keeps the
// parsed-record default of skipping the generic body scan, and only the explicit
// WithBodyEnrichment variants turn it back on. Resolution matches parserFor's, so
// the answer belongs to whichever parser actually ran.
func TestParserEnrichesBodyIsOptInAndResolvesLikeParserFor(t *testing.T) {
	noop := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{}, true
	})

	restore := swapParserTables(t)
	defer restore()

	RegisterParser(noop, "plainprog")
	RegisterParserWithBodyEnrichment(noop, "optedprog")
	RegisterParserPrefix(noop, "plainpre")
	RegisterParserPrefixWithBodyEnrichment(noop, "optedpre")

	for program, want := range map[string]bool{
		"plainprog":        false,
		"optedprog":        true,
		"plainpre_one":     false,
		"optedpre_one":     true,
		"never_registered": false,
	} {
		if got := parserEnrichesBody(program); got != want {
			t.Errorf("parserEnrichesBody(%q) = %v, want %v", program, got, want)
		}
	}

	// The opt-in variants must still register the parser itself.
	for _, program := range []string{"optedprog", "optedpre_one"} {
		if _, ok := parserFor(program); !ok {
			t.Errorf("WithBodyEnrichment did not register a parser for %q", program)
		}
	}
}

// An EXACT non-opted registration must beat a longer opted PREFIX, the same way
// parserFor resolves — otherwise a program could run one parser while being granted
// another's body-enrichment answer.
func TestParserEnrichesBodyExactBeatsPrefix(t *testing.T) {
	noop := Parser(func(Envelope, *enrich.Snapshot, func(string)) (logship.Record, bool) {
		return logship.Record{}, true
	})

	restore := swapParserTables(t)
	defer restore()

	RegisterParserPrefixWithBodyEnrichment(noop, "testprog")
	RegisterParser(noop, "testprog_exact")

	if parserEnrichesBody("testprog_exact") {
		t.Error("an exact non-opted registration inherited the prefix's body-enrichment opt-in")
	}
	if !parserEnrichesBody("testprog_other") {
		t.Error("a prefix-matched program lost its body-enrichment opt-in")
	}
}

// The two live registrations, asserted against the real init()-populated tables:
// charon and every openvpn instance keep body enrichment; filterlog must not.
func TestLiveBodyEnrichmentOptIns(t *testing.T) {
	for program, want := range map[string]bool{
		"charon":           true,
		"openvpn_server40": true,
		"openvpn_client2":  true,
		"filterlog":        false,
		"sshd":             false,
		"dhcpd":            false,
		"radiusd":          false,
		"dpinger":          false,
	} {
		if got := parserEnrichesBody(program); got != want {
			t.Errorf("parserEnrichesBody(%q) = %v, want %v", program, got, want)
		}
	}
}

// swapParserTables isolates a test from the init()-registered production tables
// so a test registration cannot leak into another test (or panic against a real
// program name). Every table a registration writes must be swapped here — a
// forgotten one leaks a test program into production dispatch.
func swapParserTables(t *testing.T) func() {
	t.Helper()
	savedExact, savedPrefix := parsers, parserPrefixes
	savedBodyExact, savedBodyPrefix := bodyEnrichedPrograms, bodyEnrichedPrefixes
	parsers = map[string]Parser{}
	parserPrefixes = map[string]Parser{}
	bodyEnrichedPrograms = map[string]bool{}
	bodyEnrichedPrefixes = map[string]bool{}
	return func() {
		parsers, parserPrefixes = savedExact, savedPrefix
		bodyEnrichedPrograms, bodyEnrichedPrefixes = savedBodyExact, savedBodyPrefix
	}
}
