package logship_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/syslog"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/zenarmor"
)

// This file lives in package logship_test (an EXTERNAL test package) so it can
// import the receiver packages to read their vocabularies. syslog and zenarmor both
// import logship, so an in-package test importing them back would be a cycle.

// literalArgs parses every non-test .go file in dir and returns the string literals
// passed as argument argIdx to any call named by names, keyed literal -> call site.
//
// Both call shapes are matched, and both are load-bearing here: a method call
// `s.m.Reject("peer")` (SelectorExpr) and a plain call `miss("rules")` (Ident).
// The enrichment miss is only ever reached through an injected func value — see
// syslog.Parser — so a selector-only matcher silently finds nothing and reports the
// whole vocabulary as dead.
//
// Non-literal arguments are ignored: the vocabularies are literal by construction,
// and a variable argument is caught by the dead-vocabulary half of the diff instead.
func literalArgs(t *testing.T, dir string, argIdx int, names ...string) map[string]string {
	t.Helper()
	want := map[string]bool{}
	for _, m := range names {
		want[m] = true
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	found := map[string]string{} // literal -> "file:line" of first call site
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) <= argIdx {
				return true
			}
			var fname string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr: // s.m.Reject("peer")
				fname = fn.Sel.Name
			case *ast.Ident: // miss("rules") — an injected func value
				fname = fn.Name
			default:
				return true
			}
			if !want[fname] {
				return true
			}
			lit, ok := call.Args[argIdx].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if _, seen := found[s]; !seen {
				found[s] = fset.Position(lit.Pos()).String()
			}
			return true
		})
	}
	return found
}

// diffVocab fails when the declared vocabulary and the call sites disagree in
// either direction. Both directions matter and for different reasons: a call site
// missing from the vocabulary is the #280 bug returning (that series stays invisible
// until it first fires), while a vocabulary entry with no call site publishes a zero
// nothing can ever increment, which claims we are watching something we are not.
func diffVocab(t *testing.T, what string, declared []string, callSites map[string]string, addTo string) {
	t.Helper()
	decl := map[string]bool{}
	for _, d := range declared {
		decl[d] = true
	}

	var missing []string
	for lit := range callSites {
		if !decl[lit] {
			missing = append(missing, lit)
		}
	}
	sort.Strings(missing)
	for _, lit := range missing {
		t.Errorf("%s: %q is used at %s but is not declared in %s, so it is not pre-initialised — "+
			"it will be absent from /metrics until it first fires (#280)", what, lit, callSites[lit], addTo)
	}

	var dead []string
	for _, d := range declared {
		if _, ok := callSites[d]; !ok {
			dead = append(dead, d)
		}
	}
	sort.Strings(dead)
	for _, d := range dead {
		t.Errorf("%s: %q is declared in %s but no call site can ever produce it — "+
			"a permanent zero advertises a check that never runs; remove it", what, d, addTo)
	}
}

// TestReceiverVocabulariesMatchCallSites is the acceptance criterion from #280 that
// a new reason cannot be added without also being pre-initialised. It derives the
// reasons/stages actually reachable from each receiver's source and diffs them
// against the declared vocabulary, in the spirit of
// opnsense/contract_postendpoints_test.go's POST-endpoint check.
func TestReceiverVocabulariesMatchCallSites(t *testing.T) {
	t.Run("syslog reasons", func(t *testing.T) {
		diffVocab(t, "syslog reject reason", syslog.RejectReasons,
			literalArgs(t, "syslog", 0, "Reject"), "syslog.RejectReasons")
	})
	t.Run("syslog stages", func(t *testing.T) {
		diffVocab(t, "syslog parse stage", syslog.ParseStages,
			literalArgs(t, "syslog", 0, "ParseError"), "syslog.ParseStages")
	})
	t.Run("zenarmor reasons", func(t *testing.T) {
		diffVocab(t, "zenarmor reject reason", zenarmor.RejectReasons,
			literalArgs(t, "zenarmor", 0, "reject"), "zenarmor.RejectReasons")
	})
	t.Run("zenarmor stages", func(t *testing.T) {
		diffVocab(t, "zenarmor parse stage", zenarmor.ParseStages,
			literalArgs(t, "zenarmor", 0, "parseError"), "zenarmor.ParseStages")
	})
}

// The enrichment miss vocabulary is checked from here rather than from inside the
// enrich package because the only production caller of Miss lives in the syslog
// package: filterlog's rule-description lookup passes the table name to the
// injected `miss` func. enrich itself never calls it.
func TestEnrichMissTablesMatchCallSites(t *testing.T) {
	diffVocab(t, "enrich miss table", enrich.MissTables,
		literalArgs(t, "syslog", 0, "miss", "Miss", "NoteMiss"), "enrich.MissTables")
}

// The receivers' declared vocabularies must be the ones actually handed to
// NewReceiverMetrics. The diffs above prove each vocabulary matches its call sites;
// this proves the vocabulary is not then left on the shelf. Without it, a receiver
// could pass ReceiverVocab{} and every diff would still pass while /metrics stayed
// empty.
func TestReceiversPassTheirVocabularyToNewReceiverMetrics(t *testing.T) {
	for _, tc := range []struct {
		dir             string
		reasons, stages string
	}{
		{"syslog", "RejectReasons", "ParseStages"},
		{"zenarmor", "RejectReasons", "ParseStages"},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			src := readPackageSource(t, tc.dir)
			if !strings.Contains(src, "NewReceiverMetrics(") {
				t.Fatalf("%s calls no NewReceiverMetrics; this test is watching the wrong thing", tc.dir)
			}
			for _, field := range []string{tc.reasons, tc.stages} {
				if !strings.Contains(src, field) {
					t.Errorf("%s declares %s but never passes it to NewReceiverMetrics, so nothing is pre-initialised (#280)",
						tc.dir, field)
				}
			}
			if strings.Contains(src, "logship.ReceiverVocab{}") {
				t.Errorf("%s passes an EMPTY ReceiverVocab; its counters stay invisible until they first fire (#280)", tc.dir)
			}
		})
	}
}

// readPackageSource concatenates every non-test .go file in dir.
func readPackageSource(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var b strings.Builder
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.Write(data)
	}
	return b.String()
}
