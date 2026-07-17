package enrich

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// gatherNames returns the set of series reg would publish, keyed `name{table="x"}`.
// It goes through Gather deliberately: reading a vec child with WithLabelValues
// would CREATE the child, so an assertion built on it would pass even against the
// unfixed code (#280).
func gatherNames(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, lp := range m.GetLabel() {
				key += "{" + lp.GetName() + "=" + strconv.Quote(lp.GetValue()) + "}"
			}
			if m.GetCounter() != nil {
				out[key] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}

// #280: the enrichment CounterVecs must read a flat 0 on a healthy exporter rather
// than vanishing until the first miss or failed refresh.
func TestEnrichCountersPreInitialisedToZero(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewMetrics(reg)

	s := gatherNames(t, reg)

	// Every table can fail a refresh.
	for _, table := range Tables {
		key := `opnsense_exporter_logs_enrich_refresh_errors_total{table="` + table + `"}`
		if v, ok := s[key]; !ok {
			t.Errorf("%s is ABSENT on a healthy exporter; rate() over it returns no-data instead of 0", key)
		} else if v != 0 {
			t.Errorf("%s = %v, want 0", key, v)
		}
	}

	// Only rules can report a LOOKUP miss.
	if v, ok := s[`opnsense_exporter_logs_enrich_misses_total{table="rules"}`]; !ok {
		t.Error(`logs_enrich_misses_total{table="rules"} is ABSENT on a healthy exporter`)
	} else if v != 0 {
		t.Errorf(`logs_enrich_misses_total{table="rules"} = %v, want 0`, v)
	}

	// The other tables never call Miss, so a zero there would advertise a lookup that
	// does not exist.
	for _, table := range []string{"interfaces", "leases", "tunnels"} {
		key := `opnsense_exporter_logs_enrich_misses_total{table="` + table + `"}`
		if _, ok := s[key]; ok {
			t.Errorf("%s was pre-initialised but nothing can ever increment it", key)
		}
	}

	// LastRefresh is a timestamp: a pre-initialised zero would read as 1970 and make
	// time() - LastRefresh report a 56-year-old cache instead of "not yet refreshed".
	if _, ok := s[`opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds{table="rules"}`]; ok {
		t.Error("logs_enrich_last_refresh_timestamp_seconds must NOT be pre-initialised; 0 would read as 1970")
	}
}

// Tables must match Run's tick() call sites, so a new enrichment table cannot be
// added without also being pre-initialised.
func TestTablesMatchTickCallSites(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "tick" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					found[s] = true
				}
			}
			return true
		})
	}

	declared := map[string]bool{}
	for _, tbl := range Tables {
		declared[tbl] = true
	}
	var missing, dead []string
	for tbl := range found {
		if !declared[tbl] {
			missing = append(missing, tbl)
		}
	}
	for tbl := range declared {
		if !found[tbl] {
			dead = append(dead, tbl)
		}
	}
	sort.Strings(missing)
	sort.Strings(dead)
	for _, tbl := range missing {
		t.Errorf("table %q is refreshed via tick() but missing from Tables, so its refresh-error counter is not pre-initialised (#280)", tbl)
	}
	for _, tbl := range dead {
		t.Errorf("table %q is in Tables but never tick()ed; its zero can never move", tbl)
	}
}
