package enrich

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// countingServer answers every request with body and counts how many it received,
// so a test can assert "the firewall was not asked" rather than only asserting on
// the data that came back — which is the whole point of #571 and would otherwise be
// invisible to a test.
func countingServer(t *testing.T, body string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestSeamHitSkipsTheAPICall is the core assertion of #571: an input a collector
// has already published is not fetched again.
func TestSeamHitSkipsTheAPICall(t *testing.T) {
	srv, hits := countingServer(t, `{"total":0,"rows":[]}`)
	seam := fetchshare.New()
	r := &Refresher{seam: seam, now: time.Now, m: NewMetrics(nil)}

	// A collector polled this endpoint a moment ago.
	seam.Publish(fetchshare.KeyArpTable, opnsense.ArpTable{TotalEntries: 7})

	got, err := seamOr(r, fetchshare.KeyArpTable, time.Minute, func() (opnsense.ArpTable, *opnsense.APICallError) {
		resp, _ := http.Get(srv.URL) //nolint:noctx,bodyclose // a stand-in fetch; the count is what is asserted
		if resp != nil {
			_ = resp.Body.Close()
		}
		return opnsense.ArpTable{TotalEntries: 99}, nil
	})
	if err != nil {
		t.Fatalf("seamOr: %v", err)
	}
	if got.TotalEntries != 7 {
		t.Errorf("got the fetched table (%d entries), want the published one (7)", got.TotalEntries)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the fetch ran %d times on a seam hit; the whole point is that it does not", n)
	}
}

// TestSeamMissFallsBackToFetching covers three of the four ways a hit does not
// happen — no seam wired, nothing published yet, and the wrong type under the key.
// The fourth, an entry older than maxAge, gets its own test below because it is the
// one asserting a boundary rather than an absence. Each must land on exactly the
// pre-#571 behaviour, because that is what makes the seam safe to add to a refresh
// function without a special case per failure mode: a disabled collector, a failing
// poll and an absent plugin all arrive here.
func TestSeamMissFallsBackToFetching(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) *Refresher
	}{
		{
			name: "no seam wired",
			setup: func(*testing.T) *Refresher {
				return &Refresher{now: time.Now, m: NewMetrics(nil)}
			},
		},
		{
			name: "nothing published yet",
			setup: func(*testing.T) *Refresher {
				return &Refresher{seam: fetchshare.New(), now: time.Now, m: NewMetrics(nil)}
			},
		},
		{
			name: "published, but the wrong type under the key",
			setup: func(*testing.T) *Refresher {
				s := fetchshare.New()
				s.Publish(fetchshare.KeyArpTable, opnsense.NDPTable{TotalEntries: 3})
				return &Refresher{seam: s, now: time.Now, m: NewMetrics(nil)}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.setup(t)
			fetched := false
			got, err := seamOr(r, fetchshare.KeyArpTable, time.Minute,
				func() (opnsense.ArpTable, *opnsense.APICallError) {
					fetched = true
					return opnsense.ArpTable{TotalEntries: 42}, nil
				})
			if err != nil {
				t.Fatalf("seamOr: %v", err)
			}
			if !fetched {
				t.Fatal("the fetch did not run; a seam miss must behave exactly as it did before #571")
			}
			if got.TotalEntries != 42 {
				t.Errorf("got %d entries, want the fetched table (42)", got.TotalEntries)
			}
		})
	}
}

// TestSeamStaleEntryIsRefetched pins the freshness bound as real rather than
// nominal: a published result older than the caller's maxAge is not used.
func TestSeamStaleEntryIsRefetched(t *testing.T) {
	seam := fetchshare.New()
	r := &Refresher{seam: seam, now: time.Now, m: NewMetrics(nil)}
	seam.Publish(fetchshare.KeyArpTable, opnsense.ArpTable{TotalEntries: 7})

	fetched := false
	// maxAge of a nanosecond: whatever the clock does, the entry is already older.
	got, _ := seamOr(r, fetchshare.KeyArpTable, time.Nanosecond,
		func() (opnsense.ArpTable, *opnsense.APICallError) {
			fetched = true
			return opnsense.ArpTable{TotalEntries: 42}, nil
		})
	if !fetched {
		t.Fatal("a stale seam entry was served; the maxAge bound is not being applied")
	}
	if got.TotalEntries != 42 {
		t.Errorf("got %d entries, want the refetched table (42)", got.TotalEntries)
	}
}

// TestSeamFetchErrorPropagates keeps the fallback honest: a failing fetch must still
// surface its error so tick() counts it and keeps the previous snapshot, rather than
// the seam swallowing it into a zero value.
func TestSeamFetchErrorPropagates(t *testing.T) {
	r := &Refresher{seam: fetchshare.New(), now: time.Now, m: NewMetrics(nil)}
	want := &opnsense.APICallError{Endpoint: "arp", Message: "boom", StatusCode: 500}
	_, err := seamOr(r, fetchshare.KeyArpTable, time.Minute,
		func() (opnsense.ArpTable, *opnsense.APICallError) { return opnsense.ArpTable{}, want })
	if err != want {
		t.Errorf("seamOr swallowed the fetch error: got %v, want %v", err, want)
	}
}

// TestSeamReadsAreCounted proves the self-metric actually moves, in both directions.
// Without it the saving is unobservable from inside the exporter: a request that was
// never made leaves no trace anywhere else.
func TestSeamReadsAreCounted(t *testing.T) {
	seam := fetchshare.New()
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	r := &Refresher{seam: seam, now: time.Now, m: m}

	fetch := func() (opnsense.ArpTable, *opnsense.APICallError) { return opnsense.ArpTable{}, nil }

	seamOr(r, fetchshare.KeyArpTable, time.Minute, fetch) // miss
	seam.Publish(fetchshare.KeyArpTable, opnsense.ArpTable{})
	seamOr(r, fetchshare.KeyArpTable, time.Minute, fetch) // hit
	seamOr(r, fetchshare.KeyArpTable, time.Minute, fetch) // hit

	if got := seamCounter(t, reg, "arp", seamOutcomeHit); got != 2 {
		t.Errorf("hit counter = %v, want 2", got)
	}
	if got := seamCounter(t, reg, "arp", seamOutcomeMiss); got != 1 {
		t.Errorf("miss counter = %v, want 1", got)
	}
}

// seamCounter reads logs_enrich_seam_reads_total for one (endpoint, outcome) pair.
// Hand-rolled for the same reason as metricValue in refresh_test.go: this repo does
// not vendor prometheus/client_golang's testutil.
func seamCounter(t *testing.T, reg *prometheus.Registry, endpoint, outcome string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "opnsense_exporter_logs_enrich_seam_reads_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["endpoint"] == endpoint && labels["outcome"] == outcome {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("no seam_reads sample for endpoint=%q outcome=%q", endpoint, outcome)
	return 0
}

// TestNilMetricsDoesNotPanic keeps seamOr usable from the several tests in this
// package that build a bare Refresher.
func TestNilMetricsDoesNotPanic(t *testing.T) {
	r := &Refresher{seam: fetchshare.New()}
	if _, err := seamOr(r, fetchshare.KeyArpTable, time.Minute,
		func() (opnsense.ArpTable, *opnsense.APICallError) { return opnsense.ArpTable{}, nil }); err != nil {
		t.Fatalf("seamOr with nil metrics: %v", err)
	}
}

// TestSeamEndpointsMatchReadCallSites keeps the label-value list honest against the
// code, in both directions. SeamEndpoints exists so NewMetrics can pre-initialise
// the series — a value it does not list would appear only on first use, which for a
// counter that is supposed to sit at a steady hit rate is the difference between
// "this endpoint is never seam-served" and "this exporter does not have that
// feature".
func TestSeamEndpointsMatchReadCallSites(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	read := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != "seamOr" || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Args[1].(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fetchshare" {
				return true
			}
			read[sel.Sel.Name] = true
			return true
		})
	}

	if len(read) == 0 {
		t.Fatal("no seamOr call sites found; the guard's AST shape no longer matches the package " +
			"and it is silently checking nothing")
	}

	declared := map[string]bool{}
	for _, e := range SeamEndpoints {
		declared[e] = true
	}

	var missing, stale []string
	for ident := range read {
		if !declared[seamKeyValue(ident)] {
			missing = append(missing, ident)
		}
	}
	byValue := map[string]bool{}
	for ident := range read {
		byValue[seamKeyValue(ident)] = true
	}
	for _, e := range SeamEndpoints {
		if !byValue[e] {
			stale = append(stale, e)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, m := range missing {
		t.Errorf("fetchshare.%s is read by a seamOr call site but its endpoint is missing from "+
			"SeamEndpoints, so its counter series will not be pre-initialised", m)
	}
	for _, s := range stale {
		t.Errorf("SeamEndpoints lists %q but no seamOr call site reads it; drop it or the metric "+
			"publishes a zero series nothing can ever increment", s)
	}
}

// seamKeyValue resolves a fetchshare Key constant identifier to its string value.
// Hand-written for the same reason as the opnsense package's twin: the AST carries
// only the identifier. Any entry it does not know about resolves to "" and fails
// the test loudly rather than passing silently.
func seamKeyValue(ident string) string {
	return string(map[string]fetchshare.Key{
		"KeyArpTable":           fetchshare.KeyArpTable,
		"KeyNDPTable":           fetchshare.KeyNDPTable,
		"KeyKeaLeases4":         fetchshare.KeyKeaLeases4,
		"KeyKeaLeases6":         fetchshare.KeyKeaLeases6,
		"KeyDnsmasqLeases":      fetchshare.KeyDnsmasqLeases,
		"KeyDHCPv4Leases":       fetchshare.KeyDHCPv4Leases,
		"KeyDHCPv6Leases":       fetchshare.KeyDHCPv6Leases,
		"KeyInterfacesOverview": fetchshare.KeyInterfacesOverview,
		"KeyInterfaces":         fetchshare.KeyInterfaces,
		"KeyIPsecPhase1":        fetchshare.KeyIPsecPhase1,
		"KeyOpenVPNInstances":   fetchshare.KeyOpenVPNInstances,
	}[ident])
}
