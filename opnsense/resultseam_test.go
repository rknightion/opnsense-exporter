package opnsense

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
)

// TestSeamPublishedKeysMatchCallSites derives the set of keys actually published
// from the package source and diffs it against seamPublishedKeys, in both
// directions — the same shape as TestPostEndpointsMatchCallSites for the POST
// contract.
//
// It matters more than a normal registry check because a seam entry is retrieved
// by TYPE ASSERTION. Two Fetch* methods publishing different Go shapes under one
// key would not fail to compile, would not panic, and would not log: every read
// would just silently miss half the time and issue an API call, which is precisely
// the behaviour this whole change exists to remove. The table naming the producer
// per key is what makes that reviewable, and this test is what stops the table
// drifting away from the code.
func TestSeamPublishedKeysMatchCallSites(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	// derived[key] = sorted list of the Fetch*/fetch* funcs that publish it.
	derived := map[string]map[string]bool{}
	dynamic := map[string]bool{} // funcs publishing a non-constant key

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isSelector(call.Fun, "c", "publishResult") || len(call.Args) != 2 {
					return true
				}
				sel, ok := call.Args[0].(*ast.SelectorExpr)
				if !ok {
					// fetchshare.Key(<expr>) — a helper publishing under a key derived
					// from its argument. Recorded separately: the constant it resolves
					// to is a caller's business, so the static check cannot see it.
					dynamic[fd.Name.Name] = true
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fetchshare" {
					return true
				}
				key := seamKeyConstValue(sel.Sel.Name)
				if key == "" {
					t.Errorf("%s publishes fetchshare.%s, which is not a Key constant this test "+
						"knows about; add it to seamKeyConstValue", fd.Name.Name, sel.Sel.Name)
					return true
				}
				if derived[key] == nil {
					derived[key] = map[string]bool{}
				}
				derived[key][fd.Name.Name] = true
				return true
			})
		}
	}

	if len(derived) == 0 && len(dynamic) == 0 {
		t.Fatal("no c.publishResult call sites found; the guard's AST shape no longer matches the " +
			"package and it is silently checking nothing")
	}

	// One producer per key. Two Fetch* publishing different shapes under one key is
	// the failure this test exists for.
	for key, producers := range derived {
		if len(producers) > 1 {
			names := make([]string, 0, len(producers))
			for p := range producers {
				names = append(names, p)
			}
			sort.Strings(names)
			t.Errorf("key %q is published by more than one function (%s). A seam entry is retrieved "+
				"by type assertion, so two producers under one key make every read a coin flip: give "+
				"each shape its own key.", key, strings.Join(names, ", "))
		}
	}

	// Every published key is declared, with the right producer named.
	for key, producers := range derived {
		want, declared := seamPublishedKeys[fetchshare.Key(key)]
		if !declared {
			t.Errorf("key %q is published by the package but missing from seamPublishedKeys; add it "+
				"with the name of the Fetch* that produces it", key)
			continue
		}
		if !producers[want] {
			names := make([]string, 0, len(producers))
			for p := range producers {
				names = append(names, p)
			}
			sort.Strings(names)
			t.Errorf("seamPublishedKeys says %q is produced by %s, but the publish call site is in %s",
				key, want, strings.Join(names, ", "))
		}
	}

	// And nothing declared has quietly stopped publishing. The two kea keys come
	// from the shared fetchKeaLeases helper under a computed key, so they are
	// covered by the dynamic set rather than a literal call site.
	for key, producer := range seamPublishedKeys {
		if _, ok := derived[string(key)]; ok {
			continue
		}
		if len(dynamic) > 0 && (key == fetchshare.KeyKeaLeases4 || key == fetchshare.KeyKeaLeases6) {
			continue
		}
		t.Errorf("seamPublishedKeys declares %q (produced by %s) but no c.publishResult call site "+
			"publishes it; the publish was lost or the entry is stale", key, producer)
	}
}

// seamKeyConstValue maps a fetchshare.Key constant's IDENTIFIER to its string
// value. The AST carries only the identifier, and resolving the constant properly
// would mean type-checking the whole module for no gain — but a hand-written map
// could silently drift, so every entry is asserted against the real constant by
// TestSeamKeyConstValuesAreCurrent below.
func seamKeyConstValue(ident string) string {
	v, ok := map[string]fetchshare.Key{
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
	}[ident]
	if !ok {
		return ""
	}
	return string(v)
}

// TestSeamKeysAreEndpointNames pins the naming rule from the fetchshare package
// comment: a key is the API endpoint name, so the seam, the response cache, the
// per-endpoint request self-metrics and the contract manifest all talk about the
// same thing under one name. A key that names nothing in the endpoint table is
// either a typo or a shape-key that needs saying so out loud.
func TestSeamKeysAreEndpointNames(t *testing.T) {
	endpoints := defaultEndpoints()
	for key := range seamPublishedKeys {
		if _, ok := endpoints[EndpointName(key)]; !ok {
			t.Errorf("seam key %q is not an endpoint name in defaultEndpoints(); the seam, the "+
				"response cache and the request self-metrics are supposed to share one vocabulary",
				key)
		}
	}
}

// TestPublishedResultsAreReadable is the end-to-end proof that the wiring works
// against a real HTTP response: a fetch through a live client populates the seam
// with a value the declared consumer type can read back.
func TestPublishedResultsAreReadable(t *testing.T) {
	const body = `{"total":1,"rowCount":1,"current":1,"rows":[
		{"mac":"00:11:22:33:44:55","ip":"10.0.0.5","intf":"igb0","hostname":"nas",
		 "intf_description":"LAN","expired":false,"permanent":false,"type":"ethernet","manufacturer":"x"}]}`
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer server.Close()

	seam := fetchshare.New()
	client.SetResultSeam(seam)

	if _, ok := fetchshare.Fresh[ArpTable](seam, fetchshare.KeyArpTable, time.Minute); ok {
		t.Fatal("precondition: the seam should be empty before the first fetch")
	}

	got, err := client.FetchArpTable()
	if err != nil {
		t.Fatalf("FetchArpTable: %v", err)
	}

	published, ok := fetchshare.Fresh[ArpTable](seam, fetchshare.KeyArpTable, time.Minute)
	if !ok {
		t.Fatal("FetchArpTable did not publish its result to the seam")
	}
	if published.TotalEntries != got.TotalEntries || len(published.Arp) != len(got.Arp) {
		t.Errorf("published %+v, want the same table the fetch returned (%+v)", published, got)
	}
}

// TestFailedFetchDoesNotPublish pins the success-path-only rule. Publishing a
// zero value on failure would be worse than not publishing at all: a reader asking
// for a fresh table would get an authoritative-looking empty one and stop asking
// the box, turning a transient API failure into silently blank enrichment for a
// full TTL.
func TestFailedFetchDoesNotPublish(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errorMessage":"boom"}`))
	})
	defer server.Close()

	seam := fetchshare.New()
	client.SetResultSeam(seam)

	if _, err := client.FetchArpTable(); err == nil {
		t.Fatal("precondition: the fetch should have failed")
	}
	if _, ok := fetchshare.Fresh[ArpTable](seam, fetchshare.KeyArpTable, time.Minute); ok {
		t.Error("a failed fetch published to the seam; only a success may publish")
	}
}

// TestClonesShareOneSeam pins the pointer-not-value requirement. The client is
// cloned per scrape via WithContext; a value field would hand every scrape a fresh
// empty seam and the dedupe would never fire in production while every unit test
// still passed.
func TestClonesShareOneSeam(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"rows":[]}`))
	})
	defer server.Close()

	seam := fetchshare.New()
	client.SetResultSeam(seam)

	if _, err := client.WithContext(t.Context()).FetchArpTable(); err != nil {
		t.Fatalf("FetchArpTable on a clone: %v", err)
	}
	if _, ok := fetchshare.Fresh[ArpTable](seam, fetchshare.KeyArpTable, time.Minute); !ok {
		t.Error("a fetch on a per-scrape clone did not reach the parent's seam")
	}
}

// TestNoSeamWiredIsANoOp keeps a client built without a seam — every test in this
// package, and any embedder — from needing to know the seam exists.
func TestNoSeamWiredIsANoOp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"rows":[]}`))
	})
	defer server.Close()

	if _, err := client.FetchArpTable(); err != nil {
		t.Errorf("FetchArpTable with no seam wired: %v", err)
	}
}
