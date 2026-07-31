package opnsense

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// derivedPathEndpoints returns the endpoint names whose REQUEST path is built from
// the registered path rather than being it — a suffix (`<base>/<provider>`) or a
// query string (`<base>?iface=`). Derived by AST from the package source rather than
// hand-listed, so a new one cannot be added without this guard seeing it.
//
// It matches the shape `EndpointPath(string(<var>) + …)` where <var> was assigned
// from `c.endpoints[<literal>]` anywhere in the same function.
func derivedPathEndpoints(t *testing.T) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	derived := map[string]string{}
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

			// var name -> endpoint key, for every `v, ok := c.endpoints["k"]` in the func.
			varKey := map[string]string{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
					return true
				}
				idx, ok := as.Rhs[0].(*ast.IndexExpr)
				if !ok || !isSelector(idx.X, "c", "endpoints") {
					return true
				}
				lit, ok := idx.Index.(*ast.BasicLit)
				if !ok {
					return true
				}
				k, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if id, ok := as.Lhs[0].(*ast.Ident); ok {
					varKey[id.Name] = k
				}
				return true
			})
			if len(varKey) == 0 {
				continue
			}

			// `EndpointPath(string(v) + …)` — v's key is requested at a derived path.
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "EndpointPath" {
					return true
				}
				bin, ok := call.Args[0].(*ast.BinaryExpr)
				if !ok || bin.Op != token.ADD {
					return true
				}
				ast.Inspect(bin, func(m ast.Node) bool {
					inner, ok := m.(*ast.CallExpr)
					if !ok || len(inner.Args) != 1 {
						return true
					}
					if id, ok := inner.Fun.(*ast.Ident); !ok || id.Name != "string" {
						return true
					}
					if id, ok := inner.Args[0].(*ast.Ident); ok {
						if key, tracked := varKey[id.Name]; tracked {
							pos := fset.Position(call.Pos())
							derived[key] = pos.Filename + ":" + strconv.Itoa(pos.Line)
						}
					}
					return true
				})
				return true
			})
		}
	}
	return derived
}

// TestDerivedPathEndpointsAreNotBodyCached closes the trap #574 walked into and
// #495 named on the negative-cache side: the response cache is keyed on the
// endpoint's REGISTERED path, but a handful of endpoints are requested at a path
// derived from it — captivePortalVoucherGroups at `<base>/<provider>`,
// captivePortalVouchers at `<base>/<provider>/<group>`, vnstatGetJsonData at
// `<base>?iface=…`. A body TTL on one of those is not merely ineffective, it is
// SILENTLY ineffective: every existing guard passes, the endpoint appears in the
// cached set and in the docs, and the box is still asked on every poll.
//
// (This is the reason #574's proposed table lists captivePortalVoucherGroups and
// this change does not. A 404 exemption is a different question, which is why
// PluginGatedEndpoints and NegativeCacheable404Endpoints stay separate lists.)
func TestDerivedPathEndpointsAreNotBodyCached(t *testing.T) {
	derived := derivedPathEndpoints(t)
	if len(derived) == 0 {
		t.Fatal("no derived-path request sites found; the guard's AST shape no longer matches " +
			"the package and it is silently checking nothing")
	}

	// Any positive TTL at all is wrong here, so probe with generous knobs rather
	// than the shipped defaults — a future default of 0 must not hide the mistake.
	ttls := options.BodyCacheTTLs(time.Hour, 12*time.Hour)

	var offenders []string
	for endpoint, site := range derived {
		if ttl, cached := ttls[endpoint]; cached {
			offenders = append(offenders, endpoint+" (body TTL "+ttl.String()+", requested at a derived path at "+site+")")
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("endpoint %s: the response cache is keyed on the REGISTERED path, so this TTL can "+
			"never match the path actually requested and is silently dead. Drop the TTL, or give the "+
			"cache the derived key.", o)
	}
}
