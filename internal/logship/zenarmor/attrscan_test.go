package zenarmor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
)

// attributeKeysSetByParser derives, from parse.go's source, every attribute key the
// parser can put on a record: the literal in `set("query", ...)` and, for
// `set(attrRCode, ...)`, the value of that constant.
//
// Deriving it beats listing it by hand, because the list it feeds
// (KnownAttributeKeys) is what --logs.zenarmor.exclude validates rule fields
// against. If the two drift, a legitimate rule fails at startup or a dead one starts
// up and silently matches nothing. Same approach as
// opnsense/contract_postendpoints_test.go and internal/logship/vocab_test.go.
//
// Returns key -> "file:line" of the first call site that sets it.
func attributeKeysSetByParser(t *testing.T) map[string]string {
	t.Helper()
	const file = "parse.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	// Resolve `const attrRCode = "rcode"` so set(attrRCode, ...) yields "rcode".
	consts := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != len(vs.Values) {
			return true
		}
		for i, name := range vs.Names {
			if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					consts[name.Name] = s
				}
			}
		}
		return true
	})

	// Keys written as `logship.AttrSubsystem` cannot be resolved from parse.go's AST
	// alone. Bind them to the REAL constants (this test compiles against them, so a
	// renamed or re-valued const shows up here rather than drifting), and fail loudly
	// on any qualified key not listed — silence here would shrink the derived
	// vocabulary and make the coverage check vacuously pass.
	qualified := map[string]string{
		"logship.AttrSubsystem":      logship.AttrSubsystem,
		"logship.AttrAction":         logship.AttrAction,
		"logship.AttrDeviceCategory": logship.AttrDeviceCategory,
		"logship.AttrInterface":      logship.AttrInterface,
	}

	// resolve turns a key expression into its string value. ok=false means "not a key
	// expression at all"; it reports its own errors for the unresolvable cases.
	resolve := func(e ast.Expr, what string, pos token.Pos) (string, bool) {
		switch a := e.(type) {
		case *ast.BasicLit:
			if a.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(a.Value)
			return s, err == nil
		case *ast.Ident:
			if v, ok := consts[a.Name]; ok {
				return v, true
			}
			return "", false
		case *ast.SelectorExpr:
			pkg, ok := a.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			name := pkg.Name + "." + a.Sel.Name
			v, ok := qualified[name]
			if !ok {
				t.Errorf("%s: %s keyed by unknown qualified constant %s at %s — add it to `qualified` "+
					"in attributeKeysSetByParser, or the exclude vocabulary check goes blind",
					file, what, name, fset.Position(pos))
				return "", false
			}
			return v, true
		}
		return "", false
	}

	found := map[string]string{}
	record := func(key string, pos token.Pos) {
		if _, seen := found[key]; !seen {
			found[key] = fset.Position(pos).String()
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// set("query", ...) / setInt("total_answers", ...) / set(attrRCode, ...)
			id, ok := node.Fun.(*ast.Ident)
			if !ok || (id.Name != "set" && id.Name != "setInt") || len(node.Args) == 0 {
				return true
			}
			if key, ok := resolve(node.Args[0], id.Name+"()", node.Pos()); ok {
				record(key, node.Pos())
			}
		case *ast.AssignStmt:
			// attrs[attrRCode] = ... — the DNS response code bypasses set() to keep a
			// deliberate "-1" that set() would treat as empty. Missing this shape once
			// already made "rcode" look unreachable.
			for _, lhs := range node.Lhs {
				idx, ok := lhs.(*ast.IndexExpr)
				if !ok {
					continue
				}
				target, ok := idx.X.(*ast.Ident)
				if !ok || target.Name != "attrs" {
					continue
				}
				// The set/setInt helper bodies assign attrs[k] from their own parameter; that is
				// the helper, not a key.
				if id, isIdent := idx.Index.(*ast.Ident); isIdent {
					if _, isConst := consts[id.Name]; !isConst {
						continue
					}
				}
				if key, ok := resolve(idx.Index, "attrs[...] assignment", node.Pos()); ok {
					record(key, node.Pos())
				}
			}
		}
		return true
	})

	if len(found) == 0 {
		t.Fatalf("derived no attribute keys from %s; the scan is broken, not the vocabulary", file)
	}
	return found
}

// setGeo takes `set` as a parameter and calls it with keys built from a prefix, so
// its keys cannot be derived from the call site alone. Guard the assumption that it
// contributes nothing the scan above must know about.
func TestGeoAttributesAreNotExcludeFields(t *testing.T) {
	produced := attributeKeysSetByParser(t)
	for k := range produced {
		if k == "geo" {
			t.Errorf("a bare %q key appeared; setGeo's prefixed keys are not in KnownAttributeKeys "+
				"and would be rejected as exclude fields", k)
		}
	}
}
