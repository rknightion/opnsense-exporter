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
)

// TestPostEndpointsMatchCallSites turns contract.go's manual grep procedure into an
// executable invariant (#145): it parses the opnsense package source, derives the set of
// endpoint keys actually reached via c.do("POST", ...) / c.doForm(...), and diffs that
// against the hand-maintained postEndpoints map. A new POST Fetch* missing from
// postEndpoints, or a stale entry whose call site is GET, fails here.
//
// Resolution: each POST call's URL argument is an identifier assigned from
// `v, ok := c.endpoints[<key>]`. When <key> is a string literal the key is direct; when
// it is a function parameter (the crowdsec helpers take the endpoint name as an arg) the
// key is resolved from the string literals callers pass at that parameter's position.
func TestPostEndpointsMatchCallSites(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var funcs []*ast.FuncDecl
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
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				funcs = append(funcs, fd)
			}
		}
	}

	derived := map[string]bool{}
	// paramPostFuncs[funcName] = param index whose string value is a POST endpoint key.
	paramPostFuncs := map[string]int{}

	for _, fd := range funcs {
		// Map local var -> endpoints key expression: `v, ok := c.endpoints[X]`.
		varKey := map[string]ast.Expr{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 {
				return true
			}
			idx, ok := as.Rhs[0].(*ast.IndexExpr)
			if !ok || !isSelector(idx.X, "c", "endpoints") {
				return true
			}
			if len(as.Lhs) >= 1 {
				if id, ok := as.Lhs[0].(*ast.Ident); ok {
					varKey[id.Name] = idx.Index
				}
			}
			return true
		})

		// Find POST call sites and the URL var they pass.
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var urlArg ast.Expr
			switch {
			case isSelector(call.Fun, "c", "doForm") && len(call.Args) >= 1:
				urlArg = call.Args[0]
			case isSelector(call.Fun, "c", "do") && len(call.Args) >= 2 && isStringLit(call.Args[0], "POST"):
				urlArg = call.Args[1]
			default:
				return true
			}
			id, ok := urlArg.(*ast.Ident)
			if !ok {
				return true
			}
			keyExpr := varKey[id.Name]
			switch k := keyExpr.(type) {
			case *ast.BasicLit:
				if s, err := strconv.Unquote(k.Value); err == nil {
					derived[s] = true
				}
			case *ast.Ident:
				if i := paramIndex(fd, k.Name); i >= 0 {
					paramPostFuncs[fd.Name.Name] = i
				}
			}
			return true
		})
	}

	// Resolve param-based helpers: find literal args callers pass at the POST-key position.
	for _, fd := range funcs {
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			idx, isHelper := paramPostFuncs[sel.Sel.Name]
			if !isHelper || idx >= len(call.Args) {
				return true
			}
			if lit, ok := call.Args[idx].(*ast.BasicLit); ok {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					derived[s] = true
				}
			}
			return true
		})
	}

	// Diff derived set against postEndpoints.
	for k := range postEndpoints {
		if !derived[string(k)] {
			t.Errorf("postEndpoints has %q but no POST/doForm call site derives it (stale/over-broad entry?)", k)
		}
	}
	var missing []string
	for k := range derived {
		if _, ok := postEndpoints[EndpointName(k)]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		t.Errorf("endpoint %q is called via POST/doForm but is missing from postEndpoints (add it in contract.go + bump the golden count)", k)
	}
}

// isSelector reports whether e is `<x>.<sel>` (e.g. c.doForm).
func isSelector(e ast.Expr, x, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != sel {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == x
}

func isStringLit(e ast.Expr, want string) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	return err == nil && s == want
}

// paramIndex returns the position of the named parameter in fd's signature, or -1.
func paramIndex(fd *ast.FuncDecl, name string) int {
	if fd.Type.Params == nil {
		return -1
	}
	i := 0
	for _, field := range fd.Type.Params.List {
		for _, n := range field.Names {
			if n.Name == name {
				return i
			}
			i++
		}
	}
	return -1
}
