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

// TestEndpointMissingErrorsNameTheirEndpoint closes the copy-paste class #576 was
// filed for: every Fetch* guards its endpoint lookup with
//
//	url, ok := c.endpoints["<key>"]
//	if !ok {
//		return ..., &APICallError{Endpoint: "<key>", ...}
//	}
//
// and the two "<key>"s are written independently, so a function cloned from its
// neighbour keeps the neighbour's name. That misattributes the error and — as
// happened during the 2026-07-31 request-volume audit — makes one endpoint look
// like it is fetched by two collectors. Nothing at runtime catches it: the branch
// is only reachable when the endpoint table itself lacks the key.
//
// The check is deliberately structural rather than a grep: it pairs each
// `c.endpoints[<literal>]` assignment with the APICallError literal inside the
// `if !ok` block that guards it, so an error constructed for an unrelated reason
// elsewhere in the function is not compared.
func TestEndpointMissingErrorsNameTheirEndpoint(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var mismatches []string
	checked := 0

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
			// Match `<var>, ok := c.endpoints[<key>]` followed by `if !ok { ... }`.
			// go/ast gives us the assignment as the if statement's Init when the two
			// are written as separate statements, so walk statement lists in pairs.
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i := 0; i+1 < len(block.List); i++ {
				key, okVar := endpointLookupKey(block.List[i])
				if key == "" {
					continue
				}
				ifStmt, ok := block.List[i+1].(*ast.IfStmt)
				if !ok || !isNegatedIdent(ifStmt.Cond, okVar) {
					continue
				}
				named, found := apiCallErrorEndpoint(ifStmt.Body)
				if !found {
					continue
				}
				checked++
				if named != key {
					pos := fset.Position(ifStmt.Body.Pos())
					mismatches = append(mismatches, pos.Filename+":"+strconv.Itoa(pos.Line)+
						": endpoint lookup is "+strconv.Quote(key)+" but its missing-endpoint error names "+
						strconv.Quote(named))
				}
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("no `url, ok := c.endpoints[...]` / `if !ok { &APICallError{Endpoint: ...} }` pairs found; " +
			"the guard's AST shape no longer matches the package and it is silently checking nothing")
	}

	sort.Strings(mismatches)
	for _, m := range mismatches {
		t.Error(m)
	}
}

// endpointLookupKey returns the literal endpoint key and the name of the ok
// variable for a statement of the form `<var>, ok := c.endpoints[<literal>]`.
// It returns "" for anything else, including a lookup keyed on a parameter (the
// crowdsec/frr helpers), whose error is constructed from the same variable and so
// cannot diverge.
func endpointLookupKey(stmt ast.Stmt) (key, okVar string) {
	as, ok := stmt.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 || len(as.Lhs) != 2 {
		return "", ""
	}
	idx, ok := as.Rhs[0].(*ast.IndexExpr)
	if !ok || !isSelector(idx.X, "c", "endpoints") {
		return "", ""
	}
	lit, ok := idx.Index.(*ast.BasicLit)
	if !ok {
		return "", ""
	}
	k, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", ""
	}
	id, ok := as.Lhs[1].(*ast.Ident)
	if !ok {
		return "", ""
	}
	return k, id.Name
}

// isNegatedIdent reports whether e is `!<name>`.
func isNegatedIdent(e ast.Expr, name string) bool {
	un, ok := e.(*ast.UnaryExpr)
	if !ok || un.Op != token.NOT {
		return false
	}
	id, ok := un.X.(*ast.Ident)
	return ok && id.Name == name
}

// apiCallErrorEndpoint returns the literal Endpoint field of the first
// APICallError composite literal constructed anywhere inside body.
func apiCallErrorEndpoint(body *ast.BlockStmt) (string, bool) {
	var name string
	var found bool
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := cl.Type.(*ast.Ident); !ok || id.Name != "APICallError" {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Endpoint" {
				continue
			}
			lit, ok := kv.Value.(*ast.BasicLit)
			if !ok {
				continue
			}
			if s, err := strconv.Unquote(lit.Value); err == nil {
				name, found = s, true
			}
		}
		return true
	})
	return name, found
}
