package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// opnsensePkg is the API-client package whose response structs are audited.
//
// # Scope boundary (#588)
//
// This is a DELIBERATE, NARROW scope, not an oversight, but it is also the
// tool's sharpest edge and the one most likely to surprise a future reader —
// worth stating plainly here rather than only in an issue thread. Three
// things to know before trusting a clean `go test ./cmd/fieldaudit/` as
// "nothing is decoded and dropped":
//
//  1. Only package opnsense's own struct declarations become audited decls
//     (collectDecls below is called exclusively for opnsensePkg). Wire/response
//     structs declared in internal/flow (the NetFlow decoder, the correlator)
//     and internal/logship (the syslog/Zenarmor parsers) are invisible to this
//     tool — a dead field there produces no Finding, ever. This is exactly
//     where NetFlow's TCPFlags hid unread for months (#585/#586): the field
//     lived in internal/flow, not opnsense, so this audit — which already
//     existed — had structurally no way to see it.
//  2. collectReads, by contrast, scans EVERY first-party package (isFirstParty
//     below has no such restriction), so a field declared in opnsense counts as
//     "read" if ANYTHING anywhere selects it — including internal/webui, which
//     renders the operator console from cached data rather than feeding a
//     metric. A field surfaced only to a debug page is therefore
//     indistinguishable here from one feeding a Prometheus series; the checker
//     has no notion of "read by a metric" versus "read by a display".
//  3. A whole-struct conversion (markAllFields, triggered by the *ast.CallExpr
//     case in collectReads) marks EVERY field of the source type read, at any
//     depth, the moment the conversion appears anywhere — even if the caller
//     only consumes one field of the result afterward. This is deliberate (the
//     alternative is false positives on legitimate carry-through), but it means
//     a field can pass this gate while being effectively unused past the
//     conversion site.
//
// Extending scope to internal/flow and internal/logship was assessed for #588
// and declined for that pass: the tree was under heavy concurrent construction
// at the time (multiple lanes landing #577-#587 simultaneously), and auditing
// packages mid-rewrite would have produced findings that were really just
// WIP wiring-in-progress, not settled dead code — exactly the false-positive
// risk TestAuditIgnoresReadFields exists to guard against. Documenting the
// boundary here was the safer choice for that pass; extending the scan set
// (widen the collectDecls call site below to a small package list, and prefix
// Finding.Key with the package name so opnsense.* and flow.* keys don't
// collide) remains open for whoever picks it up next, once those lanes have
// settled.
const opnsensePkg = "github.com/rknightion/opnsense2otel/v5/opnsense"

// Finding is one struct field that is populated by unmarshalling an OPNsense API
// response and read nowhere in the module's non-test code.
type Finding struct {
	// Key is the ledger key, "opnsense.<Type>.<Field>". Fields of anonymous
	// nested structs carry the full dotted path from their named parent.
	Key string
	// JSONTag is the field's json tag name, i.e. the payload key it decodes.
	JSONTag string
	// Pos is file:line, relative to the module root.
	Pos string
}

// FindModuleRoot walks up from start until it finds the directory holding go.mod.
func FindModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod found above " + start)
		}
		dir = parent
	}
}

// listedPackage is the subset of `go list -json` this tool needs.
type listedPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Export     string
}

// listPackages runs `go list -deps -export` over the module. -deps emits
// dependencies before their dependents, which is the order the source
// type-checker needs; -export builds (or reuses from the build cache) the
// compiler's export data for every package, so third-party and standard-library
// dependencies are resolved from export data instead of being re-checked from
// source. That keeps the analysis exact without pulling in x/tools/go/packages.
func listPackages(moduleRoot string) ([]listedPackage, error) {
	cmd := exec.Command("go", "list", "-deps", "-export",
		"-json=ImportPath,Dir,GoFiles,Export", "./...")
	cmd.Dir = moduleRoot
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}

	var pkgs []listedPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p listedPackage
		if decErr := dec.Decode(&p); decErr != nil {
			if errors.Is(decErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", decErr)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// fieldDecl records one json-tagged field declared in package opnsense.
type fieldDecl struct {
	key     string
	jsonTag string
	pos     string
}

// combinedImporter serves first-party packages from the source type-checker
// (so field objects have one identity across the whole module, which is what
// makes read-detection exact) and everything else from compiler export data.
type combinedImporter struct {
	source map[string]*types.Package
	gc     types.Importer
}

func (c *combinedImporter) Import(path string) (*types.Package, error) {
	if pkg, ok := c.source[path]; ok {
		return pkg, nil
	}
	return c.gc.Import(path)
}

// Audit type-checks every first-party package in the module and reports the
// json-tagged fields of package opnsense that nothing reads.
//
// A field is a finding when all of: it is declared in package opnsense, it
// carries a json struct tag (so it is populated by unmarshalling a response),
// and no selector expression in any non-test file of the module reads it.
// Assignment targets are writes, not reads; test files are excluded on purpose,
// since a field only a decode assertion touches is still dead in production.
func Audit(moduleRoot string) ([]Finding, error) {
	_, findings, err := auditModule(moduleRoot)
	return findings, err
}

// auditModule returns every json-tagged field key declared in package opnsense
// alongside the dead subset, so tests can tell "not a finding" from "not a
// field" — a typo in an expected key would otherwise pass silently.
func auditModule(moduleRoot string) (map[string]bool, []Finding, error) {
	pkgs, err := listPackages(moduleRoot)
	if err != nil {
		return nil, nil, err
	}

	exportFile := map[string]string{}
	for _, p := range pkgs {
		if p.Export != "" {
			exportFile[p.ImportPath] = p.Export
		}
	}

	fset := token.NewFileSet()
	imp := &combinedImporter{
		source: map[string]*types.Package{},
		gc: importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
			file, ok := exportFile[path]
			if !ok || file == "" {
				return nil, fmt.Errorf("no export data for %q", path)
			}
			return os.Open(file) //nolint:gosec // path comes from `go list -export`
		}),
	}

	var decls map[*types.Var]fieldDecl
	reads := map[*types.Var]bool{}

	for _, p := range pkgs {
		if !isFirstParty(p.ImportPath) || len(p.GoFiles) == 0 {
			continue
		}
		files, info, checked, checkErr := checkPackage(fset, imp, p)
		if checkErr != nil {
			return nil, nil, checkErr
		}
		imp.source[p.ImportPath] = checked

		if p.ImportPath == opnsensePkg {
			decls = collectDecls(checked, fset, moduleRoot)
		}
		collectReads(files, info, reads)
	}

	if decls == nil {
		return nil, nil, fmt.Errorf("package %s was not type-checked", opnsensePkg)
	}

	all := make(map[string]bool, len(decls))
	var findings []Finding
	for obj, decl := range decls {
		all[decl.key] = true
		if reads[obj] {
			continue
		}
		findings = append(findings, Finding{Key: decl.key, JSONTag: decl.jsonTag, Pos: decl.pos})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Key < findings[j].Key })
	return all, findings, nil
}

func isFirstParty(importPath string) bool {
	const mod = "github.com/rknightion/opnsense2otel/v5"
	if strings.Contains(importPath, "/vendor/") {
		return false
	}
	return importPath == mod || strings.HasPrefix(importPath, mod+"/")
}

// checkPackage type-checks one package's non-test files from source.
func checkPackage(fset *token.FileSet, imp types.Importer, p listedPackage) ([]*ast.File, *types.Info, *types.Package, error) {
	var files []*ast.File
	for _, name := range p.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse %s: %w", name, err)
		}
		files = append(files, f)
	}
	info := &types.Info{
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Types:      map[ast.Expr]types.TypeAndValue{},
	}
	conf := types.Config{Importer: imp}
	pkg, err := conf.Check(p.ImportPath, fset, files, info)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("type-check %s: %w", p.ImportPath, err)
	}
	return files, info, pkg, nil
}

// collectDecls enumerates every json-tagged field declared in the package,
// recursing through anonymous nested structs (including through slice, array,
// pointer and map element types) so `Rows []struct{...}` shapes are covered.
// Fields of embedded named types are enumerated under their own type, not the
// embedding one, so a promoted-field read and its declaration agree.
func collectDecls(pkg *types.Package, fset *token.FileSet, moduleRoot string) map[*types.Var]fieldDecl {
	decls := map[*types.Var]fieldDecl{}
	scope := pkg.Scope()

	var walk func(typeName string, prefix []string, st *types.Struct)
	walk = func(typeName string, prefix []string, st *types.Struct) {
		for i := range st.NumFields() {
			f := st.Field(i)
			if f.Embedded() {
				continue
			}
			path := append(append([]string{}, prefix...), f.Name())
			if tag, ok := jsonTagName(st.Tag(i)); ok {
				pos := fset.Position(f.Pos())
				rel, err := filepath.Rel(moduleRoot, pos.Filename)
				if err != nil {
					rel = pos.Filename
				}
				decls[f] = fieldDecl{
					key:     fmt.Sprintf("%s.%s.%s", pkg.Name(), typeName, strings.Join(path, ".")),
					jsonTag: tag,
					pos:     fmt.Sprintf("%s:%d", rel, pos.Line),
				}
			}
			if inner := anonStruct(f.Type()); inner != nil {
				walk(typeName, path, inner)
			}
		}
	}

	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		if st, ok := named.Underlying().(*types.Struct); ok {
			walk(name, nil, st)
		}
	}
	return decls
}

// jsonTagName returns the payload key a struct tag decodes, and whether the
// field is decoded at all (`json:"-"` is not).
func jsonTagName(tag string) (string, bool) {
	value, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(value, ",")
	if name == "-" {
		return "", false
	}
	return name, true
}

// anonStruct unwraps pointer, slice, array and map-element types and returns the
// anonymous struct type underneath, if any. Named types are skipped: they are
// enumerated in their own right from the package scope.
func anonStruct(t types.Type) *types.Struct {
	for {
		switch typ := t.(type) {
		case *types.Pointer:
			t = typ.Elem()
		case *types.Slice:
			t = typ.Elem()
		case *types.Array:
			t = typ.Elem()
		case *types.Map:
			t = typ.Elem()
		case *types.Struct:
			return typ
		default:
			return nil
		}
	}
}

// markAllFields marks every field of a struct type, at any depth, as read. It is
// used for whole-struct conversions, where every field is carried across.
func markAllFields(t types.Type, reads map[*types.Var]bool, seen map[types.Type]bool) {
	if t == nil || seen[t] {
		return
	}
	seen[t] = true

	if ptr, ok := t.(*types.Pointer); ok {
		markAllFields(ptr.Elem(), reads, seen)
		return
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return
	}
	for i := range st.NumFields() {
		f := st.Field(i)
		reads[f] = true
		markAllFields(f.Type(), reads, seen)
		if inner := anonStruct(f.Type()); inner != nil {
			markAllFields(inner, reads, seen)
		}
	}
}

// collectReads marks every field object reached by a selector expression that is
// not a plain assignment target. Composite-literal field keys are not selector
// expressions, so struct construction never counts as a read; whole-struct
// copies do not either, which is the point — the field has to be reached by
// name somewhere for the data to have gone anywhere.
func collectReads(files []*ast.File, info *types.Info, reads map[*types.Var]bool) {
	for _, file := range files {
		writes := map[*ast.SelectorExpr]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			// Only a plain = or := stores without reading. A compound
			// assignment (+= and friends) reads the field first.
			if assign.Tok != token.ASSIGN && assign.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range assign.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					writes[sel] = true
				}
			}
			return true
		})

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if writes[node] {
					return true
				}
				selection, ok := info.Selections[node]
				if !ok || selection.Kind() != types.FieldVal {
					return true
				}
				if v, ok := selection.Obj().(*types.Var); ok {
					reads[v] = true
				}
			case *ast.CallExpr:
				// A whole-struct conversion — FirewallInterfaceHit(entry) —
				// carries every field into the target type, so the payload
				// dimension is not dropped here even though no field is named.
				// Conversions require identical underlying types, so the whole
				// tree comes across.
				if len(node.Args) != 1 {
					return true
				}
				if tv, ok := info.Types[node.Fun]; !ok || !tv.IsType() {
					return true
				}
				arg, ok := info.Types[node.Args[0]]
				if !ok {
					return true
				}
				markAllFields(arg.Type, reads, map[types.Type]bool{})
			}
			return true
		})
	}
}
