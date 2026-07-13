package opnsense

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Mismatch is a schema field observed with a conflicting JSON type — the
// breaking class of payload drift (the decode would fail or silently zero).
type Mismatch struct {
	Path     string
	Expected FieldKind
	Got      string
}

// ValidationResult is the structural comparison of one live response against
// an endpoint's schema. Missing and UnknownTopKeys are warning-level drift;
// Mismatches are breaking. Unverified paths sit under empty arrays/maps or
// nulls — box state, not drift.
type ValidationResult struct {
	Endpoint       string
	Missing        []string
	Mismatches     []Mismatch
	UnknownTopKeys []string
	Unverified     []string
}

// Clean reports whether the response matched the schema with no drift signals.
func (r ValidationResult) Clean() bool {
	return len(r.Missing) == 0 && len(r.Mismatches) == 0 && len(r.UnknownTopKeys) == 0
}

// SchemaExemption acknowledges known, deliberate divergence between one
// endpoint's schema and a live box: paths that are legitimately absent in some
// box states (MissingOK) and top-level keys the box serves that the exporter
// deliberately does not model (KnownExtraTopKeys). Lives in the committed
// opnsense/testdata/schemas/exemptions.json.
//
// A MissingOK entry is either an exact schema path ("memory.arc") or a subtree
// prefix ending in ".*" ("data.num.*"), which exempts the bare parent
// ("data.num") and every path beneath it. The prefix form keeps the ledger
// readable for endpoints whose legacy surface is a whole sub-object.
type SchemaExemption struct {
	MissingOK         []string `json:"missingOK,omitempty"`
	KnownExtraTopKeys []string `json:"knownExtraTopKeys,omitempty"`
	Note              string   `json:"note,omitempty"`
}

// missingOKSet is the compiled MissingOK list: exact paths plus subtree
// prefixes from ".*" entries.
type missingOKSet struct {
	exact    map[string]bool
	prefixes []string // each with its trailing dot, e.g. "data.num."
	parents  []string // the bare parent of each prefix, e.g. "data.num"
}

func compileMissingOK(entries []string) missingOKSet {
	s := missingOKSet{exact: make(map[string]bool, len(entries))}
	for _, p := range entries {
		if stem, ok := strings.CutSuffix(p, ".*"); ok && stem != "" {
			s.prefixes = append(s.prefixes, stem+".")
			s.parents = append(s.parents, stem)
			continue
		}
		s.exact[p] = true
	}
	return s
}

// has reports whether a schema path is exempt from Missing reporting. The
// prefix match is dot-anchored, so "data.num.*" covers "data.num.query.tcp"
// but never the sibling section "data.numx.foo".
func (s missingOKSet) has(path string) bool {
	if s.exact[path] {
		return true
	}
	for i, prefix := range s.prefixes {
		if path == s.parents[i] || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// bootgridEnvelopeKeys are the standard OPNsense search-envelope keys. Any
// schema that models a "rows" top-level key gets these implicitly — the
// exporter often decodes only rows/total, and the envelope keys are part of
// the bootgrid protocol, not drift.
var bootgridEnvelopeKeys = []string{"total", "rowCount", "current", "searchPhrase"}

// ValidateResponseSchema checks a raw JSON response against a structure-only
// schema. The exemption suppresses Missing reports for known-optional paths
// and UnknownTopKeys reports for acknowledged unmodeled keys.
func ValidateResponseSchema(s EndpointSchema, raw []byte, ex SchemaExemption) (ValidationResult, error) {
	missingOK := compileMissingOK(ex.MissingOK)
	res := ValidationResult{Endpoint: s.Endpoint}

	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return res, fmt.Errorf("response is not valid JSON: %w", err)
	}

	// Top-level kind gate: a container-type flip is breaking on its own, and
	// deeper traversal would be meaningless.
	if got := jsonKindName(root); !kindMatches(s.TopLevelKind, root) {
		res.Mismatches = append(res.Mismatches, Mismatch{Path: "", Expected: s.TopLevelKind, Got: got})
		return res, nil
	}

	if len(s.KnownTopLevelKeys) > 0 {
		if obj, ok := root.(map[string]any); ok {
			known := make(map[string]bool, len(s.KnownTopLevelKeys))
			hasRows := false
			for _, k := range s.KnownTopLevelKeys {
				known[strings.ToLower(k)] = true
				if k == "rows" {
					hasRows = true
				}
			}
			if hasRows {
				for _, k := range bootgridEnvelopeKeys {
					known[strings.ToLower(k)] = true
				}
			}
			for _, k := range ex.KnownExtraTopKeys {
				known[strings.ToLower(k)] = true
			}
			for k := range obj {
				if !known[strings.ToLower(k)] {
					res.UnknownTopKeys = append(res.UnknownTopKeys, k)
				}
			}
			sort.Strings(res.UnknownTopKeys)
		}
	}

	for _, f := range s.Fields {
		evaluateFieldPath(f, root, missingOK, &res)
	}
	return res, nil
}

// evaluateFieldPath resolves one schema path against the decoded response and
// files it into exactly one bucket: present (kind-checked), Missing,
// Unverified, or silently skipped when an ancestor path is already Missing.
func evaluateFieldPath(f SchemaField, root any, missingOK missingOKSet, res *ValidationResult) {
	segs := splitSchemaPath(f.Path)
	cur := []any{root}
	unverifiable := false // hit a null / empty container / PHP-empty-[] on the way
	absentFinal := 0      // parents that could hold the final key but do not

	for i, seg := range segs {
		last := i == len(segs)-1
		var next []any
		for _, v := range cur {
			if v == nil {
				unverifiable = true
				continue
			}
			switch seg {
			case "[]":
				arr, ok := v.([]any)
				if !ok {
					unverifiable = true // parent path reports the kind conflict
					continue
				}
				if len(arr) == 0 {
					unverifiable = true
					continue
				}
				next = append(next, arr...)
			case "*":
				obj, ok := v.(map[string]any)
				if !ok {
					unverifiable = true // incl. the PHP []-for-empty-object quirk
					continue
				}
				if len(obj) == 0 {
					unverifiable = true
					continue
				}
				keys := make([]string, 0, len(obj))
				for k := range obj {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					next = append(next, obj[k])
				}
			default:
				obj, ok := v.(map[string]any)
				if !ok {
					unverifiable = true // incl. the PHP []-for-empty-object quirk
					continue
				}
				child, present := lookupKey(obj, seg)
				if !present {
					if last {
						absentFinal++
					}
					continue
				}
				next = append(next, child)
			}
		}
		cur = next
	}

	// Split final instances into real values and nulls (null = unverifiable).
	real := cur[:0:0]
	for _, v := range cur {
		if v == nil {
			unverifiable = true
			continue
		}
		real = append(real, v)
	}

	switch {
	case len(real) > 0:
		for _, v := range real {
			if isPHPEmptyObject(f.Kind, v) {
				// [] served where an object lives when populated — empty, not drift.
				res.Unverified = append(res.Unverified, f.Path)
				return
			}
			if !kindMatches(f.Kind, v) {
				res.Mismatches = append(res.Mismatches, Mismatch{Path: f.Path, Expected: f.Kind, Got: jsonKindName(v)})
				return
			}
		}
	case absentFinal > 0 && !unverifiable:
		if !missingOK.has(f.Path) {
			res.Missing = append(res.Missing, f.Path)
		}
	case unverifiable:
		res.Unverified = append(res.Unverified, f.Path)
		// else: an ancestor schema path is Missing and reports the drift itself.
	}
}

// lookupKey resolves a JSON object key the way encoding/json does: an exact
// match wins, otherwise a case-insensitive match is accepted.
func lookupKey(obj map[string]any, key string) (any, bool) {
	if v, ok := obj[key]; ok {
		return v, true
	}
	for k, v := range obj {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// splitSchemaPath tokenizes "rows[].name" → ["rows","[]","name"] and
// "byName.*.tags[]" → ["byName","*","tags","[]"].
func splitSchemaPath(path string) []string {
	var segs []string
	for _, part := range strings.Split(path, ".") {
		base := part
		var arrays int
		for strings.HasSuffix(base, "[]") {
			base = strings.TrimSuffix(base, "[]")
			arrays++
		}
		if base != "" {
			segs = append(segs, base)
		}
		for j := 0; j < arrays; j++ {
			segs = append(segs, "[]")
		}
	}
	return segs
}

// isPHPEmptyObject reports the OPNsense PHP quirk: an empty JSON array served
// where the schema expects an object.
func isPHPEmptyObject(expected FieldKind, v any) bool {
	if expected != KindObject {
		return false
	}
	arr, ok := v.([]any)
	return ok && len(arr) == 0
}

// kindMatches reports whether a decoded JSON value satisfies a FieldKind.
func kindMatches(k FieldKind, v any) bool {
	switch k {
	case KindAny:
		return true
	case KindNumeric:
		// json.Number decodes from a JSON number or a numeric string.
		switch t := v.(type) {
		case float64, json.Number:
			return true
		case string:
			_, err := strconv.ParseFloat(t, 64)
			return err == nil
		default:
			return false
		}
	default:
		return jsonKindName(v) == string(kindToJSONName(k))
	}
}

// jsonKindName names the JSON type of a decoded value (encoding/json mapping).
func jsonKindName(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case float64, json.Number:
		return "number"
	case bool:
		return "boolean"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

// kindToJSONName maps a FieldKind to the jsonKindName vocabulary.
func kindToJSONName(k FieldKind) FieldKind {
	return k // FieldKind constants already use the JSON type names
}
