package opnsense

import (
	"encoding/json"
	"fmt"
	"sort"
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

// ValidateResponseSchema checks a raw JSON response against a structure-only
// schema. missingOK suppresses Missing reports for known-optional paths.
func ValidateResponseSchema(s EndpointSchema, raw []byte, missingOK map[string]bool) (ValidationResult, error) {
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
			for _, k := range s.KnownTopLevelKeys {
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
func evaluateFieldPath(f SchemaField, root any, missingOK map[string]bool, res *ValidationResult) {
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
				child, present := obj[seg]
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
		if !missingOK[f.Path] {
			res.Missing = append(res.Missing, f.Path)
		}
	case unverifiable:
		res.Unverified = append(res.Unverified, f.Path)
		// else: an ancestor schema path is Missing and reports the drift itself.
	}
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
	if k == KindAny {
		return true
	}
	return jsonKindName(v) == string(kindToJSONName(k))
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
