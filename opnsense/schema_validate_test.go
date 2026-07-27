package opnsense

import (
	"reflect"
	"strings"
	"testing"
)

// validateFixtureSchema mirrors a typical search-envelope endpoint.
func validateFixtureSchema() EndpointSchema {
	return EndpointSchema{
		Endpoint:          "fixture",
		Method:            "GET",
		Path:              "api/fixture/test/get",
		TopLevelKind:      KindObject,
		KnownTopLevelKeys: []string{"details", "rows", "status", "total"},
		Fields: []SchemaField{
			{Path: "details", Kind: KindObject},
			{Path: "details.uptime", Kind: KindNumber},
			{Path: "rows", Kind: KindArray},
			{Path: "rows[]", Kind: KindObject},
			{Path: "rows[].flex", Kind: KindAny},
			{Path: "rows[].name", Kind: KindString},
			{Path: "rows[].size", Kind: KindNumber},
			{Path: "status", Kind: KindString},
			{Path: "total", Kind: KindNumber},
		},
	}
}

func TestValidateResponseSchema(t *testing.T) {
	cases := []struct {
		name           string
		raw            string
		exemption      SchemaExemption
		wantMissing    []string
		wantMismatches []Mismatch
		wantUnknownTop []string
		wantUnverified []string
	}{
		{
			name: "clean pass",
			raw:  `{"status":"ok","total":2,"details":{"uptime":41},"rows":[{"name":"a","size":1,"flex":[]},{"name":"b","size":2,"flex":"x"}]}`,
		},
		{
			name:           "retyped field is a mismatch",
			raw:            `{"status":7,"total":2,"details":{"uptime":41},"rows":[{"name":"a","size":1,"flex":1}]}`,
			wantMismatches: []Mismatch{{Path: "status", Expected: KindString, Got: "number"}},
		},
		{
			name:        "renamed field is missing",
			raw:         `{"status":"ok","total":1,"details":{"uptime":41},"rows":[{"label":"a","size":1,"flex":1}]}`,
			wantMissing: []string{"rows[].name"},
		},
		{
			name:           "new top-level key is reported",
			raw:            `{"status":"ok","total":0,"details":{"uptime":41},"rows":[],"subsystems":{}}`,
			wantUnknownTop: []string{"subsystems"},
			wantUnverified: []string{"rows[]", "rows[].flex", "rows[].name", "rows[].size"},
		},
		{
			name:           "empty rows array leaves children unverified",
			raw:            `{"status":"ok","total":0,"details":{"uptime":41},"rows":[]}`,
			wantUnverified: []string{"rows[]", "rows[].flex", "rows[].name", "rows[].size"},
		},
		{
			name:           "null field is unverified not missing",
			raw:            `{"status":null,"total":1,"details":{"uptime":41},"rows":[{"name":"a","size":1,"flex":1}]}`,
			wantUnverified: []string{"status"},
		},
		{
			name: "php empty-array quirk where object expected is unverified",
			raw:  `{"status":"ok","total":0,"details":[],"rows":[{"name":"a","size":1,"flex":1}]}`,
			wantUnverified: []string{
				"details", "details.uptime",
			},
		},
		{
			name:        "missingOK suppresses a missing path",
			raw:         `{"status":"ok","total":1,"details":{"uptime":41},"rows":[{"name":"a","flex":1}]}`,
			exemption:   SchemaExemption{MissingOK: []string{"rows[].size"}},
			wantMissing: nil,
		},
		{
			name:        "field present on one instance is not missing",
			raw:         `{"status":"ok","total":2,"details":{"uptime":41},"rows":[{"name":"a","flex":1},{"name":"b","size":9,"flex":1}]}`,
			wantMissing: nil,
		},
		{
			// encoding/json matches keys case-insensitively, so the validator must too.
			name: "case-insensitive key match like encoding/json",
			raw:  `{"Status":"ok","Total":2,"Details":{"Uptime":41},"Rows":[{"Name":"a","Size":1,"Flex":1}]}`,
		},
		{
			// Bootgrid envelope keys are protocol, not drift, on any rows schema.
			name: "bootgrid envelope keys are implicitly known",
			raw:  `{"status":"ok","total":1,"rowCount":1,"current":1,"searchPhrase":"","details":{"uptime":41},"rows":[{"name":"a","size":1,"flex":1}]}`,
		},
		{
			name:           "knownExtraTopKeys suppresses an acknowledged key",
			raw:            `{"status":"ok","total":1,"details":{"uptime":41},"rows":[{"name":"a","size":1,"flex":1}],"widget":{},"other":1}`,
			exemption:      SchemaExemption{KnownExtraTopKeys: []string{"widget"}},
			wantUnknownTop: []string{"other"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ValidateResponseSchema(validateFixtureSchema(), []byte(tc.raw), tc.exemption)
			if err != nil {
				t.Fatalf("ValidateResponseSchema: %v", err)
			}
			if !reflect.DeepEqual(res.Missing, tc.wantMissing) {
				t.Errorf("Missing = %v, want %v", res.Missing, tc.wantMissing)
			}
			if !reflect.DeepEqual(res.Mismatches, tc.wantMismatches) {
				t.Errorf("Mismatches = %v, want %v", res.Mismatches, tc.wantMismatches)
			}
			if !reflect.DeepEqual(res.UnknownTopKeys, tc.wantUnknownTop) {
				t.Errorf("UnknownTopKeys = %v, want %v", res.UnknownTopKeys, tc.wantUnknownTop)
			}
			if !reflect.DeepEqual(res.Unverified, tc.wantUnverified) {
				t.Errorf("Unverified = %v, want %v", res.Unverified, tc.wantUnverified)
			}
		})
	}
}

// prefixFixtureSchema exercises the missingOK prefix form: a schema with a
// legacy sub-object (data.num) and a same-stem sibling (data.numx) that a
// prefix exemption must NOT swallow.
func prefixFixtureSchema() EndpointSchema {
	return EndpointSchema{
		Endpoint:          "prefix",
		TopLevelKind:      KindObject,
		KnownTopLevelKeys: []string{"data", "other"},
		Fields: []SchemaField{
			{Path: "data", Kind: KindObject},
			{Path: "data.num", Kind: KindObject},
			{Path: "data.num.answer", Kind: KindNumber},
			{Path: "data.num.query", Kind: KindObject},
			{Path: "data.num.query.tcp", Kind: KindNumber},
			{Path: "data.numx", Kind: KindObject},
			{Path: "data.numx.foo", Kind: KindNumber},
			{Path: "other", Kind: KindString},
		},
	}
}

// A missingOK entry ending in ".*" exempts the whole sub-tree under its prefix
// (and the bare parent), so an endpoint with dozens of legacy siblings needs
// one entry rather than dozens. Exact entries keep their exact semantics.
func TestValidateResponseSchemaMissingOKPrefix(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		exemption   SchemaExemption
		wantMissing []string
	}{
		{
			name:        "no exemption reports every legacy path",
			raw:         `{"data":{"num":{"query":{}},"numx":{}},"other":"x"}`,
			wantMissing: []string{"data.num.answer", "data.num.query.tcp", "data.numx.foo"},
		},
		{
			name:        "prefix exempts nested paths under it",
			raw:         `{"data":{"num":{"query":{}},"numx":{"foo":1}},"other":"x"}`,
			exemption:   SchemaExemption{MissingOK: []string{"data.num.*"}},
			wantMissing: nil,
		},
		{
			name:        "prefix does not exempt a same-stem sibling section",
			raw:         `{"data":{"num":{"query":{}},"numx":{}},"other":"x"}`,
			exemption:   SchemaExemption{MissingOK: []string{"data.num.*"}},
			wantMissing: []string{"data.numx.foo"},
		},
		{
			name:        "prefix exempts the bare parent path too",
			raw:         `{"data":{"numx":{"foo":1}},"other":"x"}`,
			exemption:   SchemaExemption{MissingOK: []string{"data.num.*"}},
			wantMissing: nil,
		},
		{
			name:        "exact entries are unaffected by prefix support",
			raw:         `{"data":{"num":{"query":{}},"numx":{}},"other":"x"}`,
			exemption:   SchemaExemption{MissingOK: []string{"data.num.answer", "data.numx.foo"}},
			wantMissing: []string{"data.num.query.tcp"},
		},
		{
			name:        "exact and prefix entries compose",
			raw:         `{"data":{"num":{"query":{}},"numx":{}},"other":"x"}`,
			exemption:   SchemaExemption{MissingOK: []string{"data.num.*", "data.numx.foo"}},
			wantMissing: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ValidateResponseSchema(prefixFixtureSchema(), []byte(tc.raw), tc.exemption)
			if err != nil {
				t.Fatalf("ValidateResponseSchema: %v", err)
			}
			if !reflect.DeepEqual(res.Missing, tc.wantMissing) {
				t.Errorf("Missing = %v, want %v", res.Missing, tc.wantMissing)
			}
		})
	}
}

// json.Number fields (KindNumeric) accept a JSON number or a numeric string —
// OPNsense flips between them across releases (26.7 retyped many counters).
func TestValidateResponseSchemaNumericKind(t *testing.T) {
	s := EndpointSchema{
		Endpoint:          "num",
		TopLevelKind:      KindObject,
		KnownTopLevelKeys: []string{"count"},
		Fields:            []SchemaField{{Path: "count", Kind: KindNumeric}},
	}
	for _, raw := range []string{`{"count":5}`, `{"count":"5"}`, `{"count":"5.5"}`} {
		res, err := ValidateResponseSchema(s, []byte(raw), SchemaExemption{})
		if err != nil {
			t.Fatalf("ValidateResponseSchema(%s): %v", raw, err)
		}
		if len(res.Mismatches) != 0 {
			t.Errorf("numeric kind rejected %s: %+v", raw, res.Mismatches)
		}
	}
	res, err := ValidateResponseSchema(s, []byte(`{"count":"abc"}`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	if len(res.Mismatches) != 1 {
		t.Errorf("numeric kind accepted a non-numeric string: %+v", res)
	}
}

// A top-level kind conflict (object expected, array served) is breaking drift.
func TestValidateResponseSchemaTopLevelMismatch(t *testing.T) {
	res, err := ValidateResponseSchema(validateFixtureSchema(), []byte(`[1,2,3]`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	want := []Mismatch{{Path: "", Expected: KindObject, Got: "array"}}
	if !reflect.DeepEqual(res.Mismatches, want) {
		t.Errorf("Mismatches = %v, want %v", res.Mismatches, want)
	}
}

// Dynamic top-level keys (map schema): no KnownTopLevelKeys check, wildcard
// paths traverse every value.
func TestValidateResponseSchemaDynamicTopLevel(t *testing.T) {
	s := EndpointSchema{
		Endpoint:     "dyn",
		TopLevelKind: KindObject,
		Fields: []SchemaField{
			{Path: "*", Kind: KindObject},
			{Path: "*.status", Kind: KindString},
		},
	}
	res, err := ValidateResponseSchema(s, []byte(`{"wg0":{"status":"up"},"wg1":{"status":"down"},"extra":{"status":"up"}}`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	if len(res.Missing)+len(res.Mismatches)+len(res.UnknownTopKeys) != 0 {
		t.Errorf("dynamic top level should be clean, got %+v", res)
	}
	// A retype inside one map value must still be caught.
	res, err = ValidateResponseSchema(s, []byte(`{"wg0":{"status":5}}`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	want := []Mismatch{{Path: "*.status", Expected: KindString, Got: "number"}}
	if !reflect.DeepEqual(res.Mismatches, want) {
		t.Errorf("Mismatches = %v, want %v", res.Mismatches, want)
	}
}

// nestedFixtureSchema exercises the reverse traversal (#376): a static
// sub-object, an object inside an array, a dynamic-key map, a KindAny subtree
// and a childless object node (a struct the exporter models as an opaque
// container).
func nestedFixtureSchema() EndpointSchema {
	return EndpointSchema{
		Endpoint:          "nested",
		TopLevelKind:      KindObject,
		KnownTopLevelKeys: []string{"byName", "details", "opaque", "rows", "sealed"},
		Fields: []SchemaField{
			{Path: "byName", Kind: KindObject},
			{Path: "byName.*", Kind: KindObject},
			{Path: "byName.*.state", Kind: KindString},
			{Path: "details", Kind: KindObject},
			{Path: "details.uptime", Kind: KindNumber},
			{Path: "opaque", Kind: KindAny},
			{Path: "rows", Kind: KindArray},
			{Path: "rows[]", Kind: KindObject},
			{Path: "rows[].name", Kind: KindString},
			{Path: "sealed", Kind: KindObject},
		},
	}
}

// Unexpected keys BELOW the root are reported as normalized paths. Array
// elements collapse to "[]" and dynamic map identities to "*", so the report
// can never echo a hostname, peer identity or interface name.
func TestValidateResponseSchemaUnknownNestedPaths(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		exemption SchemaExemption
		wantPaths []string
		wantTop   []string
	}{
		{
			name: "clean nested payload",
			raw:  `{"details":{"uptime":1},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":{"anything":1},"sealed":{}}`,
		},
		{
			name:      "extra key in a nested object",
			raw:       `{"details":{"uptime":1,"newkey":2},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			wantPaths: []string{"details.newkey"},
		},
		{
			name:      "extra key inside an object in an array",
			raw:       `{"details":{"uptime":1},"rows":[{"name":"a","new_health":"ok"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			wantPaths: []string{"rows[].new_health"},
		},
		{
			// Two elements carrying the same new key are ONE finding.
			name:      "duplicate extra keys across array elements collapse",
			raw:       `{"details":{"uptime":1},"rows":[{"name":"a","new_health":1},{"name":"b","new_health":2}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			wantPaths: []string{"rows[].new_health"},
		},
		{
			// Arbitrary map identities are accepted; a new static field inside a
			// map value is reported under "*", never under the real identity.
			name:      "extra static field inside a dynamic map value",
			raw:       `{"details":{"uptime":1},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up","newfield":1},"peer.example.internal":{"state":"up","newfield":2}},"opaque":1,"sealed":{}}`,
			wantPaths: []string{"byName.*.newfield"},
		},
		{
			// KindAny covers interface{}, custom json.Unmarshalers and
			// json.RawMessage: the exporter decodes them leniently, so anything
			// underneath is by definition not drift.
			name: "KindAny subtree makes no noise",
			raw:  `{"details":{"uptime":1},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":{"deep":{"deeper":1}},"sealed":{}}`,
		},
		{
			// A modeled object with no modeled children is an opaque container,
			// not a schema that knows every key.
			name: "childless object node makes no noise",
			raw:  `{"details":{"uptime":1},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{"whatever":1}}`,
		},
		{
			name: "case-insensitive match like encoding/json",
			raw:  `{"Details":{"Uptime":1},"Rows":[{"Name":"a"}],"ByName":{"wg0":{"State":"up"}},"opaque":1,"sealed":{}}`,
		},
		{
			// Root extras keep going to UnknownTopKeys alone — the existing
			// bootgrid-envelope handling and knownExtraTopKeys ledger own depth 0.
			name:      "root extras stay top-level only",
			raw:       `{"details":{"uptime":1},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{},"brandnew":{"inner":1}}`,
			wantTop:   []string{"brandnew"},
			wantPaths: nil,
		},
		{
			name:      "knownExtraPaths exempts an exact path",
			raw:       `{"details":{"uptime":1,"newkey":2},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			exemption: SchemaExemption{KnownExtraPaths: []string{"details.newkey"}},
		},
		{
			name:      "knownExtraPaths subtree form exempts a whole branch",
			raw:       `{"details":{"uptime":1,"a":1,"b":2},"rows":[{"name":"a"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			exemption: SchemaExemption{KnownExtraPaths: []string{"details.*"}},
		},
		{
			name:      "subtree exemption does not swallow a sibling section",
			raw:       `{"details":{"uptime":1,"a":1},"rows":[{"name":"a","extra":1}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			exemption: SchemaExemption{KnownExtraPaths: []string{"details.*"}},
			wantPaths: []string{"rows[].extra"},
		},
		{
			name:      "several findings are sorted",
			raw:       `{"details":{"uptime":1,"zz":1},"rows":[{"name":"a","aa":1}],"byName":{"wg0":{"state":"up","mm":1}},"opaque":1,"sealed":{}}`,
			wantPaths: []string{"byName.*.mm", "details.zz", "rows[].aa"},
		},
		{
			// OPNsense's bootgrid UI convention emits a "%"-prefixed formatted
			// twin alongside almost every raw row field (#457). The twin is
			// protocol noise, not a second piece of information, so it is
			// suppressed structurally rather than requiring its own
			// knownExtraPaths entry — here the raw field ("aa") is itself
			// unmodeled and still reports; only the "%aa" twin is dropped.
			name:      "percent-prefixed twin of an unmodeled field is suppressed",
			raw:       `{"details":{"uptime":1},"rows":[{"name":"a","aa":1,"%aa":"1"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
			wantPaths: []string{"rows[].aa"},
		},
		{
			// Same suppression when the raw field IS modeled — the twin still
			// carries no new information and must not surface on its own.
			name: "percent-prefixed twin of a modeled field is suppressed",
			raw:  `{"details":{"uptime":1},"rows":[{"name":"a","%name":"A"}],"byName":{"wg0":{"state":"up"}},"opaque":1,"sealed":{}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ValidateResponseSchema(nestedFixtureSchema(), []byte(tc.raw), tc.exemption)
			if err != nil {
				t.Fatalf("ValidateResponseSchema: %v", err)
			}
			if !reflect.DeepEqual(res.UnknownPaths, tc.wantPaths) {
				t.Errorf("UnknownPaths = %v, want %v", res.UnknownPaths, tc.wantPaths)
			}
			if !reflect.DeepEqual(res.UnknownTopKeys, tc.wantTop) {
				t.Errorf("UnknownTopKeys = %v, want %v", res.UnknownTopKeys, tc.wantTop)
			}
			for _, p := range res.UnknownPaths {
				if strings.Contains(p, "wg0") || strings.Contains(p, "example.internal") {
					t.Errorf("UnknownPaths leaked a dynamic-map identity: %q", p)
				}
			}
		})
	}
}

// A reported path must be CANONICAL — spelled the way the schema spells its
// known segments — even when the box serves a different case. encoding/json (and
// therefore this validator) matches keys case-insensitively, so OPNsense's real
// healthCheck payload reaches the struct's `metadata.System` block through a
// lowercase `system` key. Reporting the live casing would give the same drift two
// different spellings, and a knownExtraPaths entry only ever matches one of them.
func TestValidateResponseSchemaUnknownNestedPathsCanonicalCasing(t *testing.T) {
	s := EndpointSchema{
		Endpoint:          "health",
		TopLevelKind:      KindObject,
		KnownTopLevelKeys: []string{"metadata"},
		Fields: []SchemaField{
			{Path: "metadata", Kind: KindObject},
			{Path: "metadata.System", Kind: KindObject},
			{Path: "metadata.System.status", Kind: KindAny},
		},
	}
	res, err := ValidateResponseSchema(s, []byte(`{"metadata":{"system":{"status":2,"title":"x","message":"y"}}}`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	want := []string{"metadata.System.message", "metadata.System.title"}
	if !reflect.DeepEqual(res.UnknownPaths, want) {
		t.Errorf("UnknownPaths = %v, want %v", res.UnknownPaths, want)
	}
	// And the exemption written in the schema's casing must suppress it.
	res, err = ValidateResponseSchema(s, []byte(`{"metadata":{"system":{"status":2,"title":"x","message":"y"}}}`),
		SchemaExemption{KnownExtraPaths: []string{"metadata.System.*"}})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	if len(res.UnknownPaths) != 0 {
		t.Errorf("UnknownPaths = %v, want none", res.UnknownPaths)
	}
}

// A nested extra key is drift signal, so it must make the result unclean.
func TestValidationResultCleanIncludesUnknownPaths(t *testing.T) {
	if (ValidationResult{UnknownPaths: []string{"rows[].x"}}).Clean() {
		t.Error("a result with UnknownPaths must not be Clean")
	}
	if !(ValidationResult{Unverified: []string{"rows[].x"}}).Clean() {
		t.Error("Unverified alone must stay Clean (box state, not drift)")
	}
}

// A top-level ARRAY response still gets nested extras: the root is "[]".
func TestValidateResponseSchemaUnknownNestedPathsArrayRoot(t *testing.T) {
	s := EndpointSchema{
		Endpoint:     "arr",
		TopLevelKind: KindArray,
		Fields: []SchemaField{
			{Path: "[]", Kind: KindObject},
			{Path: "[].device", Kind: KindString},
		},
	}
	res, err := ValidateResponseSchema(s, []byte(`[{"device":"cpu0","new_reading":1}]`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	if want := []string{"[].new_reading"}; !reflect.DeepEqual(res.UnknownPaths, want) {
		t.Errorf("UnknownPaths = %v, want %v", res.UnknownPaths, want)
	}
}

// A dynamic top-level map has no fixed key set, so every root key is an
// identity: extras can only be reported one level down, normalized to "*".
func TestValidateResponseSchemaUnknownNestedPathsDynamicRoot(t *testing.T) {
	s := EndpointSchema{
		Endpoint:     "dyn",
		TopLevelKind: KindObject,
		Fields: []SchemaField{
			{Path: "*", Kind: KindObject},
			{Path: "*.status", Kind: KindString},
		},
	}
	res, err := ValidateResponseSchema(s, []byte(`{"wg0":{"status":"up","newfield":1}}`), SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	if want := []string{"*.newfield"}; !reflect.DeepEqual(res.UnknownPaths, want) {
		t.Errorf("UnknownPaths = %v, want %v", res.UnknownPaths, want)
	}
	if len(res.UnknownTopKeys) != 0 {
		t.Errorf("UnknownTopKeys = %v, want none on a dynamic root", res.UnknownTopKeys)
	}
}

// Non-JSON or truncated bodies must error rather than pass silently.
func TestValidateResponseSchemaBadJSON(t *testing.T) {
	if _, err := ValidateResponseSchema(validateFixtureSchema(), []byte(`<html>`), SchemaExemption{}); err == nil {
		t.Fatal("expected an error for a non-JSON body")
	}
}

// #459: before the envelope-descent registry entry, quaggaOspfv3Interface's
// derived schema modelled the WHOLE response as a single KindAny field, so
// ValidateResponseSchema accepted literally any payload there — exactly why
// OSPFv3's absent "type" key (#458) went unnoticed until the testbed had a
// real adjacency. Now that the schema reflects through the envelope, an inner
// field that changes JSON type (a live box serving "cost" as a string instead
// of a number, say) must surface as a Mismatch — the breaking class of drift —
// not silently pass.
func TestValidateResponseSchemaOSPFv3InnerFieldTypeConflict(t *testing.T) {
	schemas, err := AllEndpointSchemas()
	if err != nil {
		t.Fatalf("AllEndpointSchemas: %v", err)
	}
	var s EndpointSchema
	found := false
	for _, sc := range schemas {
		if sc.Endpoint == "quaggaOspfv3Interface" {
			s = sc
			found = true
			break
		}
	}
	if !found {
		t.Fatal("quaggaOspfv3Interface schema not found")
	}

	// A healthy live payload: cost is a JSON number.
	healthy := []byte(`{"response":{"eth1":{"status":"up","cost":10,"ospf6InterfaceState":"BDR","pendingLsaLsUpdateCount":0,"pendingLsaLsAckCount":0}}}`)
	res, err := ValidateResponseSchema(s, healthy, SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema (healthy): %v", err)
	}
	for _, m := range res.Mismatches {
		if m.Path == "response.*.cost" {
			t.Errorf("unexpected Mismatch on a healthy payload: %+v", m)
		}
	}

	// Drift: cost arrives as a string. Before #459 this was invisible — the
	// whole "response" value was KindAny — so this assertion is the one that
	// proves the reflector actually stops being blind.
	drifted := []byte(`{"response":{"eth1":{"status":"up","cost":"ten","ospf6InterfaceState":"BDR","pendingLsaLsUpdateCount":0,"pendingLsaLsAckCount":0}}}`)
	res, err = ValidateResponseSchema(s, drifted, SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema (drifted): %v", err)
	}
	wantMismatch := Mismatch{Path: "response.*.cost", Expected: KindNumber, Got: "string"}
	foundMismatch := false
	for _, m := range res.Mismatches {
		if m == wantMismatch {
			foundMismatch = true
		}
	}
	if !foundMismatch {
		t.Errorf("Mismatches = %v, want to contain %+v", res.Mismatches, wantMismatch)
	}
}
