package opnsense

import (
	"reflect"
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

// Non-JSON or truncated bodies must error rather than pass silently.
func TestValidateResponseSchemaBadJSON(t *testing.T) {
	if _, err := ValidateResponseSchema(validateFixtureSchema(), []byte(`<html>`), SchemaExemption{}); err == nil {
		t.Fatal("expected an error for a non-JSON body")
	}
}
