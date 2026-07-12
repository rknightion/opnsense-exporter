package opnsense

import (
	"reflect"
	"testing"
)

// walkerFixtureEmbedded is flattened into its parent by the walker.
type walkerFixtureEmbedded struct {
	Inherited string `json:"inherited"`
}

type walkerFixtureRow struct {
	Name    string   `json:"name"`
	Bytes   int64    `json:"bytes"`
	Ratio   float64  `json:"ratio"`
	Enabled bool     `json:"enabled"`
	Tags    []string `json:"tags"`
	Skipped string   `json:"-"`
}

type walkerFixtureTop struct {
	walkerFixtureEmbedded
	Total    int                         `json:"total"`
	Rows     []walkerFixtureRow          `json:"rows"`
	Status   flexString                  `json:"status"`
	ByName   map[string]walkerFixtureRow `json:"byName"`
	Anything interface{}                 `json:"anything"`
	Pointer  *walkerFixtureRow           `json:"pointer"`
	NoTag    string
	Raw      []byte `json:"raw"`
}

func TestSchemaForType(t *testing.T) {
	kind, fields := schemaForType(reflect.TypeOf(walkerFixtureTop{}))
	if kind != KindObject {
		t.Fatalf("top-level kind = %q, want %q", kind, KindObject)
	}

	want := []SchemaField{
		{Path: "NoTag", Kind: KindString},
		{Path: "anything", Kind: KindAny},
		{Path: "byName", Kind: KindObject},
		{Path: "byName.*", Kind: KindObject},
		{Path: "byName.*.bytes", Kind: KindNumber},
		{Path: "byName.*.enabled", Kind: KindBool},
		{Path: "byName.*.name", Kind: KindString},
		{Path: "byName.*.ratio", Kind: KindNumber},
		{Path: "byName.*.tags", Kind: KindArray},
		{Path: "byName.*.tags[]", Kind: KindString},
		{Path: "inherited", Kind: KindString},
		{Path: "pointer", Kind: KindObject},
		{Path: "pointer.bytes", Kind: KindNumber},
		{Path: "pointer.enabled", Kind: KindBool},
		{Path: "pointer.name", Kind: KindString},
		{Path: "pointer.ratio", Kind: KindNumber},
		{Path: "pointer.tags", Kind: KindArray},
		{Path: "pointer.tags[]", Kind: KindString},
		{Path: "raw", Kind: KindString},
		{Path: "rows", Kind: KindArray},
		{Path: "rows[]", Kind: KindObject},
		{Path: "rows[].bytes", Kind: KindNumber},
		{Path: "rows[].enabled", Kind: KindBool},
		{Path: "rows[].name", Kind: KindString},
		{Path: "rows[].ratio", Kind: KindNumber},
		{Path: "rows[].tags", Kind: KindArray},
		{Path: "rows[].tags[]", Kind: KindString},
		{Path: "status", Kind: KindAny},
		{Path: "total", Kind: KindNumber},
	}
	if !reflect.DeepEqual(fields, want) {
		t.Errorf("schemaForType fields mismatch:\n got: %v\nwant: %v", fields, want)
	}
}

// A map at the top level means dynamic keys: kind object, value schema under "*".
func TestSchemaForTypeTopLevelMap(t *testing.T) {
	kind, fields := schemaForType(reflect.TypeOf(map[string]walkerFixtureEmbedded{}))
	if kind != KindObject {
		t.Fatalf("top-level kind = %q, want %q", kind, KindObject)
	}
	want := []SchemaField{
		{Path: "*", Kind: KindObject},
		{Path: "*.inherited", Kind: KindString},
	}
	if !reflect.DeepEqual(fields, want) {
		t.Errorf("top-level map fields mismatch:\n got: %v\nwant: %v", fields, want)
	}
}

// Every manifest endpoint must have a schema registry entry or an explicit
// exemption — never both, never neither.
func TestSchemaRegistryComplete(t *testing.T) {
	endpoints := defaultEndpoints()
	for name := range endpoints {
		_, registered := schemaRegistry[name]
		_, exempt := schemaExemptEndpoints[name]
		switch {
		case registered && exempt:
			t.Errorf("endpoint %q is both registered and exempt", name)
		case !registered && !exempt:
			t.Errorf("endpoint %q has neither a schema registry entry nor an exemption", name)
		}
	}
	for name := range schemaRegistry {
		if _, ok := endpoints[name]; !ok {
			t.Errorf("schema registry entry %q is not a manifest endpoint", name)
		}
	}
	for name := range schemaExemptEndpoints {
		if _, ok := endpoints[name]; !ok {
			t.Errorf("schema exemption %q is not a manifest endpoint", name)
		}
	}

	// The four endpoints exempt from the endpoint-manifest canary get their
	// ONLY automated coverage from this schema canary (#195) — they must never
	// become schema-exempt too.
	for _, name := range []EndpointName{"firmware", "firmwareInfo", "keaLeases4", "keaLeases6"} {
		if _, ok := schemaRegistry[name]; !ok {
			t.Errorf("endpoint %q must have a schema (it has no other automated coverage)", name)
		}
	}
}

// AllEndpointSchemas must derive a schema per registered endpoint, sorted,
// with method/path from the contract manifest.
func TestAllEndpointSchemas(t *testing.T) {
	schemas, err := AllEndpointSchemas()
	if err != nil {
		t.Fatalf("AllEndpointSchemas: %v", err)
	}
	if len(schemas) != len(schemaRegistry) {
		t.Fatalf("got %d schemas, want %d", len(schemas), len(schemaRegistry))
	}
	manifest := ContractManifest()
	for i, s := range schemas {
		if i > 0 && schemas[i-1].Endpoint >= s.Endpoint {
			t.Errorf("schemas not sorted: %q before %q", schemas[i-1].Endpoint, s.Endpoint)
		}
		ec := manifest[EndpointName(s.Endpoint)]
		if s.Path != string(ec.Path) || s.Method != ec.Method {
			t.Errorf("schema %q path/method = %s %s, manifest says %s %s", s.Endpoint, s.Method, s.Path, ec.Method, ec.Path)
		}
	}
}

// Types with a custom UnmarshalJSON accept several JSON shapes, so the walker
// must not descend into them or pin a kind.
func TestSchemaForTypeCustomUnmarshaler(t *testing.T) {
	kind, fields := schemaForType(reflect.TypeOf(flexStringMap{}))
	if kind != KindAny {
		t.Fatalf("flexStringMap kind = %q, want %q", kind, KindAny)
	}
	if len(fields) != 0 {
		t.Errorf("flexStringMap fields = %v, want none", fields)
	}
}
