package opnsense

import (
	"sort"
	"testing"
)

// schemaFieldKind looks up one derived field's kind by path, failing the test
// if the path is absent from the schema entirely (as opposed to present with
// an unexpected kind).
func schemaFieldKind(t *testing.T, s EndpointSchema, path string) FieldKind {
	t.Helper()
	for _, f := range s.Fields {
		if f.Path == path {
			return f.Kind
		}
	}
	var got []string
	for _, f := range s.Fields {
		got = append(got, f.Path)
	}
	sort.Strings(got)
	t.Fatalf("schema %q has no field %q; fields: %v", s.Endpoint, path, got)
	return ""
}

// endpointSchema derives and returns one endpoint's schema from the live
// registry, failing the test if the endpoint isn't registered.
func endpointSchema(t *testing.T, endpoint EndpointName) EndpointSchema {
	t.Helper()
	target, ok := schemaRegistry[endpoint]
	if !ok {
		t.Fatalf("endpoint %q has no schema registry entry", endpoint)
	}
	s, err := schemaForRegistryEntry(endpoint, target)
	if err != nil {
		t.Fatalf("schema for %q: %v", endpoint, err)
	}
	return s
}

// The two OSPFv3 endpoints are the motivating case for #459: their registry
// entry used to be the bare envelope struct (Response json.RawMessage), which
// stops the walker at KindAny and renders every path beneath "response"
// permanently invisible to the live canary. Registering an envelopeDescent
// instead must make the inner field paths — the ones backing real exported
// metrics — resolve to their real kinds.
func TestEnvelopeDescentReflectsOSPFv3Overview(t *testing.T) {
	s := endpointSchema(t, "quaggaOspfv3Overview")

	if s.TopLevelKind != KindObject {
		t.Fatalf("TopLevelKind = %q, want %q", s.TopLevelKind, KindObject)
	}
	if k := schemaFieldKind(t, s, "response"); k != KindObject {
		t.Errorf(`"response" kind = %q, want %q (was %q before #459)`, k, KindObject, KindAny)
	}
	if k := schemaFieldKind(t, s, "response.areas"); k != KindObject {
		t.Errorf(`"response.areas" kind = %q, want %q`, k, KindObject)
	}
	if k := schemaFieldKind(t, s, "response.areas.*"); k != KindObject {
		t.Errorf(`"response.areas.*" kind = %q, want %q`, k, KindObject)
	}
	if k := schemaFieldKind(t, s, "response.areas.*.numberOfAreaScopedLsa"); k != KindNumber {
		t.Errorf(`"response.areas.*.numberOfAreaScopedLsa" kind = %q, want %q`, k, KindNumber)
	}
	if k := schemaFieldKind(t, s, "response.routerId"); k != KindString {
		t.Errorf(`"response.routerId" kind = %q, want %q`, k, KindString)
	}

	for _, f := range s.Fields {
		if f.Kind == KindAny {
			t.Errorf("quaggaOspfv3Overview still has an opaque field %q — the envelope should be fully unwrapped", f.Path)
		}
	}
}

func TestEnvelopeDescentReflectsOSPFv3Interface(t *testing.T) {
	s := endpointSchema(t, "quaggaOspfv3Interface")

	if s.TopLevelKind != KindObject {
		t.Fatalf("TopLevelKind = %q, want %q", s.TopLevelKind, KindObject)
	}
	want := map[string]FieldKind{
		"response":                           KindObject,
		"response.*":                         KindObject,
		"response.*.status":                  KindString,
		"response.*.cost":                    KindNumber,
		"response.*.ospf6InterfaceState":     KindString,
		"response.*.pendingLsaLsUpdateCount": KindNumber,
		"response.*.pendingLsaLsAckCount":    KindNumber,
	}
	for path, kind := range want {
		if k := schemaFieldKind(t, s, path); k != kind {
			t.Errorf("%q kind = %q, want %q", path, k, kind)
		}
	}
	for _, f := range s.Fields {
		if f.Kind == KindAny {
			t.Errorf("quaggaOspfv3Interface still has an opaque field %q — the envelope should be fully unwrapped", f.Path)
		}
	}
}

// TestSchemaRegistryComplete (schema_test.go) already pins schemaRegistry to
// defaultEndpoints(); AllEndpointSchemas must still succeed end to end (used
// by TestSchemasUpToDate and the apischema/apidrift binaries) once some
// entries are envelopeDescent rather than a bare zero value.
func TestAllEndpointSchemasHandlesEnvelopeDescent(t *testing.T) {
	schemas, err := AllEndpointSchemas()
	if err != nil {
		t.Fatalf("AllEndpointSchemas: %v", err)
	}
	if len(schemas) != len(schemaRegistry) {
		t.Fatalf("got %d schemas, want %d", len(schemas), len(schemaRegistry))
	}
}
