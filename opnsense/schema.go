package opnsense

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// FieldKind is the JSON type category a schema field expects on the wire.
// KindAny marks fields the exporter decodes leniently (interface{} or a custom
// json.Unmarshaler such as the flex* types), so the live canary accepts any
// JSON type there.
type FieldKind string

const (
	KindString FieldKind = "string"
	KindNumber FieldKind = "number"
	// KindNumeric is json.Number: the decoder accepts a JSON number or a
	// numeric string, so both shapes are valid on the wire (OPNsense flips
	// between them across releases — 26.7 retyped many counters).
	KindNumeric FieldKind = "numeric"
	KindBool    FieldKind = "boolean"
	KindObject  FieldKind = "object"
	KindArray   FieldKind = "array"
	KindAny     FieldKind = "any"
)

// SchemaField is one expected key path in an endpoint's JSON response.
// Path segments: a literal key, "[]" for every array element, "*" for every
// value of an object with dynamic keys (a Go map).
type SchemaField struct {
	Path string    `json:"path"`
	Kind FieldKind `json:"kind"`
}

// EndpointSchema is the structure-only contract for one endpoint: the key
// paths and JSON types the exporter's response structs decode. It carries no
// response values, so it is safe to commit in a public repo.
type EndpointSchema struct {
	Endpoint          string        `json:"endpoint"`
	Method            string        `json:"method"`
	Path              string        `json:"path"`
	TopLevelKind      FieldKind     `json:"topLevelKind"`
	KnownTopLevelKeys []string      `json:"knownTopLevelKeys,omitempty"`
	Fields            []SchemaField `json:"fields"`
}

var (
	jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	jsonNumberType      = reflect.TypeOf(json.Number(""))
)

// schemaForType derives the schema of one Go type: its top-level kind and the
// sorted key paths beneath it. Types with a custom UnmarshalJSON accept several
// wire shapes by design, so they map to KindAny with no descent.
func schemaForType(t reflect.Type) (FieldKind, []SchemaField) {
	fields := map[string]FieldKind{}
	kind := walkType(t, "", fields, map[reflect.Type]bool{})
	out := make([]SchemaField, 0, len(fields))
	for p, k := range fields {
		out = append(out, SchemaField{Path: p, Kind: k})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return kind, out
}

// walkType records t's descendant paths into fields (keyed by dotted path) and
// returns t's own kind. seen breaks recursive struct cycles.
func walkType(t reflect.Type, prefix string, fields map[string]FieldKind, seen map[reflect.Type]bool) FieldKind {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t == jsonNumberType {
		return KindNumeric
	}
	if reflect.PointerTo(t).Implements(jsonUnmarshalerType) {
		return KindAny
	}

	switch t.Kind() {
	case reflect.String:
		return KindString
	case reflect.Bool:
		return KindBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return KindNumber
	case reflect.Interface:
		return KindAny
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			// []byte decodes from a base64 JSON string.
			return KindString
		}
		child := joinPath(prefix, "[]")
		fields[child] = walkType(t.Elem(), child, fields, seen)
		return KindArray
	case reflect.Map:
		child := joinPath(prefix, "*")
		fields[child] = walkType(t.Elem(), child, fields, seen)
		return KindObject
	case reflect.Struct:
		if seen[t] {
			return KindObject
		}
		seen[t] = true
		walkStructFields(t, prefix, fields, seen)
		delete(seen, t)
		return KindObject
	default:
		return KindAny
	}
}

// walkStructFields records each json-visible field of a struct, flattening
// anonymous embedded structs into the parent path (matching encoding/json).
func walkStructFields(t reflect.Type, prefix string, fields map[string]FieldKind, seen map[reflect.Type]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" && tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && !reflect.PointerTo(ft).Implements(jsonUnmarshalerType) {
				walkStructFields(ft, prefix, fields, seen)
				continue
			}
		}
		if !f.IsExported() {
			// An unexported embedded non-struct field is invisible to encoding/json.
			continue
		}
		if name == "" {
			name = f.Name
		}
		child := joinPath(prefix, name)
		fields[child] = walkType(f.Type, child, fields, seen)
	}
}

// joinPath appends a segment to a dotted path. "[]" attaches without a dot
// ("rows[]"); everything else joins with "." ("rows[].name", "byName.*").
func joinPath(prefix, seg string) string {
	if seg == "[]" {
		return prefix + "[]"
	}
	if prefix == "" {
		return seg
	}
	return prefix + "." + seg
}

// endpointSchemaFor builds the full schema for one endpoint from the registry
// entry and the contract manifest.
func endpointSchemaFor(name EndpointName, target any) (EndpointSchema, error) {
	ec, ok := ContractManifest()[name]
	if !ok {
		return EndpointSchema{}, fmt.Errorf("endpoint %q is not in the client manifest", name)
	}
	t := reflect.TypeOf(target)
	kind, fields := schemaForType(t)

	s := EndpointSchema{
		Endpoint:     string(name),
		Method:       ec.Method,
		Path:         string(ec.Path),
		TopLevelKind: kind,
		Fields:       fields,
	}
	// Only a struct top level has a fixed key set worth checking; a map/any top
	// level means dynamic keys, signalled by an empty KnownTopLevelKeys.
	base := t
	for base.Kind() == reflect.Pointer {
		base = base.Elem()
	}
	if kind == KindObject && base.Kind() == reflect.Struct {
		for _, f := range fields {
			if !strings.ContainsAny(f.Path, ".*[") {
				s.KnownTopLevelKeys = append(s.KnownTopLevelKeys, f.Path)
			}
		}
		sort.Strings(s.KnownTopLevelKeys)
	}
	return s, nil
}
