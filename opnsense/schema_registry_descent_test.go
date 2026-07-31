package opnsense

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The #589 guard: a registered type that hides a SECOND decode stage behind an
// opaque container must say so in the registry, or the live canary is blind to
// every field the exporter actually consumes.
//
// schema.go's walkType stops at KindAny whenever a type carries its own
// UnmarshalJSON, which is right for the flex* scalars (they exist precisely to
// accept several wire shapes for ONE value) but wrong for a CONTAINER: a
// json.RawMessage field, or a named map/slice alias like subsystemMap or
// firewallRuleStatMap, is re-unmarshaled downstream into a concrete Go type
// whose fields back real exported metrics. Registering only the outer type
// describes the envelope and nothing beneath it, so no live payload can ever
// contradict the schema there — the canary reports green whatever the box
// sends. #459 built envelopeDescent to name that second stage; this test is
// what stops the next such field from silently reopening the hole.
//
// Anything genuinely un-nameable (a wholesale opaque map, a field that is a
// different JSON TYPE depending on box state) belongs in deliberateOpaqueSeams
// with its reason, not left undeclared.

// descentSeam is one opaque container inside a registered type: the schema path
// where the reflection walk stops, and the Go type it stopped on.
type descentSeam struct {
	Path string
	Type reflect.Type
}

// seamKey identifies one seam for the deliberate-omission ledger.
type seamKey struct {
	Endpoint EndpointName
	Path     string
}

// deliberateOpaqueSeams are the seams that must NOT be descended, each with the
// reason. Every entry is verified against the live canary's own findings or
// upstream source — an entry here is a permanent blind spot, so it costs more
// than a descent and has to earn it.
//
// This map is also the test's own dead-man's switch: TestRegisteredTypesDeclare
// SecondDecodeStage fails if an entry here no longer corresponds to a detected
// seam. So if seam detection ever silently stops working (a walkType change, a
// refactor of the registry value shape), every entry goes stale at once and the
// test shouts instead of quietly checking nothing.
var deliberateOpaqueSeams = map[seamKey]string{
	{"hasyncVersion", "response"}:         "genuinely polymorphic on the wire: an object only when HA is configured and the peer answers, a bare JSON boolean on the overwhelming majority of installs, null on some error paths. See the schemaRegistry comment and the hasyncVersion note in testdata/schemas/coverage.json (#459).",
	{"quaggaOspfInterface", "response"}:   "FRR>=8 wraps per-interface data in {\"interfaces\": {...}} but older FRR returns the flat map at the top level, and only the wrapped shape has ever been confirmed live. Naming either shape would invent an untested claim. See the coverage.json note (#459).",
	{"socketStatistics", "statistics.*"}:  "by design a wholesale opaque map: FetchSocketStatistics never extracts a named field from it, so there is no second-stage Go type to point at and nothing beneath it backs a metric (#589 explicitly scoped this one out).",
	{"apcupsdUpsStatus", "error"}:         "a polymorphic SCALAR, not a container: null on success, a plain error string on failure (see apcupsdStatusResponse). There is no second stage — the client only tests whether it is a string.",
	{"apcupsdUpsStatus", "status.*.norm"}: "a polymorphic SCALAR: a JSON float for numeric-with-unit apcaccess fields, a JSON string for plain ones (STATUS, MODEL), null when unset. normFloat() accepts a number and rejects everything else; there is no inner shape to describe.",
	{"idsSearchInstalledRules", "rows"}:   "deliberately never decoded. Only `total` (count(*) over the SQLite rule cache) is consumed — there is no per-SID series, so the rows have no second-stage Go type by design, and inventing one would model data the exporter refuses to emit.",
}

// findDescentSeams mirrors schema.go's walkType traversal and returns (a) every
// path where the walk stops at KindAny, and (b) the subset of those that stop on
// a CONTAINER — the seams.
//
// It deliberately re-implements the traversal rather than reusing walkType,
// because walkType throws away exactly the thing this guard needs: the reflect
// .Type it stopped on. Divergence between the two walks is caught by
// TestDescentSeamWalkMatchesSchemaWalker, which asserts the KindAny path sets
// are identical for every registered type — so this mirror cannot drift out of
// sync with the real walker and start checking a different tree.
func findDescentSeams(t reflect.Type, prefix string, seen map[reflect.Type]bool) (anyPaths []string, seams []descentSeam) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t == jsonNumberType {
		return nil, nil
	}
	if reflect.PointerTo(t).Implements(jsonUnmarshalerType) {
		// The walk stops here. Whether that is a problem depends on what it
		// stopped ON: a scalar flex type has no inner structure to lose, a
		// container has all of it.
		if isOpaqueContainer(t) {
			return []string{prefix}, []descentSeam{{Path: prefix, Type: t}}
		}
		return []string{prefix}, nil
	}

	switch t.Kind() {
	case reflect.Interface:
		// A bare `any` field is polymorphic by construction (healthCheck's
		// metadata status is an int on a quiet box and a string enum
		// otherwise). There is no second-stage type to name, so it is not a
		// seam — but it IS a KindAny stop, so it is reported for the
		// cross-check against the real walker.
		return []string{prefix}, nil
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil, nil // []byte decodes from a base64 string
		}
		return findDescentSeams(t.Elem(), joinPath(prefix, "[]"), seen)
	case reflect.Map:
		return findDescentSeams(t.Elem(), joinPath(prefix, "*"), seen)
	case reflect.Struct:
		if seen[t] {
			return nil, nil // recursion break, same as walkType
		}
		seen[t] = true
		defer delete(seen, t)
		return findStructSeams(t, prefix, seen)
	default:
		return nil, nil
	}
}

// findStructSeams mirrors walkStructFields, including the anonymous-embedding
// flattening encoding/json performs.
func findStructSeams(t reflect.Type, prefix string, seen map[reflect.Type]bool) (anyPaths []string, seams []descentSeam) {
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
				a, s := findStructSeams(ft, prefix, seen)
				anyPaths = append(anyPaths, a...)
				seams = append(seams, s...)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		a, s := findDescentSeams(f.Type, joinPath(prefix, name), seen)
		anyPaths = append(anyPaths, a...)
		seams = append(seams, s...)
	}
	return anyPaths, seams
}

// isOpaqueContainer reports whether a custom-unmarshaling type HIDES WIRE KEYS —
// the only kind of stop #589 is about. Three shapes qualify, and the distinction
// is what keeps this guard from crying wolf over every tolerant reader in the
// package:
//
//   - json.RawMessage. Always. Its whole purpose is to defer a second decode,
//     and the type system cannot tell you what that decode targets — only the
//     Fetch* call site can, which is exactly why the registry has to say.
//   - a map/slice whose ELEMENT is itself a struct/map/slice. subsystemMap
//     (map[string]HealthCheckSubsystem) hides message/status/statusCode;
//     flexStringMap (map[string]flexString) and captivePortalZoneMap
//     (map[string]string) hide nothing but "these values are scalars", so the
//     canary loses no checkable field name and they are NOT seams.
//   - a struct with at least one json-tagged field. A custom-unmarshaling struct
//     in this package is otherwise a hand-parsed polymorphic SCALAR whose Go
//     fields are not wire keys at all (ntpGPSField's Present/Fix,
//     frrOSPFDeadIntervalDue's Msec/Present) — nothing beneath it to describe.
//
// KNOWN LIMIT, stated rather than hidden: a custom-unmarshaling struct that
// mirrors wire keys WITHOUT json tags (relying on Go field names) would slip
// through. No such type exists here, and json.RawMessage covers the shape this
// bug class actually takes.
func isOpaqueContainer(t reflect.Type) bool {
	if t == jsonRawMessageType {
		return true
	}
	switch t.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		elem := t.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		switch elem.Kind() {
		case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
			return elem.Kind() != reflect.Slice || elem.Elem().Kind() != reflect.Uint8
		default:
			return false
		}
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if _, ok := t.Field(i).Tag.Lookup("json"); ok {
				return true
			}
		}
		return false
	default:
		return false
	}
}

var jsonRawMessageType = reflect.TypeOf(json.RawMessage(nil))

// registryEntrySeams resolves one registry value to the seams still opaque
// AFTER its declared descents are applied. An envelopeDescent removes the seam
// at its Field and contributes its Inner's seams re-anchored beneath it, so a
// nested descent (monitStatus: status -> service -> port) resolves in full.
func registryEntrySeams(t *testing.T, name EndpointName, target any, prefix string) []descentSeam {
	t.Helper()

	if de, ok := target.(descentElement); ok {
		return registryEntrySeams(t, name, de.Elem, prefix+"[]")
	}

	ed, ok := target.(envelopeDescent)
	if !ok {
		_, seams := findDescentSeams(reflect.TypeOf(target), prefix, map[reflect.Type]bool{})
		return seams
	}

	envSeams := registryEntrySeams(t, name, ed.Envelope, prefix)
	declared := prefixSchemaPath(prefix, ed.Field)
	if prefix == "" {
		declared = ed.Field
	}

	var out []descentSeam
	covered := false
	for _, s := range envSeams {
		if s.Path == declared {
			covered = true
			continue
		}
		out = append(out, s)
	}
	if !covered {
		// A descent that names a field which is not an opaque seam is a
		// registry bug: it either misspells the JSON key or points at a field
		// the walker already describes, and in both cases the operator reading
		// the registry is being told something untrue.
		t.Errorf("endpoint %q: envelopeDescent names field %q, which is not an opaque container in %T — misspelled JSON key, or a descent that is not needed",
			name, declared, ed.Envelope)
	}
	return append(out, registryEntrySeams(t, name, ed.Inner, declared)...)
}

// TestRegisteredTypesDeclareSecondDecodeStage is the #589 guard.
func TestRegisteredTypesDeclareSecondDecodeStage(t *testing.T) {
	used := map[seamKey]bool{}
	var undeclared []string

	names := make([]string, 0, len(schemaRegistry))
	for name := range schemaRegistry {
		names = append(names, string(name))
	}
	sort.Strings(names)

	for _, n := range names {
		name := EndpointName(n)
		for _, s := range registryEntrySeams(t, name, schemaRegistry[name], "") {
			key := seamKey{name, s.Path}
			if _, ok := deliberateOpaqueSeams[key]; ok {
				used[key] = true
				continue
			}
			undeclared = append(undeclared, fmt.Sprintf("%s: path %q stops on %s", n, s.Path, s.Type))
		}
	}

	for _, u := range undeclared {
		t.Errorf("undeclared second decode stage — %s\n"+
			"\tThe golden schema describes the opaque container and nothing beneath it, so the live canary\n"+
			"\tcannot see drift on any field the exporter consumes there (#589). Either register an\n"+
			"\tenvelopeDescent naming the type the payload is re-unmarshaled into, or add the seam to\n"+
			"\tdeliberateOpaqueSeams with the reason it cannot be named.", u)
	}

	// Dead-man's switch: every ledgered omission must still be a seam the walk
	// actually finds. If detection breaks, these all go stale at once.
	if len(deliberateOpaqueSeams) == 0 {
		t.Fatal("deliberateOpaqueSeams is empty — this guard's only self-check is that its ledger still resolves; an empty ledger means it can silently degrade to checking nothing")
	}
	for key := range deliberateOpaqueSeams {
		if !used[key] {
			t.Errorf("stale deliberateOpaqueSeams entry {%s, %q}: no such opaque seam is reachable from the registry.\n"+
				"\tEither the endpoint/path changed and the entry should follow it, or seam detection itself has\n"+
				"\tbroken — do NOT delete the entry without confirming which.", key.Endpoint, key.Path)
		}
	}
}

// TestDescentSeamWalkMatchesSchemaWalker pins the mirror walk above to
// schema.go's real walker. Without it, a change to walkType (a new leaf case, a
// different embedding rule) would leave the guard quietly inspecting a
// different tree from the one the goldens are derived from — checking
// something, but not the thing that matters.
func TestDescentSeamWalkMatchesSchemaWalker(t *testing.T) {
	checked := 0
	for name, target := range schemaRegistry {
		// Only plain entries: an envelopeDescent's derived schema is assembled
		// by envelopeDescentSchemaFor, whose own agreement with the walker is
		// covered by the golden schemas.
		if _, ok := target.(envelopeDescent); ok {
			continue
		}
		checked++

		_, fields := schemaForType(reflect.TypeOf(target))
		want := map[string]bool{}
		for _, f := range fields {
			if f.Kind == KindAny {
				want[f.Path] = true
			}
		}

		anyPaths, _ := findDescentSeams(reflect.TypeOf(target), "", map[reflect.Type]bool{})
		got := map[string]bool{}
		for _, p := range anyPaths {
			// The top level itself is not a field path; schemaForType returns
			// it as the kind, not in Fields.
			if p == "" {
				continue
			}
			got[p] = true
		}

		if !reflect.DeepEqual(want, got) {
			t.Errorf("endpoint %q: mirror walk disagrees with walkType on which paths are KindAny\n\twalkType: %v\n\tmirror:   %v",
				name, sortedKeys(want), sortedKeys(got))
		}
	}
	if checked == 0 {
		t.Fatal("no plain registry entries walked — the cross-check ran against nothing")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
