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
// an endpoint's schema. Missing, UnknownTopKeys and UnknownPaths are
// warning-level drift; Mismatches are breaking. Unverified paths sit under
// empty arrays/maps or nulls — box state, not drift.
//
// UnknownTopKeys and UnknownPaths split the "data we do not model" signal by
// depth on purpose: the root has a fixed, ledgered key set (plus the bootgrid
// envelope), while everything below it is discovered by the reverse traversal
// (#376). UnknownPaths therefore holds NESTED extras only (depth >= 1), as
// normalized paths — array elements collapse to "[]" and dynamic map
// identities to "*".
type ValidationResult struct {
	Endpoint       string
	Missing        []string
	Mismatches     []Mismatch
	UnknownTopKeys []string
	UnknownPaths   []string
	Unverified     []string
}

// Clean reports whether the response matched the schema with no drift signals.
func (r ValidationResult) Clean() bool {
	return len(r.Missing) == 0 && len(r.Mismatches) == 0 &&
		len(r.UnknownTopKeys) == 0 && len(r.UnknownPaths) == 0
}

// SchemaExemption acknowledges known, deliberate divergence between one
// endpoint's schema and a live box: paths that are legitimately absent in some
// box states (MissingOK), top-level keys the box serves that the exporter
// deliberately does not model (KnownExtraTopKeys) and NESTED keys the box
// serves that we deliberately do not model (KnownExtraPaths). Lives in the
// committed opnsense/testdata/schemas/exemptions.json.
//
// A MissingOK entry takes one of three forms. An exact schema path
// ("memory.arc"). A subtree prefix ending in ".*" ("data.num.*"), which
// exempts the bare parent ("data.num") and every path beneath it - this keeps
// the ledger readable for endpoints whose legacy surface is a whole
// sub-object. Or a segment-prefix wildcard, a bare trailing "*" on the final
// segment ("data.thread*"), which exempts any single path segment starting
// with that prefix plus that segment's own subtree - this is for endpoints
// whose per-instance breakdown is keyed by something that varies with the
// box (unbound's data.thread0..data.threadN, one per configured worker
// thread), where enumerating exact indices just moves the goalpost to the
// next box with a different count. KnownExtraPaths takes the SAME three
// forms, over the normalized paths reported in ValidationResult.UnknownPaths
// ("rows[].widget", "byName.*.legacy", "details.*").
type SchemaExemption struct {
	MissingOK         []string `json:"missingOK,omitempty"`
	KnownExtraTopKeys []string `json:"knownExtraTopKeys,omitempty"`
	KnownExtraPaths   []string `json:"knownExtraPaths,omitempty"`
	Note              string   `json:"note,omitempty"`

	// Profiles scopes extra entries to one probe target (#490). See
	// ForProfile; a nested Profiles inside one of these is ignored.
	Profiles map[string]SchemaExemption `json:"profiles,omitempty"`
}

// Probe profiles are the canary's targets. This is a closed set on purpose: a
// mistyped profile name in the ledger would compile to a block that silently
// never applies, so TestExemptionProfileNamesAreKnown checks the committed file
// against these.
//
// It keys on the TARGET rather than the OPNsense generation #490 first asked
// for, because the three targets differ on three independent axes - generation,
// plugin set, and real-vs-virtual hardware - and generation is the axis that
// explains the fewest findings. smartInfo's extra keys are prod-only because
// prod has real disks, not because it runs 26.7; the release-VM target runs the
// same generation and will never produce them. Keying on generation would make
// that target inherit prod's hardware exemptions and go blind to them.
const (
	// ProbeProfileNightly is CI against the devel-channel testbed VM.
	ProbeProfileNightly = "nightly"
	// ProbeProfileReleaseVM is CI against the release-channel testbed VM: the
	// same plugin set and virtual hardware as nightly, so a difference between
	// the two is attributable to the generation alone.
	ProbeProfileReleaseVM = "release-vm"
	// ProbeProfileProd is camden against the production firewall: real
	// hardware and a real network, but a sparse plugin set.
	ProbeProfileProd = "prod"
)

// KnownProbeProfiles returns the closed set of valid profile names.
func KnownProbeProfiles() []string {
	return []string{ProbeProfileNightly, ProbeProfileReleaseVM, ProbeProfileProd}
}

// ForProfile flattens the ledger for one probe target: the base entries, which
// apply everywhere, plus any scoped to profile. The result carries no Profiles
// of its own, so everything downstream keeps treating an exemption as a plain
// list and nothing has to know profiles exist.
//
// An empty or unledgered profile yields the base entries alone. That is
// deliberately not an error - the failure it would guard against is a typo, and
// a typo fails the build in TestExemptionProfileNamesAreKnown instead, where the
// check can see the whole committed file.
func (e SchemaExemption) ForProfile(profile string) SchemaExemption {
	out := SchemaExemption{
		// Copy rather than alias: probing one profile must not append into the
		// base ledger's backing array and leak those entries into every
		// endpoint validated afterwards.
		MissingOK:         append([]string(nil), e.MissingOK...),
		KnownExtraTopKeys: append([]string(nil), e.KnownExtraTopKeys...),
		KnownExtraPaths:   append([]string(nil), e.KnownExtraPaths...),
		Note:              e.Note,
	}
	scoped, ok := e.Profiles[profile]
	if !ok {
		return out
	}
	out.MissingOK = append(out.MissingOK, scoped.MissingOK...)
	out.KnownExtraTopKeys = append(out.KnownExtraTopKeys, scoped.KnownExtraTopKeys...)
	out.KnownExtraPaths = append(out.KnownExtraPaths, scoped.KnownExtraPaths...)
	return out
}

// pathSet is a compiled schema-path ledger: exact paths, subtree prefixes from
// ".*" entries, and segment-prefix wildcards from a bare trailing "*". Used
// for both MissingOK and KnownExtraPaths, which share the same semantics.
type pathSet struct {
	exact       map[string]bool
	prefixes    []string // each with its trailing dot, e.g. "data.num."
	parents     []string // the bare parent of each prefix, e.g. "data.num"
	segPrefixes []segPrefixEntry
}

// segPrefixEntry is a compiled "data.thread*" style entry. dirPrefix is
// everything up to and including the last dot before the wildcarded segment
// ("data.", or "" if the wildcarded segment is itself top-level); seg is the
// literal prefix the segment must start with ("thread"). Matching happens
// against the WHOLE segment, not a raw substring, so "data.thread*" reaches
// "data.threads.foo" (the segment "threads" starts with "thread", and ".foo"
// is its subtree) but never crosses into a different branch: in
// "data.x.thread0" the segment right after "data." is "x", not
// thread-prefixed, so the wildcard never even looks past it.
type segPrefixEntry struct {
	dirPrefix string
	seg       string
}

// matches reports whether path's segment at this entry's position begins
// with seg. Once that segment matches, everything after it - the wildcard's
// subtree - is accepted without further inspection; the segment match alone
// decides it, the same way the ".*" subtree prefix works.
func (e segPrefixEntry) matches(path string) bool {
	if !strings.HasPrefix(path, e.dirPrefix) {
		return false
	}
	seg, _, _ := strings.Cut(path[len(e.dirPrefix):], ".")
	return strings.HasPrefix(seg, e.seg)
}

func compilePathSet(entries []string) pathSet {
	s := pathSet{exact: make(map[string]bool, len(entries))}
	for _, p := range entries {
		if stem, ok := strings.CutSuffix(p, ".*"); ok && stem != "" {
			s.prefixes = append(s.prefixes, stem+".")
			s.parents = append(s.parents, stem)
			continue
		}
		// The ".*" subtree form above gets first refusal, so "data.num.*" is
		// never reinterpreted here even though it also ends in a bare "*". What
		// remains is a segment-prefix wildcard: "data.thread*" splits into the
		// directory before the wildcarded segment ("data.") and the prefix that
		// segment must start with ("thread"). An entry that is just "*", or
		// otherwise reduces to an empty segment prefix, is refused and falls
		// through to the exact-match map instead - the alternative would compile
		// into something that matches every segment there is, silently blinding
		// the whole canary, the worst possible failure mode for this ledger.
		if seg, ok := strings.CutSuffix(p, "*"); ok && seg != "" {
			dir, prefix := "", seg
			if i := strings.LastIndexByte(seg, '.'); i >= 0 {
				dir, prefix = seg[:i+1], seg[i+1:]
			}
			if prefix != "" {
				s.segPrefixes = append(s.segPrefixes, segPrefixEntry{dirPrefix: dir, seg: prefix})
				continue
			}
		}
		s.exact[p] = true
	}
	return s
}

// has reports whether a schema path is in the ledger. The prefix match is
// dot-anchored, so "data.num.*" covers "data.num.query.tcp" but never the
// sibling section "data.numx.foo".
func (s pathSet) has(path string) bool {
	if s.exact[path] {
		return true
	}
	for i, prefix := range s.prefixes {
		if path == s.parents[i] || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for _, e := range s.segPrefixes {
		if e.matches(path) {
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

// knownKeyNode is one node of the normalized known-key trie derived from an
// EndpointSchema's Fields. It is the reverse of evaluateFieldPath: instead of
// asking "does the response carry every path we expect?", the trie lets the
// walker ask "does the response carry a key we do NOT expect?" (#376).
//
// A struct maps to static children (keyed LOWERCASED, because encoding/json
// matches keys case-insensitively); a Go map maps to the single dynamic child
// ("*"), which accepts arbitrary identities; a slice maps to the element child
// ("[]").
type knownKeyNode struct {
	kind FieldKind
	// name is the schema's own spelling of this node's key. Reported paths use
	// it rather than the live key, so one drift has one canonical spelling
	// whatever case the box serves — OPNsense's healthCheck reaches the struct's
	// "metadata.System" block through a lowercase "system" key, and an exemption
	// entry must not have to guess which casing a given release sends.
	name    string
	static  map[string]*knownKeyNode
	dynamic *knownKeyNode // the "*" child: a Go map's value shape
	element *knownKeyNode // the "[]" child: an array element's shape
}

// opaque reports whether the walker must stop here. Two cases, and they are the
// whole noise-control story:
//   - KindAny — interface{}, a custom json.Unmarshaler (the flex* types) or
//     json.RawMessage. The exporter decodes these leniently, so nothing
//     underneath can be drift.
//   - a node with no modeled children at all. The schema derivation produces
//     one for an empty struct and for the recursion-cycle break in walkType, so
//     treating it as an opaque container is what keeps a self-referential or
//     field-less struct from reporting every live key as unexpected.
func (n *knownKeyNode) opaque() bool {
	return n.kind == KindAny || (len(n.static) == 0 && n.dynamic == nil && n.element == nil)
}

// child resolves a live object key against the node's static children the way
// encoding/json does: exact first, then case-insensitive (the map is keyed
// lowercased, so a single lookup covers both).
func (n *knownKeyNode) child(key string) *knownKeyNode {
	return n.static[strings.ToLower(key)]
}

// buildKnownKeyTrie derives the trie from a schema. Intermediate nodes are
// created on demand, so a schema listing only "rows[].name" still yields the
// rows → [] → name chain; their kind is filled in when (and if) their own field
// entry is walked.
func buildKnownKeyTrie(s EndpointSchema) *knownKeyNode {
	root := &knownKeyNode{kind: s.TopLevelKind}
	for _, f := range s.Fields {
		cur := root
		for _, seg := range splitSchemaPath(f.Path) {
			switch seg {
			case "[]":
				if cur.element == nil {
					cur.element = &knownKeyNode{}
				}
				cur = cur.element
			case "*":
				if cur.dynamic == nil {
					cur.dynamic = &knownKeyNode{}
				}
				cur = cur.dynamic
			default:
				if cur.static == nil {
					cur.static = map[string]*knownKeyNode{}
				}
				lk := strings.ToLower(seg)
				if cur.static[lk] == nil {
					cur.static[lk] = &knownKeyNode{name: seg}
				}
				cur = cur.static[lk]
			}
		}
		cur.kind = f.Kind
	}
	return root
}

// isBootgridFormattedTwin reports whether a live object key is the
// "%"-prefixed formatted-value companion bootgrid emits alongside a raw row
// field ("action" / "%action", "priv" / "%priv"). It is a UI-rendering
// convention, not a second piece of data, so it is never itself drift (#457).
func isBootgridFormattedTwin(key string) bool {
	return strings.HasPrefix(key, "%") && key != "%"
}

// collectUnknownPaths walks the decoded response alongside the trie and records
// every key the schema does not model, as a normalized path.
//
// Depth 0 (the root object's own keys) is deliberately skipped: the root has a
// fixed ledgered key set plus the bootgrid envelope, and ValidateResponseSchema
// already reports it via UnknownTopKeys. Unknown keys are never descended into
// — one finding per new branch, not one per leaf inside it.
func collectUnknownPaths(n *knownKeyNode, v any, prefix string, extra pathSet, out map[string]bool) {
	if n == nil || n.opaque() {
		return
	}
	switch val := v.(type) {
	case map[string]any:
		if n.dynamic != nil && len(n.static) == 0 {
			// Every key here is an identity (hostname, peer, interface name).
			// Normalizing to "*" is a PRIVACY requirement: the report and any
			// exemption derived from it must never carry a real identity.
			for _, mv := range val {
				collectUnknownPaths(n.dynamic, mv, joinPath(prefix, "*"), extra, out)
			}
			return
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if isBootgridFormattedTwin(k) {
				// OPNsense's bootgrid UI convention emits a "%"-prefixed
				// formatted-value twin alongside almost every raw row field
				// (e.g. "action" / "%action"). It carries no information the
				// raw field doesn't already, so it is suppressed here
				// structurally rather than needing its own knownExtraPaths
				// entry per field (#457) — the raw field's own presence or
				// absence in this map still reports (or doesn't) on its own
				// merits via the next iteration.
				continue
			}
			c := n.child(k)
			if c == nil {
				c = n.dynamic // a struct+map hybrid cannot arise today; tolerate it
			}
			if c == nil {
				path := joinPath(prefix, k)
				if prefix != "" && !extra.has(path) {
					out[path] = true
				}
				continue
			}
			// Canonical casing: the schema's spelling for a known segment, the
			// live key only for a segment the schema has never seen.
			seg := k
			if c.name != "" {
				seg = c.name
			}
			collectUnknownPaths(c, val[k], joinPath(prefix, seg), extra, out)
		}
	case []any:
		for _, ev := range val {
			collectUnknownPaths(n.element, ev, joinPath(prefix, "[]"), extra, out)
		}
	}
}

// payloadNormalizers maps an endpoint to a transform applied to its decoded
// response BEFORE validation, for the narrow case where the API client itself
// discards part of the payload as synthetic. Validating what the client throws
// away produces findings that are neither drift nor box-state and that an
// exemption would answer wrongly — a missingOK on such a path also silences the
// real field for the day the box has real data (#618).
//
// This is deliberately NOT a general-purpose tolerance hook. A normalizer is
// only correct where the discard rule is SHARED with the client, so the two
// cannot drift; each entry below must call the client's own predicate rather
// than reimplement it. Anything else — an optional key, a changed
// representation, an unmodeled extra — belongs in exemptions.json, where it is
// visible in the compat ledger, rather than being quietly normalised out here.
var payloadNormalizers = map[EndpointName]func(any) any{
	// setkey -D's "No SAD entries." sentence, parsed by upstream into a fake
	// row. FetchIPsecSAD drops it; so must the probe.
	"ipsecSad": normalizeIPsecSADPayload,
}

// ValidateResponseSchema checks a raw JSON response against a structure-only
// schema. The exemption suppresses Missing reports for known-optional paths,
// UnknownTopKeys reports for acknowledged unmodeled root keys and UnknownPaths
// reports for acknowledged unmodeled nested keys.
func ValidateResponseSchema(s EndpointSchema, raw []byte, ex SchemaExemption) (ValidationResult, error) {
	missingOK := compilePathSet(ex.MissingOK)
	res := ValidationResult{Endpoint: s.Endpoint}

	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return res, fmt.Errorf("response is not valid JSON: %w", err)
	}

	// Strip rows the API CLIENT discards as synthetic before validating, so the
	// probe and the client see the same records (#618). Without this the canary
	// validates against payload the exporter never models and reports Missing
	// for keys a placeholder simply does not carry — findings that can never be
	// resolved and must never be exempted, because the same keys are real and
	// consumed the moment the box has actual data.
	if norm, ok := payloadNormalizers[EndpointName(s.Endpoint)]; ok {
		root = norm(root)
	}

	// An EMPTY top-level array where an object is expected is the same PHP
	// empty-map quirk the nested walker already tolerates, one level up: an
	// endpoint whose whole body is an associative array (netflowCacheStats)
	// serialises to [] when it has nothing to report. That is box state, not
	// drift, and there is nothing below it to traverse (#499). A POPULATED
	// array still falls through to the gate as a genuine container flip.
	if isPHPEmptyObject(s.TopLevelKind, root) {
		return res, nil
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

	// Reverse traversal: nested keys the schema does not model (#376). Kept
	// separate from the root check above so the existing envelope handling and
	// knownExtraTopKeys ledger stay untouched.
	unknown := map[string]bool{}
	collectUnknownPaths(buildKnownKeyTrie(s), root, "", compilePathSet(ex.KnownExtraPaths), unknown)
	if len(unknown) > 0 {
		res.UnknownPaths = make([]string, 0, len(unknown))
		for p := range unknown {
			res.UnknownPaths = append(res.UnknownPaths, p)
		}
		sort.Strings(res.UnknownPaths)
	}

	for _, f := range s.Fields {
		evaluateFieldPath(f, root, missingOK, &res)
	}
	return res, nil
}

// evaluateFieldPath resolves one schema path against the decoded response and
// files it into exactly one bucket: present (kind-checked), Missing,
// Unverified, or silently skipped when an ancestor path is already Missing.
func evaluateFieldPath(f SchemaField, root any, missingOK pathSet, res *ValidationResult) {
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
