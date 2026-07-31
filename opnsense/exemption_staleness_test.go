package opnsense

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestKnownExtraPathsNotModelled is the ledger-side twin of
// cmd/fieldaudit's TestExemptionLedgerIsCurrent (#588). That checker fails
// when an Exemptions entry names a struct field that is now read; this one
// fails when a testdata/schemas/exemptions.json knownExtraPaths entry names a
// schema path the REGISTERED STRUCT now decodes.
//
// Severity is different from that sibling check, and the difference matters:
// TestExemptionLedgerIsCurrent guards against silently un-suppressing a real
// finding (a stale entry there hides live drift). A stale knownExtraPaths
// entry hides NOTHING — collectUnknownPaths (schema_validate.go) only
// consults ex.KnownExtraPaths for paths ABSENT from the schema trie
// (schema_validate.go:359, the `!extra.has(path)` guard only runs once `c ==
// nil`, i.e. the schema has no node there at all). Once a path IS in the
// trie, collectUnknownPaths never asks the exemption set about it, so a
// knownExtraPaths entry naming an already-modelled path is dead weight, not a
// suppression: deleting it changes no test's behaviour anywhere. The actual
// damage is a confidently-worded, source-cited note that is simply WRONG —
// the two rotted entries this test was written against both asserted "struct
// X decodes only A/B" in prose while the struct's own field list said
// otherwise (interfaceStatisticsRow gained received-packets/received-bytes/
// sent-packets/sent-bytes/dropped-packets in 49913c9, and keaLeaseRow gained
// ClientID in #482 — neither commit touched this ledger). A future triager
// reads the note, trusts it, and re-derives a wrong conclusion. This test is
// documentation-rot prevention, never re-escalate a finding here into
// "canary blindness".
func TestKnownExtraPathsNotModelled(t *testing.T) {
	schemas, err := AllEndpointSchemas()
	if err != nil {
		t.Fatalf("AllEndpointSchemas: %v", err)
	}
	byEndpoint := make(map[string]EndpointSchema, len(schemas))
	for _, s := range schemas {
		byEndpoint[s.Endpoint] = s
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "schemas", "exemptions.json"))
	if err != nil {
		t.Fatalf("read exemptions.json: %v", err)
	}
	var ledger map[string]SchemaExemption
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatalf("parse exemptions.json: %v", err)
	}

	endpoints := make([]string, 0, len(ledger))
	for name := range ledger {
		endpoints = append(endpoints, name)
	}
	sort.Strings(endpoints)

	var stale []string
	for _, name := range endpoints {
		schema, ok := byEndpoint[name]
		if !ok {
			// A ledger entry for an endpoint with no registered schema (the two
			// schemaExemptEndpoints, or a typo) can't be checked against a
			// trie at all — TestExemptionProfileNamesAreKnown and
			// TestSchemaRegistryComplete already guard endpoint-name typos
			// from a different angle, so this test stays silent about them
			// rather than duplicating that gate.
			continue
		}
		for _, scope := range knownExtraPathScopes(ledger[name]) {
			// Reuse compilePathSet/pathSet.has exactly as production does
			// (schema_validate.go): compile the ONE entry under test into its
			// own pathSet, then ask whether any field path the CURRENT schema
			// decodes falls inside it. This is the same exact/".*"-subtree/
			// segment-prefix-wildcard matching evaluateFieldPath and
			// collectUnknownPaths use for the ledger at scrape time, so a
			// "data.thread*"-style entry is judged by the identical rule that
			// would suppress it live — no separate wildcard reimplementation
			// to keep in sync, and no risk of the gate flagging a legitimate
			// entry that compilePathSet itself would still treat as unmatched
			// (e.g. a bare "*" degrades to an inert exact-match key in both
			// places, per compilePathSet's own doc comment).
			single := compilePathSet([]string{scope.path})
			for _, f := range schema.Fields {
				if single.has(f.Path) {
					stale = append(stale, name+scope.label+": "+scope.path+
						" (now decoded as "+f.Path+", kind "+string(f.Kind)+")")
					break
				}
			}
		}
	}

	if len(stale) > 0 {
		t.Errorf("%d stale knownExtraPaths entr(y/ies) — the registered struct now decodes these paths. "+
			"Prune the entry (and its now-wrong note) from testdata/schemas/exemptions.json:\n\t%s",
			len(stale), joinLines(stale))
	}
}

// extraPathScope is one knownExtraPaths entry plus a human-readable label for
// where it came from — the base ledger or one named profile — so a failure
// message can say exactly which block to edit.
type extraPathScope struct {
	path  string
	label string
}

// knownExtraPathScopes flattens an exemption's base knownExtraPaths and every
// profile's knownExtraPaths into one list. A path is "modelled" or not
// independent of which probe profile found it — the registered struct is the
// same struct whichever box asked — so a profile-scoped entry is exactly as
// stale as a base one if the struct now decodes it.
func knownExtraPathScopes(ex SchemaExemption) []extraPathScope {
	out := make([]extraPathScope, 0, len(ex.KnownExtraPaths))
	for _, p := range ex.KnownExtraPaths {
		out = append(out, extraPathScope{path: p, label: ""})
	}
	profiles := make([]string, 0, len(ex.Profiles))
	for name := range ex.Profiles {
		profiles = append(profiles, name)
	}
	sort.Strings(profiles)
	for _, name := range profiles {
		for _, p := range ex.Profiles[name].KnownExtraPaths {
			out = append(out, extraPathScope{path: p, label: " (profile " + name + ")"})
		}
	}
	return out
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n\t"
		}
		out += l
	}
	return out
}
