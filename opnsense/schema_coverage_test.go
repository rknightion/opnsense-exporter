package opnsense

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const coverageLedgerTestPath = "testdata/schemas/coverage.json"

func TestLoadCoverageLedgerMissingFileIsEmpty(t *testing.T) {
	l, err := LoadCoverageLedger(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadCoverageLedger on a missing file: %v", err)
	}
	if len(l) != 0 {
		t.Errorf("want an empty ledger, got %v", l)
	}
}

func TestLoadCoverageLedgerBadJSONErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "coverage.json")
	if err := os.WriteFile(p, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCoverageLedger(p); err == nil {
		t.Fatal("want an error for malformed ledger JSON")
	}
}

// Classify resolves an endpoint/path pair to its coverage class. Paths are the
// validator's NORMALIZED schema paths, so a wildcard entry matches every map
// identity and a concrete identity is not a ledger path at all.
func TestCoverageIndexClassify(t *testing.T) {
	ix := CoverageLedger{
		"epA": {
			Required: []CoveragePath{
				{Path: "peers.details[].status", Metrics: []string{"opnsense_x_peer_connected"}, Exercise: "enrol a peer"},
				{Path: "byName.*.state", Metrics: []string{"opnsense_x_state"}, Exercise: "bring a tunnel up"},
			},
			StateOptional: []CoveragePath{
				{Path: "hardware.*", Reason: "no such hardware on a VM", PruneTrigger: "canary moves to metal"},
			},
		},
	}.Index("")

	cases := []struct {
		endpoint, path string
		wantClass      CoverageClass
		wantFound      bool
	}{
		{"epA", "peers.details[].status", CoverageRequired, true},
		{"epA", "byName.*.state", CoverageRequired, true},
		{"epA", "hardware.psu", CoverageStateOptional, true},
		{"epA", "hardware", CoverageStateOptional, true},
		{"epA", "hardwarex.psu", "", false},
		{"epA", "peers.details[].fqdn", "", false},
		// A real map identity is never a ledger path: normalization to "*" is
		// what keeps identities out of the ledger and the report.
		{"epA", "byName.wg0.state", "", false},
		{"epB", "peers.details[].status", "", false},
	}
	for _, tc := range cases {
		class, entry, found := ix.Classify(tc.endpoint, tc.path)
		if found != tc.wantFound || class != tc.wantClass {
			t.Errorf("Classify(%q,%q) = (%q,%v), want (%q,%v)", tc.endpoint, tc.path, class, found, tc.wantClass, tc.wantFound)
		}
		if found && entry.Path == "" {
			t.Errorf("Classify(%q,%q) returned an empty entry", tc.endpoint, tc.path)
		}
	}
}

// Per-profile scoping (#611). A required entry may be re-classed stateOptional
// for ONE probe target, because a path can be metric-backing and exercisable on
// the testbeds while being permanently unreachable on prod - prod has no CARP
// VIP, no Kea DHCPv4, no DHCPv6 PD pool and no WireGuard instance, and prod is
// read-only so none of that can be provisioned.
//
// The override resolves at COMPILE time, exactly as SchemaExemption.ForProfile
// flattens: Index(profile) bakes the class in, so Classify and everything
// downstream keep treating an entry as a plain class and nothing else has to
// know profiles exist.
func TestCoverageIndexProfileOverride(t *testing.T) {
	ledger := CoverageLedger{
		"epA": {
			Required: []CoveragePath{
				{
					Path: "rows[].vhid", Metrics: []string{"opnsense_x_vip"}, Exercise: "add a VIP",
					Blocker: "no VIP on the testbed",
					Profiles: map[string]CoverageProfileOverride{
						ProbeProfileProd: {
							Class:        CoverageStateOptional,
							Reason:       "prod has no CARP VIP and is read-only",
							PruneTrigger: "a second production firewall exists",
						},
					},
				},
				// A sibling with NO override: proves the override is per-entry and
				// does not leak across entries in the same endpoint section.
				{Path: "rows[].other", Metrics: []string{"opnsense_x_other"}, Exercise: "poke it", Verified: "seen"},
			},
		},
	}

	for _, profile := range KnownProbeProfiles() {
		want := CoverageRequired
		if profile == ProbeProfileProd {
			want = CoverageStateOptional
		}
		ix := ledger.Index(profile)

		class, entry, found := ix.Classify("epA", "rows[].vhid")
		if !found {
			t.Fatalf("profile %q: Classify lost the entry", profile)
		}
		if class != want {
			t.Errorf("profile %q: class = %q, want %q", profile, class, want)
		}
		// The override's reason/prune trigger must reach the resolved entry, or
		// the report cannot print why the path is informational on this target.
		if want == CoverageStateOptional {
			if entry.Reason == "" || entry.PruneTrigger == "" {
				t.Errorf("profile %q: resolved entry has reason=%q pruneTrigger=%q, want both from the override",
					profile, entry.Reason, entry.PruneTrigger)
			}
		}
		// The resolved entry must carry no Profiles of its own, so no consumer
		// can re-resolve against a different profile downstream.
		if len(entry.Profiles) != 0 {
			t.Errorf("profile %q: resolved entry still carries Profiles %v", profile, entry.Profiles)
		}

		if class, _, _ := ix.Classify("epA", "rows[].other"); class != CoverageRequired {
			t.Errorf("profile %q: the un-overridden sibling became %q, want required", profile, class)
		}
	}
}

// THE WIDENING GUARD (#611 acceptance). An override keyed to one profile must
// change that profile and no other. This is the failure mode that would make the
// mechanism worse than the warning it replaces: a prod-scoped stateOptional that
// silently also applied to nightly would blind the two targets that DO verify
// these paths, which is exactly what the base-scoped `stateOptional` knob
// already does and why #611 could not use it.
//
// Written as an invariant over the committed ledger rather than over a fixture,
// so it holds for every override anybody adds later.
func TestCommittedCoverageOverridesNeverWiden(t *testing.T) {
	ledger, err := LoadCoverageLedger(coverageLedgerTestPath)
	if err != nil {
		t.Fatalf("LoadCoverageLedger: %v", err)
	}

	// Base class per (endpoint, path), read straight off which array the entry
	// sits in - the class every profile must see unless it is the named one.
	type key struct{ endpoint, path string }
	base := map[key]CoverageClass{}
	overrides := map[key]map[string]CoverageClass{}
	for endpoint, cov := range ledger {
		for class, entries := range map[CoverageClass][]CoveragePath{
			CoverageRequired:      cov.Required,
			CoverageStateOptional: cov.StateOptional,
		} {
			for _, e := range entries {
				k := key{endpoint, e.Path}
				base[k] = class
				for profile, ov := range e.Profiles {
					if overrides[k] == nil {
						overrides[k] = map[string]CoverageClass{}
					}
					overrides[k][profile] = ov.Class
				}
			}
		}
	}
	if len(overrides) == 0 {
		t.Fatal("no profile-scoped coverage overrides in the committed ledger — #611 scoped four endpoint groups under prod")
	}

	for _, profile := range KnownProbeProfiles() {
		ix := ledger.Index(profile)
		for k, wantBase := range base {
			got, _, found := ix.Classify(k.endpoint, k.path)
			if !found {
				t.Errorf("profile %q: %s %q vanished from the index", profile, k.endpoint, k.path)
				continue
			}
			want := wantBase
			if ov, ok := overrides[k][profile]; ok {
				want = ov
			}
			if got != want {
				t.Errorf("profile %q: %s %q resolved to %q, want %q (overrides: %v)",
					profile, k.endpoint, k.path, got, want, overrides[k])
			}
		}
	}
}

// An empty profile - no --profile passed - resolves to the BASE class on every
// entry. It must never pick up an override: a local run with no target named is
// not a claim about any target, and silently inheriting one profile's scoping
// would make an ad-hoc run disagree with CI for no visible reason.
func TestCoverageIndexEmptyProfileIsBase(t *testing.T) {
	ledger, err := LoadCoverageLedger(coverageLedgerTestPath)
	if err != nil {
		t.Fatalf("LoadCoverageLedger: %v", err)
	}
	ix := ledger.Index("")
	for endpoint, cov := range ledger {
		for _, e := range cov.Required {
			if len(e.Profiles) == 0 {
				continue
			}
			class, _, found := ix.Classify(endpoint, e.Path)
			if !found || class != CoverageRequired {
				t.Errorf("%s %q with an empty profile = (%q,%v), want (required,true)", endpoint, e.Path, class, found)
			}
		}
	}
}

// The committed ledger must stay honest: every entry has to name a real
// endpoint and match at least one path in that endpoint's DERIVED schema, so a
// struct rename cannot leave a dead required entry silently protecting nothing.
func TestCommittedCoverageLedgerIntegrity(t *testing.T) {
	ledger, err := LoadCoverageLedger(coverageLedgerTestPath)
	if err != nil {
		t.Fatalf("LoadCoverageLedger: %v", err)
	}
	if len(ledger) == 0 {
		t.Fatal("the committed coverage ledger is empty")
	}

	schemas, err := AllEndpointSchemas()
	if err != nil {
		t.Fatalf("AllEndpointSchemas: %v", err)
	}
	byEndpoint := make(map[string]EndpointSchema, len(schemas))
	for _, s := range schemas {
		byEndpoint[s.Endpoint] = s
	}

	for endpoint, cov := range ledger {
		s, ok := byEndpoint[endpoint]
		if !ok {
			t.Errorf("%s: not a known endpoint schema", endpoint)
			continue
		}
		seen := map[string]bool{}
		check := func(class CoverageClass, entries []CoveragePath) {
			for _, e := range entries {
				if e.Path == "" {
					t.Errorf("%s: a %s entry has no path", endpoint, class)
					continue
				}
				if seen[e.Path] {
					t.Errorf("%s %s: path %q is listed twice", endpoint, class, e.Path)
				}
				seen[e.Path] = true

				set := compilePathSet([]string{e.Path})
				var matched []SchemaField
				for _, f := range s.Fields {
					if f.Path == e.Path || set.has(f.Path) {
						matched = append(matched, f)
					}
				}
				if len(matched) == 0 {
					t.Errorf("%s %s: path %q matches no field in the derived schema", endpoint, class, e.Path)
					continue
				}
				// Opaque marks a path the live canary can NEVER verify
				// structurally: the schema models it as KindAny. It must be
				// declared iff that is true, so nobody can add an inert
				// required entry (or forget to flag a real blind spot).
				exactKindAny := len(matched) == 1 && matched[0].Path == e.Path && matched[0].Kind == KindAny
				if e.Opaque != exactKindAny {
					t.Errorf("%s %s %q: opaque=%v but the schema field is %v (opaque must be set iff the exact path is kind %q)",
						endpoint, class, e.Path, e.Opaque, matched[0].Kind, KindAny)
				}

				switch class {
				case CoverageRequired:
					if len(e.Metrics) == 0 {
						t.Errorf("%s required %q: no metric family named", endpoint, e.Path)
					}
					for _, m := range e.Metrics {
						if !strings.HasPrefix(m, "opnsense_") {
							t.Errorf("%s required %q: %q is not an exporter metric name", endpoint, e.Path, m)
						}
					}
					if e.Exercise == "" {
						t.Errorf("%s required %q: no testbed exercise recipe", endpoint, e.Path)
					}
					// Every required path is either currently observed or has a
					// named blocker. Neither means an unexplained required path,
					// which is the anonymous count this ledger replaces.
					if e.Blocker == "" && e.Verified == "" {
						t.Errorf("%s required %q: neither a blocker nor a verified note", endpoint, e.Path)
					}
				case CoverageStateOptional:
					if e.Reason == "" {
						t.Errorf("%s stateOptional %q: no reason", endpoint, e.Path)
					}
					if e.PruneTrigger == "" {
						t.Errorf("%s stateOptional %q: no prune trigger", endpoint, e.Path)
					}
				}

				// A per-profile override carries the SAME burden of proof as a
				// base stateOptional entry, and for the same reason (#611): the
				// class exists so it cannot quietly become a dumping ground. An
				// override with no reason is an unexplained blind spot on one
				// target, which is harder to notice than a base one because two
				// other profiles keep verifying the path and the ledger looks
				// healthy.
				for profile, ov := range e.Profiles {
					if !slices.Contains(KnownProbeProfiles(), profile) {
						t.Errorf("%s %s %q: override names unknown profile %q, want one of %v",
							endpoint, class, e.Path, profile, KnownProbeProfiles())
					}
					switch ov.Class {
					case CoverageRequired, CoverageStateOptional:
					default:
						t.Errorf("%s %s %q: override for %q has class %q, want %q or %q",
							endpoint, class, e.Path, profile, ov.Class, CoverageRequired, CoverageStateOptional)
					}
					if ov.Class == class {
						t.Errorf("%s %s %q: override for %q re-states the base class %q, so it does nothing",
							endpoint, class, e.Path, profile, class)
					}
					if ov.Reason == "" {
						t.Errorf("%s %s %q: override for %q has no reason", endpoint, class, e.Path, profile)
					}
					if ov.PruneTrigger == "" {
						t.Errorf("%s %s %q: override for %q has no prune trigger", endpoint, class, e.Path, profile)
					}
				}
			}
		}
		check(CoverageRequired, cov.Required)
		check(CoverageStateOptional, cov.StateOptional)
	}
}

// The ledger is committed to a public repo. Identities cannot get in via a
// PATH by construction — TestCommittedCoverageLedgerIntegrity requires every
// path to match a DERIVED schema path, and those carry "*" where a Go map's
// dynamic keys live. What that invariant does not cover is somebody pasting a
// capture, an address or a credential into a note, exercise recipe or blocker,
// so guard the free-text prose directly.
//
// The check is deliberately shape-based, not a banned-word list: the ledger has
// to be able to SAY "a setup key must never enter this file" without tripping
// its own guard.
func TestCommittedCoverageLedgerCarriesNoValues(t *testing.T) {
	raw, err := os.ReadFile(coverageLedgerTestPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	body := string(raw)
	for name, re := range map[string]*regexp.Regexp{
		"an IPv4 literal":        regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
		"an IPv6 literal":        regexp.MustCompile(`\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){3,}`),
		"a MAC address":          regexp.MustCompile(`\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`),
		"a PEM block":            regexp.MustCompile(`-----BEGIN`),
		"an Authorization value": regexp.MustCompile(`(?i)bearer [A-Za-z0-9._-]+`),
	} {
		if m := re.FindString(body); m != "" {
			t.Errorf("ledger carries %s (%q) — structure and prose only", name, m)
		}
	}
	if strings.Contains(body, "\"value\"") {
		t.Error("ledger has a \"value\" field — the ledger records paths, never payload values")
	}
}
