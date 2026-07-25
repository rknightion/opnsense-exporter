package opnsense

import (
	"os"
	"path/filepath"
	"regexp"
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
	}.Index()

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
