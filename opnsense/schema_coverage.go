package opnsense

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// The live-box coverage ledger (#377).
//
// ValidateResponseSchema files a path it could not reach — because the array
// above it was empty, the map was empty, or the value was null — into
// Unverified. That is box state, not drift, so it deliberately never makes a
// result unclean. The problem the ledger solves is the other half: a path that
// backs an exported metric and is NEVER exercised is source-derived, possibly
// wrong, and permanently green in CI, and "20 endpoints have unverifiable
// paths" gives nobody anything to act on.
//
// So the ledger classifies selected endpoint/path pairs into exactly two
// classes and nothing else is reclassified: an unledgered unverified path stays
// informational, as it was.
//
//   - required — the path backs an emitted metric, so the canary is EXPECTED to
//     exercise it. While it is unverified the run warns, and the report names
//     the metric it protects, how to exercise it on the testbed, and the current
//     blocker. Warning-level, never breaking.
//   - stateOptional — legitimate hardware/licence/topology state a VM cannot
//     produce (a PSU rail, a GPS receiver, SFP diagnostics, ZFS ARC, a
//     temperature sensor). Informational, with a reason and a prune trigger, so
//     the class cannot quietly become a dumping ground.
//
// A ledger path is a NORMALIZED schema path — array elements are "[]" and a Go
// map's dynamic keys are "*" — exactly as reported by the validator, so no
// hostname, peer identity or interface name can enter the ledger. It takes the
// same two forms as a MissingOK entry: an exact path, or a "prefix.*" subtree.

// CoverageClass is a ledgered path's class.
type CoverageClass string

const (
	// CoverageRequired marks a metric-bearing path the canary must exercise.
	CoverageRequired CoverageClass = "required"
	// CoverageStateOptional marks state the testbed legitimately cannot produce.
	CoverageStateOptional CoverageClass = "stateOptional"
)

// CoveragePath is one ledger entry. Metrics/Exercise are mandatory on a
// required entry; Reason/PruneTrigger are mandatory on a stateOptional one
// (enforced by TestCommittedCoverageLedgerIntegrity, not by the loader — a
// half-filled ledger must fail CI loudly, not be silently accepted at canary
// runtime).
type CoveragePath struct {
	Path string `json:"path"`

	// Metrics names the metric families the path backs, e.g.
	// "opnsense_netbird_peer_connected". Required entries only.
	Metrics []string `json:"metrics,omitempty"`
	// Exercise is a concise, reproducible recipe for making the testbed produce
	// the state. Required entries only.
	Exercise string `json:"exercise,omitempty"`
	// Blocker names what currently stops the path from being observed. It is
	// documentary and does NOT suppress the warning: the point of the ledger is
	// a NAMED blocker instead of an anonymous count.
	Blocker string `json:"blocker,omitempty"`
	// Verified records when and in what box state the path was last observed
	// live. A required entry carries a Blocker or a Verified note (or both, when
	// the state is not durable) so no required path is ever unexplained — and
	// so a path can move from unresolved to resolved by editing THIS field
	// alone, with no schema or code change.
	Verified string `json:"verified,omitempty"`
	// Opaque records that the endpoint's schema models this path as KindAny, so
	// the live canary can never verify its inner structure whatever the box
	// does. Such an entry is reported as a standing blind spot rather than a
	// warning — a warning no live run can ever clear is exactly the permanent
	// noise this ledger exists to avoid.
	Opaque bool `json:"opaque,omitempty"`

	// Reason explains why the state is legitimately absent. stateOptional only.
	Reason string `json:"reason,omitempty"`
	// PruneTrigger names the change that should delete the entry. stateOptional
	// only.
	PruneTrigger string `json:"pruneTrigger,omitempty"`
}

// EndpointCoverage is one endpoint's ledger section.
type EndpointCoverage struct {
	Required      []CoveragePath `json:"required,omitempty"`
	StateOptional []CoveragePath `json:"stateOptional,omitempty"`
	Note          string         `json:"note,omitempty"`
}

// CoverageLedger is the committed opnsense/testdata/schemas/coverage.json,
// keyed by endpoint name — the same shape and loading contract as
// exemptions.json.
type CoverageLedger map[string]EndpointCoverage

// LoadCoverageLedger reads the committed ledger. A missing file is an empty
// ledger, not an error (mirroring the exemptions loader), so the canary still
// runs on a checkout that predates the file. Malformed JSON IS an error: a
// silently-ignored ledger would turn every required path informational again.
func LoadCoverageLedger(path string) (CoverageLedger, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return CoverageLedger{}, nil
		}
		return nil, err
	}
	out := CoverageLedger{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

// coverageMatcher is one compiled ledger entry.
type coverageMatcher struct {
	set   pathSet
	class CoverageClass
	entry CoveragePath
}

// CoverageIndex is the compiled ledger: per endpoint, its entries in
// required-then-stateOptional order.
type CoverageIndex map[string][]coverageMatcher

// Index compiles the ledger for lookup. Required entries come first so a path
// listed in both classes resolves as required — the stricter reading — though
// the integrity test rejects that ledger anyway.
func (l CoverageLedger) Index() CoverageIndex {
	ix := make(CoverageIndex, len(l))
	for endpoint, cov := range l {
		matchers := make([]coverageMatcher, 0, len(cov.Required)+len(cov.StateOptional))
		for _, e := range cov.Required {
			matchers = append(matchers, coverageMatcher{set: compilePathSet([]string{e.Path}), class: CoverageRequired, entry: e})
		}
		for _, e := range cov.StateOptional {
			matchers = append(matchers, coverageMatcher{set: compilePathSet([]string{e.Path}), class: CoverageStateOptional, entry: e})
		}
		ix[endpoint] = matchers
	}
	return ix
}

// LedgerEntry is one compiled ledger entry with the endpoint and class it was
// filed under, for callers that need to enumerate the ledger rather than look a
// path up in it (the report's standing-blind-spot section).
type LedgerEntry struct {
	CoveragePath
	Endpoint string
	Class    CoverageClass
}

// Entries returns every ledger entry, sorted by endpoint then path, so a
// ledger-driven report section is deterministic.
func (ix CoverageIndex) Entries() []LedgerEntry {
	var out []LedgerEntry
	for endpoint, matchers := range ix {
		for _, m := range matchers {
			out = append(out, LedgerEntry{CoveragePath: m.entry, Endpoint: endpoint, Class: m.class})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// Classify resolves one endpoint/path pair against the ledger. The path must be
// a normalized schema path as reported in ValidationResult.Unverified. A pair
// that is not ledgered returns found=false and stays informational.
func (ix CoverageIndex) Classify(endpoint, path string) (CoverageClass, CoveragePath, bool) {
	for _, m := range ix[endpoint] {
		if m.entry.Path == path || m.set.has(path) {
			return m.class, m.entry, true
		}
	}
	return "", CoveragePath{}, false
}
