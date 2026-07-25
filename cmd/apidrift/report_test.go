package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

func TestAggregateSeverity(t *testing.T) {
	cases := []struct {
		name         string
		results      []probeResult
		wantDrift    bool
		wantWarnings bool
	}{
		{"clean", []probeResult{{Endpoint: "a"}}, false, false},
		{"mismatch is drift", []probeResult{{Endpoint: "a", Res: opnsense.ValidationResult{Mismatches: []opnsense.Mismatch{{Path: "x"}}}}}, true, false},
		{"missing is warning", []probeResult{{Endpoint: "a", Res: opnsense.ValidationResult{Missing: []string{"x"}}}}, false, true},
		{"unknown key is warning", []probeResult{{Endpoint: "a", Res: opnsense.ValidationResult{UnknownTopKeys: []string{"x"}}}}, false, true},
		// Report-only during the #376 baseline: nested extras render in full but
		// must NOT raise a warning, or the 1003 paths the first live run found
		// would keep the drift issue permanently open. #457 triages them and
		// then flips this to (false, true).
		{"unknown nested path is report-only, not a warning", []probeResult{{Endpoint: "a", Res: opnsense.ValidationResult{UnknownPaths: []string{"rows[].x"}}}}, false, false},
		{"core 404 is warning", []probeResult{{Endpoint: "a", Absent: true}}, false, true},
		{"plugin-gated 404 is not a warning", []probeResult{{Endpoint: "siproxdRegistrations", Absent: true}}, false, false},
		{"probe error is warning", []probeResult{{Endpoint: "a", ProbeErr: "boom"}}, false, true},
		{"skipped param is warning", []probeResult{{Endpoint: "a", SkippedParam: true}}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drift, warnings := aggregate(tc.results)
			if drift != tc.wantDrift || warnings != tc.wantWarnings {
				t.Errorf("aggregate = (%v,%v), want (%v,%v)", drift, warnings, tc.wantDrift, tc.wantWarnings)
			}
		})
	}
}

// The report must carry structure only: endpoint names, paths, kinds — and it
// must not echo anything that could be a payload value.
func TestRenderReportStructureOnly(t *testing.T) {
	results := []probeResult{
		{
			Endpoint: "gatewaysStatus",
			Path:     "api/routing/settings/searchGateway",
			Res: opnsense.ValidationResult{
				Mismatches:     []opnsense.Mismatch{{Path: "rows[].status", Expected: opnsense.KindString, Got: "number"}},
				Missing:        []string{"rows[].delay"},
				UnknownTopKeys: []string{"newkey"},
			},
		},
		{Endpoint: "chrony", Path: "api/chrony/service/status", Absent: true, Status: 404},
		{Endpoint: "smartInfo", SkippedParam: true},
	}
	report := renderReport(results, map[string]string{"exempted": "reason"})

	for _, want := range []string{
		"rows[].status", "expected string, live box serves number",
		"rows[].delay", "newkey", "chrony", "404", "smartInfo",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

// Nested unexpected keys (#376) get their own section, printed as normalized
// paths.
func TestRenderReportUnknownNestedPaths(t *testing.T) {
	report := renderReport([]probeResult{{
		Endpoint: "protocolStatistics",
		Res:      opnsense.ValidationResult{UnknownPaths: []string{"byName.*.new_field", "statistics.tcp.new-counter"}},
	}}, nil)

	for _, want := range []string{
		"statistics.tcp.new-counter", "byName.*.new_field", "protocolStatistics",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
	if !strings.Contains(report, "1 with unexpected nested keys") {
		t.Errorf("headline should count nested-key endpoints:\n%s", report)
	}
}

// The report is a PUBLIC issue body. Drive a real validation over a payload
// whose every scalar is a sentinel, then assert not one sentinel — value or
// dynamic-map identity — reaches the rendered markdown. Only key names, JSON
// type names, endpoint names and HTTP statuses may appear.
func TestRenderReportNeverEchoesResponseValues(t *testing.T) {
	s := opnsense.EndpointSchema{
		Endpoint:          "sentinel",
		Method:            "GET",
		Path:              "api/sentinel/test/get",
		TopLevelKind:      opnsense.KindObject,
		KnownTopLevelKeys: []string{"byName", "rows", "status"},
		Fields: []opnsense.SchemaField{
			{Path: "byName", Kind: opnsense.KindObject},
			{Path: "byName.*", Kind: opnsense.KindObject},
			{Path: "byName.*.state", Kind: opnsense.KindString},
			{Path: "rows", Kind: opnsense.KindArray},
			{Path: "rows[]", Kind: opnsense.KindObject},
			{Path: "rows[].name", Kind: opnsense.KindString},
			{Path: "rows[].size", Kind: opnsense.KindNumber},
			{Path: "status", Kind: opnsense.KindString},
		},
	}
	// Every scalar and every dynamic-map identity is a sentinel. rows[].size is
	// retyped (breaking), rows[].name is renamed (missing), plus a new nested key
	// and a new root key.
	raw := []byte(`{
		"status":"SENTINELSTATUS",
		"rows":[{"label":"SENTINELNAME","size":"SENTINELSIZE","new_health":"SENTINELHEALTH"}],
		"byName":{"SENTINELIDENTITY":{"state":"SENTINELSTATE","new_field":"SENTINELFIELD"}},
		"SENTINELROOTKEY":{"inner":"SENTINELINNER"}
	}`)
	vr, err := opnsense.ValidateResponseSchema(s, raw, opnsense.SchemaExemption{})
	if err != nil {
		t.Fatalf("ValidateResponseSchema: %v", err)
	}
	if len(vr.UnknownPaths) == 0 || len(vr.Mismatches) == 0 || len(vr.Missing) == 0 {
		t.Fatalf("fixture must produce all three signals, got %+v", vr)
	}

	report := renderReport([]probeResult{
		{Endpoint: s.Endpoint, Path: s.Path, Status: 200, Res: vr},
		{Endpoint: "othererr", ProbeErr: "HTTP 500", Status: 500},
	}, map[string]string{"exempted": "reason"})

	for _, leak := range []string{
		"SENTINELSTATUS", "SENTINELNAME", "SENTINELSIZE", "SENTINELHEALTH",
		"SENTINELIDENTITY", "SENTINELSTATE", "SENTINELFIELD", "SENTINELINNER",
	} {
		if strings.Contains(report, leak) {
			t.Errorf("report echoed response value %q:\n%s", leak, report)
		}
	}
	// The structural findings themselves must still be there.
	for _, want := range []string{"rows[].new_health", "byName.*.new_field", "SENTINELROOTKEY"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing structural finding %q:\n%s", want, report)
		}
	}
}

// withTestCoverageLedger points the report/aggregate ledger lookup at a
// temporary ledger for the duration of one test.
func withTestCoverageLedger(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "coverage.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := coverageLedgerPath
	coverageLedgerPath = p
	t.Cleanup(func() { coverageLedgerPath = prev })
}

const testLedger = `{
  "epA": {
    "required": [
      {"path":"rows[].addr","metrics":["opnsense_x_lease_info"],"exercise":"take a lease","blocker":"no client on the testbed"},
      {"path":"response","opaque":true,"metrics":["opnsense_x_area_lsa_count"],"exercise":"bring up an adjacency","blocker":"no v6 stack in the lab"}
    ],
    "stateOptional": [
      {"path":"sensors.*","reason":"no thermal sensor on a VM","pruneTrigger":"canary moves to metal"}
    ]
  }
}`

// Only an UNRESOLVED required path is warning-level. State-optional,
// unledgered and structurally-opaque paths stay informational — a warning no
// live run could ever clear is the permanent noise the ledger exists to avoid.
func TestAggregateCoverageSeverity(t *testing.T) {
	withTestCoverageLedger(t, testLedger)

	cases := []struct {
		name         string
		results      []probeResult
		wantWarnings bool
	}{
		{"required path unverified warns", []probeResult{{Endpoint: "epA", Res: opnsense.ValidationResult{Unverified: []string{"rows[].addr"}}}}, true},
		{"required path verified is silent", []probeResult{{Endpoint: "epA"}}, false},
		{"opaque required path does not warn", []probeResult{{Endpoint: "epA", Res: opnsense.ValidationResult{Unverified: []string{"response"}}}}, false},
		{"state-optional path does not warn", []probeResult{{Endpoint: "epA", Res: opnsense.ValidationResult{Unverified: []string{"sensors.psu"}}}}, false},
		{"unledgered path does not warn", []probeResult{{Endpoint: "epA", Res: opnsense.ValidationResult{Unverified: []string{"rows[].other"}}}}, false},
		{"same path on another endpoint does not warn", []probeResult{{Endpoint: "epB", Res: opnsense.ValidationResult{Unverified: []string{"rows[].addr"}}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drift, warnings := aggregate(tc.results)
			if drift {
				t.Error("coverage must never be breaking drift")
			}
			if warnings != tc.wantWarnings {
				t.Errorf("warnings = %v, want %v", warnings, tc.wantWarnings)
			}
		})
	}
}

// Unverified paths are rendered per path, split by coverage class, and never as
// a bare count.
func TestRenderReportUnverifiedPathsPerPath(t *testing.T) {
	withTestCoverageLedger(t, testLedger)

	report := renderReport([]probeResult{
		{Endpoint: "epA", Res: opnsense.ValidationResult{Unverified: []string{
			"rows[].addr", "sensors.psu", "rows[].other",
		}}},
		{Endpoint: "epB", Res: opnsense.ValidationResult{Unverified: []string{"stats.*"}}},
	}, nil)

	for _, want := range []string{
		// required: path, metric family and the named blocker
		"`epA` `rows[].addr`", "opnsense_x_lease_info", "no client on the testbed",
		// state-optional: path plus its reason
		"`epA` `sensors.psu`", "no thermal sensor on a VM",
		// unledgered, still named rather than counted
		"`epA` `rows[].other`", "`epB` `stats.*`",
		// standing blind spot, listed from the ledger even though the run did
		// not report it unverified
		"`epA` `response`", "opnsense_x_area_lsa_count",
		// the aggregate count stays as the headline
		"2 endpoints have paths that could not be verified",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

// A path repeated in one endpoint's unverified list is ONE report line.
func TestRenderReportUnverifiedPathsDeduplicate(t *testing.T) {
	withTestCoverageLedger(t, testLedger)

	report := renderReport([]probeResult{{Endpoint: "epA", Res: opnsense.ValidationResult{
		Unverified: []string{"rows[].addr", "rows[].addr", "rows[].other", "rows[].other"},
	}}}, nil)

	for _, line := range []string{"`epA` `rows[].addr`", "`epA` `rows[].other`"} {
		if n := strings.Count(report, line); n != 1 {
			t.Errorf("line %q appears %d times, want 1:\n%s", line, n, report)
		}
	}
}

// Empty sections must not leave dangling headers.
func TestRenderReportCleanRun(t *testing.T) {
	report := renderReport([]probeResult{{Endpoint: "a"}, {Endpoint: "b"}}, nil)
	if strings.Contains(report, "###") {
		t.Errorf("clean report should have no drift sections:\n%s", report)
	}
	if !strings.Contains(report, "2 clean") {
		t.Errorf("clean report should count clean endpoints:\n%s", report)
	}
}
