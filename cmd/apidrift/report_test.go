package main

import (
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
		{"404 is warning", []probeResult{{Endpoint: "a", Absent: true}}, false, true},
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
