package main

import "testing"

func TestLoadUpstream(t *testing.T) {
	ups, err := loadUpstream("testdata/upstream_min.json")
	if err != nil {
		t.Fatalf("loadUpstream: %v", err)
	}
	if len(ups) != 4 {
		t.Fatalf("expected 4 upstream endpoints, got %d", len(ups))
	}
	if ups[0].Path != "api/core/service/search" {
		t.Errorf("unexpected first path %q", ups[0].Path)
	}
}

func ups() []UpstreamEndpoint {
	u, _ := loadUpstream("testdata/upstream_min.json")
	return u
}

func TestDiffExactMatchNoFindings(t *testing.T) {
	ours := []Endpoint{{Name: "services", Path: "api/core/service/search", Method: "GET"}}
	rep := Diff(ours, ups(), nil)
	if len(rep.Errors) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("expected no findings, got errors=%v warnings=%v", rep.Errors, rep.Warnings)
	}
}

func TestDiffPositionalSuffixMatches(t *testing.T) {
	// Our path carries a positional arg the controller/command does not.
	ours := []Endpoint{{Name: "pfStates", Path: "api/diagnostics/firewall/pf_states/1", Method: "GET"}}
	rep := Diff(ours, ups(), nil)
	if len(rep.Errors) != 0 {
		t.Fatalf("expected suffix match, got errors=%v", rep.Errors)
	}
}

func TestDiffMissingPathIsError(t *testing.T) {
	ours := []Endpoint{{Name: "ghost", Path: "api/core/service/gone", Method: "GET"}}
	rep := Diff(ours, ups(), nil)
	if len(rep.Errors) != 1 || rep.Errors[0].Endpoint != "ghost" {
		t.Fatalf("expected 1 missing-path error, got %v", rep.Errors)
	}
}

func TestDiffVerbMismatchIsWarning(t *testing.T) {
	// We GET an endpoint the source advertises as POST-only.
	ours := []Endpoint{{Name: "firewallRules", Path: "api/firewall/filter/search_rule", Method: "GET"}}
	rep := Diff(ours, ups(), nil)
	if len(rep.Errors) != 0 {
		t.Fatalf("verb drift must not be an error, got %v", rep.Errors)
	}
	if len(rep.Warnings) != 1 || rep.Warnings[0].Endpoint != "firewallRules" {
		t.Fatalf("expected 1 verb warning, got %v", rep.Warnings)
	}
}

func TestDiffExemptEndpointSkipped(t *testing.T) {
	ours := []Endpoint{{Name: "firmware", Path: "api/core/firmware/status", Method: "GET"}}
	rep := Diff(ours, ups(), map[string]bool{"firmware": true})
	if len(rep.Errors) != 0 {
		t.Fatalf("exempt endpoint must not error, got %v", rep.Errors)
	}
}

func TestDiffSnakeCaseMatchesCamelCase(t *testing.T) {
	// Our map uses camelCase commands; OPNsense's parser emits snake_case. They
	// must compare equal after normalization (no false "missing" finding).
	ups := []UpstreamEndpoint{
		{Module: "routing", Controller: "settings", Command: "search_gateway", Methods: []string{"GET"}, Path: "api/routing/settings/search_gateway"},
		{Module: "diagnostics", Controller: "system", Command: "system_disk", Methods: []string{"GET"}, Path: "api/diagnostics/system/system_disk"},
	}
	ours := []Endpoint{
		{Name: "gatewaysStatus", Path: "api/routing/settings/searchGateway", Method: "GET"},
		{Name: "systemDisk", Path: "api/diagnostics/system/systemDisk", Method: "GET"},
	}
	rep := Diff(ours, ups, nil)
	if len(rep.Errors) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("camelCase vs snake_case must match cleanly, got errors=%v warnings=%v", rep.Errors, rep.Warnings)
	}
}

func TestDiffPostAgainstGetSourceIsSilent(t *testing.T) {
	// We POST to an endpoint the parser labels GET-only. This is the noisy
	// direction (parser under-reports POST for search endpoints) and must NOT warn.
	ups := []UpstreamEndpoint{
		{Module: "firewall", Controller: "filter", Command: "search_rule", Methods: []string{"GET"}, Path: "api/firewall/filter/search_rule"},
	}
	ours := []Endpoint{{Name: "firewallRules", Path: "api/firewall/filter/search_rule", Method: "POST"}}
	rep := Diff(ours, ups, nil)
	if len(rep.Errors) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("POST-vs-GET-source must be silent, got errors=%v warnings=%v", rep.Errors, rep.Warnings)
	}
}

func TestDiffNoFalsePrefixMatch(t *testing.T) {
	// "search" must NOT match "search_rule" (only a "/" boundary counts).
	ours := []Endpoint{{Name: "x", Path: "api/firewall/filter/search_rule_extra", Method: "GET"}}
	rep := Diff(ours, ups(), nil)
	// search_rule is present; search_rule_extra is a different command -> error.
	if len(rep.Errors) != 1 {
		t.Fatalf("expected error for non-existent command, got %v", rep.Errors)
	}
}
