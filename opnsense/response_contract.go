package opnsense

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ResponseValidator decodes a captured raw API response and reports whether the
// data the exporter relies on actually came through. It returns a descriptive
// error when the payload shape drifted in a way that breaks extraction — the
// class of change the endpoint-manifest canary (cmd/apicontract) cannot see,
// because the endpoint path and HTTP verb are unchanged (e.g. OPNsense 26.1
// moving per-subsystem health into a top-level "subsystems" map).
type ResponseValidator func(raw []byte) error

// ResponseContract pins one endpoint's response shape. KnownTopLevelKeys is the
// set of top-level JSON object keys the exporter expects — a key outside this set
// is a drift signal (it is how 26.1's "subsystems" data first appeared). Validate
// asserts the consumed fields decode into usable values.
type ResponseContract struct {
	Endpoint          EndpointName
	FixtureGlobs      []string
	KnownTopLevelKeys []string
	Validate          ResponseValidator
}

// Fixtures resolves FixtureGlobs to the set of captured response files. Globs are
// relative to the package directory (where the test runs).
func (c ResponseContract) Fixtures() ([]string, error) {
	var out []string
	for _, g := range c.FixtureGlobs {
		m, err := filepath.Glob(g)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", g, err)
		}
		out = append(out, m...)
	}
	return out, nil
}

// UnknownTopLevelKeys returns the top-level JSON object keys in raw that are not
// in KnownTopLevelKeys (case-insensitive, matching Go's json field matching). A
// non-empty result means OPNsense returned data at a key the exporter does not
// model — a payload-shape drift signal.
func (c ResponseContract) UnknownTopLevelKeys(raw []byte) ([]string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("decode top-level object: %w", err)
	}
	known := make(map[string]bool, len(c.KnownTopLevelKeys))
	for _, k := range c.KnownTopLevelKeys {
		known[strings.ToLower(k)] = true
	}
	var unknown []string
	for k := range top {
		if !known[strings.ToLower(k)] {
			unknown = append(unknown, k)
		}
	}
	return unknown, nil
}

// ResponseContracts returns the registry of response-shape contracts. Grow it by
// capturing a real-box response (`just capture`) and adding an entry here.
func ResponseContracts() []ResponseContract {
	return []ResponseContract{
		{
			Endpoint:          "healthCheck",
			FixtureGlobs:      []string{"testdata/health/*.json", "testdata/captures/healthCheck*.json"},
			KnownTopLevelKeys: []string{"System", "CrashReporter", "Firewall", "metadata", "subsystems"},
			Validate:          validateHealthResponse,
		},
		{
			Endpoint:          "gatewaysStatus",
			FixtureGlobs:      []string{"testdata/gateways/*.json", "testdata/captures/gatewaysStatus*.json"},
			KnownTopLevelKeys: []string{"total", "rowCount", "current", "rows"},
			Validate:          validateGatewaysResponse,
		},
		{
			Endpoint:          "pfStates",
			FixtureGlobs:      []string{"testdata/pf_states/*.json", "testdata/captures/pfStates*.json"},
			KnownTopLevelKeys: []string{"current", "limit"},
			Validate:          validatePFStatesResponse,
		},
		{
			Endpoint:          "unboundDNSStatus",
			FixtureGlobs:      []string{"testdata/unbound/*.json", "testdata/captures/unboundDNSStatus*.json"},
			KnownTopLevelKeys: []string{"status", "data"},
			Validate:          validateUnboundResponse,
		},
		{
			Endpoint:     "firmware",
			FixtureGlobs: []string{"testdata/firmware/*.json", "testdata/captures/firmware*.json"},
			KnownTopLevelKeys: []string{
				"status", "last_check", "needs_reboot", "os_version", "product_id",
				"product_version", "product_abi", "new_packages", "upgrade_packages", "product",
			},
			Validate: validateFirmwareResponse,
		},
	}
}

// validateGatewaysResponse asserts the gateway search envelope decodes and each row's
// consumed fields (name + status) come through — a rename of `rows`/`name`/`status`
// would otherwise silently yield zero gateways with no error.
func validateGatewaysResponse(raw []byte) error {
	var resp gatewayConfigurationResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode gatewayConfigurationResponse: %w", err)
	}
	if resp.Total > 0 && len(resp.Rows) == 0 {
		return fmt.Errorf("total=%d but rows decoded empty — the `rows` field may have moved/renamed", resp.Total)
	}
	for _, r := range resp.Rows {
		if r.Name == "" {
			return fmt.Errorf("a gateway row decoded with an empty name — the `name` field may have moved/renamed")
		}
	}
	return nil
}

// validatePFStatesResponse asserts the current/limit fields decode into usable numbers.
func validatePFStatesResponse(raw []byte) error {
	var resp pfStatesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode pfStatesResponse: %w", err)
	}
	if resp.Current == "" && resp.Limit == "" {
		return fmt.Errorf("both current and limit decoded empty — the pf_states fields may have moved/renamed")
	}
	return nil
}

// validateUnboundResponse asserts the status + data envelope decodes and, for an
// ok status, the query totals are reachable (the fields the collector consumes).
func validateUnboundResponse(raw []byte) error {
	var resp unboundDNSStatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode unboundDNSStatusResponse: %w", err)
	}
	if resp.Status == "" {
		return fmt.Errorf("unbound response has no top-level status — the `status` field may have moved/renamed")
	}
	return nil
}

// validateFirmwareResponse asserts the firmware status envelope decodes and the
// consumed status/version fields are present.
func validateFirmwareResponse(raw []byte) error {
	var resp firmwareStatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode firmwareStatusResponse: %w", err)
	}
	if resp.Status == "" {
		return fmt.Errorf("firmware response has no top-level status — the `status` field may have moved/renamed")
	}
	return nil
}

// validateHealthResponse asserts the system-status response yields a usable
// overall status and that any reported subsystem problem is actually consumed —
// the two ways the 26.1 shape change silently broke extraction.
func validateHealthResponse(raw []byte) error {
	var resp HealthCheckResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode HealthCheckResponse: %w", err)
	}

	// The rolled-up overall status must be resolvable. A non-empty, non-numeric
	// metadata.system.status that maps to no known SystemStatusCode enum is the
	// exact 26.1 drift ("ERROR") that silently resolved to 0 before the fix.
	if s, ok := resp.Metadata.System.Status.(string); ok && s != "" {
		if _, err := strconv.Atoi(s); err != nil {
			if _, known := systemStatusStringToCode(s); !known {
				return fmt.Errorf("metadata.system.status %q is neither numeric nor a known SystemStatusCode enum "+
					"(OK/NOTICE/WARNING/ERROR) — the overall status would silently resolve to 0", s)
			}
		}
	}

	// Any per-subsystem entry reporting a problem must be reflected by the matching
	// accessor; otherwise the exporter is decoding the payload but dropping the
	// status (a false-OK, like 26.1 crash_reporter_status before the fix).
	for name, entry := range resp.Subsystems {
		if entry.isHealthy() {
			continue
		}
		switch name {
		case SubsystemCrashReporter:
			if resp.CrashReporterIsHealthy() {
				return fmt.Errorf("subsystems.crashreporter status %q is not OK but CrashReporterIsHealthy() reports healthy (status not consumed)", entry.Status)
			}
		case SubsystemFirewall:
			if resp.FirewallIsHealthy() {
				return fmt.Errorf("subsystems.firewall status %q is not OK but FirewallIsHealthy() reports healthy (status not consumed)", entry.Status)
			}
		}
	}
	return nil
}
