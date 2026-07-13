package opnsense

// The four MVC-managed NAT rule types each have their own
// Firewall/Api/*Controller (SourceNatController, DNatController,
// OneToOneController, NptController), all sharing FilterBaseController's
// generic searchRuleAction bootgrid response. Only the enabled/disabled state
// is needed for the inventory-count metric, so these are narrow row
// structs — no source/destination/target fields are captured, since those
// can carry LAN topology details (internal IPs, port-forward targets) that
// don't belong in a metric label.
//
// GOTCHA (confirmed against a live OPNsense 26.7-devel box, #221): the four
// NAT rule types do NOT share one field name for their enabled/disabled
// state.
//   - source_nat, one_to_one and npt rows carry "enabled" ("1" = enabled),
//     matching the regular filter-rule convention (see firewallRule in
//     firewall_rules.go).
//   - d_nat (destination NAT / port forward) rows carry "disabled" instead
//     ("1" = disabled): the DNat MVC model (Firewall/DNat.xml) literally names
//     the field "disabled", mirroring the GUI's "Disabled" checkbox column.
//
// This is permanent upstream API shape, not a cross-version drift — each row
// type gets its own struct below so every endpoint's registered schema only
// declares the field that endpoint actually serves.
type natRuleRow struct {
	Enabled flexString `json:"enabled"`
}

// isEnabled reports the row's enabled state for the "enabled"-field NAT
// types (source_nat, one_to_one, npt). Only an explicit "1" counts as
// enabled; missing/empty/other -> disabled (mirrors firewallRule.Enabled
// handling in firewall_rules.go).
func (r natRuleRow) isEnabled() bool {
	return r.Enabled.String() == "1"
}

// natRuleRowDisabled is the d_nat (port forward) row shape, which inverts the
// enabled/disabled encoding (see the natRuleRow doc comment above).
type natRuleRowDisabled struct {
	Disabled flexString `json:"disabled"`
}

// isEnabled reports the row's enabled state for the "disabled"-field NAT
// type (d_nat). Only an explicit "1" counts as disabled; missing/empty/other
// -> enabled.
func (r natRuleRowDisabled) isEnabled() bool {
	return r.Disabled.String() != "1"
}

// natSearchRuleResponse is the bootgrid envelope for source_nat, one_to_one
// and npt search_rule endpoints.
type natSearchRuleResponse struct {
	Rows []natRuleRow `json:"rows"`
}

// natSearchRuleResponseDNAT is the bootgrid envelope for the d_nat
// search_rule endpoint (see the natRuleRowDisabled doc comment).
type natSearchRuleResponseDNAT struct {
	Rows []natRuleRowDisabled `json:"rows"`
}

// NATRuleCounts is the enabled/disabled row count for one NAT rule type.
type NATRuleCounts struct {
	// Type is one of "source_nat", "d_nat", "one_to_one", "npt".
	Type     string
	Enabled  int
	Disabled int
}

// FetchFirewallNATRuleCounts returns the enabled/disabled row counts for each
// of the four MVC-managed NAT rule types (source NAT / outbound, destination
// NAT / port forward, 1:1 BINAT, IPv6 NPt). These are config-only inventory
// counts: NAT rule pf hit/byte statistics do not exist on OPNsense —
// rule_stats.py (backing api/firewall/filter_util/rule_stats, see
// firewall_rules.go) covers filter rules only, verified against a live box's
// `pfctl -sr -v` output, which carries no NAT rule entries (#221). Rules
// created before an admin migrated to the MVC-managed NAT backend are
// invisible here — the search_rule endpoints only see MVC-managed rows, the
// same caveat api/firewall/filter/search_rule has for legacy filter rules.
//
// All four endpoints are core (never plugin-gated, never answer 404) and
// wholly config-derived, so they are cache-TTL eligible like the other MVC
// search_rule endpoints.
func (c *Client) FetchFirewallNATRuleCounts() ([]NATRuleCounts, *APICallError) {
	enabledTypes := []struct {
		typeName string
		endpoint EndpointName
	}{
		{"source_nat", "natSourceNATRules"},
		{"one_to_one", "natOneToOneRules"},
		{"npt", "natNPTRules"},
	}

	counts := make([]NATRuleCounts, 0, len(enabledTypes)+1)

	for _, t := range enabledTypes {
		path, ok := c.endpoints[t.endpoint]
		if !ok {
			return nil, &APICallError{
				Endpoint:   string(t.endpoint),
				Message:    "endpoint not found in client endpoints",
				StatusCode: 0,
			}
		}

		var resp natSearchRuleResponse
		if err := c.do("GET", path, nil, &resp); err != nil {
			return nil, err
		}

		rc := NATRuleCounts{Type: t.typeName}
		for _, row := range resp.Rows {
			if row.isEnabled() {
				rc.Enabled++
			} else {
				rc.Disabled++
			}
		}
		counts = append(counts, rc)
	}

	dNatPath, ok := c.endpoints["natDNATRules"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "natDNATRules",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var dNatResp natSearchRuleResponseDNAT
	if err := c.do("GET", dNatPath, nil, &dNatResp); err != nil {
		return nil, err
	}

	dNatCounts := NATRuleCounts{Type: "d_nat"}
	for _, row := range dNatResp.Rows {
		if row.isEnabled() {
			dNatCounts.Enabled++
		} else {
			dNatCounts.Disabled++
		}
	}
	counts = append(counts, dNatCounts)

	return counts, nil
}
