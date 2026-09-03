package opnsense

import "net/http"

// firewallMigrationCountResponse is the complete response from either
// api/firewall/migration/countRules or countOutbound. Both actions return
// the same source-derived object, including status:"ok" and an integer count.
type firewallMigrationCountResponse struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// FirewallMigrationDebt is the normalized view of the remaining pre-MVC
// firewall configuration. Presence is tracked per action so a partially
// upgraded box never turns a missing endpoint into a misleading zero gauge.
type FirewallMigrationDebt struct {
	Present bool

	LegacyRules              int
	LegacyRulesPresent       bool
	LegacyOutboundNATRules   int
	LegacyOutboundNATPresent bool
}

func (c *Client) fetchFirewallMigrationCount(endpointName EndpointName) (int, bool, *APICallError) {
	path, ok := c.endpoints[endpointName]
	if !ok {
		return 0, false, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp firewallMigrationCountResponse
	if err := c.do("GET", path, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return 0, false, nil
		}
		return 0, false, err
	}
	if resp.Status != "ok" {
		return 0, false, nil
	}
	return resp.Count, true, nil
}

// FetchFirewallMigration fetches both 26.7 migration-debt counters. A 404 on
// either action means that action is unavailable on this pre-26.7 box and is
// silently omitted. Other errors remain loud.
func (c *Client) FetchFirewallMigration() (FirewallMigrationDebt, *APICallError) {
	var data FirewallMigrationDebt

	rules, rulesPresent, err := c.fetchFirewallMigrationCount("firewallMigrationRules")
	if err != nil {
		return data, err
	}
	data.LegacyRules = rules
	data.LegacyRulesPresent = rulesPresent

	outbound, outboundPresent, err := c.fetchFirewallMigrationCount("firewallMigrationOutbound")
	if err != nil {
		return data, err
	}
	data.LegacyOutboundNATRules = outbound
	data.LegacyOutboundNATPresent = outboundPresent
	data.Present = rulesPresent || outboundPresent

	return data, nil
}
