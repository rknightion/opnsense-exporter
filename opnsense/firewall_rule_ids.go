package opnsense

import "encoding/json"

// FirewallRuleID is one entry of the firewall's rule-id map: the identifier pf
// stamps on a log line ("rid") paired with the rule's human description.
//
// The id is EITHER a dashed rule UUID (a user-authored rule from
// firewall/filter) OR an undashed 32-hex content hash (an automatically
// generated system rule: anti-lockout, default-deny, bogons, DHCP-allow, ...).
// This is why the rule inventory the exporter already fetches
// (firewall/filter/search_rule) is not a substitute: it holds only the
// user-authored subset — a small minority of the rules that actually appear in
// filterlog — and no system-rule hash appears in it at all.
type FirewallRuleID struct {
	ID    string `json:"id"`
	Descr string `json:"descr"`
}

// firewallRuleIDsResponse is the enveloped JSON returned by
// api/diagnostics/firewall/list_rule_ids. OPNsense core's
// Diagnostics\Api\FirewallController::listRuleIdsAction wraps the configd
// output as {"items": [...]} on both releases in the support window
// (stable/26.1 and stable/26.7, read from source 2026-07-14), and that is the
// shape the golden schema pins.
//
// FetchFirewallRuleIDs nevertheless also accepts a bare top-level array: the
// underlying `filter list rule_ids` configd command emits one unwrapped, so a
// build or release that returns it straight through must not silently leave
// every log line unlabelled. Tolerating both costs one extra Unmarshal attempt
// on an endpoint fetched at most once a minute.
type firewallRuleIDsResponse struct {
	Items []FirewallRuleID `json:"items"`
}

// FetchFirewallRuleIDs calls api/diagnostics/firewall/list_rule_ids and returns
// every rule id the running ruleset can stamp on a log line, user-authored and
// system-generated alike. It is the resolver for a filterlog "rid".
func (c *Client) FetchFirewallRuleIDs() ([]FirewallRuleID, *APICallError) {
	url, ok := c.endpoints["firewallRuleIDs"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "firewallRuleIDs",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var raw json.RawMessage
	if err := c.do("GET", url, nil, &raw); err != nil {
		return nil, err
	}

	var env firewallRuleIDsResponse
	if err := json.Unmarshal(raw, &env); err == nil {
		return env.Items, nil
	}

	var bare []FirewallRuleID
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, &APICallError{
			Endpoint:   string(url),
			Message:    "failed to unmarshal rule ids: " + err.Error(),
			StatusCode: 0,
		}
	}
	return bare, nil
}
