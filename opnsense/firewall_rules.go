package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

type firewallRuleStatsResponse struct {
	Status string              `json:"status"`
	Stats  firewallRuleStatMap `json:"stats"`
}

// firewallRuleStatMap decodes the api/firewall/filter_util/rule_stats "stats"
// field. It is built by PHP as an associative array keyed by rule UUID, so
// json_encode renders it as a JSON object ({...}) when at least one rule has
// stats, but as an empty JSON array ([]) on a box with nothing to report — a
// fresh install, or one just stripped of its config (#481). A plain map field
// cannot unmarshal "[]", which fails the whole fetch and kills the collector
// rather than reporting zero rules. This type tolerates the empty-array form.
//
// A NON-empty array is deliberately treated as an error rather than absorbed:
// rule stats are always keyed by UUID, never by sequential index, so upstream
// has no encoding path that produces a populated array here (unlike e.g.
// captivePortalZoneMap's numeric-key re-integerization). A populated array
// would mean the payload shape genuinely changed and should surface as drift,
// not be silently swallowed into an empty result.
type firewallRuleStatMap map[string]firewallRuleStat

// UnmarshalJSON implements json.Unmarshaler.
func (m *firewallRuleStatMap) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*m = nil
		return nil
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return fmt.Errorf("firewallRuleStatMap array: %w", err)
		}
		if len(arr) > 0 {
			return fmt.Errorf("firewallRuleStatMap: unexpected non-empty array with %d elements", len(arr))
		}
		*m = nil
		return nil
	}
	var raw map[string]firewallRuleStat
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return fmt.Errorf("firewallRuleStatMap object: %w", err)
	}
	*m = raw
	return nil
}

type firewallRuleStat struct {
	// int64 so large evaluation/packet/byte counters (>2^31) unmarshal correctly
	// on 32-bit source builds instead of failing the whole fetch (#103).
	PfRules     int64 `json:"pf_rules"`
	Evaluations int64 `json:"evaluations"`
	Packets     int64 `json:"packets"`
	Bytes       int64 `json:"bytes"`
	States      int64 `json:"states"`
}

type firewallRuleSearchResponse struct {
	Total    int            `json:"total"`
	RowCount int            `json:"rowCount"`
	Current  int            `json:"current"`
	Rows     []firewallRule `json:"rows"`
}

type firewallRule struct {
	UUID           string `json:"uuid"`
	Description    string `json:"description"`
	Action         string `json:"action"`
	RawInterface   string `json:"interface"`
	HumanInterface string `json:"%interface"`
	Direction      string `json:"direction"`
	Protocol       string `json:"protocol"`
	Enabled        string `json:"enabled"`
}

type FirewallRuleStats struct {
	UUID        string
	Description string
	Action      string
	Interface   string
	Direction   string
	PfRules     int64
	Evaluations int64
	Packets     int64
	Bytes       int64
	States      int64
}

type FirewallRulesData struct {
	Rules []FirewallRuleStats

	// ConfiguredRulesEnabled/Disabled count the user-configured filter rules
	// returned by api/firewall/filter/search_rule by enabled state. Only
	// populated when FetchFirewallRuleStats is called with detailsEnabled —
	// the search response is not fetched otherwise.
	ConfiguredRulesEnabled  int
	ConfiguredRulesDisabled int
}

const fetchFirewallRulesPayload = `{"current":1,"rowCount":-1,"sort":{},"searchPhrase":""}`

func (c *Client) FetchFirewallRuleStats(detailsEnabled bool) (FirewallRulesData, *APICallError) {
	var statsResp firewallRuleStatsResponse
	var data FirewallRulesData

	statsPath, ok := c.endpoints["firewallRuleStats"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "firewallRuleStats",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", statsPath, nil, &statsResp); err != nil {
		return data, err
	}

	if !detailsEnabled {
		data.Rules = make([]FirewallRuleStats, 0, len(statsResp.Stats))
		for id, stat := range statsResp.Stats {
			data.Rules = append(data.Rules, FirewallRuleStats{
				UUID:        id,
				Description: "system",
				PfRules:     stat.PfRules,
				Evaluations: stat.Evaluations,
				Packets:     stat.Packets,
				Bytes:       stat.Bytes,
				States:      stat.States,
			})
		}
		return data, nil
	}

	var searchResp firewallRuleSearchResponse

	searchPath, ok := c.endpoints["firewallRules"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "firewallRules",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", searchPath, strings.NewReader(fetchFirewallRulesPayload), &searchResp); err != nil {
		return data, err
	}

	ruleMap := make(map[string]firewallRule, len(searchResp.Rows))
	for _, rule := range searchResp.Rows {
		ruleMap[rule.UUID] = rule
		// Only an explicit "1" counts as enabled; missing/empty/other → disabled.
		if rule.Enabled == "1" {
			data.ConfiguredRulesEnabled++
		} else {
			data.ConfiguredRulesDisabled++
		}
	}

	data.Rules = make([]FirewallRuleStats, 0, len(statsResp.Stats))
	for id, stat := range statsResp.Stats {
		rs := FirewallRuleStats{
			UUID:        id,
			PfRules:     stat.PfRules,
			Evaluations: stat.Evaluations,
			Packets:     stat.Packets,
			Bytes:       stat.Bytes,
			States:      stat.States,
		}

		if rule, found := ruleMap[id]; found {
			rs.Description = rule.Description
			rs.Action = rule.Action
			rs.Interface = rule.HumanInterface
			rs.Direction = rule.Direction
		} else {
			rs.Description = "system"
		}

		data.Rules = append(data.Rules, rs)
	}

	return data, nil
}
