package opnsense

import (
	"strings"
)

type firewallRuleStatsResponse struct {
	Status string                      `json:"status"`
	Stats  map[string]firewallRuleStat `json:"stats"`
}

type firewallRuleStat struct {
	PfRules     int `json:"pf_rules"`
	Evaluations int `json:"evaluations"`
	Packets     int `json:"packets"`
	Bytes       int `json:"bytes"`
	States      int `json:"states"`
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
	PfRules     int
	Evaluations int
	Packets     int
	Bytes       int
	States      int
}

type FirewallRulesData struct {
	Rules []FirewallRuleStats
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
