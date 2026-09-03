package opnsense

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// gatewayGroupMember is the status object appended by
// Routing/Api/GroupSettingsController::searchAction to each gateway-group
// tier. The object is produced by routes/gateway_status.php. A member that is
// disabled or inactive can contain only name, status_translated and label;
// the other fields then retain their zero value.
//
// Source-derived from OPNsense core 26.7:
//   - src/opnsense/mvc/app/controllers/OPNsense/Routing/Api/GroupSettingsController.php
//   - src/opnsense/scripts/routes/gateway_status.php
//
// The probe values are strings (for example "1.2 ms", "0.0 %" or "~"), so
// they stay strings here. GatewayGroups does not turn them into labels; the
// existing gateways collector already owns the numeric gateway-health series.
type gatewayGroupMember struct {
	Name             string `json:"name"`
	Address          string `json:"address"`
	Status           string `json:"status"`
	Loss             string `json:"loss"`
	Delay            string `json:"delay"`
	StdDev           string `json:"stddev"`
	Monitor          string `json:"monitor"`
	StatusTranslated string `json:"status_translated"`
	Label            string `json:"label"`
}

// gatewayGroupRow is one row from api/routing/group_settings/search. The
// endpoint is a UIModelGrid response, so the model fields are flattened into
// the row and selected-list descriptions are emitted under %-prefixed keys.
// Item through Item5 are retained to preserve the source shape and the
// configured tier relationship; the gateway status objects under Gateways are
// the values consumed by the collector.
type gatewayGroupRow struct {
	UUID        string                          `json:"uuid"`
	Name        string                          `json:"name"`
	Item        string                          `json:"item"`
	Item2       string                          `json:"item2"`
	Item3       string                          `json:"item3"`
	Item4       string                          `json:"item4"`
	Item5       string                          `json:"item5"`
	ItemDesc    string                          `json:"%item"`
	Item2Desc   string                          `json:"%item2"`
	Item3Desc   string                          `json:"%item3"`
	Item4Desc   string                          `json:"%item4"`
	Item5Desc   string                          `json:"%item5"`
	Trigger     string                          `json:"trigger"`
	PoolOpts    string                          `json:"poolopts"`
	Description string                          `json:"descr"`
	Gateways    map[string][]gatewayGroupMember `json:"gateways"`
}

type gatewayGroupSearchResponse struct {
	Total    int               `json:"total"`
	RowCount int               `json:"rowCount"`
	Current  int               `json:"current"`
	Rows     []gatewayGroupRow `json:"rows"`
}

// GatewayGroupMember is one configured gateway in one failover-group tier.
// Name and Address intentionally match the labels on the existing gateway
// status metrics, allowing a PromQL join on (name, address,
// opnsense_instance). The remaining fields retain the status object for
// bounded non-metric consumers and source-shape fidelity.
type GatewayGroupMember struct {
	Tier             int
	Name             string
	Address          string
	Status           string
	Loss             string
	Delay            string
	StdDev           string
	Monitor          string
	StatusTranslated string
	Label            string
}

// GatewayGroup is the normalized representation of one configured gateway
// failover group. Members are ordered by numeric tier and then by gateway
// identity for deterministic snapshots.
type GatewayGroup struct {
	UUID        string
	Name        string
	Description string
	Trigger     string
	PoolOpts    string

	// ConfiguredTiers retains the selected gateway names from the model fields
	// item/item2..item5. The API also returns the richer status-bearing Members;
	// retaining both makes the model relationship explicit without exposing
	// UUIDs or raw UI description fields as metric labels.
	ConfiguredTiers            map[int][]string
	ConfiguredTierDescriptions map[int]string
	Members                    []GatewayGroupMember
}

// GatewayGroups holds the result of FetchGatewayGroups. Present distinguishes
// a successful empty response from a pre-26.7 box where the endpoint is absent.
type GatewayGroups struct {
	Present  bool
	Total    int
	RowCount int
	Current  int
	Groups   []GatewayGroup
}

// GatewayGroupSettings is kept as a descriptive alias for callers that name
// the endpoint rather than the resource. It is the same normalized result.
type GatewayGroupSettings = GatewayGroups

// splitGatewayGroupNames converts the UIModelGrid's comma-separated selected
// list to names. Empty selections are normal for unused tiers.
func splitGatewayGroupNames(raw string) []string {
	var result []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			result = append(result, name)
		}
	}
	return result
}

func gatewayGroupConfiguredTiers(row gatewayGroupRow) (map[int][]string, map[int]string) {
	values := [...]string{row.Item, row.Item2, row.Item3, row.Item4, row.Item5}
	descriptions := [...]string{row.ItemDesc, row.Item2Desc, row.Item3Desc, row.Item4Desc, row.Item5Desc}
	tiers := make(map[int][]string, len(values))
	tierDescriptions := make(map[int]string, len(values))
	for i, value := range values {
		tiers[i+1] = splitGatewayGroupNames(value)
		tierDescriptions[i+1] = descriptions[i]
	}
	return tiers, tierDescriptions
}

func gatewayGroupMembers(row gatewayGroupRow) []GatewayGroupMember {
	keys := make([]string, 0, len(row.Gateways))
	for key := range row.Gateways {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, leftErr := strconv.Atoi(keys[i])
		right, rightErr := strconv.Atoi(keys[j])
		if leftErr == nil && rightErr == nil && left != right {
			return left < right
		}
		return keys[i] < keys[j]
	})

	var members []GatewayGroupMember
	seen := make(map[string]bool)
	for _, key := range keys {
		tier, err := strconv.Atoi(key)
		if err != nil || tier < 1 {
			// Core emits tiers 1 through 5. Ignore a malformed future key rather
			// than creating a tier=0 metric that cannot be joined meaningfully.
			continue
		}
		for _, member := range row.Gateways[key] {
			m := GatewayGroupMember{
				Tier:             tier,
				Name:             member.Name,
				Address:          member.Address,
				Status:           member.Status,
				Loss:             member.Loss,
				Delay:            member.Delay,
				StdDev:           member.StdDev,
				Monitor:          member.Monitor,
				StatusTranslated: member.StatusTranslated,
				Label:            member.Label,
			}
			// A repeated member in one group/tier would otherwise produce a
			// duplicate Prometheus label tuple. Keep the first source row; a
			// gateway appearing in different tiers remains distinct.
			identity := strconv.Itoa(tier) + "\x00" + m.Name + "\x00" + m.Address
			if seen[identity] {
				continue
			}
			seen[identity] = true
			members = append(members, m)
		}
	}
	return members
}

// FetchGatewayGroups calls api/routing/group_settings/search. OPNsense 26.7
// introduced this core endpoint; on an older box it returns HTTP 404, which is
// a feature-absent result rather than a failed collector. The root wiring adds
// this route to the negative 404 cache because its absence is version-gated.
func (c *Client) FetchGatewayGroups() (GatewayGroups, *APICallError) {
	var resp gatewayGroupSearchResponse
	var data GatewayGroups

	path, ok := c.endpoints["gatewayGroups"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "gatewayGroups",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.Total = resp.Total
	data.RowCount = resp.RowCount
	data.Current = resp.Current
	data.Groups = make([]GatewayGroup, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		configuredTiers, tierDescriptions := gatewayGroupConfiguredTiers(row)
		data.Groups = append(data.Groups, GatewayGroup{
			UUID:                       row.UUID,
			Name:                       row.Name,
			Description:                row.Description,
			Trigger:                    row.Trigger,
			PoolOpts:                   row.PoolOpts,
			ConfiguredTiers:            configuredTiers,
			ConfiguredTierDescriptions: tierDescriptions,
			Members:                    gatewayGroupMembers(row),
		})
	}

	return data, nil
}

// FetchGatewayGroupSettings is an endpoint-oriented alias for
// FetchGatewayGroups.
func (c *Client) FetchGatewayGroupSettings() (GatewayGroupSettings, *APICallError) {
	return c.FetchGatewayGroups()
}
