package opnsense

import (
	"net/http"
	"net/url"
	"strings"
)

// zerotierNetworkSearchRow mirrors the network fields selected by
// Zerotier\Api\NetworkController::searchAction. The plugin's BooleanField is
// serialized as either "0"/"1" or a JSON boolean depending on the OPNsense
// serializer, so flexBool keeps the read tolerant without widening the public
// model.
type zerotierNetworkSearchRow struct {
	UUID        string     `json:"uuid"`
	Enabled     flexBool   `json:"enabled"`
	NetworkID   flexString `json:"networkId"`
	Description flexString `json:"description"`
}

type zerotierNetworkSearchResponse struct {
	Total    int                        `json:"total"`
	RowCount int                        `json:"rowCount"`
	Current  int                        `json:"current"`
	Rows     []zerotierNetworkSearchRow `json:"rows"`
}

// zerotierNetworkInfoResponse is returned by infoAction. The title is a
// localized presentation string and is deliberately not consumed; message is
// the plain-text output of `zerotier-cli listnetworks` for the configured
// network.
type zerotierNetworkInfoResponse struct {
	Title   string `json:"title"`
	Message string `json:"message"`
}

// ZeroTierNetwork is the normalized view of one configured ZeroTier network.
// UUID is the OPNsense configuration node reference and is used only to form
// the info endpoint path; NetworkID is the stable network identity used by
// metric labels. Status and AssignedAddresses are present only when the
// daemon's listnetworks row was successfully parsed.
type ZeroTierNetwork struct {
	UUID        string
	NetworkID   string
	Description string
	Enabled     bool

	Status               string
	HasStatus            bool
	AssignedAddresses    int
	HasAssignedAddresses bool
}

// ZeroTierNetworks is the aggregated result of FetchZeroTierNetworks.
type ZeroTierNetworks struct {
	// Present is false when os-zerotier is not installed (HTTP 404 from search).
	Present  bool
	Total    int
	Networks []ZeroTierNetwork
}

// The status values are the closed vocabulary emitted by ZeroTier's
// ZT_VirtualNetworkStatus enum. Keep the raw wire value out of labels: a future
// daemon status belongs in the bounded "unknown" bucket.
var zeroTierNetworkStatuses = map[string]string{
	"requesting_configuration": "REQUESTING_CONFIGURATION",
	"ok":                       "OK",
	"access_denied":            "ACCESS_DENIED",
	"not_found":                "NOT_FOUND",
	"port_error":               "PORT_ERROR",
	"client_too_old":           "CLIENT_TOO_OLD",
	"authentication_required":  "AUTHENTICATION_REQUIRED",
}

// canonicalizeZeroTierNetworkStatus maps a daemon status to the bounded label
// vocabulary. An empty value means that no status was reported and therefore
// produces no status/address metrics; a non-empty unknown value is retained as
// the safe "unknown" bucket.
func canonicalizeZeroTierNetworkStatus(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "-" {
		return "", false
	}
	if canonical, ok := zeroTierNetworkStatuses[strings.ToLower(s)]; ok {
		return canonical, true
	}
	return "unknown", true
}

// isZeroTierMAC recognizes the fixed six-byte MAC column in listnetworks. The
// CLI has emitted both colon-separated and compact forms over its history; the
// test is intentionally limited to hex shape so a network name containing a
// status word cannot be mistaken for the status column.
func isZeroTierMAC(s string) bool {
	compact := strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	if len(compact) != 12 {
		return false
	}
	for _, r := range compact {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// parseZeroTierNetworkMessage extracts one listnetworks row for networkID.
// The plain CLI format has a variable-width name column:
//
//	200 listnetworks <network-id> <name...> <mac> <status> <type> <dev> <ips>
//
// Consequently the fixed columns are located from the MAC token rather than
// by assuming that a name has no spaces. The address column is comma-separated
// in current ZeroTier releases; accepting additional whitespace is harmless
// and makes old output with a space-separated list readable too.
func parseZeroTierNetworkMessage(message, networkID string) (status string, assigned int, ok bool) {
	target := strings.TrimSpace(networkID)
	if target == "" {
		return "", 0, false
	}

	for _, line := range strings.Split(message, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Locate the ID as a token. This handles both the usual
		// "200 listnetworks ..." prefix and output where configd has already
		// removed that prefix from a subsequent line.
		idIndex := -1
		for i, field := range fields {
			if strings.EqualFold(field, target) {
				idIndex = i
				break
			}
		}
		if idIndex < 0 {
			continue
		}

		// The MAC is followed by status, network type and interface name.
		// Scan for the MAC so names with spaces remain lossless. At least
		// those three columns must follow it; an optional address column is
		// counted below.
		for macIndex := idIndex + 1; macIndex+3 < len(fields); macIndex++ {
			if !isZeroTierMAC(fields[macIndex]) {
				continue
			}
			canonical, statusOK := canonicalizeZeroTierNetworkStatus(fields[macIndex+1])
			if !statusOK {
				continue
			}
			// The type column is currently PRIVATE/PUBLIC. Require a
			// non-empty type and device token but do not make either a label
			// or a closed vocabulary: they are not part of the metric.
			if strings.TrimSpace(fields[macIndex+2]) == "" || strings.TrimSpace(fields[macIndex+3]) == "" {
				continue
			}

			for _, field := range fields[macIndex+4:] {
				for _, address := range strings.Split(field, ",") {
					address = strings.TrimSpace(address)
					if address != "" && address != "-" {
						assigned++
					}
				}
			}
			return canonical, assigned, true
		}
	}
	return "", 0, false
}

// zeroTierNetworkInfo is the parsed, metric-ready subset of one listnetworks
// row. Presence is explicit so an unavailable runtime row is not collapsed
// into a fabricated zero value.
type zeroTierNetworkInfo struct {
	Status               string
	HasStatus            bool
	AssignedAddresses    int
	HasAssignedAddresses bool
}

func parseZeroTierNetworkInfo(message, networkID string) (zeroTierNetworkInfo, bool) {
	status, assigned, ok := parseZeroTierNetworkMessage(message, networkID)
	if !ok {
		return zeroTierNetworkInfo{}, false
	}
	return zeroTierNetworkInfo{
		Status:               status,
		HasStatus:            true,
		AssignedAddresses:    assigned,
		HasAssignedAddresses: true,
	}, true
}

// fetchZeroTierNetworkInfo fetches one configured network's runtime row. The
// request uses the OPNsense configuration UUID, not the ZeroTier network ID:
// NetworkController::infoAction resolves networks.network.<uuid> before it
// shells out with the network ID. The observer is collapsed back to the static
// registered endpoint so UUIDs never become request self-metric labels.
func (c *Client) fetchZeroTierNetworkInfo(uuid, networkID string) (string, int, bool, *APICallError) {
	base, ok := c.endpoints["zerotierNetworkInfo"]
	if !ok {
		return "", 0, false, &APICallError{
			Endpoint:   "zerotierNetworkInfo",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if strings.TrimSpace(uuid) == "" {
		return "", 0, false, nil
	}

	path := EndpointPath(string(base) + "/" + url.PathEscape(uuid))
	requestClient := *c
	if c.observer != nil {
		requestClient.observer = requestObserverAtPath{observer: c.observer, path: string(base)}
	}

	var response zerotierNetworkInfoResponse
	if err := requestClient.do("GET", path, nil, &response); err != nil {
		if err.StatusCode == http.StatusNotFound {
			// A stale configuration UUID or a stripped plugin can make only
			// this row unavailable. Keep the search-derived membership data.
			return "", 0, false, nil
		}
		return "", 0, false, err
	}
	status, assigned, parsed := parseZeroTierNetworkMessage(response.Message, networkID)
	if !parsed {
		return "", 0, false, nil
	}
	return status, assigned, true, nil
}

// FetchZeroTierNetworks fetches configured network membership from search and
// joins each row with the daemon's listnetworks output from info/<uuid>.
//
// A 404 on search means os-zerotier is absent and returns Present=false,nil.
// Per-network info failures are intentionally non-fatal: configured enabled
// and membership metrics remain useful when a daemon is down, a UUID is stale,
// or one malformed text row cannot be decoded. Runtime fields are omitted for
// that row rather than fabricated.
func (c *Client) FetchZeroTierNetworks() (ZeroTierNetworks, *APICallError) {
	var response zerotierNetworkSearchResponse
	var data ZeroTierNetworks

	path, ok := c.endpoints["zerotierNetworks"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "zerotierNetworks",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if err := c.do("GET", path, nil, &response); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}
	data.Present = true
	data.Total = response.Total

	seen := make(map[string]bool, len(response.Rows))
	data.Networks = make([]ZeroTierNetwork, 0, len(response.Rows))
	for _, row := range response.Rows {
		networkID := strings.TrimSpace(row.NetworkID.String())
		identityKey := strings.ToLower(networkID)
		if networkID == "" || seen[identityKey] {
			// NetworkID is the metric identity. A blank or repeated identity
			// cannot safely produce a Prometheus series; retain the first valid
			// source row only.
			continue
		}
		seen[identityKey] = true

		network := ZeroTierNetwork{
			UUID:        strings.TrimSpace(row.UUID),
			NetworkID:   networkID,
			Description: row.Description.String(),
			Enabled:     row.Enabled.Bool(),
		}
		if status, assigned, infoOK, err := c.fetchZeroTierNetworkInfo(network.UUID, network.NetworkID); err != nil {
			if c.log != nil {
				c.log.Warn("failed to fetch ZeroTier network info", "network_id", network.NetworkID, "err", err)
			}
		} else if infoOK {
			network.Status = status
			network.HasStatus = true
			network.AssignedAddresses = assigned
			network.HasAssignedAddresses = true
		}
		data.Networks = append(data.Networks, network)
	}

	return data, nil
}
