package opnsense

import (
	"encoding/json"
	"github.com/rknightion/opnsense2otel/v5/internal/fetchshare"
	"strconv"
	"strings"
)

const fetchOpenVPNPayload = `{"current":1,"rowCount":-1,"sort":{},"searchPhrase":""}`

type openVPNSearchResponse struct {
	Rows []struct {
		UUID        string `json:"uuid"`
		Description string `json:"description"`
		Role        string `json:"role"`
		DevType     string `json:"dev_type"`
		Enabled     string `json:"enabled"`
		// MaxClients is the server's configured concurrent-client cap
		// (OpenVPN.xml: IntegerField, MinimumValue 1, no Default). Genuinely
		// optional config, not a plain int that happens to default to 0: an
		// empty string (or the key absent entirely, which client-role
		// instances always do -- maxclients is a server-only field) means "no
		// cap configured", not "cap of 0" (#584). See parseOpenVPNMaxClients.
		MaxClients string `json:"maxclients"`
	} `json:"rows"`
	RowCount int `json:"rowCount"`
	Total    int `json:"total"`
	Current  int `json:"current"`
}

type openVPNSearchSessionsResponse struct {
	Rows []struct {
		Description    string `json:"description"`
		Username       string `json:"username"`
		RealAddress    string `json:"real_address"`
		VirtualAddress string `json:"virtual_address"`
		// VirtualIPv6Address is virtual_ipv6_address, a peer field to
		// virtual_address rather than derived data: both come from the same
		// OpenVPN status-3 CLIENT_LIST row (scripts/openvpn/ovpn_status.py
		// zips the row against the header, renaming nothing), and OPNsense's
		// own code treats them as equal-status siblings when building
		// dual-stack alias-group address lists (scripts/filter/lib/alias/
		// auth.py). Empty for v4-only sessions, populated for dual-stack and
		// v6-only sessions (#483).
		VirtualIPv6Address string `json:"virtual_ipv6_address"`
		Status             string `json:"status"`
		// IsClient is true only for real per-client session rows. The
		// searchSessionsAction controller also appends a synthetic row for a
		// running server with zero clients and a stub row for each
		// enabled-but-stopped server; those carry no is_client flag and must not
		// be counted as sessions (#88). Defaults to false when the field is
		// absent (older fixtures / API shapes).
		IsClient flexBool `json:"is_client"`
		// CommonName is the TLS certificate common name of the connected
		// client. Present for cert-based sessions; null for username/password-
		// only sessions (#212). flexString tolerates the null/absent shapes.
		CommonName flexString `json:"common_name"`
		// BytesReceived/BytesSent are cumulative per-connection byte counters
		// (resets on reconnect — expected counter behaviour). OPNsense sends
		// these as quoted numeric strings on 26.7-devel (verified against a
		// live box), but json.Number also accepts a bare JSON number, so both
		// wire shapes decode (#212).
		BytesReceived json.Number `json:"bytes_received"`
		BytesSent     json.Number `json:"bytes_sent"`
		// ConnectedSince is connected_since__time_t_ (the double-underscore
		// comes from upstream's PHP field-name mangling), a unix-seconds
		// timestamp. json.Number so it tolerates a quoted numeric string, a
		// bare number, or an absent/null field (#212).
		ConnectedSince json.Number `json:"connected_since__time_t_"`
	} `json:"rows"`
	RowCount int `json:"rowCount"`
	Total    int `json:"total"`
	Current  int `json:"current"`
}

type OpenVPN struct {
	UUID        string
	Description string
	Role        string
	DevType     string
	Enabled     int64
	// MaxClients is the configured concurrent-client cap; only meaningful
	// when MaxClientsConfigured is true. Divided into the live per-instance
	// session count (opnsense_openvpn_sessions_by_instance), it gives a
	// utilization/headroom signal that did not exist before #584 -- nothing
	// warned an operator before the server started refusing connections at
	// cap.
	MaxClients int64
	// MaxClientsConfigured is false when the box sent no cap at all (empty
	// string or the key omitted, e.g. every client-role row) -- "unlimited",
	// not "capped at 0". Callers must check this before emitting a metric.
	MaxClientsConfigured bool
}
type OpenVPNInstances struct {
	Rows []OpenVPN
}

type Sessions struct {
	Description    string
	Username       string
	CommonName     string
	RealAddress    string
	VirtualAddress string
	// VirtualIPv6Address is the session's IPv6 tunnel address, populated
	// alongside (or instead of) VirtualAddress for dual-stack and v6-only
	// clients (#483). Empty for v4-only sessions.
	VirtualIPv6Address string
	Status             int
	BytesReceived      int64
	BytesTransmitted   int64
	// ConnectedSince is a unix-seconds timestamp, or 0 if the box did not send
	// connected_since__time_t_ (absent field or an unparseable value).
	ConnectedSince int64
}
type OpenVPNSessions struct {
	Rows []Sessions
}

// Identity returns the session's display identity for metric labels: the TLS
// common name when present (cert-based auth), falling back to the OpenVPN
// username field. OPNsense reports username as the literal string "UNDEF" for
// sessions that used no username/password auth, but the common_name fallback
// preference here means that literal is only ever surfaced when both fields
// are genuinely empty/unset (#212).
func (s Sessions) Identity() string {
	if s.CommonName != "" {
		return s.CommonName
	}
	return s.Username
}

// parseOpenVPNMaxClients parses the raw maxclients string. An empty string
// (or the key absent entirely, which decodes identically since Go's encoding/
// json leaves the string field at its zero value) means "no cap configured",
// distinguished from a genuine configured value by the ok return -- never
// fabricate MaxClients=0 for it (#584).
func parseOpenVPNMaxClients(raw string) (value int64, ok bool) {
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func (c *Client) FetchOpenVPNInstances() (OpenVPNInstances, *APICallError) {
	var resp openVPNSearchResponse
	var data OpenVPNInstances

	url, ok := c.endpoints["openVPNInstances"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "openVPNInstances",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", url, strings.NewReader(fetchOpenVPNPayload), &resp); err != nil {
		return data, err
	}

	for _, v := range resp.Rows {
		enabled, err := parseStringToInt(v.Enabled, url)
		if err != nil {
			return data, err
		}
		maxClients, maxClientsConfigured := parseOpenVPNMaxClients(v.MaxClients)
		data.Rows = append(data.Rows, OpenVPN{
			UUID:                 v.UUID,
			Description:          v.Description,
			Role:                 strings.ToLower(v.Role),
			DevType:              v.DevType,
			Enabled:              enabled,
			MaxClients:           maxClients,
			MaxClientsConfigured: maxClientsConfigured,
		})
	}

	c.publishResult(fetchshare.KeyOpenVPNInstances, data)
	return data, nil
}

func (c *Client) FetchOpenVPNSessions() (OpenVPNSessions, *APICallError) {
	var resp openVPNSearchSessionsResponse
	var data OpenVPNSessions

	url, ok := c.endpoints["openVPNSessions"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "openVPNSessions",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, v := range resp.Rows {
		// Only real client rows are sessions. Idle running-instance rows and
		// enabled-but-stopped stub rows have no is_client flag and would inflate
		// the session count by one per idle/stopped instance (#88).
		if !v.IsClient.Bool() {
			continue
		}
		data.Rows = append(data.Rows, Sessions{
			Description:        v.Description,
			Username:           v.Username,
			CommonName:         v.CommonName.String(),
			RealAddress:        v.RealAddress,
			VirtualAddress:     v.VirtualAddress,
			VirtualIPv6Address: v.VirtualIPv6Address,
			Status:             parseOpenVPNsessionStatusToInt(v.Status),
			BytesReceived:      numToInt(v.BytesReceived),
			BytesTransmitted:   numToInt(v.BytesSent),
			ConnectedSince:     numToInt(v.ConnectedSince),
		})
	}

	return data, nil
}
