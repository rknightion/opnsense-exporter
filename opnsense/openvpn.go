package opnsense

import (
	"encoding/json"
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
		Status         string `json:"status"`
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
}
type OpenVPNInstances struct {
	Rows []OpenVPN
}

type Sessions struct {
	Description      string
	Username         string
	CommonName       string
	RealAddress      string
	VirtualAddress   string
	Status           int
	BytesReceived    int64
	BytesTransmitted int64
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
		data.Rows = append(data.Rows, OpenVPN{
			UUID:        v.UUID,
			Description: v.Description,
			Role:        strings.ToLower(v.Role),
			DevType:     v.DevType,
			Enabled:     enabled,
		})
	}

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
			Description:      v.Description,
			Username:         v.Username,
			CommonName:       v.CommonName.String(),
			RealAddress:      v.RealAddress,
			VirtualAddress:   v.VirtualAddress,
			Status:           parseOpenVPNsessionStatusToInt(v.Status),
			BytesReceived:    numToInt(v.BytesReceived),
			BytesTransmitted: numToInt(v.BytesSent),
			ConnectedSince:   numToInt(v.ConnectedSince),
		})
	}

	return data, nil
}
