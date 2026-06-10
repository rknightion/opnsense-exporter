package opnsense

import (
	"strconv"
)

type ntpPeerRow struct {
	Status  string `json:"status"`
	Server  string `json:"server"`
	RefID   string `json:"refid"`
	Stratum string `json:"stratum"`
	Type    string `json:"type"`
	When    string `json:"when"`
	Poll    string `json:"poll"`
	Reach   string `json:"reach"`
	Delay   string `json:"delay"`
	Offset  string `json:"offset"`
	Jitter  string `json:"jitter"`
}

type ntpStatusResponse struct {
	Rows []ntpPeerRow `json:"rows"`
}

type NTPPeer struct {
	Status       string
	Server       string
	RefID        string
	Type         string
	Stratum      int64
	WhenSeconds  float64
	PollSeconds  float64
	Reach        int
	DelayMillis  float64
	OffsetMillis float64
	JitterMillis float64
}

type NTPStatus struct {
	Peers []NTPPeer
}

func (c *Client) FetchNTPStatus() (NTPStatus, *APICallError) {
	var resp ntpStatusResponse
	var data NTPStatus

	url, ok := c.endpoints["ntpStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ntpStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, row := range resp.Rows {
		whenSeconds := 0.0
		if row.When != "-" {
			whenSeconds = safeParseFloat(row.When)
		}

		// Reach is an 8-bit NTP shift register rendered as octal (0-377 == 0-255).
		// Parse with bit size 32 so the value provably fits an int on every
		// platform, avoiding a narrowing conversion (CWE-190/681).
		reach := 0
		if row.Reach != "" {
			parsed, err := strconv.ParseInt(row.Reach, 8, 32)
			if err == nil {
				reach = int(parsed)
			}
		}

		peer := NTPPeer{
			Status:       row.Status,
			Server:       row.Server,
			RefID:        row.RefID,
			Type:         row.Type,
			Stratum:      safeAtoi(row.Stratum),
			WhenSeconds:  whenSeconds,
			PollSeconds:  safeParseFloat(row.Poll),
			Reach:        reach,
			DelayMillis:  safeParseFloat(row.Delay),
			OffsetMillis: safeParseFloat(row.Offset),
			JitterMillis: safeParseFloat(row.Jitter),
		}

		data.Peers = append(data.Peers, peer)
	}

	return data, nil
}
