package opnsense

import (
	"strconv"
	"strings"
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
	WhenValid    bool // false when "when" is "-" or otherwise unparseable
	PollSeconds  float64
	PollValid    bool // false when "poll" is "-" or otherwise unparseable
	Reach        int
	DelayMillis  float64
	OffsetMillis float64
	JitterMillis float64
}

// parseNTPInterval converts an ntpq prettyinterval field (plain seconds below
// ~2048s, otherwise unit-suffixed "34m"/"12h"/"3d") to seconds. Mirrors
// chrony.go's parseChronyInterval; ported here because ntpq's when/poll columns
// suffer the same suffix-vs-plain-seconds ambiguity (#89). Returns ok=false for
// "-" or any unparseable value so callers can distinguish "unknown" from 0.
func parseNTPInterval(s string) (float64, bool) {
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "m"):
		mult, s = 60, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "h"):
		mult, s = 3600, strings.TrimSuffix(s, "h")
	case strings.HasSuffix(s, "d"):
		mult, s = 86400, strings.TrimSuffix(s, "d")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v * mult, true
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
		// ntpq renders when/poll as prettyinterval: plain seconds below ~2048s,
		// otherwise unit-suffixed ("34m"). Parse suffix-aware and track validity
		// so a stale/unknown peer never masquerades as "responded 0s ago" (#89).
		whenSeconds, whenValid := parseNTPInterval(row.When)
		pollSeconds, pollValid := parseNTPInterval(row.Poll)

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
			WhenValid:    whenValid,
			PollSeconds:  pollSeconds,
			PollValid:    pollValid,
			Reach:        reach,
			DelayMillis:  safeParseFloat(row.Delay),
			OffsetMillis: safeParseFloat(row.Offset),
			JitterMillis: safeParseFloat(row.Jitter),
		}

		data.Peers = append(data.Peers, peer)
	}

	return data, nil
}
