package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// ntpGPSFix holds the NMEA-derived GPS refclock fields from api/ntpd/service/gps
// we choose to model. sat/lat/lon/alt are also emitted by the configd script,
// but lat/lon are deliberately never modelled here (location privacy, #224).
//
// "ok" varies shape by NMEA sentence: $GPRMC/$GPGLL emit a genuine JSON
// boolean (PHP `=== 'A'`), while $GPGGA emits the raw quality-indicator digit
// as a string ("0"/"1"/"2"/...). flexBool tolerates both.
type ntpGPSFix struct {
	Sentence flexString `json:"sentence"`
	OK       flexBool   `json:"ok"`
	Sat      flexString `json:"sat"`
}

// ntpGPSField decodes the "gps" key of api/ntpd/service/gps. The configd
// script (ntpd_status.php) initializes `$result['gps'] = []` (a PHP empty
// array, encoded as a JSON array) and only replaces it with an associative
// array (encoded as a JSON object) when a GPS refclock reports a fix via
// `ntpq -c clockvar`. VERIFIED empty-array shape live against the 26.7-devel
// test box (no GPS hardware attached, #224); the populated object shape is
// derived from the PHP source since no GPS hardware is available to capture
// against — treat consumers of this as experimental until validated live.
type ntpGPSField struct {
	Present bool
	Fix     ntpGPSFix
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *ntpGPSField) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" || (len(trimmed) > 0 && trimmed[0] == '[') {
		// Empty/absent, or the PHP empty-array shape: no GPS refclock fix.
		f.Present = false
		f.Fix = ntpGPSFix{}
		return nil
	}

	var fix ntpGPSFix
	if err := json.Unmarshal(data, &fix); err != nil {
		return fmt.Errorf("ntpGPSField: %w", err)
	}
	f.Present = true
	f.Fix = fix
	return nil
}

type ntpGPSResponse struct {
	// ntpq_servers duplicates the same-request ntpd_status.php peer rows
	// already covered by FetchNTPStatus's "rows" (statusAction wraps the same
	// configd output through searchRecordsetBase); intentionally not modelled
	// here, see testdata/schemas/exemptions.json.
	GPS ntpGPSField `json:"gps"`
}

// NTPGPSStatus is the normalised, privacy-trimmed view of api/ntpd/service/gps.
// Present is false when no GPS refclock reports a fix (or none is attached).
type NTPGPSStatus struct {
	Present bool
	OK      bool

	Satellites      int64
	SatellitesValid bool // false when "sat" was absent/unparseable (e.g. $GPRMC never carries it)
}

// FetchNTPGPSStatus fetches GPS refclock fix status from api/ntpd/service/gps.
// This is a core endpoint (no plugin gating): a GPS-less box simply reports
// Present=false forever, which is the expected default deployment.
func (c *Client) FetchNTPGPSStatus() (NTPGPSStatus, *APICallError) {
	var data NTPGPSStatus

	url, ok := c.endpoints["ntpGPS"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ntpGPS",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp ntpGPSResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	if !resp.GPS.Present {
		return data, nil
	}

	data.Present = true
	data.OK = resp.GPS.Fix.OK.Bool()

	if sat := resp.GPS.Fix.Sat.String(); sat != "" {
		if n, err := strconv.ParseInt(sat, 10, 64); err == nil {
			data.Satellites = n
			data.SatellitesValid = true
		}
	}

	return data, nil
}
