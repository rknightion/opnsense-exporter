package opnsense

import (
	"net/http"
	"net/url"
	"sort"
)

// captivePortalSessionRow mirrors one row from api/captiveportal/session/search.
// Only zoneid is decoded; PII fields (userName, macAddress, ipAddress) are
// deliberately not modeled per D10 (no per-session detail).
//
// VERIFICATION: core endpoint — validate shapes against the live OPNsense box
// via ~/repos/chat/opnsense/CLAUDE.md (read-only GET). The unconfigured shape
// (zones returns [] and sessions returns {total:0,rows:[]}) was verified live.
// The populated fixture is derived from CaptivePortal/Api/SessionController.php.
type captivePortalSessionRow struct {
	ZoneID flexString `json:"zoneid"`
}

// captivePortalSessionSearch is the bootgrid response from session/search.
type captivePortalSessionSearch struct {
	Total    int                       `json:"total"`
	RowCount int                       `json:"rowCount"`
	Current  int                       `json:"current"`
	Rows     []captivePortalSessionRow `json:"rows"`
}

// CaptivePortalZone is the normalised per-zone session count, joined with the
// configured zone description.
type CaptivePortalZone struct {
	ZoneID      string
	Description string
	Sessions    float64
}

// CaptivePortalSessions holds the aggregated result of FetchCaptivePortalSessions.
type CaptivePortalSessions struct {
	Present       bool
	Zones         []CaptivePortalZone // one entry per configured zone (0 sessions included)
	SessionsTotal float64
}

// FetchCaptivePortalSessions fetches per-zone session counts from the captive
// portal endpoints. Two requests are issued per scrape:
//  1. GET api/captiveportal/session/zones — flat map of zone ID → description
//     (returns [] when no zones are configured).
//  2. POST api/captiveportal/session/search (rowCount=-1) — all active sessions.
//     Only the zoneid field is decoded; PII fields are not modeled (D10).
//
// Sessions whose zoneid has no corresponding configured zone are counted in a
// synthetic zone with ZoneID "unknown" (only emitted when non-zero).
//
// A HTTP 404 on the zones endpoint is treated as "feature absent" for defensive
// compatibility with older/stripped builds that lack the captive portal module.
func (c *Client) FetchCaptivePortalSessions() (CaptivePortalSessions, *APICallError) {
	var data CaptivePortalSessions

	zonesURL, ok := c.endpoints["captivePortalZones"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "captivePortalZones",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	sessionsURL, ok := c.endpoints["captivePortalSessions"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "captivePortalSessions",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// Fetch zones: an empty/unconfigured portal returns PHP [] → flexStringMap decodes it as empty map.
	var zones flexStringMap
	if err := c.do("GET", zonesURL, nil, &zones); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // feature absent
		}
		return data, err
	}
	data.Present = true

	// Build a session count map keyed by zone ID.
	sessionCounts := make(map[string]float64)

	form := url.Values{
		"current":  {"1"},
		"rowCount": {"-1"},
	}
	var sessResp captivePortalSessionSearch
	if err := c.doForm(sessionsURL, form, &sessResp); err != nil {
		return data, err
	}

	for _, row := range sessResp.Rows {
		sessionCounts[row.ZoneID.String()]++
	}
	data.SessionsTotal = float64(sessResp.Total)

	// Build one CaptivePortalZone per configured zone (0 sessions included).
	for zoneID, description := range zones {
		data.Zones = append(data.Zones, CaptivePortalZone{
			ZoneID:      zoneID,
			Description: description,
			Sessions:    sessionCounts[zoneID],
		})
		delete(sessionCounts, zoneID)
	}

	// Any remaining zone IDs in sessionCounts are unknown — emit a synthetic entry.
	unknownCount := 0.0
	for _, count := range sessionCounts {
		unknownCount += count
	}
	if unknownCount > 0 {
		data.Zones = append(data.Zones, CaptivePortalZone{
			ZoneID:      "unknown",
			Description: "",
			Sessions:    unknownCount,
		})
	}

	// Sort by ZoneID for deterministic output and tests.
	sort.Slice(data.Zones, func(i, j int) bool {
		return data.Zones[i].ZoneID < data.Zones[j].ZoneID
	})

	return data, nil
}
