package opnsense

import (
	"net/url"
	"strconv"
)

// UnboundSearchQueriesRowCap bounds how many of the newest DNS query rows the
// exporter requests per call to api/unbound/overview/search_queries. It is not
// a tunable optimization — see FetchUnboundSearchQueries — it simply matches
// the ceiling the backend itself imposes, so raising it would fetch nothing
// extra.
const UnboundSearchQueriesRowCap = 1000

// unboundSearchQueriesResponse is the bootgrid envelope from
// api/unbound/overview/search_queries.
type unboundSearchQueriesResponse struct {
	Total    flexInt                 `json:"total"`
	RowCount flexInt                 `json:"rowCount"`
	Current  flexInt                 `json:"current"`
	Rows     []UnboundSearchQueryRow `json:"rows"`
}

// UnboundSearchQueryRow is one per-query DNS log line from Unbound's
// DuckDB-backed query log (api/unbound/overview/search_queries), newest first.
//
// UUID is part of the documented schema but is observed to be always null on a
// live OPNsense 26.7-devel box (validated against the dev testbed, #233) —
// callers must not assume it is populated and should fall back to a
// content-derived identity for same-second dedup (see internal/logship's
// rowFingerprint).
type UnboundSearchQueryRow struct {
	UUID          flexString `json:"uuid"`
	Time          flexInt    `json:"time"` // unix seconds
	Client        flexString `json:"client"`
	Family        flexString `json:"family"`
	Type          flexString `json:"type"` // DNS qtype, e.g. "A", "AAAA"
	Domain        flexString `json:"domain"`
	Action        flexString `json:"action"` // "Pass" | "Block" | "Drop"
	Source        flexString `json:"source"` // "Recursion" | "Local" | "Local-data" | "Cache"
	Blocklist     flexString `json:"blocklist"`
	RCode         flexString `json:"rcode"`
	ResolveTimeMs flexInt    `json:"resolve_time_ms"`
	DNSSECStatus  flexString `json:"dnssec_status"`
	TTL           flexInt    `json:"ttl"`
	Policy        flexString `json:"policy"`
	Status        flexInt    `json:"status"`
}

// FetchUnboundSearchQueries calls api/unbound/overview/search_queries and
// returns the newest UnboundSearchQueriesRowCap DNS query rows, in the order
// the backend returns them (time descending, newest first).
//
// CRITICAL ACCEPTED-LOSS BEHAVIOUR (#233, docs/development/api-landmines.md):
// without a client filter, this DuckDB-backed endpoint only ever exposes the
// latest 1000 rows total — the client+timeStart+timeEnd form is the only mode
// that gets a genuine time range, and per-client polling does not scale to a
// whole-resolver query log. On a resolver sustaining more than roughly 1000
// queries between polls, older rows fall out of this window before they are
// ever fetched. This is a silent sampling loss by design of the upstream
// backend, not a bug in this client: callers (internal/logship's unbound
// source) must detect the discontinuity and count it rather than present the
// stream as complete.
//
// unbound is a CORE subsystem (the resolver always has this endpoint once
// Unbound reporting/statistics is enabled), not a plugin, so a 404 here is a
// real error, never "feature absent" — mirroring FetchIDSRecentAlerts.
func (c *Client) FetchUnboundSearchQueries() ([]UnboundSearchQueryRow, *APICallError) {
	var resp unboundSearchQueriesResponse

	endpointURL, ok := c.endpoints["unboundSearchQueries"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "unboundSearchQueries",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	form := url.Values{"current": {"1"}, "rowCount": {strconv.Itoa(UnboundSearchQueriesRowCap)}}
	if err := c.doForm(endpointURL, form, &resp); err != nil {
		return nil, err
	}

	return resp.Rows, nil
}
