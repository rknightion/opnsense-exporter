package opnsense

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
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

// unboundSearchQueriesResponseDecoder preserves the one response-shape bit the
// log source needs without adding category to the public row model. OPNsense
// 26.7 adds rows[].category and overwrites rows[].blocklist with a display
// value; the category key is therefore the reliable generation marker, even
// when that display value happens to look like a legacy short code.
//
// This wrapper is used only at the fetch call site. The schema registry keeps
// unboundSearchQueriesResponse as its plain reflection target, so category
// remains an intentionally unmodelled canary opportunity and rows[] does not
// become opaque.
type unboundSearchQueriesResponseDecoder struct {
	response *unboundSearchQueriesResponse
}

func (d *unboundSearchQueriesResponseDecoder) UnmarshalJSON(data []byte) error {
	var response unboundSearchQueriesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		if d.response != nil {
			*d.response = response
		}
		return err
	}

	var shape struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(data, &shape); err != nil {
		if d.response != nil {
			*d.response = response
		}
		return err
	}
	for i, rawRow := range shape.Rows {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(rawRow, &row); err != nil {
			if d.response != nil {
				*d.response = response
			}
			return err
		}
		if _, ok := row["category"]; ok {
			response.Rows[i].blocklistDisplayValue = true
		}
	}

	if d.response != nil {
		*d.response = response
	}
	return nil
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
	UUID   flexString `json:"uuid"`
	Time   flexInt    `json:"time"` // unix seconds
	Client flexString `json:"client"`
	Family flexString `json:"family"`
	Type   flexString `json:"type"` // DNS qtype, e.g. "A", "AAAA"
	Domain flexString `json:"domain"`
	Action flexString `json:"action"` // "Pass" | "Block" | "Drop"
	Source flexString `json:"source"` // "Recursion" | "Local" | "Local-data" | "Cache"
	// Blocklist is a backend short code on legacy responses but a configured
	// display value on OPNsense 26.7 responses; call BlocklistIdentity before
	// shipping it as an identity.
	Blocklist     flexString `json:"blocklist"`
	RCode         flexString `json:"rcode"`
	ResolveTimeMs flexInt    `json:"resolve_time_ms"`
	DNSSECStatus  flexString `json:"dnssec_status"`
	TTL           flexInt    `json:"ttl"`
	Policy        flexString `json:"policy"`
	Status        flexInt    `json:"status"`

	// blocklistDisplayValue is set by unboundSearchQueriesResponseDecoder when
	// the 26.7-only category key is present. It is deliberately unexported and
	// not part of the JSON/schema model; callers use BlocklistIdentity.
	blocklistDisplayValue bool
}

// BlocklistIdentity returns the stable blocklist short code when the response
// carries an unambiguous backend identifier, or false when the row is empty or
// carries a display value. It intentionally does not manufacture an identity
// from a human-readable value.
func (r UnboundSearchQueryRow) BlocklistIdentity() (string, bool) {
	if r.blocklistDisplayValue {
		return "", false
	}
	identity := strings.TrimSpace(r.Blocklist.String())
	if !isUnboundBlocklistShortCode(identity) {
		return "", false
	}
	return identity, true
}

// isUnboundBlocklistShortCode accepts the shape used by the legacy OPNsense
// Unbound type table: lower-case ASCII letters and digits only. OPNsense 26.7
// replaces that short code with a configured display value and adds category;
// the original code is absent, so values outside this strict identifier shape
// are not treated as recoverable. This is shape-based, not a provider allowlist
// or a release/version check.
func isUnboundBlocklistShortCode(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
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
	decoder := unboundSearchQueriesResponseDecoder{response: &resp}

	endpointURL, ok := c.endpoints["unboundSearchQueries"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "unboundSearchQueries",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	form := url.Values{"current": {"1"}, "rowCount": {strconv.Itoa(UnboundSearchQueriesRowCap)}}
	if err := c.doForm(endpointURL, form, &decoder); err != nil {
		return nil, err
	}

	return resp.Rows, nil
}
