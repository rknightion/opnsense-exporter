package opnsense

import (
	"bytes"
	"encoding/json"
	"net/url"
)

// diagLogMaxRowCount is the server-side hard cap on rowCount: OPNsense's
// LogController clamps every request with min(rowCount, 9999) (verified
// against a live 26.7 devel box), so the client never asks for more. Sending
// any negative value OTHER than the server's own "-1 means default 5000"
// sentinel is a footgun: queryLog.py's `str.isdigit()` check rejects it and
// silently treats the limit as UNLIMITED, bypassing the cap entirely — so
// FetchDiagLog clamps defensively rather than forwarding a caller value as-is.
const diagLogMaxRowCount = 9999

// diagLogRequest mirrors the POST body accepted by
// api/diagnostics/log/<module>/<scope> (OPNsense's Diagnostics\Api\LogController
// search action, backed by scripts/syslog/queryLog.py).
//
// ValidFrom is an epoch-SECONDS lower bound on a reverse (newest-first) scan:
// the server's LogMatcher stops scanning the instant it reaches a record
// strictly older than ValidFrom, so the bound is INCLUSIVE — a record exactly
// at ValidFrom is returned again on the next poll. Callers must dedupe that
// boundary. Zero omits the filter entirely, which scans the full retained log
// for the scope (expensive) — callers should reserve that for a case where no
// cursor exists yet, or better, bootstrap the cursor to "now" instead (see
// internal/logship/diaglog.go).
type diagLogRequest struct {
	RowCount  int   `json:"rowCount"`
	Current   int   `json:"current"`
	ValidFrom int64 `json:"validFrom,omitempty"`
}

// diagLogRow is one parsed log line as OPNsense's syslog-ng-backed log reader
// returns it.
//
// Timestamp is a NAIVE local wall-clock string ("2026-07-13T20:22:11", whole
// seconds, no UTC offset) for the scopes backed by OPNsense's own
// ServiceLogFormat (audit, configd, system, gateways, portalauth, and most
// other core/* scopes — verified live). The server's own code parses it back
// with no timezone awareness either (Python's isoparse(...).timestamp() on a
// naive datetime resolves in the box's LOCAL system timezone), so callers that
// need a Unix cursor deliberately mirror that and read it as UTC — consistent
// with how this package already treats every other naive OPNsense timestamp
// (see firewall_geoip.go, ids.go's parseIDSLocalTime). KNOWN LIMITATION: on a
// box whose system clock is not UTC, a validFrom cursor computed this way is
// off by the box's UTC offset; see docs/log-shipping.md.
type diagLogRow struct {
	Timestamp   string     `json:"timestamp"`
	Facility    flexInt    `json:"facility"`
	Severity    string     `json:"severity"`
	ProcessName string     `json:"process_name"`
	Pid         flexString `json:"pid"`
	Rnum        int        `json:"rnum"`
	Line        string     `json:"line"`
}

// diagLogResponse mirrors the full envelope of one
// api/diagnostics/log/<module>/<scope> page.
type diagLogResponse struct {
	Rows      []diagLogRow `json:"rows"`
	TotalRows int          `json:"total_rows"`
	Origin    string       `json:"origin"`
	RowCount  int          `json:"rowCount"`
	Total     int          `json:"total"`
	Current   int          `json:"current"`
}

// FetchDiagLog queries one page of api/diagnostics/log/<module>/<scope>. This
// is the generic diagnostics-log reader (#230): module/scope select the event
// class (e.g. "core"/"audit", "core"/"gateways"), and the base path is
// registered once ("diagLog") — the concrete path is built per call, mirroring
// how FetchCaptivePortalVoucherGroups appends its own dynamic path segment.
//
// rowCount is clamped to [1, diagLogMaxRowCount]; current below 1 is treated as
// page 1. validFrom of 0 omits the server-side lower bound (full-scope scan).
func (c *Client) FetchDiagLog(module, scope string, validFrom int64, rowCount, current int) (diagLogResponse, *APICallError) {
	var resp diagLogResponse

	// path starts as the registered base and is then extended with the
	// module/scope segments (mirroring FetchCaptivePortalVoucherGroups' dynamic
	// path build). It deliberately keeps the same identifier throughout, rather
	// than introducing a second variable for the extended path: TestPostEndpointsMatchCallSites
	// (opnsense/contract_postendpoints_test.go) derives the POST endpoint set by
	// tracing the identifier passed to c.do("POST", ...) back to its
	// `x, ok := c.endpoints[...]` assignment, and only recognizes that pattern
	// when it is the very same variable.
	path, ok := c.endpoints["diagLog"]
	if !ok {
		return resp, &APICallError{
			Endpoint:   "diagLog",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if rowCount <= 0 || rowCount > diagLogMaxRowCount {
		rowCount = diagLogMaxRowCount
	}
	if current <= 0 {
		current = 1
	}

	path = EndpointPath(string(path) + "/" + url.PathEscape(module) + "/" + url.PathEscape(scope))

	reqBody := diagLogRequest{RowCount: rowCount, Current: current, ValidFrom: validFrom}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return resp, &APICallError{Endpoint: "diagLog", Message: err.Error(), StatusCode: 0}
	}

	if apiErr := c.do("POST", path, bytes.NewReader(body), &resp); apiErr != nil {
		return resp, apiErr
	}
	return resp, nil
}
