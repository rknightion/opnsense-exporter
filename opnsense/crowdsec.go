package opnsense

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// crowdsecSearchEnvelope is the common bootgrid envelope returned by all four
// CrowdSec search endpoints.  Total is a pointer so that the
// {"message":"unable to retrieve data"} HTTP-200 error envelope (which has no
// "total" key) decodes to Total==nil rather than silently emitting a false 0.
//
// VERIFICATION: unvalidated against a live os-crowdsec box — shape derived from
// security/crowdsec/.../Api/*.php + ApiControllerBase::searchRecordsetBase.
// Re-check field names against a real installation when available.
type crowdsecSearchEnvelope struct {
	Total *int            `json:"total"` // nil on the {"message":"unable to retrieve data"} envelope
	Rows  json.RawMessage `json:"rows"`
}

// crowdsecBouncerRow is one row from the bouncers/search bootgrid response.
type crowdsecBouncerRow struct {
	Name     flexString `json:"name"`
	Type     flexString `json:"type"`
	Valid    flexBool   `json:"valid"`
	LastSeen flexString `json:"last_seen"`
}

// crowdsecMachineRow is one row from the machines/search bootgrid response.
type crowdsecMachineRow struct {
	Name      flexString `json:"name"`
	Validated flexBool   `json:"validated"`
	LastSeen  flexString `json:"last_seen"`
}

// crowdsecHubItemRow is one row from any of the six hub-component search
// bootgrids (collections/scenarios/parsers/postoverflows/appsecconfigs/
// appsecrules). Only Status is aggregated: name/local_version/local_path/
// description are per-item detail deliberately not exported as labels — a
// single collection can pull in 50-200 scenarios/parsers (#205).
//
// VERIFICATION: dev-box captures 2026-07-13 (captures/crowdsec/*_search.json)
// confirm the row shape and the tainted vocabulary: a locally-edited scenario
// reports status "enabled,tainted" (comma-joined, no space) with
// local_version "?". appsecconfigs/appsecrules return valid empty bootgrids
// ({"total":0,"rows":[]}) when nothing is configured.
type crowdsecHubItemRow struct {
	Status flexString `json:"status"`
}

// CrowdSecHubItemCount is one aggregated (component, status) count — e.g.
// component="scenario" status="enabled,tainted" count=1.
type CrowdSecHubItemCount struct {
	Component string
	Status    string
	Count     int
}

// CrowdSecBouncer is the normalised per-bouncer data returned by FetchCrowdSecStatus.
type CrowdSecBouncer struct {
	Name, Type      string
	Valid           bool
	LastPullSeconds float64 // Unix timestamp; valid only when HasLastPull==true
	HasLastPull     bool
}

// CrowdSecMachine is the normalised per-machine data returned by FetchCrowdSecStatus.
type CrowdSecMachine struct {
	Name                 string
	Validated            bool
	LastHeartbeatSeconds float64 // Unix timestamp; valid only when HasLastHeartbeat==true
	HasLastHeartbeat     bool
}

// CrowdSecStatus is the aggregated result of FetchCrowdSecStatus.
type CrowdSecStatus struct {
	Present           bool
	HasAlertsTotal    bool // false when alerts/search returned the message envelope
	AlertsTotal       float64
	HasDecisionsTotal bool // false when decisions/search returned the message envelope
	DecisionsTotal    float64
	HasBouncers       bool // false when bouncers/search returned the message envelope
	Bouncers          []CrowdSecBouncer
	HasMachines       bool // false when machines/search returned the message envelope
	Machines          []CrowdSecMachine

	// HasHubItems is true once at least one of the six hub-component search
	// endpoints returned real data (a message envelope or an undecodable rows
	// shape for a given component just omits that component's contribution).
	HasHubItems bool
	HubItems    []CrowdSecHubItemCount

	// HasVersion is true when version/get's raw text parsed to a version token.
	HasVersion bool
	Version    string
}

// crowdsecFetchCount sends a bootgrid form-POST with rowCount=1 and reads
// the total count.  Returns (total, true, nil) on success, (0, false, nil) when
// the response is the error-envelope (nil Total), or (0, false, err) on error.
func (c *Client) crowdsecFetchCount(endpointName EndpointName) (float64, bool, *APICallError) {
	epURL, ok := c.endpoints[endpointName]
	if !ok {
		return 0, false, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var env crowdsecSearchEnvelope
	form := url.Values{"current": {"1"}, "rowCount": {"1"}}
	if err := c.doForm(epURL, form, &env); err != nil {
		return 0, false, err
	}

	if env.Total == nil {
		// {"message":"unable to retrieve data"} HTTP-200 envelope — no data.
		c.log.Debug("crowdsec search returned message envelope (daemon not running?)",
			"endpoint", endpointName)
		return 0, false, nil
	}

	return float64(*env.Total), true, nil
}

// crowdsecFetchRows sends a bootgrid form-POST with rowCount=-1 to retrieve all
// rows.  Returns (rawRows, true, nil) on success, (nil, false, nil) on the
// error-envelope, or (nil, false, err) on HTTP/parse errors.
func (c *Client) crowdsecFetchRows(endpointName EndpointName) (json.RawMessage, bool, *APICallError) {
	epURL, ok := c.endpoints[endpointName]
	if !ok {
		return nil, false, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var env crowdsecSearchEnvelope
	form := url.Values{"current": {"1"}, "rowCount": {"-1"}}
	if err := c.doForm(epURL, form, &env); err != nil {
		return nil, false, err
	}

	if env.Total == nil {
		c.log.Debug("crowdsec search returned message envelope (daemon not running?)",
			"endpoint", endpointName)
		return nil, false, nil
	}

	return env.Rows, true, nil
}

// normalizeCrowdSecHubStatus canonicalises a cscli hub-item status string for
// use as a metric label value. The wire format is a comma-joined set of
// tokens (confirmed live: "enabled" and "enabled,tainted" — a locally-edited
// scenario reports local_version "?" alongside the "tainted" token); this
// trims whitespace around each token and drops empty ones so
// "enabled, tainted" and "enabled,tainted" collapse to the same label value.
// Unknown tokens pass through unchanged — forward-compatible with cscli
// vocabulary this exporter hasn't seen yet (e.g. a future "update-available").
// An empty/all-whitespace input returns "unknown" rather than an empty label.
func normalizeCrowdSecHubStatus(raw string) string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return "unknown"
	}
	return strings.Join(out, ",")
}

// parseCrowdSecVersion extracts the engine version token from cscli version's
// raw multi-line text output (version/get is NOT JSON — see
// crowdsecVersion's schema exemption). The confirmed live shape is:
//
//	version: v1.7.8_1-6322745
//	Codename: alphaga
//	BuildDate: ...
//
// The label value is everything after the colon on the first "version: ..."
// line, trimmed. Returns ("", false) — never an error — when the text is
// empty or its first line isn't a "key: value" pair naming "version", so a
// cscli output format this exporter doesn't recognise omits the metric
// instead of failing the scrape.
func parseCrowdSecVersion(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	first := raw
	if idx := strings.IndexByte(raw, '\n'); idx >= 0 {
		first = raw[:idx]
	}
	first = strings.TrimSpace(first)
	sep := strings.IndexByte(first, ':')
	if sep < 0 {
		return "", false
	}
	key := strings.TrimSpace(first[:sep])
	val := strings.TrimSpace(first[sep+1:])
	if !strings.EqualFold(key, "version") || val == "" {
		return "", false
	}
	return val, true
}

// parseCrowdSecTimestamp parses a cscli RFC3339 timestamp string (with or
// without fractional seconds) into a Unix float64.  Returns (0, false) when
// the string is empty or unparseable.
func parseCrowdSecTimestamp(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, false
	}
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9, true
}

// FetchCrowdSecStatus fetches aggregated CrowdSec data from four bootgrid
// endpoints (alerts, decisions, bouncers, machines).
//
// Decision D3: alerts and decisions are count-only (rowCount=1, reading `total`).
// Bouncers and machines use rowCount=-1 (all rows; bounded by operator config).
//
// If the os-crowdsec plugin is absent all endpoints return HTTP 404; the first
// 404 sets Present=false and returns immediately (nil error).
// If cscli cannot execute (daemon stopped, bouncer-only install, …) each
// endpoint returns HTTP 200 with {"message":"unable to retrieve data"} — the
// corresponding Has* flag is set to false and that metric is omitted.
//
// Timestamp parsing uses time.RFC3339Nano (handles both plain RFC3339 and
// fractional seconds from cscli); unparseable timestamps set Has* = false.
func (c *Client) FetchCrowdSecStatus() (CrowdSecStatus, *APICallError) {
	var data CrowdSecStatus

	// Alerts (count-only).
	alertsTotal, hasAlerts, err := c.crowdsecFetchCount("crowdsecAlerts")
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent
		}
		return data, err
	}
	data.Present = true
	data.HasAlertsTotal = hasAlerts
	data.AlertsTotal = alertsTotal

	// Decisions (count-only).
	decisionsTotal, hasDecisions, err := c.crowdsecFetchCount("crowdsecDecisions")
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			// Treat as absent — skip remaining endpoints.
			data.Present = false
			return data, nil
		}
		return data, err
	}
	data.HasDecisionsTotal = hasDecisions
	data.DecisionsTotal = decisionsTotal

	// Bouncers (all rows).
	bouncerRows, hasBouncers, err := c.crowdsecFetchRows("crowdsecBouncers")
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, err
	}
	data.HasBouncers = hasBouncers
	if hasBouncers && bouncerRows != nil {
		var rows []crowdsecBouncerRow
		if jsonErr := json.Unmarshal(bouncerRows, &rows); jsonErr == nil {
			for _, row := range rows {
				b := CrowdSecBouncer{
					Name:  row.Name.String(),
					Type:  row.Type.String(),
					Valid: row.Valid.Bool(),
				}
				if ts, ok := parseCrowdSecTimestamp(row.LastSeen.String()); ok {
					b.LastPullSeconds = ts
					b.HasLastPull = true
				}
				data.Bouncers = append(data.Bouncers, b)
			}
		} else {
			// A row-shape drift (e.g. array → object) would otherwise be swallowed
			// silently, leaving HasBouncers=true with an empty slice → a false
			// bouncers_total=0. Mark absent and log so the metric goes away rather
			// than reporting a fake zero (#104).
			data.HasBouncers = false
			c.log.Warn("crowdsec: failed to decode bouncers rows; omitting bouncers metrics",
				"err", jsonErr)
		}
	}

	// Machines (all rows).
	machineRows, hasMachines, err := c.crowdsecFetchRows("crowdsecMachines")
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, err
	}
	data.HasMachines = hasMachines
	if hasMachines && machineRows != nil {
		var rows []crowdsecMachineRow
		if jsonErr := json.Unmarshal(machineRows, &rows); jsonErr == nil {
			for _, row := range rows {
				m := CrowdSecMachine{
					Name:      row.Name.String(),
					Validated: row.Validated.Bool(),
				}
				if ts, ok := parseCrowdSecTimestamp(row.LastSeen.String()); ok {
					m.LastHeartbeatSeconds = ts
					m.HasLastHeartbeat = true
				}
				data.Machines = append(data.Machines, m)
			}
		} else {
			// See the bouncers branch above: mark absent + log on decode failure
			// rather than emitting a false machines_total=0 (#104).
			data.HasMachines = false
			c.log.Warn("crowdsec: failed to decode machines rows; omitting machines metrics",
				"err", jsonErr)
		}
	}

	// Hub component health (#205): aggregate item counts by component + normalised
	// status across the six hub-component search endpoints. Never per-item name
	// labels — a collection pulls in 50-200 scenarios/parsers. A message envelope
	// or an undecodable rows shape for one component just omits that component's
	// contribution (logged), matching the bouncers/machines decode-failure
	// handling above; it does not discard the other components already counted.
	//
	// Each crowdsecFetchRows call below passes its endpoint name as a literal
	// (rather than looping over a table) so TestPostEndpointsMatchCallSites's
	// AST-based POST-endpoint derivation — which only resolves a literal string
	// argument at the call site — can see all six (#145).
	counts := map[[2]string]int{} // key: [component, normalised status]
	var hubItemsFetched bool

	accumulateHubRows := func(component string, rows json.RawMessage) {
		var items []crowdsecHubItemRow
		if jsonErr := json.Unmarshal(rows, &items); jsonErr != nil {
			c.log.Warn("crowdsec: failed to decode hub item rows; omitting hub metrics for component",
				"component", component, "err", jsonErr)
			return
		}
		for _, item := range items {
			status := normalizeCrowdSecHubStatus(item.Status.String())
			counts[[2]string{component, status}]++
		}
	}

	collectionRows, hasCollections, fetchErr := c.crowdsecFetchRows("crowdsecCollections")
	if fetchErr != nil {
		if fetchErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, fetchErr
	}
	if hasCollections {
		hubItemsFetched = true
		if collectionRows != nil {
			accumulateHubRows("collection", collectionRows)
		}
	}

	scenarioRows, hasScenarios, fetchErr := c.crowdsecFetchRows("crowdsecScenarios")
	if fetchErr != nil {
		if fetchErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, fetchErr
	}
	if hasScenarios {
		hubItemsFetched = true
		if scenarioRows != nil {
			accumulateHubRows("scenario", scenarioRows)
		}
	}

	parserRows, hasParsers, fetchErr := c.crowdsecFetchRows("crowdsecParsers")
	if fetchErr != nil {
		if fetchErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, fetchErr
	}
	if hasParsers {
		hubItemsFetched = true
		if parserRows != nil {
			accumulateHubRows("parser", parserRows)
		}
	}

	postoverflowRows, hasPostoverflows, fetchErr := c.crowdsecFetchRows("crowdsecPostoverflows")
	if fetchErr != nil {
		if fetchErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, fetchErr
	}
	if hasPostoverflows {
		hubItemsFetched = true
		if postoverflowRows != nil {
			accumulateHubRows("postoverflow", postoverflowRows)
		}
	}

	appsecConfigRows, hasAppsecConfigs, fetchErr := c.crowdsecFetchRows("crowdsecAppsecConfigs")
	if fetchErr != nil {
		if fetchErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, fetchErr
	}
	if hasAppsecConfigs {
		hubItemsFetched = true
		if appsecConfigRows != nil {
			accumulateHubRows("appsec_config", appsecConfigRows)
		}
	}

	appsecRuleRows, hasAppsecRules, fetchErr := c.crowdsecFetchRows("crowdsecAppsecRules")
	if fetchErr != nil {
		if fetchErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, fetchErr
	}
	if hasAppsecRules {
		hubItemsFetched = true
		if appsecRuleRows != nil {
			accumulateHubRows("appsec_rule", appsecRuleRows)
		}
	}

	data.HasHubItems = hubItemsFetched
	if hubItemsFetched {
		data.HubItems = make([]CrowdSecHubItemCount, 0, len(counts))
		for key, n := range counts {
			data.HubItems = append(data.HubItems, CrowdSecHubItemCount{
				Component: key[0],
				Status:    key[1],
				Count:     n,
			})
		}
		sort.Slice(data.HubItems, func(i, j int) bool {
			if data.HubItems[i].Component != data.HubItems[j].Component {
				return data.HubItems[i].Component < data.HubItems[j].Component
			}
			return data.HubItems[i].Status < data.HubItems[j].Status
		})
	}

	// Engine version (#205): version/get returns raw multi-line cscli version
	// text, NOT JSON — bypass the JSON envelope via the *[]byte sentinel in
	// unmarshalBody (see client.go). Parsing is tolerant: a format this exporter
	// doesn't recognise omits the metric rather than failing the scrape.
	versionEP, ok := c.endpoints["crowdsecVersion"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "crowdsecVersion",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	var rawVersion []byte
	if verErr := c.do("GET", versionEP, nil, &rawVersion); verErr != nil {
		if verErr.StatusCode == http.StatusNotFound {
			data.Present = false
			return data, nil
		}
		return data, verErr
	}
	if v, ok := parseCrowdSecVersion(string(rawVersion)); ok {
		data.HasVersion = true
		data.Version = v
	} else {
		c.log.Debug("crowdsec: could not parse engine version from version/get text")
	}

	return data, nil
}
