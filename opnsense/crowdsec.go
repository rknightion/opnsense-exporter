package opnsense

import (
	"encoding/json"
	"net/http"
	"net/url"
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
		}
	}

	return data, nil
}
