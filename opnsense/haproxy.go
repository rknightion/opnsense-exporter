package opnsense

import (
	"encoding/json"
	"net/http"
	"strings"
)

// haproxyStatRow mirrors one element of the api/haproxy/statistics/counters
// response. The os-haproxy plugin runs `show stat` on the HAProxy admin socket
// and converts the CSV to JSON objects (queryStats.php) — every value is a
// JSON string ("" when HAProxy reports no value).
//
// VERIFICATION: unvalidated against a live os-haproxy box — shape derived from
// net/haproxy/src/opnsense/scripts/OPNsense/HAProxy/queryStats.php and the
// HAProxy management API `show stat` CSV column set. Re-check on real hardware
// when available: empty-string numerics, listener rows (type "3"), and the
// stray non-object array elements queryStats leaves for incomplete CSV lines.
type haproxyStatRow struct {
	PXName    string `json:"pxname"`
	SVName    string `json:"svname"`
	Qcur      string `json:"qcur"`
	Scur      string `json:"scur"`
	Stot      string `json:"stot"`
	Bin       string `json:"bin"`
	Bout      string `json:"bout"`
	Dreq      string `json:"dreq"`
	Ereq      string `json:"ereq"`
	Econ      string `json:"econ"`
	Eresp     string `json:"eresp"`
	Wretr     string `json:"wretr"`
	Wredis    string `json:"wredis"`
	Status    string `json:"status"`
	Weight    string `json:"weight"`
	Act       string `json:"act"`
	Bck       string `json:"bck"`
	Chkfail   string `json:"chkfail"`
	Downtime  string `json:"downtime"`
	Type      string `json:"type"`
	Hrsp1xx   string `json:"hrsp_1xx"`
	Hrsp2xx   string `json:"hrsp_2xx"`
	Hrsp3xx   string `json:"hrsp_3xx"`
	Hrsp4xx   string `json:"hrsp_4xx"`
	Hrsp5xx   string `json:"hrsp_5xx"`
	HrspOther string `json:"hrsp_other"`
}

// HAProxyFrontend is the normalised per-frontend statistics row.
type HAProxyFrontend struct {
	Name            string
	StatusUp        float64
	CurrentSessions float64
	SessionsTotal   float64
	BytesIn         float64
	BytesOut        float64
	RequestErrors   float64
	RequestsDenied  float64
	ResponsesByCode map[string]float64
}

// HAProxyBackend is the normalised per-backend statistics row.
type HAProxyBackend struct {
	Name             string
	StatusUp         float64
	CurrentSessions  float64
	SessionsTotal    float64
	BytesIn          float64
	BytesOut         float64
	QueueCurrent     float64
	ConnectionErrors float64
	ResponseErrors   float64
	Retries          float64
	Redispatches     float64
	ActiveServers    float64
	BackupServers    float64
	ResponsesByCode  map[string]float64
}

// HAProxyServer is the normalised per-server statistics row.
type HAProxyServer struct {
	Backend          string
	Name             string
	StatusUp         float64
	CurrentSessions  float64
	SessionsTotal    float64
	BytesIn          float64
	BytesOut         float64
	QueueCurrent     float64
	ConnectionErrors float64
	ResponseErrors   float64
	CheckFailures    float64
	DowntimeSeconds  float64
	Weight           float64
}

// HAProxyInfo is the normalised process-level `show info` data.
type HAProxyInfo struct {
	Version            string
	UptimeSeconds      float64
	CurrentConnections float64
	ConnectionsTotal   float64
	RequestsTotal      float64
	IdlePercent        float64
}

// HAProxyStats holds the aggregated result of FetchHAProxyStats.
type HAProxyStats struct {
	Present   bool // false when the plugin is absent (counters endpoint 404s)
	Frontends []HAProxyFrontend
	Backends  []HAProxyBackend
	Servers   []HAProxyServer
	Info      HAProxyInfo
	HasInfo   bool
}

// haproxyResponses builds the hrsp_* response-code map, including only the codes
// whose CSV cell is actually present. HAProxy leaves these cells empty ("") for
// tcp-mode proxies (SMTP/DB/TLS-passthrough) because the stat is not applicable —
// which safeParseFloat would otherwise collapse to a fabricated 0, indistinguishable
// from a genuine "0" (zero HTTP responses served). A present "0" is kept as a real
// zero; an empty cell is omitted entirely so no series is emitted (#164).
func haproxyResponses(row haproxyStatRow) map[string]float64 {
	m := make(map[string]float64, 6)
	for code, cell := range map[string]string{
		"1xx":   row.Hrsp1xx,
		"2xx":   row.Hrsp2xx,
		"3xx":   row.Hrsp3xx,
		"4xx":   row.Hrsp4xx,
		"5xx":   row.Hrsp5xx,
		"other": row.HrspOther,
	} {
		if strings.TrimSpace(cell) == "" {
			continue
		}
		m[code] = safeParseFloat(cell)
	}
	return m
}

// haproxyStatusUp maps a HAProxy proxy/server status string to 1 (up/open)
// or 0 (down/maint/drain/nolb/no check). "UP 1/3" style transitional states
// count as up.
func haproxyStatusUp(status string) float64 {
	if status == "OPEN" || strings.HasPrefix(status, "UP") {
		return 1
	}
	return 0
}

// FetchHAProxyStats calls the HAProxy statistics endpoints and returns
// aggregated frontend/backend/server and process-level data.
//
// If the os-haproxy plugin is not installed the endpoints return HTTP 404,
// which is treated as "feature absent" — empty data, no error. When the
// HAProxy service is stopped the plugin returns JSON null bodies, which also
// yield empty data.
func (c *Client) FetchHAProxyStats() (HAProxyStats, *APICallError) {
	var data HAProxyStats

	countersURL, ok := c.endpoints["haproxyCounters"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "haproxyCounters",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	infoURL, ok := c.endpoints["haproxyInfo"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "haproxyInfo",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// The counters payload is a heterogeneous JSON array: complete rows are
	// objects, incomplete CSV lines survive as raw arrays. Decode elementwise.
	var rawRows []json.RawMessage
	if err := c.do("GET", countersURL, nil, &rawRows); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent: Present stays false
		}
		return data, err
	}
	data.Present = true

	for _, raw := range rawRows {
		var row haproxyStatRow
		if err := json.Unmarshal(raw, &row); err != nil {
			continue // non-object filler element, skip
		}
		switch {
		case row.SVName == "FRONTEND":
			data.Frontends = append(data.Frontends, HAProxyFrontend{
				Name:            row.PXName,
				StatusUp:        haproxyStatusUp(row.Status),
				CurrentSessions: safeParseFloat(row.Scur),
				SessionsTotal:   safeParseFloat(row.Stot),
				BytesIn:         safeParseFloat(row.Bin),
				BytesOut:        safeParseFloat(row.Bout),
				RequestErrors:   safeParseFloat(row.Ereq),
				RequestsDenied:  safeParseFloat(row.Dreq),
				ResponsesByCode: haproxyResponses(row),
			})
		case row.SVName == "BACKEND":
			data.Backends = append(data.Backends, HAProxyBackend{
				Name:             row.PXName,
				StatusUp:         haproxyStatusUp(row.Status),
				CurrentSessions:  safeParseFloat(row.Scur),
				SessionsTotal:    safeParseFloat(row.Stot),
				BytesIn:          safeParseFloat(row.Bin),
				BytesOut:         safeParseFloat(row.Bout),
				QueueCurrent:     safeParseFloat(row.Qcur),
				ConnectionErrors: safeParseFloat(row.Econ),
				ResponseErrors:   safeParseFloat(row.Eresp),
				Retries:          safeParseFloat(row.Wretr),
				Redispatches:     safeParseFloat(row.Wredis),
				ActiveServers:    safeParseFloat(row.Act),
				BackupServers:    safeParseFloat(row.Bck),
				ResponsesByCode:  haproxyResponses(row),
			})
		case row.Type == "2":
			data.Servers = append(data.Servers, HAProxyServer{
				Backend:          row.PXName,
				Name:             row.SVName,
				StatusUp:         haproxyStatusUp(row.Status),
				CurrentSessions:  safeParseFloat(row.Scur),
				SessionsTotal:    safeParseFloat(row.Stot),
				BytesIn:          safeParseFloat(row.Bin),
				BytesOut:         safeParseFloat(row.Bout),
				QueueCurrent:     safeParseFloat(row.Qcur),
				ConnectionErrors: safeParseFloat(row.Econ),
				ResponseErrors:   safeParseFloat(row.Eresp),
				CheckFailures:    safeParseFloat(row.Chkfail),
				DowntimeSeconds:  safeParseFloat(row.Downtime),
				Weight:           safeParseFloat(row.Weight),
			})
		}
		// listeners (type "3") and anything unclassified are skipped
	}

	var info map[string]flexString
	if err := c.do("GET", infoURL, nil, &info); err != nil {
		// Counters succeeded so the plugin exists; surface real info errors
		// but tolerate 404 (defensive: endpoint variations across versions).
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}
	if len(info) > 0 {
		data.HasInfo = true
		data.Info = HAProxyInfo{
			Version:            info["Version"].String(),
			UptimeSeconds:      safeParseFloat(info["Uptime_sec"].String()),
			CurrentConnections: safeParseFloat(info["CurrConns"].String()),
			ConnectionsTotal:   safeParseFloat(info["CumConns"].String()),
			RequestsTotal:      safeParseFloat(info["CumReq"].String()),
			IdlePercent:        safeParseFloat(info["Idle_pct"].String()),
		}
	}

	return data, nil
}
