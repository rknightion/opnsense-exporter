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
// VERIFICATION: confirmed against a live os-haproxy dev-box box (issue #201,
// 2026-07-13 heavy-topology captures — a stick-table frontend + 2-server HTTP
// backend, including a live health-check DOWN transition). Shape derived from
// net/haproxy/src/opnsense/scripts/OPNsense/HAProxy/queryStats.php and the
// HAProxy management API `show stat` CSV column set. qtime/ctime/rtime/ttime,
// chkdown, lastchg, slim, req_tot, lbtot and cli_abrt/srv_abrt are only
// present on the rows they apply to (FRONTEND vs BACKEND vs server) and go
// empty for tcp-mode proxies — never fabricate a 0 for an empty cell (#164).
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
	Chkdown   string `json:"chkdown"`
	Lastchg   string `json:"lastchg"`
	Downtime  string `json:"downtime"`
	Slim      string `json:"slim"`
	ReqTot    string `json:"req_tot"`
	LbTot     string `json:"lbtot"`
	CliAbrt   string `json:"cli_abrt"`
	SrvAbrt   string `json:"srv_abrt"`
	Qtime     string `json:"qtime"`
	Ctime     string `json:"ctime"`
	Rtime     string `json:"rtime"`
	Ttime     string `json:"ttime"`
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
	// RequestsTotal (req_tot) and SessionLimit (slim) are nil when the CSV
	// cell was empty (tcp-mode proxies leave req_tot blank) — never a
	// fabricated 0 (#164).
	RequestsTotal *float64
	SessionLimit  *float64
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
	// QueueTimeAvg/ConnectTimeAvg/ResponseTimeAvg/TotalTimeAvg are the
	// show-stat qtime/ctime/rtime/ttime rolling averages (last 1024 requests)
	// converted from milliseconds to seconds. SelectedTotal is lbtot
	// (cumulative times this backend was selected); ClientAborts/ServerAborts
	// are cli_abrt/srv_abrt. All nil when the CSV cell was empty (tcp-mode
	// proxies leave several of these blank) — never a fabricated 0 (#164).
	QueueTimeAvg    *float64
	ConnectTimeAvg  *float64
	ResponseTimeAvg *float64
	TotalTimeAvg    *float64
	SelectedTotal   *float64
	ClientAborts    *float64
	ServerAborts    *float64
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
	// QueueTimeAvg/ConnectTimeAvg/ResponseTimeAvg/TotalTimeAvg mirror the
	// backend-level rolling averages (see HAProxyBackend) but per server.
	// CheckDowns (chkdown) counts UP->DOWN transitions; LastStateChangeSeconds
	// (lastchg) is seconds since the last state change. All nil when the CSV
	// cell was empty — never a fabricated 0 (#164).
	QueueTimeAvg           *float64
	ConnectTimeAvg         *float64
	ResponseTimeAvg        *float64
	TotalTimeAvg           *float64
	CheckDowns             *float64
	LastStateChangeSeconds *float64
}

// HAProxyStickTable is the normalised per-table row from
// api/haproxy/statistics/tables ("show table" over the admin socket).
type HAProxyStickTable struct {
	Table string
	Type  string
	Size  float64
	Used  float64
}

// HAProxyInfo is the normalised process-level `show info` data.
type HAProxyInfo struct {
	Version            string
	UptimeSeconds      float64
	CurrentConnections float64
	ConnectionsTotal   float64
	RequestsTotal      float64
	IdlePercent        float64
	// ConnectionLimit (Maxconn) and SslCurrentConnections (CurrSslConns) are
	// nil when the field is absent from `show info` — never a fabricated 0.
	ConnectionLimit       *float64
	SslCurrentConnections *float64
}

// haproxyTableRow mirrors one element of the api/haproxy/statistics/tables
// response ("show table" parsed by queryStats.php). Every value is a JSON
// string, mirroring haproxyStatRow. VERIFIED against a live os-haproxy
// dev-box (issue #201, 2026-07-13): a stick-table frontend with `used > 0`.
type haproxyTableRow struct {
	Table string `json:"table"`
	Type  string `json:"type"`
	Size  string `json:"size"`
	Used  string `json:"used"`
}

// HAProxyStats holds the aggregated result of FetchHAProxyStats.
type HAProxyStats struct {
	Present     bool // false when the plugin is absent (counters endpoint 404s)
	Frontends   []HAProxyFrontend
	Backends    []HAProxyBackend
	Servers     []HAProxyServer
	StickTables []HAProxyStickTable
	Info        HAProxyInfo
	HasInfo     bool
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

// haproxyOptFloat parses a show-stat CSV cell to *float64, returning nil for
// an empty/unparseable cell instead of a fabricated 0 — several fields added
// for #201 (qtime/ctime/rtime/ttime, chkdown, lastchg, slim, req_tot, lbtot,
// cli_abrt/srv_abrt, Maxconn, CurrSslConns) go empty on rows or proxy modes
// they don't apply to (tcp-mode proxies, FRONTEND rows lacking backend-only
// timing fields, older HAProxy builds missing a `show info` key).
func haproxyOptFloat(s string) *float64 {
	v, ok := safeParseFloatOK(s)
	if !ok {
		return nil
	}
	return &v
}

// haproxyMillisToSeconds converts a show-stat *time field (milliseconds) to
// seconds, preserving nil for an absent/empty cell (#164).
func haproxyMillisToSeconds(s string) *float64 {
	v := haproxyOptFloat(s)
	if v == nil {
		return nil
	}
	sec := *v / 1000
	return &sec
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
	tablesURL, ok := c.endpoints["haproxyTables"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "haproxyTables",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// Fetch counters, info and tables concurrently — independent endpoints written to
	// separate local vars, processed single-threaded after the join, so wall time is
	// the slowest of the three rather than their sum (#129). Counters still gates
	// plugin-presence. The counters payload is a heterogeneous JSON array: complete
	// rows are objects, incomplete CSV lines survive as raw arrays. Decode elementwise.
	var rawRows []json.RawMessage
	var info map[string]flexString
	var tableRows []haproxyTableRow
	fetchErrs := runConcurrentFetches(
		func() *APICallError { return c.do("GET", countersURL, nil, &rawRows) },
		func() *APICallError { return c.do("GET", infoURL, nil, &info) },
		func() *APICallError { return c.do("GET", tablesURL, nil, &tableRows) },
	)
	countersErr, infoErr, tablesErr := fetchErrs[0], fetchErrs[1], fetchErrs[2]

	if countersErr != nil {
		if countersErr.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent: Present stays false (info result discarded)
		}
		return data, countersErr
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
				RequestsTotal:   haproxyOptFloat(row.ReqTot),
				SessionLimit:    haproxyOptFloat(row.Slim),
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
				QueueTimeAvg:     haproxyMillisToSeconds(row.Qtime),
				ConnectTimeAvg:   haproxyMillisToSeconds(row.Ctime),
				ResponseTimeAvg:  haproxyMillisToSeconds(row.Rtime),
				TotalTimeAvg:     haproxyMillisToSeconds(row.Ttime),
				SelectedTotal:    haproxyOptFloat(row.LbTot),
				ClientAborts:     haproxyOptFloat(row.CliAbrt),
				ServerAborts:     haproxyOptFloat(row.SrvAbrt),
			})
		case row.Type == "2":
			data.Servers = append(data.Servers, HAProxyServer{
				Backend:                row.PXName,
				Name:                   row.SVName,
				StatusUp:               haproxyStatusUp(row.Status),
				CurrentSessions:        safeParseFloat(row.Scur),
				SessionsTotal:          safeParseFloat(row.Stot),
				BytesIn:                safeParseFloat(row.Bin),
				BytesOut:               safeParseFloat(row.Bout),
				QueueCurrent:           safeParseFloat(row.Qcur),
				ConnectionErrors:       safeParseFloat(row.Econ),
				ResponseErrors:         safeParseFloat(row.Eresp),
				CheckFailures:          safeParseFloat(row.Chkfail),
				DowntimeSeconds:        safeParseFloat(row.Downtime),
				Weight:                 safeParseFloat(row.Weight),
				QueueTimeAvg:           haproxyMillisToSeconds(row.Qtime),
				ConnectTimeAvg:         haproxyMillisToSeconds(row.Ctime),
				ResponseTimeAvg:        haproxyMillisToSeconds(row.Rtime),
				TotalTimeAvg:           haproxyMillisToSeconds(row.Ttime),
				CheckDowns:             haproxyOptFloat(row.Chkdown),
				LastStateChangeSeconds: haproxyOptFloat(row.Lastchg),
			})
		}
		// listeners (type "3") and anything unclassified are skipped
	}

	if infoErr != nil {
		// Counters succeeded so the plugin exists; surface real info errors
		// but tolerate 404 (defensive: endpoint variations across versions).
		if infoErr.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, infoErr
	}
	if len(info) > 0 {
		data.HasInfo = true
		data.Info = HAProxyInfo{
			Version:               info["Version"].String(),
			UptimeSeconds:         safeParseFloat(info["Uptime_sec"].String()),
			CurrentConnections:    safeParseFloat(info["CurrConns"].String()),
			ConnectionsTotal:      safeParseFloat(info["CumConns"].String()),
			RequestsTotal:         safeParseFloat(info["CumReq"].String()),
			IdlePercent:           safeParseFloat(info["Idle_pct"].String()),
			ConnectionLimit:       haproxyOptFloat(info["Maxconn"].String()),
			SslCurrentConnections: haproxyOptFloat(info["CurrSslConns"].String()),
		}
	}

	if tablesErr != nil {
		// Counters succeeded so the plugin exists; surface real tables errors
		// but tolerate 404 (older os-haproxy builds without the tables
		// controller route, or a service that has no stick tables configured
		// and answers 404 for the summary — never fatal to the rest of the scrape).
		if tablesErr.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, tablesErr
	}
	for _, row := range tableRows {
		data.StickTables = append(data.StickTables, HAProxyStickTable{
			Table: row.Table,
			Type:  row.Type,
			Size:  safeParseFloat(row.Size),
			Used:  safeParseFloat(row.Used),
		})
	}

	return data, nil
}
