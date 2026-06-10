package opnsense

import "net/http"

// nginxVtsResponses holds HTTP response counts by status code class, as
// reported by the nginx vhost_traffic_status module.
type nginxVtsResponses struct {
	R1xx float64 `json:"1xx"`
	R2xx float64 `json:"2xx"`
	R3xx float64 `json:"3xx"`
	R4xx float64 `json:"4xx"`
	R5xx float64 `json:"5xx"`
}

// nginxVtsServerZone is one entry from the serverZones map in the VTS payload.
type nginxVtsServerZone struct {
	RequestCounter float64           `json:"requestCounter"`
	InBytes        float64           `json:"inBytes"`
	OutBytes       float64           `json:"outBytes"`
	Responses      nginxVtsResponses `json:"responses"`
}

// nginxVtsUpstream is one upstream server entry inside the upstreamZones map.
type nginxVtsUpstream struct {
	Server         string            `json:"server"`
	RequestCounter float64           `json:"requestCounter"`
	InBytes        float64           `json:"inBytes"`
	OutBytes       float64           `json:"outBytes"`
	Responses      nginxVtsResponses `json:"responses"`
	ResponseMsec   float64           `json:"responseMsec"`
	Down           bool              `json:"down"`
}

// nginxVtsResponse is the raw JSON structure returned by the nginx VTS endpoint
// (api/nginx/service/vts). VTS values are real JSON numbers (produced by nginx,
// not PHP-mangled), so float64 fields decode directly without flexString.
type nginxVtsResponse struct {
	Connections struct {
		Active   float64 `json:"active"`
		Reading  float64 `json:"reading"`
		Writing  float64 `json:"writing"`
		Waiting  float64 `json:"waiting"`
		Accepted float64 `json:"accepted"`
		Handled  float64 `json:"handled"`
		Requests float64 `json:"requests"`
	} `json:"connections"`
	SharedZones struct {
		MaxSize  float64 `json:"maxSize"`
		UsedSize float64 `json:"usedSize"`
		UsedNode float64 `json:"usedNode"`
	} `json:"sharedZones"`
	ServerZones   map[string]nginxVtsServerZone `json:"serverZones"`
	UpstreamZones map[string][]nginxVtsUpstream `json:"upstreamZones"`
}

// NginxServerZone holds normalised per-virtual-host traffic statistics.
// The aggregate zone "*" is excluded to avoid double-counting.
type NginxServerZone struct {
	Zone                        string
	Requests, BytesIn, BytesOut float64
	ResponsesByCode             map[string]float64 // keys: 1xx, 2xx, 3xx, 4xx, 5xx
}

// NginxUpstreamServer holds normalised per-upstream-server statistics.
type NginxUpstreamServer struct {
	Upstream, Server            string
	Requests, BytesIn, BytesOut float64
	ResponsesByCode             map[string]float64 // keys: 1xx, 2xx, 3xx, 4xx, 5xx
	Down                        bool
	ResponseTimeSeconds         float64 // responseMsec / 1000
}

// NginxVTS holds the aggregated result of FetchNginxVTS.
type NginxVTS struct {
	Present bool // false when 404 (plugin absent or nginx stopped)

	ConnectionsActive, ConnectionsReading, ConnectionsWriting, ConnectionsWaiting float64
	ConnectionsAccepted, ConnectionsHandled, RequestsTotal                        float64

	SharedMaxBytes, SharedUsedBytes, SharedUsedNodes float64

	ServerZones     []NginxServerZone     // zone "*" is excluded
	UpstreamServers []NginxUpstreamServer // flattened from upstreamZones map
}

// nginxVtsResponsesToMap converts the VTS responses struct to the common
// map[string]float64 keyed by code class string ("1xx"…"5xx").
func nginxVtsResponsesToMap(r nginxVtsResponses) map[string]float64 {
	return map[string]float64{
		"1xx": r.R1xx,
		"2xx": r.R2xx,
		"3xx": r.R3xx,
		"4xx": r.R4xx,
		"5xx": r.R5xx,
	}
}

// FetchNginxVTS fetches the nginx vhost_traffic_status VTS data from the
// api/nginx/service/vts endpoint.
//
// The nginx plugin controller passes the VTS JSON through verbatim, but returns
// HTTP 404 with body "[]" when nginx is stopped or VTS has no data. Both cases
// are treated as "plugin absent or no data" — empty result, no error.
//
// VERIFICATION: unvalidated against a live os-nginx box with VTS enabled.
// Shape derived from www/nginx src/opnsense/mvc/app/controllers/OPNsense/Nginx/Api/ServiceController.php
// and the nginx-module-vts JSON output format. Re-check field names on real
// hardware when available.
func (c *Client) FetchNginxVTS() (NginxVTS, *APICallError) {
	var data NginxVTS

	url, ok := c.endpoints["nginxVts"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "nginxVts",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var raw nginxVtsResponse
	if err := c.do("GET", url, nil, &raw); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent or nginx stopped: Present stays false
		}
		return data, err
	}

	data.Present = true

	// Top-level connection stats
	data.ConnectionsActive = raw.Connections.Active
	data.ConnectionsReading = raw.Connections.Reading
	data.ConnectionsWriting = raw.Connections.Writing
	data.ConnectionsWaiting = raw.Connections.Waiting
	data.ConnectionsAccepted = raw.Connections.Accepted
	data.ConnectionsHandled = raw.Connections.Handled
	data.RequestsTotal = raw.Connections.Requests

	// Shared memory zone stats
	data.SharedMaxBytes = raw.SharedZones.MaxSize
	data.SharedUsedBytes = raw.SharedZones.UsedSize
	data.SharedUsedNodes = raw.SharedZones.UsedNode

	// Server zones — skip the aggregate zone "*" to avoid double-counting
	for zone, sz := range raw.ServerZones {
		if zone == "*" {
			continue
		}
		data.ServerZones = append(data.ServerZones, NginxServerZone{
			Zone:            zone,
			Requests:        sz.RequestCounter,
			BytesIn:         sz.InBytes,
			BytesOut:        sz.OutBytes,
			ResponsesByCode: nginxVtsResponsesToMap(sz.Responses),
		})
	}

	// Upstream zones — flatten the map[upstream][]server into a flat slice
	for upstream, servers := range raw.UpstreamZones {
		for _, srv := range servers {
			data.UpstreamServers = append(data.UpstreamServers, NginxUpstreamServer{
				Upstream:            upstream,
				Server:              srv.Server,
				Requests:            srv.RequestCounter,
				BytesIn:             srv.InBytes,
				BytesOut:            srv.OutBytes,
				ResponsesByCode:     nginxVtsResponsesToMap(srv.Responses),
				Down:                srv.Down,
				ResponseTimeSeconds: srv.ResponseMsec / 1000,
			})
		}
	}

	return data, nil
}
