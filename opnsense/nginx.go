package opnsense

import "net/http"

// nginxVtsResponses holds HTTP response counts by status code class, as
// reported for upstreamZones entries. Upstream servers are never cache-aware
// (a cache sits in front of a server zone, not a specific upstream peer), so
// this shape carries no cache-status fields — verified against a live
// heavy-topology capture (#200, 2026-07-13): upstreamZones.*[].responses only
// ever has 1xx..5xx keys.
type nginxVtsResponses struct {
	R1xx float64 `json:"1xx"`
	R2xx float64 `json:"2xx"`
	R3xx float64 `json:"3xx"`
	R4xx float64 `json:"4xx"`
	R5xx float64 `json:"5xx"`
}

// nginxVtsServerZoneResponses holds a serverZones entry's responses object:
// the HTTP status code classes PLUS cache-status counts. The cache-status
// fields (miss/bypass/expired/stale/updating/revalidated/hit/scarce) are only
// actually sent when this vts build has the cache-status extension compiled
// in — on builds without it they are simply absent from the JSON (not
// present-as-zero), so NginxVTS.CacheStatusPresent gates whether the
// exporter treats them as meaningful rather than reading a false zero.
type nginxVtsServerZoneResponses struct {
	R1xx float64 `json:"1xx"`
	R2xx float64 `json:"2xx"`
	R3xx float64 `json:"3xx"`
	R4xx float64 `json:"4xx"`
	R5xx float64 `json:"5xx"`

	Miss        float64 `json:"miss"`
	Bypass      float64 `json:"bypass"`
	Expired     float64 `json:"expired"`
	Stale       float64 `json:"stale"`
	Updating    float64 `json:"updating"`
	Revalidated float64 `json:"revalidated"`
	Hit         float64 `json:"hit"`
	Scarce      float64 `json:"scarce"`
}

// nginxVtsCacheZoneResponses holds a cacheZones entry's responses object:
// cache-status counts only. Verified live: a cache zone's responses object
// never carries 1xx..5xx keys (a cache zone doesn't see raw HTTP status
// codes, only cache outcomes) — distinct from nginxVtsServerZoneResponses.
type nginxVtsCacheZoneResponses struct {
	Miss        float64 `json:"miss"`
	Bypass      float64 `json:"bypass"`
	Expired     float64 `json:"expired"`
	Stale       float64 `json:"stale"`
	Updating    float64 `json:"updating"`
	Revalidated float64 `json:"revalidated"`
	Hit         float64 `json:"hit"`
	Scarce      float64 `json:"scarce"`
}

// nginxVtsOverCounts is an overCounts group: nginx-module-vts's own
// wrap-detection counters. The add_oc macro
// (ngx_http_vhost_traffic_status_module.h) bumps a dedicated _oc field by 1 each
// time a worker-shard's raw counter is found to be LESS than the already-
// accumulated total, i.e. that shard's counter wrapped. Each _oc field is
// itself monotonic and resets only alongside every other vts counter on an
// nginx reload, so all of these are COUNTERS.
//
// #609: there is one wrap counter PER underlying counter, and
// display_json.h emits them as an OBJECT keyed exactly like the counters they
// shadow. #584 modelled the group as a single float64, which made the entire
// payload fail to unmarshal — and since unmarshalBody turns any decode error
// into an APICallError, that lost every VTS metric rather than just this one.
//
// Which keys are present varies by build and by zone kind, and absent is NOT
// the same as zero-that-was-sent: the eight cache keys appear only on an
// NGX_HTTP_CACHE build, responseMsecCounter only on upstream zones. Absent keys
// decode to 0 and contribute 0 to total(), which is the correct reading — a
// counter that cannot wrap has not wrapped.
type nginxVtsOverCounts struct {
	// MaxIntegerSize is the build's counter ceiling (2^64-1 on a 64-bit box),
	// emitted with a %s conversion as a bare literal. It overflows int64, so it
	// is carried as a flexString: it is a capability constant, never exported,
	// and modelled only so the canary does not report it as unmodelled drift.
	MaxIntegerSize flexString `json:"maxIntegerSize"`

	RequestCounter float64 `json:"requestCounter"`
	InBytes        float64 `json:"inBytes"`
	OutBytes       float64 `json:"outBytes"`

	R1xx float64 `json:"1xx"`
	R2xx float64 `json:"2xx"`
	R3xx float64 `json:"3xx"`
	R4xx float64 `json:"4xx"`
	R5xx float64 `json:"5xx"`

	// Cache-status wrap counters: NGX_HTTP_CACHE builds only, server zones and
	// cache zones only.
	Miss        float64 `json:"miss"`
	Bypass      float64 `json:"bypass"`
	Expired     float64 `json:"expired"`
	Stale       float64 `json:"stale"`
	Updating    float64 `json:"updating"`
	Revalidated float64 `json:"revalidated"`
	Hit         float64 `json:"hit"`
	Scarce      float64 `json:"scarce"`

	RequestMsecCounter float64 `json:"requestMsecCounter"`
	// ResponseMsecCounter is emitted for upstream zones only.
	ResponseMsecCounter float64 `json:"responseMsecCounter"`
}

// total sums every wrap counter in the group, excluding MaxIntegerSize (a
// capability constant, not a wrap count). This is what the exported
// *_counter_wraps_total metrics carry, and it matches what they already
// promise: the number of times ONE OF this zone's counters was seen to wrap.
//
// A per-sub-counter breakdown was considered and rejected (#609): it would be
// more faithful but multiplies series ~17x per zone for values that are
// permanently 0 on any 64-bit box, and the operational question — did anything
// wrap in this zone, so is a rate() here discontinuous — is answered exactly by
// the sum.
func (o nginxVtsOverCounts) total() float64 {
	return o.RequestCounter + o.InBytes + o.OutBytes +
		o.R1xx + o.R2xx + o.R3xx + o.R4xx + o.R5xx +
		o.Miss + o.Bypass + o.Expired + o.Stale +
		o.Updating + o.Revalidated + o.Hit + o.Scarce +
		o.RequestMsecCounter + o.ResponseMsecCounter
}

// nginxVtsServerZone is one entry from the serverZones map in the VTS payload.
type nginxVtsServerZone struct {
	RequestCounter     float64                     `json:"requestCounter"`
	InBytes            float64                     `json:"inBytes"`
	OutBytes           float64                     `json:"outBytes"`
	Responses          nginxVtsServerZoneResponses `json:"responses"`
	RequestMsecCounter float64                     `json:"requestMsecCounter"` // cumulative sum of request times, ms
	// OverCounts is this zone's wrap-detection group -- see nginxVtsOverCounts.
	OverCounts nginxVtsOverCounts `json:"overCounts"`
}

// nginxVtsUpstream is one upstream server entry inside the upstreamZones map.
type nginxVtsUpstream struct {
	Server              string            `json:"server"`
	RequestCounter      float64           `json:"requestCounter"`
	InBytes             float64           `json:"inBytes"`
	OutBytes            float64           `json:"outBytes"`
	Responses           nginxVtsResponses `json:"responses"`
	ResponseMsec        float64           `json:"responseMsec"`
	RequestMsecCounter  float64           `json:"requestMsecCounter"`  // cumulative sum of request times, ms
	ResponseMsecCounter float64           `json:"responseMsecCounter"` // cumulative sum of response times, ms
	Down                bool              `json:"down"`
	// OverCounts: see nginxVtsOverCounts -- same wrap-detection group, one per
	// upstream server entry. An upstream group additionally carries
	// responseMsecCounter and never carries the cache keys.
	OverCounts nginxVtsOverCounts `json:"overCounts"`
}

// nginxVtsCacheZone is one entry from the cacheZones map in the VTS payload —
// one per configured proxy_cache_path. Zone names are cache_path model UUIDs
// with the dashes stripped (nginx module naming); relabeling them to the
// configured path would need an extra api/nginx/settings/get call, which #200
// Part 1 deliberately rules out ("zero new API calls"), so they are exported
// raw, same as the vhost-name-keyed serverZones.
type nginxVtsCacheZone struct {
	MaxSize   float64                    `json:"maxSize"`
	UsedSize  float64                    `json:"usedSize"`
	InBytes   float64                    `json:"inBytes"`
	OutBytes  float64                    `json:"outBytes"`
	Responses nginxVtsCacheZoneResponses `json:"responses"`
}

// nginxVtsResponse is the raw JSON structure returned by the nginx VTS endpoint
// (api/nginx/service/vts). VTS values are real JSON numbers (produced by nginx,
// not PHP-mangled), so float64 fields decode directly without flexString.
type nginxVtsResponse struct {
	LoadMsec    float64 `json:"loadMsec"` // config-load (reload) time, epoch ms; 0 on old vts builds that omit it
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
	CacheZones    map[string]nginxVtsCacheZone  `json:"cacheZones"`
}

// NginxServerZone holds normalised per-virtual-host traffic statistics.
// The aggregate zone "*" is excluded to avoid double-counting.
type NginxServerZone struct {
	Zone                        string
	Requests, BytesIn, BytesOut float64
	ResponsesByCode             map[string]float64 // keys: 1xx, 2xx, 3xx, 4xx, 5xx
	CacheResponsesByCode        map[string]float64 // keys: hit, miss, bypass, expired, stale, updating, revalidated, scarce
	RequestSecondsTotal         float64            // requestMsecCounter / 1000 (cumulative)
	// CounterWraps is nginx-module-vts's own overCounts wrap-detection
	// counter for this zone (see nginxVtsServerZone.OverCounts) -- a COUNTER,
	// not a gauge: it only increases, and a non-zero value means one of this
	// zone's other counters above wrapped and its rate() has a discontinuity.
	CounterWraps float64
}

// NginxUpstreamServer holds normalised per-upstream-server statistics.
type NginxUpstreamServer struct {
	Upstream, Server            string
	Requests, BytesIn, BytesOut float64
	ResponsesByCode             map[string]float64 // keys: 1xx, 2xx, 3xx, 4xx, 5xx
	Down                        bool
	ResponseTimeSeconds         float64 // responseMsec / 1000 (instantaneous moving average)
	RequestSecondsTotal         float64 // requestMsecCounter / 1000 (cumulative)
	ResponseSecondsTotal        float64 // responseMsecCounter / 1000 (cumulative)
	// CounterWraps: see NginxServerZone.CounterWraps -- same wrap-detection
	// counter, for this upstream server entry.
	CounterWraps float64
}

// NginxCacheZone holds normalised per-proxy_cache_path statistics.
type NginxCacheZone struct {
	Zone                string
	MaxBytes, UsedBytes float64
	BytesIn, BytesOut   float64
	ResponsesByCode     map[string]float64 // keys: hit, miss, bypass, expired, stale, updating, revalidated, scarce
}

// NginxVTS holds the aggregated result of FetchNginxVTS.
type NginxVTS struct {
	Present bool // false when 404 (plugin absent or nginx stopped)

	ConnectionsActive, ConnectionsReading, ConnectionsWriting, ConnectionsWaiting float64
	ConnectionsAccepted, ConnectionsHandled, RequestsTotal                        float64

	SharedMaxBytes, SharedUsedBytes, SharedUsedNodes float64

	ServerZones     []NginxServerZone     // zone "*" is excluded
	UpstreamServers []NginxUpstreamServer // flattened from upstreamZones map
	CacheZones      []NginxCacheZone      // flattened from cacheZones map; empty when none configured

	// CacheStatusPresent reports whether this vts build reports cache-status
	// response fields at all (derived from the top-level "cacheZones" key
	// being present in the payload, even as an empty object) — distinct from
	// "no cache configured" (CacheZones simply empty). Older vts builds
	// without the cache-status extension never send this key, so per-server-
	// zone cache-status counters would otherwise be meaningless zeros.
	CacheStatusPresent bool

	// ConfigLoadTimestampSeconds is the nginx config (re)load time (loadMsec /
	// 1000); 0 when the vts build omits loadMsec.
	ConfigLoadTimestampSeconds float64
}

// nginxVtsResponsesToMap converts the upstreamZones VTS responses struct to
// the common map[string]float64 keyed by HTTP status code class string
// ("1xx"…"5xx").
func nginxVtsResponsesToMap(r nginxVtsResponses) map[string]float64 {
	return map[string]float64{
		"1xx": r.R1xx,
		"2xx": r.R2xx,
		"3xx": r.R3xx,
		"4xx": r.R4xx,
		"5xx": r.R5xx,
	}
}

// nginxVtsServerZoneHTTPResponsesToMap converts the HTTP-status-code half of a
// serverZones responses object to the common map[string]float64.
func nginxVtsServerZoneHTTPResponsesToMap(r nginxVtsServerZoneResponses) map[string]float64 {
	return map[string]float64{
		"1xx": r.R1xx,
		"2xx": r.R2xx,
		"3xx": r.R3xx,
		"4xx": r.R4xx,
		"5xx": r.R5xx,
	}
}

// nginxVtsServerZoneCacheResponsesToMap converts the cache-status half of a
// serverZones responses object to the common map[string]float64 keyed by
// cache status string.
func nginxVtsServerZoneCacheResponsesToMap(r nginxVtsServerZoneResponses) map[string]float64 {
	return map[string]float64{
		"hit":         r.Hit,
		"miss":        r.Miss,
		"bypass":      r.Bypass,
		"expired":     r.Expired,
		"stale":       r.Stale,
		"updating":    r.Updating,
		"revalidated": r.Revalidated,
		"scarce":      r.Scarce,
	}
}

// nginxVtsCacheZoneResponsesToMap converts a cacheZones responses object to
// the common map[string]float64 keyed by cache status string.
func nginxVtsCacheZoneResponsesToMap(r nginxVtsCacheZoneResponses) map[string]float64 {
	return map[string]float64{
		"hit":         r.Hit,
		"miss":        r.Miss,
		"bypass":      r.Bypass,
		"expired":     r.Expired,
		"stale":       r.Stale,
		"updating":    r.Updating,
		"revalidated": r.Revalidated,
		"scarce":      r.Scarce,
	}
}

// FetchNginxVTS fetches the nginx vhost_traffic_status VTS data from the
// api/nginx/service/vts endpoint.
//
// The nginx plugin controller passes the VTS JSON through verbatim, but returns
// HTTP 404 with body "[]" when nginx is stopped or VTS has no data. Both cases
// are treated as "plugin absent or no data" — empty result, no error.
//
// VERIFICATION: validated against a live os-nginx box (OPNsense 26.7-devel
// testbed, 2026-07-13) with a vhost, a 2-server upstream and a proxy_cache
// zone driving real traffic — see opnsense/testdata/schemas for the golden
// shape and the issue #200 capture notes for the raw payload. Shape also
// cross-checked against www/nginx
// src/opnsense/mvc/app/controllers/OPNsense/Nginx/Api/ServiceController.php
// and the nginx-module-vts JSON output format.
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
	data.CacheStatusPresent = raw.CacheZones != nil
	data.ConfigLoadTimestampSeconds = raw.LoadMsec / 1000

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
			Zone:                 zone,
			Requests:             sz.RequestCounter,
			BytesIn:              sz.InBytes,
			BytesOut:             sz.OutBytes,
			ResponsesByCode:      nginxVtsServerZoneHTTPResponsesToMap(sz.Responses),
			CacheResponsesByCode: nginxVtsServerZoneCacheResponsesToMap(sz.Responses),
			RequestSecondsTotal:  sz.RequestMsecCounter / 1000,
			CounterWraps:         sz.OverCounts.total(),
		})
	}

	// Upstream zones — flatten the map[upstream][]server into a flat slice
	for upstream, servers := range raw.UpstreamZones {
		for _, srv := range servers {
			data.UpstreamServers = append(data.UpstreamServers, NginxUpstreamServer{
				Upstream:             upstream,
				Server:               srv.Server,
				Requests:             srv.RequestCounter,
				BytesIn:              srv.InBytes,
				BytesOut:             srv.OutBytes,
				ResponsesByCode:      nginxVtsResponsesToMap(srv.Responses),
				Down:                 srv.Down,
				ResponseTimeSeconds:  srv.ResponseMsec / 1000,
				RequestSecondsTotal:  srv.RequestMsecCounter / 1000,
				ResponseSecondsTotal: srv.ResponseMsecCounter / 1000,
				CounterWraps:         srv.OverCounts.total(),
			})
		}
	}

	// Cache zones — one per configured proxy_cache_path; empty map when none
	// configured (or on vts builds without the cache-status extension).
	for zone, cz := range raw.CacheZones {
		data.CacheZones = append(data.CacheZones, NginxCacheZone{
			Zone:            zone,
			MaxBytes:        cz.MaxSize,
			UsedBytes:       cz.UsedSize,
			BytesIn:         cz.InBytes,
			BytesOut:        cz.OutBytes,
			ResponsesByCode: nginxVtsCacheZoneResponsesToMap(cz.Responses),
		})
	}

	return data, nil
}

// nginxBanRow mirrors one row from the api/nginx/bans/searchban bootgrid
// endpoint — an autoblock-banned IP, keyed by the ban model's uuid.
//
// Despite living under nginx/bans (a "settings" style controller path), these
// rows are runtime state: created by the autoblock cron when a client's
// User-Agent matches the configured bot list or trips the request-rate ACL,
// and pruned once ban_ttl (nginx/settings general.ban_ttl, minutes) expires —
// there is no separate "ban expiry" event to poll for, only this list shrinking.
type nginxBanRow struct {
	UUID string     `json:"uuid"`
	IP   string     `json:"ip"`
	Time flexString `json:"time"` // unix ban timestamp, seconds; PHP int, but flexString for resilience
}

// nginxBanSearchResponse is the raw bootgrid envelope for nginx/bans/searchban.
type nginxBanSearchResponse struct {
	Total    int           `json:"total"`
	RowCount int           `json:"rowCount"`
	Current  int           `json:"current"`
	Rows     []nginxBanRow `json:"rows"`
}

// NginxBans holds the aggregated result of FetchNginxBans.
type NginxBans struct {
	Present bool // false when the os-nginx plugin is not installed (HTTP 404)
	Count   int  // current number of active autoblock bans

	// LastBanTimestampSeconds is the maximum `time` across all returned rows
	// (the most recent ban); 0 when there are no active bans.
	LastBanTimestampSeconds float64
}

// FetchNginxBans calls the nginx autoblock ban list search endpoint
// (api/nginx/bans/searchban) and returns the current ban count plus the most
// recent ban's timestamp.
//
// Deliberately does NOT export per-IP rows as labels: banned IPs are
// attacker-controlled input, so turning them into a label would make the
// series cardinality unbounded. Only the aggregate count and a single scalar
// "most recent ban" timestamp are exported (#200).
//
// If the os-nginx plugin is not installed the endpoint returns HTTP 404
// (verified against a live OPNsense 26.7-devel box, 2026-07-13, same as
// FetchNginxVTS). That is treated as "feature absent" — empty data with no
// error — mirroring FetchACMECertificates.
func (c *Client) FetchNginxBans() (NginxBans, *APICallError) {
	var resp nginxBanSearchResponse
	var data NginxBans

	url, ok := c.endpoints["nginxBans"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "nginxBans",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.Count = resp.Total

	for _, row := range resp.Rows {
		if ts := safeParseFloat(row.Time.String()); ts > data.LastBanTimestampSeconds {
			data.LastBanTimestampSeconds = ts
		}
	}

	return data, nil
}
