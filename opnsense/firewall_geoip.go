package opnsense

import (
	"strings"
	"time"
)

// geoIPAliasResponse mirrors api/firewall/alias/get_geo_i_p
// (Firewall/Api/AliasController::getGeoIPAction), which merges three sources
// into one object: the `geoip` config node (Firewall/Alias.xml — a single
// UrlField), an alias-usage count computed on the fly, and the cached result
// of the last `filter geoip stats` configd run (geoip.py's GEOIP._update,
// persisted to /usr/local/share/GeoIP/alias.stats).
//
// SECURITY (#221): the config node's `url` field is the full MaxMind/ipinfo
// download URL WITH the license key embedded as a query parameter. It is
// deliberately NOT decoded here — a narrow struct, mirroring the
// caRow/certificateRow pattern in certificates.go — so the credential never
// enters exporter memory beyond the transient response buffer, and can never
// reach a metric, log line, or error message via the normal decode path. The
// `subscription`, `locations_filename` and `address_sources` fields are
// likewise omitted: not sensitive, but not needed by any metric either.
type geoIPAliasResponse struct {
	Alias struct {
		GeoIP struct {
			// Usages is incremented once per configured alias of type "geoip",
			// regardless of whether the GeoIP database itself has ever downloaded.
			Usages flexString `json:"usages"`
			// AddressCount/FileCount/Timestamp come from the cached geoip.py stats
			// file and read as zero/null until a MaxMind (or ipinfo) key is
			// configured and the box has downloaded at least once.
			AddressCount flexString `json:"address_count"`
			FileCount    flexString `json:"file_count"`
			// Timestamp is a naive (no timezone) ISO-8601 string when the database
			// has been downloaded at least once, or JSON null otherwise. flexString
			// decodes null to "", so an empty string and a failed parse are both
			// treated as "never downloaded" by parseGeoIPTimestamp.
			Timestamp flexString `json:"timestamp"`
		} `json:"geoip"`
	} `json:"alias"`
}

// geoIPTimestampLayouts are tried in order against the geoip.py timestamp
// string. The zip-source path (process_zip) writes
// datetime.datetime(*zipinfo_date_time).isoformat() — whole seconds, no
// microseconds; the gzip-source path (process_gzip, e.g. ipinfo) writes
// datetime.datetime.now().isoformat() — which does carry microseconds. Both
// are naive (no timezone offset), so they are parsed as UTC deterministically
// rather than resolving against the host's local zone, mirroring
// parseClamAVSignatureDB's handling of the same ambiguity in clamav.go.
var geoIPTimestampLayouts = []string{
	"2006-01-02T15:04:05.999999",
	"2006-01-02T15:04:05",
}

// parseGeoIPTimestamp parses geoip.py's naive ISO-8601 timestamp string into
// Unix seconds. Returns ok=false for an empty string (never downloaded) or a
// shape that fails every known layout — the caller must skip the metric
// rather than emit epoch 0, which would misreport a stale-forever database.
func parseGeoIPTimestamp(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for _, layout := range geoIPTimestampLayouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return float64(t.Unix()), true
		}
	}
	return 0, false
}

// GeoIPStatus is the normalised firewall GeoIP alias-database freshness
// summary: is the database actually downloading, and how stale is it.
// GeoIP aliases silently stop matching any traffic once the database stops
// updating (expired MaxMind key, download failure) — this is the direct
// health signal for that failure mode.
type GeoIPStatus struct {
	// AliasUsages is the number of configured aliases of type "geoip",
	// regardless of database download state.
	AliasUsages float64
	// AddressCount/FileCount are 0 until the database has downloaded at least
	// once (no MaxMind/ipinfo key configured, or the last download failed).
	AddressCount float64
	FileCount    float64
	// LastUpdateTimestamp is the Unix-seconds time of the last successful
	// database download. HasLastUpdateTimestamp is false when the database has
	// never downloaded (JSON null) or the timestamp failed to parse — never
	// treat 0 as a real epoch value for this field.
	LastUpdateTimestamp    float64
	HasLastUpdateTimestamp bool
}

// FetchFirewallGeoIPStatus returns the firewall GeoIP alias-database
// freshness summary from api/firewall/alias/get_geo_i_p. This is a core
// endpoint — it is never plugin-gated and never answers 404 — served from
// the cached geoip.py stats file, so it is cheap and slow-moving (cache-TTL
// eligible).
func (c *Client) FetchFirewallGeoIPStatus() (GeoIPStatus, *APICallError) {
	var resp geoIPAliasResponse
	var data GeoIPStatus

	path, ok := c.endpoints["firewallGeoIP"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "firewallGeoIP",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		return data, err
	}

	g := resp.Alias.GeoIP
	data.AliasUsages = safeParseFloat(g.Usages.String())
	data.AddressCount = safeParseFloat(g.AddressCount.String())
	data.FileCount = safeParseFloat(g.FileCount.String())
	if ts, ok := parseGeoIPTimestamp(g.Timestamp.String()); ok {
		data.LastUpdateTimestamp = ts
		data.HasLastUpdateTimestamp = true
	}

	return data, nil
}
