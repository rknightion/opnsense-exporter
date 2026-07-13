package opnsense

import (
	"net/http"
	"net/url"
)

// vnstatInterfaceListResponse mirrors api/vnstat/service/interface_list.
//
// It returns EVERY interface vnstat's own on-disk database currently holds
// data for (physical NICs, VLANs, and virtual/tunnel devices such as enc0 or
// tailscale0) — NOT the subset the os-vnstat plugin's General settings page
// has been configured to monitor. That admin-selected set lives behind
// api/vnstat/general/get and only exposes OPNsense's logical wan/lan/optN
// identifiers (plus a friendly description), which cannot be mapped back to
// a device name without a third endpoint call outside this issue's scope.
//
// Verified live against a dev box (#215): interface_list returned 7 devices
// (enc0, tailscale0, vlan01, vlan02, vtnet0, vtnet1, vtnet2) while only 2
// logical interfaces were selected for vnstat monitoring in general/get.
// FetchVnstat deliberately exports every device the DB actually holds data
// for rather than cross-referencing that config: the device set is bounded
// by the box's own interface topology (a handful of NICs/VLANs, fixed at
// boot/config time), not unbounded user data like DHCP leases or ARP
// entries, so this does not introduce a cardinality risk.
type vnstatInterfaceListResponse struct {
	Interfaces []string `json:"interfaces"`
}

// vnstatJSONResponse mirrors the `vnstat --json` payload OPNsense proxies
// through api/vnstat/service/get_json_data?iface=<device> (jsonversion "2",
// verified against a live 26.7-devel box, #215). Only the traffic figures
// this collector exports are modeled: the fiveminute/hour/top arrays are
// redundant with Prometheus's own native scrape-interval resolution, and year
// is out of scope for this issue.
type vnstatJSONResponse struct {
	Interfaces []vnstatJSONInterface `json:"interfaces"`
}

type vnstatJSONInterface struct {
	Name    string            `json:"name"`
	Updated vnstatJSONWhen    `json:"updated"`
	Traffic vnstatJSONTraffic `json:"traffic"`
}

// vnstatJSONWhen mirrors vnstat's "updated" block: the date vnstat last wrote
// a sample for this interface. Used to pick the "current" day/month bucket
// out of the day/month arrays below, rather than trusting array order.
type vnstatJSONWhen struct {
	Date vnstatJSONYMD `json:"date"`
}

// vnstatJSONYMD is the {"year":...,"month":...,"day":...} shape vnstat uses
// throughout its JSON output. Month-bucket entries omit "day" entirely; the
// zero value is fine there since day is never compared for a month match.
type vnstatJSONYMD struct {
	Year  int `json:"year"`
	Month int `json:"month"`
	Day   int `json:"day"`
}

type vnstatJSONTraffic struct {
	// Total is cumulative since the interface's vnstat database was created;
	// it only resets on `vnstat --resetdb` (or the interface being dropped
	// from vnstat's DB).
	Total vnstatJSONRxTx `json:"total"`

	// Day/Month are ordered lists of daily/monthly buckets. In every capture
	// observed they are chronologically ascending (oldest first), but
	// currentEntry below matches by date against Updated rather than
	// assuming that order.
	Day   []vnstatJSONEntry `json:"day"`
	Month []vnstatJSONEntry `json:"month"`
}

type vnstatJSONRxTx struct {
	// RX/TX use flexInt (not a plain int64) for the same reason Kea's lease
	// fields do: OPNsense has flipped numeric fields between a JSON number
	// and a quoted numeric string across releases before, and vnstat's own
	// upstream JSON format has changed versions (jsonversion) historically.
	RX flexInt `json:"rx"`
	TX flexInt `json:"tx"`
}

type vnstatJSONEntry struct {
	Date vnstatJSONYMD `json:"date"`
	RX   flexInt       `json:"rx"`
	TX   flexInt       `json:"tx"`
}

// VnstatInterface is one interface's persistent traffic accounting, read from
// vnstat's on-disk database. Unlike the live interface counters
// (opnsense_interfaces_*), these figures survive reboots and exporter
// restarts, which is what makes them the right source for ISP data-cap
// tracking: an `increase()` over a live counter loses data across a reboot or
// counter reset, but vnstat's day/month/total figures do not.
type VnstatInterface struct {
	// Name is the device name vnstat tracks it under (e.g. "vtnet1") — the
	// same string interface_list returns and get_json_data's iface query
	// parameter accepts.
	Name string

	// TotalRXBytes/TotalTXBytes are cumulative since this interface's vnstat
	// database was created. They only go backwards if an admin runs
	// `vnstat --resetdb`, a legitimate counter reset with the same semantics
	// Prometheus already handles for any counter.
	TotalRXBytes int64
	TotalTXBytes int64

	// CurrentDayRXBytes/CurrentDayTXBytes are today's accumulated bytes so
	// far, taken from vnstat's own "day" bucket matching its last-updated
	// date. These reset to 0 at local midnight in vnstat's bookkeeping, so
	// they are NOT monotonic and are exported as gauges, not counters.
	CurrentDayRXBytes int64
	CurrentDayTXBytes int64

	// CurrentMonthRXBytes/CurrentMonthTXBytes are this month's accumulated
	// bytes so far. Reset monthly; gauge, not counter, for the same reason.
	CurrentMonthRXBytes int64
	CurrentMonthTXBytes int64
}

// VnstatData is the aggregated result of FetchVnstat.
type VnstatData struct {
	// Present is false when the os-vnstat plugin is not installed
	// (interface_list 404s). The collector gates all emission on this so it
	// stays silent on boxes without the plugin.
	Present bool

	Interfaces []VnstatInterface
}

// FetchVnstat calls the os-vnstat plugin API to enumerate every interface its
// database holds data for and fetch each one's persistent traffic
// accounting. It returns an error only when the list endpoint itself fails
// for a reason other than "plugin absent"; an individual interface's
// get_json_data call failing only skips that one interface (mirroring
// FetchSMARTDevices's per-device tolerance).
func (c *Client) FetchVnstat() (VnstatData, *APICallError) {
	var data VnstatData

	listPath, ok := c.endpoints["vnstatInterfaceList"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "vnstatInterfaceList",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	dataPath, ok := c.endpoints["vnstatGetJsonData"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "vnstatGetJsonData",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// Step 1: enumerate interfaces vnstat tracks. os-vnstat plugin not
	// installed -> 404. Treat as "feature absent" (mirrors
	// FetchACMECertificates/FetchSMARTDevices) so the collector, which is
	// opt-in via --exporter.enable-vnstat, stays quiet rather than erroring
	// on boxes without the plugin.
	var listResp vnstatInterfaceListResponse
	if err := c.do("GET", listPath, nil, &listResp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}
	data.Present = true

	// Step 2: fetch persistent traffic accounting for each interface. The
	// iface value goes in the query string (novel for this client — every
	// other per-item fan-out, e.g. smartInfo, is a POST with the item in the
	// form body); the request path is built ad hoc per interface rather than
	// through the registered (query-less) endpoint, so this call is never
	// eligible for the response cache's positive-TTL path (correct: these
	// figures are live and must never be cached — see cache.go). It is also
	// deliberately left off PluginGatedEndpoints: that mechanism keys a
	// negative cache off the fixed, registered path, which never matches a
	// query-carrying request, so listing it there would be inert. The
	// interface_list gate above already prevents any get_json_data calls at
	// all on a box without the plugin.
	for _, ifaceName := range listResp.Interfaces {
		query := url.Values{}
		query.Set("iface", ifaceName)
		ifacePath := EndpointPath(string(dataPath) + "?" + query.Encode())

		var jr vnstatJSONResponse
		if err := c.do("GET", ifacePath, nil, &jr); err != nil {
			c.log.Debug("vnstat get_json_data call failed for interface; skipping",
				"component", "opnsense-client",
				"interface", ifaceName,
				"err", err.Error())
			continue
		}
		if len(jr.Interfaces) == 0 {
			continue
		}
		ji := jr.Interfaces[0]

		vi := VnstatInterface{
			Name:         ifaceName,
			TotalRXBytes: int64(ji.Traffic.Total.RX),
			TotalTXBytes: int64(ji.Traffic.Total.TX),
		}
		if d := currentVnstatEntry(ji.Traffic.Day, ji.Updated.Date, true); d != nil {
			vi.CurrentDayRXBytes = int64(d.RX)
			vi.CurrentDayTXBytes = int64(d.TX)
		}
		if m := currentVnstatEntry(ji.Traffic.Month, ji.Updated.Date, false); m != nil {
			vi.CurrentMonthRXBytes = int64(m.RX)
			vi.CurrentMonthTXBytes = int64(m.TX)
		}

		data.Interfaces = append(data.Interfaces, vi)
	}

	return data, nil
}

// currentVnstatEntry returns the entry in entries whose date matches updated
// (vnstat's own last-write timestamp for this interface): year+month+day when
// matchDay is true (the day bucket), year+month only otherwise (the month
// bucket, whose entries carry no day field). Falls back to the last element
// when no exact match is found — an edge case that should not occur in
// practice, since Updated is itself derived from the most recent sample, but
// still picks the most recent bucket rather than an arbitrary one if it does.
func currentVnstatEntry(entries []vnstatJSONEntry, updated vnstatJSONYMD, matchDay bool) *vnstatJSONEntry {
	for i := range entries {
		e := &entries[i]
		if e.Date.Year == updated.Year && e.Date.Month == updated.Month && (!matchDay || e.Date.Day == updated.Day) {
			return e
		}
	}
	if len(entries) == 0 {
		return nil
	}
	return &entries[len(entries)-1]
}
