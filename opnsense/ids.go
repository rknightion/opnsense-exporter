package opnsense

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

// idsAlertRowCap bounds how many of the newest eve.json alert rows query_alerts
// is asked for. The backing script (queryAlertLog.py) reads eve.json in reverse
// from the tail, so a cap keeps that read — and the response size — bounded on a
// busy box. recent-alert counts are therefore a FLOOR: if more than this many
// alerts land inside the lookback window, the surplus is not counted.
const idsAlertRowCap = 500

// IDSAlertRowCap exports idsAlertRowCap for callers outside the package. The
// logs.ids log-shipping source (internal/logship/ids.go) uses it to detect
// when a query_alerts read hit the row cap — the trigger for its
// window-overflow gap accounting, since a full window whose oldest row is
// still newer than the source's cursor means older alerts fell outside what
// this read could reach.
const IDSAlertRowCap = idsAlertRowCap

// idsSelectOption is one entry of an OPNsense "field with options" map
// (e.g. general.mode). Only the selected flag is consumed; the human-readable
// value is ignored.
type idsSelectOption struct {
	Selected flexInt `json:"selected"`
}

// idsSettingsResponse decodes the subset of ids/settings/get the exporter uses.
// The model carries far more (homenet, eveLog, detect profiles, per-rule
// overrides …); those keys are intentionally not modelled.
//
// IPS-mode representation differs across the support window: ≤ 26.1 carries the
// boolean general.ips, while 26.7 replaced it with the general.mode
// pcap/netmap/divert selector (pcap = IDS, netmap/divert = IPS). ipsModeEnabled
// reads whichever is present.
type idsSettingsResponse struct {
	IDS struct {
		General struct {
			IPS     flexString                 `json:"ips"`
			Promisc flexString                 `json:"promisc"`
			Mode    map[string]idsSelectOption `json:"mode"`
		} `json:"general"`
	} `json:"ids"`
}

// ipsModeEnabled reports whether Suricata is running as an IPS (inline drop)
// rather than a passive IDS, tolerant of both the legacy boolean and the newer
// mode selector.
func (r idsSettingsResponse) ipsModeEnabled() bool {
	g := r.IDS.General
	if g.IPS.String() == "1" {
		return true
	}
	return g.Mode["netmap"].Selected.Int() == 1 || g.Mode["divert"].Selected.Int() == 1
}

// promiscuousEnabled reports whether the monitoring interface is put in
// promiscuous mode.
func (r idsSettingsResponse) promiscuousEnabled() bool {
	return r.IDS.General.Promisc.String() == "1"
}

// idsAlertLogEntry is one Suricata eve log file from service/get_alert_logs
// (the live eve.json plus any rotated eve.json.N).
type idsAlertLogEntry struct {
	Filename flexString `json:"filename"`
	Size     flexInt    `json:"size"` // bytes
	Modified flexString `json:"modified"`
}

// idsRulesetsResponse is the bootgrid envelope from settings/list_rulesets.
type idsRulesetsResponse struct {
	Rows []idsRulesetRow `json:"rows"`
}

// idsRulesetRow is one installable ruleset. modified_local is the box-local
// wall-clock ("Y/m/d G:i") of the last download, or null when never downloaded.
type idsRulesetRow struct {
	Filename      flexString `json:"filename"`
	Enabled       flexString `json:"enabled"`
	ModifiedLocal flexString `json:"modified_local"`
}

// idsInstalledRulesResponse is the bootgrid envelope from
// settings/searchInstalledRules. Only the total (count(*) over the SQLite rule
// cache) is consumed; the rows are not decoded per-rule (no per-SID series).
type idsInstalledRulesResponse struct {
	Total flexInt         `json:"total"`
	Rows  json.RawMessage `json:"rows"`
}

// idsAlertsResponse is the bootgrid envelope from service/query_alerts, newest
// eve alerts first. Only the timestamp and the (bounded) alert_action are
// consumed — never the signature, SIDs or IP addresses.
type idsAlertsResponse struct {
	Rows []idsAlertRow `json:"rows"`
}

type idsAlertRow struct {
	Timestamp   flexString `json:"timestamp"`
	AlertAction flexString `json:"alert_action"`
	// The remaining fields are consumed only by FetchIDSAlertRecords (the
	// logs.ids log source): flow_id/alert_sid key its cursor dedupe ring, the
	// rest feed the bounded structured-metadata attributes documented on
	// IDSAlertRecord. FetchIDSRecentAlerts (the metrics collector) ignores them.
	FlowID   flexInt    `json:"flow_id"`
	InIface  flexString `json:"in_iface"`
	SrcIP    flexString `json:"src_ip"`
	DestIP   flexString `json:"dest_ip"`
	Proto    flexString `json:"proto"`
	Alert    flexString `json:"alert"`
	AlertSID flexInt    `json:"alert_sid"`
}

// IDSAlertLog is one normalised Suricata eve log file.
type IDSAlertLog struct {
	Filename  string
	SizeBytes float64
}

// IDSRuleset is one normalised installed ruleset.
type IDSRuleset struct {
	Filename       string
	Enabled        bool
	LastUpdated    float64 // unix seconds; valid only when HasLastUpdated
	HasLastUpdated bool
}

// IDSInfo is the default-on IDS data bundle: service status, IPS/promiscuous
// mode, eve log inventory, ruleset inventory and installed-rule count.
type IDSInfo struct {
	Status              string // "running" | "stopped" | "disabled" | other
	IPSMode             bool
	PromiscuousMode     bool
	AlertLogs           []IDSAlertLog
	Rulesets            []IDSRuleset
	InstalledRulesTotal float64
}

// IDSAlertActivity is the opt-in alert-window data derived from query_alerts.
// ByAction maps a bounded alert action ("allowed"/"blocked") to the count of
// alerts seen inside the lookback window. Both keys are always present (0 when
// none), so the series never disappears on a quiet scrape.
type IDSAlertActivity struct {
	ByAction map[string]float64
}

// FetchIDS fetches the default-on IDS bundle. IDS is a CORE subsystem, not a
// plugin: the endpoints do not 404 when Suricata is unconfigured — status
// returns "disabled" and the data endpoints return empty structures — so a 404
// is a real error here, never "feature absent".
func (c *Client) FetchIDS() (IDSInfo, *APICallError) {
	var info IDSInfo

	status, err := c.FetchServiceStatus("idsStatus")
	if err != nil {
		return info, err
	}
	info.Status = status

	var settings idsSettingsResponse
	if err := c.do("GET", c.endpoints["idsSettings"], nil, &settings); err != nil {
		return info, err
	}
	info.IPSMode = settings.ipsModeEnabled()
	info.PromiscuousMode = settings.promiscuousEnabled()

	var logs []idsAlertLogEntry
	if err := c.do("GET", c.endpoints["idsAlertLogs"], nil, &logs); err != nil {
		return info, err
	}
	for _, l := range logs {
		info.AlertLogs = append(info.AlertLogs, IDSAlertLog{
			Filename:  l.Filename.String(),
			SizeBytes: float64(l.Size.Int()),
		})
	}

	var rulesets idsRulesetsResponse
	if err := c.do("GET", c.endpoints["idsRulesets"], nil, &rulesets); err != nil {
		return info, err
	}
	for _, row := range rulesets.Rows {
		r := IDSRuleset{
			Filename: row.Filename.String(),
			Enabled:  row.Enabled.String() == "1",
		}
		if ts, ok := parseIDSLocalTime(row.ModifiedLocal.String()); ok {
			r.LastUpdated = ts
			r.HasLastUpdated = true
		}
		info.Rulesets = append(info.Rulesets, r)
	}

	// Rule count is a cheap count(*) over the SQLite rule cache in steady state.
	// rowCount=1 fetches a single row purely to read the envelope total.
	var rules idsInstalledRulesResponse
	rulesURL := c.endpoints["idsSearchInstalledRules"]
	form := url.Values{"current": {"1"}, "rowCount": {"1"}}
	if err := c.doForm(rulesURL, form, &rules); err != nil {
		return info, err
	}
	info.InstalledRulesTotal = float64(rules.Total.Int())

	return info, nil
}

// FetchIDSRecentAlerts counts eve.json alerts inside the lookback window,
// grouped by the bounded alert action. It is opt-in: query_alerts triggers a
// reverse read of eve.json on the box, so it is gated behind
// --exporter.enable-ids-alerts.
//
// The result is a GAUGE by design, never a counter: query_alerts reads a
// windowed, saturating backend (its `total` saturates at rowCount+1, and the
// eve log rotates), so a monotonic per-scrape count is impossible without
// unbounded reads. Counts are a floor when more than idsAlertRowCap alerts fall
// inside the window.
func (c *Client) FetchIDSRecentAlerts(lookback time.Duration) (IDSAlertActivity, *APICallError) {
	act := IDSAlertActivity{ByAction: map[string]float64{"allowed": 0, "blocked": 0}}

	var resp idsAlertsResponse
	alertsURL := c.endpoints["idsQueryAlerts"]
	form := url.Values{"current": {"1"}, "rowCount": {strconv.Itoa(idsAlertRowCap)}}
	if err := c.doForm(alertsURL, form, &resp); err != nil {
		return act, err
	}

	cutoff := time.Now().Add(-lookback)
	for _, row := range resp.Rows {
		ts, ok := parseIDSAlertTime(row.Timestamp.String())
		if !ok || ts.Before(cutoff) {
			continue
		}
		action := row.AlertAction.String()
		if action == "" {
			continue
		}
		act.ByAction[action]++
	}
	return act, nil
}

// idsAlertRecordsResponse is the bootgrid envelope from service/query_alerts,
// decoded with the rows kept as raw JSON so FetchIDSAlertRecords can ship each
// eve record byte-for-byte (only whitespace-compacted) as the log body while
// still parsing the bounded fields below out of the very same bytes.
type idsAlertRecordsResponse struct {
	Rows []json.RawMessage `json:"rows"`
}

// IDSAlertRecord is one full Suricata EVE alert record read via query_alerts,
// for the logs.ids log-shipping source (never the metrics collector, which
// only needs the bounded action count from FetchIDSRecentAlerts). Body is the
// compact JSON of the raw eve record exactly as received: full fidelity, not a
// reconstruction from the typed fields below, so every key Suricata emits —
// including ones this struct does not model, e.g. the nested "flow" object,
// "app_proto", "filepos"/"fileid", "event_type" — travels through unmodified.
// The typed fields exist only to key the log source's cursor/dedupe and its
// bounded structured-metadata attributes (never IPs/SIDs as metric labels).
type IDSAlertRecord struct {
	Timestamp   time.Time
	FlowID      int64
	AlertSID    int
	AlertAction string
	Signature   string
	SrcIP       string
	DestIP      string
	InIface     string
	Proto       string
	Body        string // compact JSON of the full raw eve record
}

// FetchIDSAlertRecords fetches up to IDSAlertRowCap of the newest eve alert
// records, newest-first exactly as the wire returns them — the caller (the
// logs.ids source) owns cursor/dedupe/gap accounting, mirroring the "chase"
// pattern of keeping the raw shape and resolving semantics in the accessor
// rather than in the decode step.
//
// This reuses the exact query_alerts POST contract FetchIDSRecentAlerts
// already uses (current=1, rowCount=IDSAlertRowCap): one endpoint, one
// request shape, two consumers — no new endpoint/contract entry is needed.
//
// A row with no parseable timestamp is dropped: without a timestamp there is
// nothing to cursor it on, so it can neither be deduplicated nor ordered
// safely. Every other per-row decode failure is best-effort — flexString/
// flexInt already degrade to zero values rather than erroring, so a
// partially-shaped row still ships (with its raw Body intact) rather than
// losing the whole batch.
func (c *Client) FetchIDSAlertRecords() ([]IDSAlertRecord, *APICallError) {
	var resp idsAlertRecordsResponse
	alertsURL := c.endpoints["idsQueryAlerts"]
	form := url.Values{"current": {"1"}, "rowCount": {strconv.Itoa(idsAlertRowCap)}}
	if err := c.doForm(alertsURL, form, &resp); err != nil {
		return nil, err
	}

	records := make([]IDSAlertRecord, 0, len(resp.Rows))
	for _, raw := range resp.Rows {
		var row idsAlertRow
		_ = json.Unmarshal(raw, &row) // best-effort; see doc comment above
		ts, ok := parseIDSAlertTime(row.Timestamp.String())
		if !ok {
			continue
		}
		records = append(records, IDSAlertRecord{
			Timestamp:   ts,
			FlowID:      int64(row.FlowID.Int()),
			AlertSID:    row.AlertSID.Int(),
			AlertAction: row.AlertAction.String(),
			Signature:   row.Alert.String(),
			SrcIP:       row.SrcIP.String(),
			DestIP:      row.DestIP.String(),
			InIface:     row.InIface.String(),
			Proto:       row.Proto.String(),
			Body:        compactAlertJSON(raw),
		})
	}
	return records, nil
}

// compactAlertJSON strips insignificant whitespace from a raw eve record.
// OPNsense's own JSON encoding is already compact in practice, but this makes
// no assumption about it; on a (should-never-happen) compact error the raw
// bytes ship as-is rather than dropping the record.
func compactAlertJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// idsAlertTimeLayouts covers the Suricata eve timestamp shapes: microsecond
// fractional seconds with a numeric-offset timezone ("2026-07-13T18:15:59.475210+0100"),
// plus colon-offset and fraction-less fallbacks.
var idsAlertTimeLayouts = []string{
	"2006-01-02T15:04:05.999999-0700",
	"2006-01-02T15:04:05-0700",
	time.RFC3339Nano,
	time.RFC3339,
}

// parseIDSAlertTime parses a Suricata eve alert timestamp. Returns ok=false for
// an empty or unparseable value.
func parseIDSAlertTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range idsAlertTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseIDSLocalTime parses a ruleset modified_local wall-clock ("Y/m/d G:i")
// into unix seconds, best-effort. The string carries no timezone, so it is read
// as UTC: for the "rules haven't updated in N days" use case the box-local
// offset is immaterial. Returns ok=false for null/empty/unparseable input.
func parseIDSLocalTime(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	t, err := time.Parse("2006/01/02 15:04", s)
	if err != nil {
		return 0, false
	}
	return float64(t.Unix()), true
}
