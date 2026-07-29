package syslog

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

func init() {
	RegisterParser(parseSuricata, "suricata")
}

// Suricata sends TWO different things under program("suricata") with no way to tell
// them apart at the syslog layer:
//
//	engine text:  [207442] <Notice> -- rule reload complete
//	EVE alert:    {"timestamp":"...","event_type":"alert","alert":{...},...}
//
// There is no separate program name to filter on, so we discriminate by attempting a
// JSON decode. Anything that is not JSON is the engine's own log and ships generic.
//
// EVE-over-syslog is OFF by default on OPNsense (the `syslog_eve` setting). When a
// user turns it on, this is the better path than the `ids` poll lane: it is push, it
// is lossless, and it arrives the moment Suricata raises the alert rather than up to
// a poll interval later.
//
// THE SYSLOG COPY IS REDUCED, and users must know it: alerts only (no http/tls/dns/
// flow event types), and OPNsense hardcodes `payload: no` for the syslog output even
// when the file-based EVE log has payload enabled. Anyone who needs the payload or
// the other event types keeps the poll lane.
//
// Attribute names deliberately MIRROR internal/logship/ids.go (alert_sid, signature,
// src_ip, …) so a dashboard or alert rule does not care which path an alert arrived
// by. Double-shipping is prevented at startup, not here — see options.LogsSyslog's
// conflict check.
func parseSuricata(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if len(env.Message) == 0 || env.Message[0] != '{' {
		return logship.Record{}, false // engine text, not EVE
	}

	var e eveRecord
	if err := json.Unmarshal([]byte(env.Message), &e); err != nil {
		// Malformed JSON under this program is not an alert we can trust. Ship it raw
		// rather than guessing at half-decoded fields.
		return logship.Record{}, false
	}
	if e.EventType == "" {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("event_type", e.EventType)
	set("src_ip", e.SrcIP)
	set("dest_ip", e.DestIP)
	set("proto", e.Proto)
	set("in_iface", e.InIface)
	if e.SrcPort != 0 {
		set("src_port", strconv.Itoa(e.SrcPort))
	}
	if e.DestPort != 0 {
		set("dest_port", strconv.Itoa(e.DestPort))
	}
	if e.Alert != nil {
		set("signature", e.Alert.Signature)
		set("alert_action", e.Alert.Action)
		set(logship.AttrAction, logship.MapSuricataAction(e.Alert.Action))
		set("alert_category", e.Alert.Category)
		if e.Alert.SignatureID != 0 {
			set("alert_sid", strconv.Itoa(e.Alert.SignatureID))
		}
		if e.Alert.Severity != 0 {
			set("alert_severity", strconv.Itoa(e.Alert.Severity))
		}
		// Mirror the poll lane's severity rule: an alert Suricata (or the firewall)
		// actually acted on is a warning; an observed-but-allowed one is informational.
		if e.Alert.Action == "blocked" {
			rec.Severity = logship.SeverityWarn
		}
	}

	// Resolve both endpoints the way filterlog does (hostname/MAC/scope/service). An
	// unknown address is normal here -- an alert is usually about something external
	// -- so no miss is reported.
	enrichEndpoint(set, snap, "src", e.SrcIP, strconv.Itoa(e.SrcPort), eveProto(e.Proto))
	enrichEndpoint(set, snap, "dst", e.DestIP, strconv.Itoa(e.DestPort), eveProto(e.Proto))
	// GeoIP (#528): an IDS alert's source geo is directly operationally useful.
	// geoAttrs is a no-op unless a GeoIP source is configured.
	geoAttrs(set, "src", e.SrcIP)
	geoAttrs(set, "dst", e.DestIP)

	return rec, true
}

// eveOther is the single bucket every value outside the closed vocabularies below
// folds into. One bucket, not one label value per invented input: the receiver is
// push-based over a spoofable UDP source, so a metric label must never be a
// pass-through of what a sender chose to put on the wire.
const eveOther = "other"

// eveEventTypes is the allowlist of EVE event types that may become a metric label,
// in the same shape as dhcp.go's iscActions/keaActions: an explicit map, so a type
// we have not seen on a real box cannot mint a series by arriving.
//
// OPNsense's syslog_eve output is alerts only — "alert" is the only value observed
// in practice. The rest are listed because they are EVE's own documented types and
// are what a differently-configured Suricata would send; anything at all outside
// this set is a sender inventing values and folds into eveOther.
var eveEventTypes = map[string]string{
	"alert":   "alert",
	"anomaly": "anomaly",
	"drop":    "drop",
	"stats":   "stats",
}

// eveSeverities is the same treatment for Suricata's numeric alert priority. The
// real range is 1-4 (1 = most severe); the field is a JSON number, so without this
// a sender could push an unbounded integer straight into a label value.
var eveSeverities = map[string]string{
	"1": "1",
	"2": "2",
	"3": "3",
	"4": "4",
}

// mapEveEventType folds an EVE event type to the label vocabulary. Absent stays
// absent — an empty label means "the line carried none", which must stay distinct
// from "the line carried something we do not recognise".
func mapEveEventType(v string) string {
	if v == "" {
		return ""
	}
	if mapped, ok := eveEventTypes[v]; ok {
		return mapped
	}
	return eveOther
}

// mapEveSeverity folds an EVE alert severity to the label vocabulary, on the same
// absent-vs-unknown rule as mapEveEventType.
func mapEveSeverity(v string) string {
	if v == "" {
		return ""
	}
	if mapped, ok := eveSeverities[v]; ok {
		return mapped
	}
	return eveOther
}

// eveRecord is the subset of Suricata's EVE schema that survives the syslog copy.
type eveRecord struct {
	EventType string    `json:"event_type"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port"`
	DestIP    string    `json:"dest_ip"`
	DestPort  int       `json:"dest_port"`
	Proto     string    `json:"proto"`
	InIface   string    `json:"in_iface"`
	Alert     *eveAlert `json:"alert"`
}

type eveAlert struct {
	Action      string `json:"action"`
	SignatureID int    `json:"signature_id"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// eveProto lowercases Suricata's protocol ("TCP") so it matches the service table's
// keys, which are keyed the way filterlog spells them ("tcp").
func eveProto(p string) string {
	return strings.ToLower(p)
}
