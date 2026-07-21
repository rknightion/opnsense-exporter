package zenarmor

import (
	"bytes"
	"strconv"
	"strings"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"

	"encoding/json"
)

// indexFamilies maps Zenarmor's index token onto our family name. Frozen: these six
// are the reporting families ipdrstreamer streams, and the family name is what
// becomes AttrSubsystem, so renaming one is a breaking change to the label model.
var indexFamilies = map[string]string{
	"conn":  "flow",
	"dns":   "dns",
	"tls":   "tls",
	"http":  "web",
	"alert": "ids",
	"sip":   "voip",
}

// Attribute keys that BOTH parse.go and derive.go depend on. They are consts rather
// than literals on each side because the two files must agree exactly: a key set
// under one spelling and read under another yields a silently empty metric label,
// with nothing failing anywhere. (That is not hypothetical — syslog's haproxy lane
// sets "http.response.status_code" and derives from "http.status_code".)
const (
	attrInterfaceName  = "interface.name"
	attrInterfaceDev   = "interface"
	attrAppCategory    = "app_category"
	attrDomainCategory = "domain_category"
	attrHTTPStatus     = "http.status_code"
	attrRCode          = "rcode"
	attrAlertCategory  = "alert_category"
	attrAlertSeverity  = "alert_severity"
)

// familyFor resolves an index name to its family, or "" when it is not one of ours.
//
// Two forms arrive: the _write alias (zenarmor_0000000000_<uuid>_conn_write), which
// is what bulk writes target, and the dated index behind it
// (zenarmor_0000000000_<uuid>_conn-260716).
func familyFor(index string) string {
	tok := strings.TrimSuffix(index, "_write")
	if i := strings.LastIndex(tok, "_"); i >= 0 {
		tok = tok[i+1:]
	}
	// The date suffix is stripped only AFTER the last underscore has been taken: the
	// index's uuid segment is full of dashes, so reaching for the last "-" of the whole
	// name would cut it to pieces.
	if i := strings.LastIndex(tok, "-"); i > 0 {
		tok = tok[:i]
	}
	return indexFamilies[tok]
}

// buildRecord turns one Zenarmor document into a Record.
//
// ok reports whether the record should be shipped, and is true even for a document
// that does not decode: a receiver that silently discards what it cannot understand
// looks healthy while losing data, so garbage ships with its raw body. Callers that
// also need to know whether the decode succeeded (to count ParseError) use parseDoc.
func buildRecord(family string, doc []byte, snap *enrich.Snapshot) (logship.Record, bool) {
	rec, _ := parseDoc(family, doc, snap)
	return rec, true
}

// parseDoc is buildRecord's inner form. parsed reports whether the document decoded
// cleanly; the returned record is shippable either way.
func parseDoc(family string, doc []byte, snap *enrich.Snapshot) (logship.Record, bool) {
	rec, _, parsed := parseDocFull(family, doc, snap)
	return rec, parsed
}

// parseDocFull is parseDoc plus the decoded document itself, for the one caller
// that needs the typed fields rather than the string attributes: the flow adapter,
// which builds a flow.Record out of the byte and packet counts.
//
// It exists as a separate entry point rather than as a wider parseDoc signature
// because parseDoc has seven call sites, all of them wanting only the record, and
// widening it would churn every one of them for a single caller's benefit. d is nil
// when the document did not decode.
func parseDocFull(family string, doc []byte, snap *enrich.Snapshot) (logship.Record, *zenDoc, bool) {
	var d zenDoc
	if err := json.Unmarshal(doc, &d); err != nil {
		return logship.Record{Body: string(doc)}, nil, false
	}

	attrs := make(map[string]string, 40)
	set := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	setInt := func(k string, v int64) {
		if v != 0 {
			attrs[k] = strconv.FormatInt(v, 10)
		}
	}

	set(logship.AttrSubsystem, family)

	// is_blocked is an explicit allowlist, and absent means UNSET rather than "pass":
	// claiming a disposition the document never stated would corrupt the very query
	// ({opnsense_action="pass"}) the label exists to serve.
	blocked := false
	if d.IsBlocked != nil {
		switch *d.IsBlocked {
		case 0:
			set(logship.AttrAction, logship.ActionPass)
		case 1:
			set(logship.AttrAction, logship.ActionBlock)
			blocked = true
		}
	}

	rec := logship.Record{
		// The raw line, not a re-encoding of the struct below: re-marshalling would
		// silently drop every field we do not model, and the body is the lossless copy.
		// NDJSON is one document per line, so it is already compact.
		Body:       string(doc),
		Severity:   logship.SeverityInfo,
		Attributes: attrs,
	}
	if blocked || family == "ids" {
		rec.Severity = logship.SeverityWarn
	}
	if ts := d.timestamp(); !ts.IsZero() {
		rec.Timestamp = ts
	}

	proto := strings.ToLower(d.TransportProto)
	set("transport_proto", d.TransportProto)
	set(attrInterfaceDev, d.Interface)
	set("vlanid", d.VLANID)
	set("direction", d.Direction)
	set("conn_uuid", d.ConnUUID)
	set("community_id", d.CommunityID)
	set("policyid", d.PolicyID)
	set("organization", d.Organization)
	set("encryption", d.Encryption)

	set("ip_src_saddr", d.SrcIP)
	set("ip_dst_saddr", d.DstIP)
	setInt("ip_src_port", int64(d.SrcPort))
	setInt("ip_dst_port", int64(d.DstPort))
	set("src_hostname", d.SrcHostname)
	set("dst_hostname", d.DstHostname)
	set("src_hwaddr", d.SrcHWAddr)
	set("dst_hwaddr", d.DstHWAddr)
	// Empty on a box with no identity provider wired into Zenarmor, which is why the
	// live capture never showed one. They populate where one is, so they are modelled.
	set("src_username", d.SrcUsername)
	set("dst_username", d.DstUsername)

	setGeo(set, "src_geoip", d.SrcGeoIP)
	setGeo(set, "dst_geoip", d.DstGeoIP)
	if d.Device != nil {
		set("device.id", d.Device.ID)
		set("device.name", d.Device.Name)
		set("device.category", d.Device.Category)
		set("device.vendor", d.Device.Vendor)
		set("device.os", d.Device.OS)
		set("device.osver", d.Device.OSVer)
	}

	switch family {
	case "flow":
		set("app_name", d.AppName)
		set("app_proto", d.AppProto)
		set(attrAppCategory, d.AppCategory)
		setInt("src_npackets", d.SrcNPackets)
		setInt("src_nbytes", d.SrcNBytes)
		setInt("dst_npackets", d.DstNPackets)
		setInt("dst_nbytes", d.DstNBytes)
		// pbytes is the PAYLOAD byte count, distinct from nbytes' wire count by the
		// per-packet header overhead. It is worth shipping in its own right, and it is
		// what the flow rollup falls back to: Zenarmor leaves nbytes at zero until it
		// has tracked a flow past its first packets, which is 27.6% of flow-sides with
		// packets>0 on a live box — all of them short UDP (#346).
		setInt("src_pbytes", d.SrcPBytes)
		setInt("dst_pbytes", d.DstPBytes)

	case "dns":
		set("query", d.Query)
		set("qtype", d.QType)
		set("qclass", d.QClass)
		set("answers", d.Answers)
		setInt("total_answers", int64(d.TotalAnswers))
		if d.RespCode != nil {
			// -1 is Zenarmor's "this is the request, there is no response yet", which is a
			// value worth keeping rather than a missing one.
			attrs[attrRCode] = strconv.Itoa(*d.RespCode)
		}
		// Zenarmor sends domain_categories, an ARRAY (up to two entries live). Only the
		// primary becomes the singular attribute derive.go reads: joining them would
		// square the category taxonomy into the label, and the full array is in the body.
		if len(d.DomainCategories) > 0 {
			set(attrDomainCategory, d.DomainCategories[0])
		}

	case "tls":
		set("server_name", d.ServerName)
		set("ja3", d.JA3)
		// tls and http spell the same taxonomy "category"; dns spells it
		// "domain_categories". Normalised here so one key carries it for all three.
		set(attrDomainCategory, d.Category)

	case "web":
		set("method", d.Method)
		set("host", d.Host)
		set("uri", d.URI)
		set("user_agent", d.UserAgent)
		set("http.version", d.Version)
		set("referrer", d.Referrer)
		set(attrDomainCategory, d.Category)
		// Zenarmor calls the numeric response status "status_msg".
		set(attrHTTPStatus, d.StatusMsg)
		setInt("req_body_len", d.ReqBodyLen)
		setInt("rsp_body_len", d.RspBodyLen)

	case "ids":
		set(attrAlertCategory, d.AlertCategory)
		set(attrAlertSeverity, d.AlertSeverity)
		if d.AlertInfo != nil {
			set("alertinfo.signature", string(d.AlertInfo.Signature))
			set("alertinfo.category", string(d.AlertInfo.Category))
			set("alertinfo.sid", string(d.AlertInfo.SID))
			set("alertinfo.severity", string(d.AlertInfo.Severity))
			set("alertinfo.action", d.AlertInfo.Action)
		}

	case "voip":
		set("sip_method", d.SIPMethod)
		set("sip_uri", d.SIPURI)
		set("sip_status", d.SIPStatus)
	}

	// Enrichment is a handful of map lookups on a lock-free snapshot, costing
	// nanoseconds on the request goroutine. Deps.Miss is deliberately NOT called from
	// here: Zenarmor flows are overwhelmingly external addresses, so reporting a miss
	// would ask for a snapshot refresh on essentially every internet-bound flow.
	if snap != nil {
		if name, ok := snap.InterfaceName(d.Interface); ok {
			set(attrInterfaceName, name)
		}
		if d.SrcIP != "" {
			set("src.scope", snap.Scope(d.SrcIP))
		}
		if d.DstIP != "" {
			set("dst.scope", snap.Scope(d.DstIP))
		}
		if d.DstPort != 0 {
			if svc, ok := enrich.ServiceName(strconv.Itoa(d.DstPort), proto); ok {
				set("dst.service", svc)
			}
		}
	}

	return rec, &d, true
}

// timestamp resolves the document's event time.
//
// end_time (the flow CLOSE) always wins. start_time is only a fallback for the
// families that carry no end_time at all — live capture shows that is dns, tls and
// http, not just dns. Preferring start_time would be actively wrong: it is the flow
// OPEN time and runs hours stale on a long-lived flow, which scatters records
// backwards across Loki and invents rate() plateaus.
func (d *zenDoc) timestamp() time.Time {
	ms := d.EndTime
	if ms == 0 {
		ms = d.StartTime
	}
	if ms == 0 {
		return time.Time{} // the pipeline stamps arrival time
	}
	return time.UnixMilli(ms)
}

// setGeo flattens a geoip block under a dotted prefix, skipping the zero values
// Zenarmor sends for an address it could not locate.
func setGeo(set func(k, v string), prefix string, g *zenGeo) {
	if g == nil {
		return
	}
	set(prefix+".country_code2", g.CountryCode2)
	set(prefix+".country_code3", g.CountryCode3)
	set(prefix+".country_name", g.CountryName)
	set(prefix+".city_name", g.CityName)
	set(prefix+".continent_code", g.ContinentCode)
	set(prefix+".region_name", g.RegionName)
	set(prefix+".timezone", g.Timezone)
	// "0" is Zenarmor's empty ASN, not AS0 — it is what every record on the capture
	// box carried. Modelled anyway because it populates elsewhere.
	if g.ASN != "" && g.ASN != "0" {
		set(prefix+".asn", g.ASN)
	}
	if g.Latitude != 0 || g.Longitude != 0 {
		set(prefix+".latitude", strconv.FormatFloat(g.Latitude, 'f', -1, 64))
		set(prefix+".longitude", strconv.FormatFloat(g.Longitude, 'f', -1, 64))
	}
}

// zenDoc is the union of the fields worth modelling across the six families. They
// share one envelope (endpoints, device, geoip, timing) and differ only in a tail,
// so one struct beats six near-copies. Unmodelled fields are not lost: the body
// carries the document verbatim.
//
// is_blocked and resp_code are pointers because their zero values are meaningful
// (0 = "passed", 0 = NOERROR); an int would make an absent field indistinguishable
// from a stated one.
type zenDoc struct {
	StartTime      int64  `json:"start_time"`
	EndTime        int64  `json:"end_time"`
	TransportProto string `json:"transport_proto"`
	Interface      string `json:"interface"`
	VLANID         string `json:"vlanid"`
	Direction      string `json:"direction"`
	ConnUUID       string `json:"conn_uuid"`
	CommunityID    string `json:"community_id"`
	PolicyID       string `json:"policyid"`
	Organization   string `json:"organization"`
	Encryption     string `json:"encryption"`
	IsBlocked      *int   `json:"is_blocked"`

	SrcIP       string `json:"ip_src_saddr"`
	SrcPort     int    `json:"ip_src_port"`
	SrcHostname string `json:"src_hostname"`
	SrcHWAddr   string `json:"src_hwaddr"`
	SrcUsername string `json:"src_username"`
	DstIP       string `json:"ip_dst_saddr"`
	DstPort     int    `json:"ip_dst_port"`
	DstHostname string `json:"dst_hostname"`
	DstHWAddr   string `json:"dst_hwaddr"`
	DstUsername string `json:"dst_username"`

	SrcGeoIP *zenGeo    `json:"src_geoip"`
	DstGeoIP *zenGeo    `json:"dst_geoip"`
	Device   *zenDevice `json:"device"`

	// conn -> flow
	AppName     string `json:"app_name"`
	AppProto    string `json:"app_proto"`
	AppCategory string `json:"app_category"`
	SrcNPackets int64  `json:"src_npackets"`
	SrcNBytes   int64  `json:"src_nbytes"`
	SrcPBytes   int64  `json:"src_pbytes"`
	DstNPackets int64  `json:"dst_npackets"`
	DstNBytes   int64  `json:"dst_nbytes"`
	DstPBytes   int64  `json:"dst_pbytes"`

	// dns
	Query            string   `json:"query"`
	QType            string   `json:"qtype"`
	QClass           string   `json:"qclass"`
	Answers          string   `json:"answers"`
	TotalAnswers     int      `json:"total_answers"`
	RespCode         *int     `json:"resp_code"`
	DomainCategories []string `json:"domain_categories"`

	// tls (+ http): the shared category taxonomy
	ServerName string `json:"server_name"`
	JA3        string `json:"ja3"`
	Category   string `json:"category"`

	// http -> web
	Method     string `json:"method"`
	Host       string `json:"host"`
	URI        string `json:"uri"`
	UserAgent  string `json:"user_agent"`
	Version    string `json:"version"`
	Referrer   string `json:"referrer"`
	StatusMsg  string `json:"status_msg"`
	ReqBodyLen int64  `json:"req_body_len"`
	RspBodyLen int64  `json:"rsp_body_len"`

	// alert -> ids. No alert fired during the live capture, so unlike every field
	// above these are modelled from Zenarmor's documented shape rather than observed
	// bytes. An unmodelled or misnamed field here costs nothing beyond the attribute:
	// the body still carries the document verbatim.
	AlertCategory string        `json:"alert_category"`
	AlertSeverity string        `json:"alert_severity"`
	AlertInfo     *zenAlertInfo `json:"alertinfo"`

	// sip -> voip. Also unobserved, same caveat.
	SIPMethod string `json:"sip_method"`
	SIPURI    string `json:"sip_uri"`
	SIPStatus string `json:"sip_status"`
}

type zenGeo struct {
	Timezone      string  `json:"timezone"`
	ContinentCode string  `json:"continent_code"`
	CityName      string  `json:"city_name"`
	CountryName   string  `json:"country_name"`
	CountryCode2  string  `json:"country_code2"`
	CountryCode3  string  `json:"country_code3"`
	RegionName    string  `json:"region_name"`
	ASN           string  `json:"asn"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
}

type zenDevice struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Vendor   string `json:"vendor"`
	OS       string `json:"os"`
	OSVer    string `json:"osver"`
}

// flexStrings decodes a JSON value that is EITHER a string or an array of strings.
// Zenarmor's alertinfo.category and alertinfo.signature arrive as arrays on 26.x
// but have appeared as bare scalars on older payloads; pinning either Go type
// fails the whole document decode. An array is joined with ", ".
type flexStrings string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '[' {
		var xs []string
		if err := json.Unmarshal(b, &xs); err != nil {
			return err
		}
		*f = flexStrings(strings.Join(xs, ", "))
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*f = flexStrings(s)
	return nil
}

// flexScalar decodes a JSON scalar that may arrive as EITHER a string or a number,
// stored as its string form. Zenarmor sends alertinfo.severity as a number and
// alertinfo.sid as a string, but both have been typed the other way across
// releases, so neither may be pinned.
type flexScalar string

func (f *flexScalar) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexScalar(s)
		return nil
	}
	*f = flexScalar(string(b)) // number kept as its literal text
	return nil
}

type zenAlertInfo struct {
	Signature flexStrings `json:"signature"`
	Category  flexStrings `json:"category"`
	SID       flexScalar  `json:"sid"`
	Severity  flexScalar  `json:"severity"`
	Action    string      `json:"action"`
}
