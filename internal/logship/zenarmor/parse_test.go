package zenarmor

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

func TestFamilyFor(t *testing.T) {
	const uuid = "019695d7-5a92-4449-911a-d46a81c5f40f"
	cases := map[string]string{
		// The _write alias, which is what bulk writes target — the only form the live
		// capture ever showed.
		"zenarmor_0000000000_" + uuid + "_conn_write":  "flow",
		"zenarmor_0000000000_" + uuid + "_dns_write":   "dns",
		"zenarmor_0000000000_" + uuid + "_tls_write":   "tls",
		"zenarmor_0000000000_" + uuid + "_http_write":  "web",
		"zenarmor_0000000000_" + uuid + "_alert_write": "ids",
		"zenarmor_0000000000_" + uuid + "_sip_write":   "voip",

		// The dated form behind the alias. The uuid segment is full of dashes, so this is
		// the case that catches a date-strip reaching for the wrong "-".
		"zenarmor_0000000000_" + uuid + "_conn-260716": "flow",
		"zenarmor_0000000000_abc_conn-260716":          "flow",
		"zenarmor_0000000000_abc_http-260716":          "web",

		"something_else": "",
		"zenarmor_0000000000_" + uuid + "_bogus_write": "",
		"":     "",
		"conn": "flow",
	}
	for in, want := range cases {
		if got := familyFor(in); got != want {
			t.Errorf("familyFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func attr(t *testing.T, rec logship.Record, k string) string {
	t.Helper()
	return rec.Attributes[k]
}

func assertAttr(t *testing.T, rec logship.Record, k, want string) {
	t.Helper()
	if got := rec.Attributes[k]; got != want {
		t.Errorf("attribute %q = %q, want %q", k, got, want)
	}
}

// The body must stay byte-identical to what arrived. Re-encoding it from the struct
// would silently drop every field we do not model.
func assertBodyIsVerbatim(t *testing.T, rec logship.Record, doc string) {
	t.Helper()
	if rec.Body != doc {
		t.Errorf("body was not the verbatim document\n got: %s\nwant: %s", rec.Body, doc)
	}
	var v any
	if err := json.Unmarshal([]byte(rec.Body), &v); err != nil {
		t.Errorf("body is not valid JSON: %v", err)
	}
}

func TestBuildRecordConn(t *testing.T) {
	rec, ok := buildRecord("flow", []byte(connDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, logship.AttrSubsystem, "flow")
	assertAttr(t, rec, logship.AttrAction, logship.ActionPass) // is_blocked=0

	// Timestamp comes from end_time (flow close), NEVER start_time: this fixture's flow
	// was open for two minutes, so start_time would place the record 120s in the past
	// and scatter it backwards across Loki.
	if got := rec.Timestamp.UnixMilli(); got != 1784224415000 {
		t.Errorf("Timestamp = %d, want end_time 1784224415000 (start_time is 1784224295000)", got)
	}
	if rec.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want Info for a passed flow", rec.Severity)
	}
	assertBodyIsVerbatim(t, rec, connDoc)

	// Per-flow fields belong in structured metadata.
	assertAttr(t, rec, "ip_src_saddr", "10.0.0.114")
	assertAttr(t, rec, "ip_dst_saddr", "10.0.0.254")
	assertAttr(t, rec, "ip_dst_port", "1900")
	assertAttr(t, rec, "app_name", "SSDP")
	assertAttr(t, rec, attrAppCategory, "Network Management")
	assertAttr(t, rec, attrInterfaceDev, "ixl0")
	assertAttr(t, rec, "device.name", "opnsense-devel")
	assertAttr(t, rec, "src_npackets", "1")

	// Empty strings never become attributes.
	if _, ok := rec.Attributes["organization"]; ok {
		t.Error(`empty "organization" was set; empty strings must be skipped`)
	}
	// An unlocatable address sends an all-zero geo block, which must contribute nothing
	// — including asn, whose empty value Zenarmor spells "0".
	for k := range rec.Attributes {
		if strings.HasPrefix(k, "src_geoip.") || strings.HasPrefix(k, "dst_geoip.") {
			t.Errorf("zero geo produced attribute %q = %q", k, rec.Attributes[k])
		}
	}
}

func TestBuildRecordDNS(t *testing.T) {
	rec, ok := buildRecord("dns", []byte(dnsDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, logship.AttrSubsystem, "dns")
	assertAttr(t, rec, logship.AttrAction, logship.ActionPass)
	assertBodyIsVerbatim(t, rec, dnsDoc)
	assertAttr(t, rec, "query", "WINSRV")
	assertAttr(t, rec, "qtype", "ALL")

	// dns carries NO end_time, so the timestamp falls back to start_time. That is the
	// only reason the fallback exists.
	if got := rec.Timestamp.UnixMilli(); got != 1784224414000 {
		t.Errorf("Timestamp = %d, want start_time 1784224414000", got)
	}
	// resp_code -1 means "this is the request, no response yet" — a real value, not a
	// missing one, so it must survive rather than be skipped as a zero.
	assertAttr(t, rec, attrRCode, "-1")
	// domain_categories is empty on this fixture.
	if got := attr(t, rec, attrDomainCategory); got != "" {
		t.Errorf("domain_category = %q, want empty", got)
	}
}

// Zenarmor sends the dns category taxonomy as domain_categories, an ARRAY — not the
// singular "domain_category" the spec assumed. Only the primary becomes the label.
func TestBuildRecordDNSAnswered(t *testing.T) {
	rec, ok := buildRecord("dns", []byte(dnsAnsweredDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, "query", "time.windows.com")
	assertAttr(t, rec, attrRCode, "0") // NOERROR: a zero that must not be skipped
	assertAttr(t, rec, attrDomainCategory, "Technology and Computer")
}

func TestBuildRecordTLS(t *testing.T) {
	rec, ok := buildRecord("tls", []byte(tlsDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, logship.AttrSubsystem, "tls")
	assertBodyIsVerbatim(t, rec, tlsDoc)
	assertAttr(t, rec, "server_name", "www.tinionet.net")
	assertAttr(t, rec, "ja3", "d4532a81f32dbfb55a549c648cddc3da")
	// tls spells the taxonomy "category"; it is normalised onto the same key dns's
	// domain_categories lands on, so derive.go reads one key for both.
	assertAttr(t, rec, attrDomainCategory, "Uncategorized")
	if got := rec.Timestamp.UnixMilli(); got != 1784224405000 {
		t.Errorf("Timestamp = %d, want start_time 1784224405000 (tls has no end_time)", got)
	}
	// A located address DOES produce geo attributes.
	assertAttr(t, rec, "dst_geoip.country_code2", "CN")
	assertAttr(t, rec, "dst_geoip.city_name", "Guangdong")
	// ...but its asn is Zenarmor's empty "0", which must not be shipped as AS0.
	if _, ok := rec.Attributes["dst_geoip.asn"]; ok {
		t.Errorf(`asn "0" was shipped; it is Zenarmor's empty value, not AS0`)
	}
	// ...and it does NOT carry coordinates: a located address is described by its
	// country/city, which is all anything consumes. See
	// TestGeoCoordinatesAreNotAttributed for the full statement of #475.
	if got, present := rec.Attributes["dst_geoip.latitude"]; present {
		t.Errorf("dst_geoip.latitude = %q was shipped; coordinates are pruned (#475)", got)
	}
}

func TestBuildRecordHTTP(t *testing.T) {
	rec, ok := buildRecord("web", []byte(httpDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, logship.AttrSubsystem, "web")
	assertBodyIsVerbatim(t, rec, httpDoc)
	assertAttr(t, rec, "method", "POST")
	assertAttr(t, rec, "uri", "/inform")
	assertAttr(t, rec, "user_agent", "ESP32 HTTP Client/1.0")
	// Zenarmor calls the numeric response status "status_msg".
	assertAttr(t, rec, attrHTTPStatus, "200")
	if got := rec.Timestamp.UnixMilli(); got != 1784224408000 {
		t.Errorf("Timestamp = %d, want start_time 1784224408000 (http has no end_time)", got)
	}
}

// Constructed fixture — no alert fired during the capture. What this really pins is
// the family-independent behaviour: subsystem, action and the ids severity rule.
func TestBuildRecordAlert(t *testing.T) {
	rec, ok := buildRecord("ids", []byte(alertDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, logship.AttrSubsystem, "ids")
	assertAttr(t, rec, logship.AttrAction, logship.ActionBlock)
	assertBodyIsVerbatim(t, rec, alertDoc)
	assertAttr(t, rec, attrAlertCategory, "Attempted Administrator Privilege Gain")
	assertAttr(t, rec, attrAlertSeverity, "1")
	assertAttr(t, rec, "alertinfo.signature", "ET EXPLOIT Possible CVE-2021-44228")
	assertAttr(t, rec, "alertinfo.action", "reject")
	if rec.Severity != logship.SeverityWarn {
		t.Errorf("Severity = %v, want Warn for an ids record", rec.Severity)
	}
}

func TestParseDoc_AlertInfoRealShape(t *testing.T) {
	// Verbatim alertinfo from a live 26.x capture: category/signature are arrays,
	// severity is a number, sid is a string. The pre-fix struct fails all four.
	doc := []byte(`{
		"start_time":1784368506000,"transport_proto":"UDP","interface":"ixl0",
		"ip_src_saddr":"10.0.0.120","ip_dst_saddr":"239.255.255.250","is_blocked":1,
		"alertinfo":{"match":{"dst_hostname":"239.255.255.250"},"action":"reject",
			"category":["Application Category"],"signature":["Network Management"],
			"severity":0,"sid":"appcategories.689585a5-37ba-41f9-86e4-160e8a0de793",
			"gid":0,"rev":0}
	}`)
	rec, parsed := parseDoc("ids", doc, nil)
	if !parsed {
		t.Fatalf("alert document failed to decode; want parsed=true")
	}
	want := map[string]string{
		"alertinfo.category":  "Application Category",
		"alertinfo.signature": "Network Management",
		"alertinfo.severity":  "0",
		"alertinfo.sid":       "appcategories.689585a5-37ba-41f9-86e4-160e8a0de793",
		"alertinfo.action":    "reject",
	}
	for k, v := range want {
		if got := rec.Attributes[k]; got != v {
			t.Errorf("attr %q = %q, want %q", k, got, v)
		}
	}
}

// An ids record is a warning even when nothing was blocked: an alert is worth
// surfacing whether or not the firewall acted on it.
func TestBuildRecordUnblockedAlertIsStillWarn(t *testing.T) {
	rec, _ := buildRecord("ids", []byte(`{"is_blocked":0,"alert_category":"Misc"}`), nil)
	if rec.Attributes[logship.AttrAction] != logship.ActionPass {
		t.Errorf("action = %q, want pass", rec.Attributes[logship.AttrAction])
	}
	if rec.Severity != logship.SeverityWarn {
		t.Errorf("Severity = %v, want Warn", rec.Severity)
	}
}

// Constructed fixture — no SIP traffic crossed the box during the capture.
func TestBuildRecordSIP(t *testing.T) {
	rec, ok := buildRecord("voip", []byte(sipDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	assertAttr(t, rec, logship.AttrSubsystem, "voip")
	assertAttr(t, rec, logship.AttrAction, logship.ActionPass)
	assertAttr(t, rec, "sip_method", "INVITE")
	assertBodyIsVerbatim(t, rec, sipDoc)
}

func TestBuildRecordBlockedFlowMapsToBlock(t *testing.T) {
	rec, _ := buildRecord("flow", []byte(`{"is_blocked":1,"end_time":1784224394000}`), nil)
	if rec.Attributes[logship.AttrAction] != logship.ActionBlock {
		t.Errorf("action = %q, want block", rec.Attributes[logship.AttrAction])
	}
	if rec.Severity != logship.SeverityWarn {
		t.Error("a blocked flow should be a warning")
	}
}

// AttrAction is an explicit allowlist. A document that never stated a disposition
// must leave the label UNSET rather than default to "pass": {opnsense_action="pass"}
// has to mean the firewall really did let it through.
func TestBuildRecordAbsentIsBlockedLeavesActionUnset(t *testing.T) {
	rec, _ := buildRecord("flow", []byte(`{"end_time":1784224394000,"app_name":"SSDP"}`), nil)
	if got, ok := rec.Attributes[logship.AttrAction]; ok {
		t.Errorf("action = %q, want unset when is_blocked is absent", got)
	}
}

func TestBuildRecordUnknownIsBlockedLeavesActionUnset(t *testing.T) {
	rec, _ := buildRecord("flow", []byte(`{"is_blocked":7,"end_time":1784224394000}`), nil)
	if got, ok := rec.Attributes[logship.AttrAction]; ok {
		t.Errorf("action = %q, want unset for an unrecognised is_blocked", got)
	}
}

// A parse failure must NEVER drop the record.
func TestBuildRecordGarbageIsStillShipped(t *testing.T) {
	rec, ok := buildRecord("flow", []byte(`not json at all`), nil)
	if !ok {
		t.Fatal("garbage must still ship with a raw body, not be dropped")
	}
	if rec.Body != "not json at all" {
		t.Errorf("body = %q, want the raw bytes", rec.Body)
	}
}

// parseDoc is the inner form the source uses: it reports the decode outcome so a
// ParseError can be counted, while still returning a shippable record.
func TestParseDocReportsDecodeOutcome(t *testing.T) {
	if _, parsed := parseDoc("flow", []byte(connDoc), nil); !parsed {
		t.Error("a real document must report parsed=true")
	}
	rec, parsed := parseDoc("flow", []byte(`not json at all`), nil)
	if parsed {
		t.Error("garbage must report parsed=false so the caller can count a ParseError")
	}
	if rec.Body != "not json at all" {
		t.Errorf("body = %q, want the raw bytes even when unparsed", rec.Body)
	}
}

// A document with no usable time leaves the timestamp zero, which the pipeline stamps
// at emit. Inventing one would be worse than admitting we do not know.
func TestBuildRecordNoTimeLeavesTimestampZero(t *testing.T) {
	rec, _ := buildRecord("flow", []byte(`{"is_blocked":0}`), nil)
	if !rec.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero", rec.Timestamp)
	}
}

// enrichSnapshotForTest builds a snapshot matching the connDoc fixture: it flows
// 10.0.0.114 -> 10.0.0.254:1900/udp over ixl0.
func enrichSnapshotForTest(t *testing.T) *enrich.Snapshot {
	t.Helper()
	return &enrich.Snapshot{
		IfaceNames: map[string]string{"ixl0": "LAN"},
		LocalNets:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		SelfIPs:    map[netip.Addr]bool{netip.MustParseAddr("10.0.0.254"): true},
	}
}

func TestBuildRecordEnrichment(t *testing.T) {
	rec, ok := buildRecord("flow", []byte(connDoc), enrichSnapshotForTest(t))
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	// ixl0 resolves to its friendly name via the snapshot.
	assertAttr(t, rec, attrInterfaceName, "LAN")
	assertAttr(t, rec, "src.scope", "local")
	assertAttr(t, rec, "dst.scope", "self")
	// dst port 1900 over transport_proto "UDP". Zenarmor gives the port as an int and
	// the proto upper-cased, so this only resolves if both are converted.
	assertAttr(t, rec, "dst.service", "ssdp")
}

// An unresolvable interface leaves interface.name unset and the raw device in place,
// rather than inventing a name.
func TestBuildRecordEnrichmentUnknownInterface(t *testing.T) {
	snap := &enrich.Snapshot{
		IfaceNames: map[string]string{"vtnet9": "WAN"},
		LocalNets:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	rec, _ := buildRecord("flow", []byte(connDoc), snap)
	if v, ok := rec.Attributes[attrInterfaceName]; ok {
		t.Errorf("interface.name = %q, want unset for an unknown device", v)
	}
	assertAttr(t, rec, attrInterfaceDev, "ixl0")
}

// Without a snapshot the record still ships, just unenriched.
func TestBuildRecordNilSnapshotSkipsEnrichment(t *testing.T) {
	rec, _ := buildRecord("flow", []byte(connDoc), nil)
	for _, k := range []string{attrInterfaceName, "src.scope", "dst.scope", "dst.service"} {
		if v, ok := rec.Attributes[k]; ok {
			t.Errorf("attribute %q = %q was set without a snapshot", k, v)
		}
	}
}

// rcode and alert_severity both reach a metric LABEL, and both come off the wire
// from a push sender. DNS RCODE is a 4-bit field and IDS severity is a 1-4 scale, so
// anything outside those folds into ONE bucket rather than minting a series per
// value a sender invents. -1 is Zenarmor's own "request, no response yet" sentinel
// and is kept.
func TestParseDoc_RCodeClamped(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"noerror", `{"resp_code":0}`, "0"},
		{"nxdomain", `{"resp_code":3}`, "3"},
		{"top of the 4-bit range", `{"resp_code":15}`, "15"},
		{"no-response sentinel", `{"resp_code":-1}`, "-1"},
		{"above the 4-bit range", `{"resp_code":16}`, zenOther},
		{"absurd", `{"resp_code":999999}`, zenOther},
		{"below the sentinel", `{"resp_code":-2}`, zenOther},
		{"absent stays absent", `{"query":"example.com"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := buildRecord("dns", []byte(tt.doc), nil)
			if !ok {
				t.Fatal("buildRecord returned !ok")
			}
			assertAttr(t, rec, attrRCode, tt.want)
		})
	}
}

func TestParseDoc_AlertSeverityClamped(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"most severe", `{"alert_severity":"1"}`, "1"},
		{"least severe of the real range", `{"alert_severity":"4"}`, "4"},
		{"zero is not a severity", `{"alert_severity":"0"}`, zenOther},
		{"out of range", `{"alert_severity":"9001"}`, zenOther},
		{"free text", `{"alert_severity":"critical-é"}`, zenOther},
		{"absent stays absent", `{"alert_category":"trojan"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := buildRecord("ids", []byte(tt.doc), nil)
			if !ok {
				t.Fatal("buildRecord returned !ok")
			}
			assertAttr(t, rec, attrAlertSeverity, tt.want)
		})
	}
}

// --- #473: the two shape dimensions hoisted onto the OTLP resource ----------

// device.category comes straight off the wire from a PUSH sender, and once promoted
// it is a Loki index label — so an unrecognised value is not data, it is a sender
// minting streams. It folds into Zenarmor's own `other` bucket. The record keeps the
// raw value under device.category regardless, so nothing is actually lost.
func TestParseDoc_DeviceCategoryPromotedAndClamped(t *testing.T) {
	tests := []struct {
		name, category, want string
	}{
		{"laptop", "laptop", "laptop"},
		{"camera", "camera", "camera"},
		{"iot", "iot", "iot"},
		{"zenarmor's own unknown bucket", "other", "other"},
		{"an unclassified category folds", "toaster", zenOther},
		{"free text folds", "'; DROP TABLE devices; --", zenOther},
		{"absent stays absent", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := json.Marshal(map[string]any{"device": map[string]string{"category": tt.category}})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			rec, ok := buildRecord("flow", doc, nil)
			if !ok {
				t.Fatal("buildRecord returned !ok")
			}
			assertAttr(t, rec, logship.AttrDeviceCategory, tt.want)
			// The lane's own key keeps full fidelity — clamping is for the label only.
			assertAttr(t, rec, "device.category", tt.category)
		})
	}
}

// The promoted interface must be the DESCRIPTION space (LAN/IOT/MGMT), never the
// kernel device space (ixl0) — the two are disjoint (#98), and a kernel name here
// would produce a label that silently matches nothing on the dashboard.
//
// It is also the guard that makes the key closed WITHOUT a clamp: the value is
// resolved from the exporter's own snapshot of the box's interface config, so a
// sender naming an interface the box does not have gets no attribute at all.
func TestParseDoc_InterfacePromotedFromEnrichmentOnly(t *testing.T) {
	t.Run("resolved name is promoted", func(t *testing.T) {
		rec, ok := buildRecord("flow", []byte(connDoc), enrichSnapshotForTest(t))
		if !ok {
			t.Fatal("buildRecord returned !ok")
		}
		assertAttr(t, rec, logship.AttrInterface, "LAN")
		// The kernel device stays where it was, and stays OUT of the promoted key.
		assertAttr(t, rec, attrInterfaceDev, "ixl0")
	})

	t.Run("an interface the box does not have is not promotable", func(t *testing.T) {
		snap := &enrich.Snapshot{IfaceNames: map[string]string{"vtnet9": "WAN"}}
		rec, _ := buildRecord("flow", []byte(connDoc), snap)
		assertAttr(t, rec, logship.AttrInterface, "")
	})

	t.Run("no snapshot means no promotion", func(t *testing.T) {
		rec, _ := buildRecord("flow", []byte(connDoc), nil)
		assertAttr(t, rec, logship.AttrInterface, "")
	})
}
