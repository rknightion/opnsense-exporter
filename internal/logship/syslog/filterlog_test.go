package syslog

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// testSnapshot is the enrichment fixture used across the filterlog tests: the
// anti-lockout rule id from the real IPv4/TCP line, vtnet0 -> LAN, and a lease
// for the laptop that originates the connection.
func testSnapshot(t *testing.T) *enrich.Snapshot {
	t.Helper()
	return &enrich.Snapshot{
		RuleLabels: map[string]string{
			"60533d555322b9f6a009f71c1c471480": "anti-lockout rule",
		},
		IfaceNames: map[string]string{
			"vtnet0": "LAN",
			"vtnet1": "WAN",
			"vtnet2": "OPT1",
		},
		Hostnames: map[string]string{
			"10.0.0.6": "robs-laptop",
		},
		MACs: map[string]string{
			"10.0.0.6": "aa:bb:cc:dd:ee:ff",
		},
		LocalNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		SelfIPs:   map[netip.Addr]bool{netip.MustParseAddr("10.0.0.114"): true},
	}
}

// missRecorder counts miss() calls per table so a test can assert both "exactly
// one rules miss" and "zero misses".
type missRecorder struct {
	calls []string
}

func (m *missRecorder) miss(table string) { m.calls = append(m.calls, table) }

func (m *missRecorder) count(table string) int {
	n := 0
	for _, c := range m.calls {
		if c == table {
			n++
		}
	}
	return n
}

func testEnvelope(msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "filterlog",
		PID:       "12345",
		Facility:  16,
		Severity:  6,
		Message:   msg,
	}
}

func attr(t *testing.T, rec logship.Record, key string) string {
	t.Helper()
	return rec.Attributes[key]
}

func assertAttr(t *testing.T, rec logship.Record, key, want string) {
	t.Helper()
	got, ok := rec.Attributes[key]
	if !ok {
		t.Errorf("attribute %q missing (want %q)", key, want)
		return
	}
	if got != want {
		t.Errorf("attribute %q = %q, want %q", key, got, want)
	}
}

func assertNoAttr(t *testing.T, rec logship.Record, key string) {
	t.Helper()
	if got, ok := rec.Attributes[key]; ok {
		t.Errorf("attribute %q present (%q), want absent", key, got)
	}
}

// A real line from a live OPNsense 26.7 box. Nine TCP tail fields — window and
// options included (OPNsense's own read_log.py names eight and loses both).
const realIPv4TCPLine = `117,,,60533d555322b9f6a009f71c1c471480,vtnet0,match,pass,in,4,0x0,,64,42046,0,DF,6,tcp,60,10.0.0.6,10.0.0.114,57920,22,0,S,1621336252,,64240,,mss;sackOK;TS;nop;wscale`

// IPv6 puts protoname BEFORE protonum; IPv4 is the reverse.
const realIPv6ICMPLine = `10,,,0,vtnet1,match,block,in,6,0x00,0x00000,255,ipv6-icmp,58,32,fe80::1,ff02::1,datalength=72`

// UDP with rid=0: a NAT/floating match that carries no rule id.
const realIPv4UDPLine = `16,115,,0,vtnet2,match,pass,out,4,0x0,,64,0,0,DF,17,udp,48,10.0.0.5,10.0.0.6,55124,65001,28`

func TestParseFilterlog_IPv4TCP_EveryTailField(t *testing.T) {
	var m missRecorder
	rec, ok := parseFilterlog(testEnvelope(realIPv4TCPLine), testSnapshot(t), m.miss)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true")
	}

	assertAttr(t, rec, "action", "pass")
	assertAttr(t, rec, "direction", "in")
	assertAttr(t, rec, "interface", "vtnet0")
	assertAttr(t, rec, "ip.version", "4")
	assertAttr(t, rec, "network.type", "ipv4") // semconv, alongside ip.version
	assertAttr(t, rec, "protocol", "tcp")
	assertAttr(t, rec, "network.transport", "tcp") // semconv, tcp/udp only
	assertAttr(t, rec, "src.ip", "10.0.0.6")
	assertAttr(t, rec, "dst.ip", "10.0.0.114")
	assertAttr(t, rec, "src.port", "57920")
	assertAttr(t, rec, "dst.port", "22")
	assertAttr(t, rec, "rule.id", "60533d555322b9f6a009f71c1c471480")

	// The whole nine-field TCP tail, asserted field by field.
	assertAttr(t, rec, "tcp.flags", "S")
	assertAttr(t, rec, "tcp.seq", "1621336252")
	assertNoAttr(t, rec, "tcp.ack") // empty in the real line -> never an empty attribute
	assertAttr(t, rec, "tcp.window", "64240")
	assertNoAttr(t, rec, "tcp.urg")
	assertAttr(t, rec, "tcp.options", "mss;sackOK;TS;nop;wscale")
	assertNoAttr(t, rec, "icmp_extra")

	// Enrichment.
	assertAttr(t, rec, "rule.description", "anti-lockout rule")
	assertNoAttr(t, rec, "rule.ref")
	assertAttr(t, rec, "interface.name", "LAN")
	assertAttr(t, rec, "src.hostname", "robs-laptop")
	assertNoAttr(t, rec, "dst.hostname")
	assertAttr(t, rec, "src.mac", "aa:bb:cc:dd:ee:ff")
	assertAttr(t, rec, "src.scope", "local")
	assertAttr(t, rec, "dst.scope", "self")
	assertAttr(t, rec, "dst.service", "ssh")

	if rec.Severity != logship.SeverityInfo {
		t.Errorf("Severity = %v, want SeverityInfo (action=pass)", rec.Severity)
	}
	if want := "pass in on LAN: 10.0.0.6:57920 -> 10.0.0.114:22 (tcp)"; rec.Body != want {
		t.Errorf("Body = %q, want %q", rec.Body, want)
	}
	if !rec.Timestamp.Equal(testEnvelope("").Timestamp) {
		t.Errorf("Timestamp = %v, want the envelope timestamp", rec.Timestamp)
	}
	if n := m.count("rules"); n != 0 {
		t.Errorf("miss(rules) called %d times, want 0 (rid is known)", n)
	}
}

func TestParseFilterlog_IPv6ICMP_ProtoOrderInversion(t *testing.T) {
	var m missRecorder
	rec, ok := parseFilterlog(testEnvelope(realIPv6ICMPLine), testSnapshot(t), m.miss)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true")
	}

	// If IPv4's protonum-then-protoname order were applied to IPv6, protocol
	// would read "58" here. This assertion is the guard on the inversion.
	assertAttr(t, rec, "protocol", "ipv6-icmp")
	assertAttr(t, rec, "ip.version", "6")
	assertAttr(t, rec, "network.type", "ipv6") // semconv
	assertNoAttr(t, rec, "network.transport")  // icmp is not an L4 transport
	assertAttr(t, rec, "src.ip", "fe80::1")
	assertAttr(t, rec, "dst.ip", "ff02::1")
	assertAttr(t, rec, "icmp_extra", "datalength=72")
	assertAttr(t, rec, "action", "block")
	assertAttr(t, rec, "interface", "vtnet1")
	assertAttr(t, rec, "interface.name", "WAN")
	assertNoAttr(t, rec, "src.port")
	assertNoAttr(t, rec, "dst.port")
	assertNoAttr(t, rec, "tcp.flags")

	// rid == "0": no lookup, no miss, a rendered rule.ref instead.
	assertNoAttr(t, rec, "rule.description")
	assertNoAttr(t, rec, "rule.id")
	// subrulenr is empty on this line, so the ref degrades to the rule number.
	assertAttr(t, rec, "rule.ref", "rule #10")

	if rec.Severity != logship.SeverityWarn {
		t.Errorf("Severity = %v, want SeverityWarn (action=block)", rec.Severity)
	}
	if want := "block in on WAN: fe80::1 -> ff02::1 (ipv6-icmp)"; rec.Body != want {
		t.Errorf("Body = %q, want %q", rec.Body, want)
	}
	if len(m.calls) != 0 {
		t.Errorf("miss called %v, want no calls", m.calls)
	}
}

func TestParseFilterlog_UDP_RidZeroIsNotAMiss(t *testing.T) {
	var m missRecorder
	rec, ok := parseFilterlog(testEnvelope(realIPv4UDPLine), testSnapshot(t), m.miss)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true")
	}

	assertAttr(t, rec, "protocol", "udp")
	assertAttr(t, rec, "src.ip", "10.0.0.5")
	assertAttr(t, rec, "dst.ip", "10.0.0.6")
	assertAttr(t, rec, "src.port", "55124")
	assertAttr(t, rec, "dst.port", "65001")
	assertAttr(t, rec, "dst.hostname", "robs-laptop")
	assertAttr(t, rec, "direction", "out")

	assertNoAttr(t, rec, "rule.description")
	assertNoAttr(t, rec, "rule.id")
	assertAttr(t, rec, "rule.ref", "rule #16.115")

	if len(m.calls) != 0 {
		t.Errorf("miss called %v, want ZERO calls: rid==0 means 'no rule id', not a stale cache", m.calls)
	}
}

func TestParseFilterlog_UnknownRidIsExactlyOneRulesMiss(t *testing.T) {
	line := `117,,,deadbeefdeadbeefdeadbeefdeadbeef,vtnet0,match,pass,in,4,0x0,,64,42046,0,DF,6,tcp,60,10.0.0.6,10.0.0.114,57920,22,0,S,1621336252,,64240,,mss;sackOK;TS;nop;wscale`
	var m missRecorder
	rec, ok := parseFilterlog(testEnvelope(line), testSnapshot(t), m.miss)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true")
	}
	assertNoAttr(t, rec, "rule.description")
	assertAttr(t, rec, "rule.id", "deadbeefdeadbeefdeadbeefdeadbeef")
	if n := m.count("rules"); n != 1 {
		t.Errorf("miss(rules) called %d times, want exactly 1 (calls=%v)", n, m.calls)
	}
	if len(m.calls) != 1 {
		t.Errorf("miss calls = %v, want only the single rules miss (hostname/MAC/scope misses are normal)", m.calls)
	}
}

func TestParseFilterlog_NilSnapshotStillShipsUnenriched(t *testing.T) {
	rec, ok := parseFilterlog(testEnvelope(realIPv4TCPLine), nil, nil)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true: enrichment failure must never drop a record")
	}
	assertAttr(t, rec, "src.ip", "10.0.0.6")
	assertAttr(t, rec, "tcp.window", "64240")
	assertNoAttr(t, rec, "rule.description")
	assertNoAttr(t, rec, "interface.name")
	assertNoAttr(t, rec, "src.hostname")
	// Service names come from the static table, not the snapshot.
	assertAttr(t, rec, "dst.service", "ssh")
	if want := "pass in on vtnet0: 10.0.0.6:57920 -> 10.0.0.114:22 (tcp)"; rec.Body != want {
		t.Errorf("Body = %q, want %q", rec.Body, want)
	}
}

func TestParseFilterlog_ColdSnapshotStillShipsUnenriched(t *testing.T) {
	var m missRecorder
	rec, ok := parseFilterlog(testEnvelope(realIPv4TCPLine), &enrich.Snapshot{}, m.miss)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true")
	}
	assertAttr(t, rec, "src.ip", "10.0.0.6")
	assertNoAttr(t, rec, "rule.description")
	if n := m.count("rules"); n != 1 {
		t.Errorf("miss(rules) = %d, want 1 (cold cache with a non-zero rid IS a miss)", n)
	}
}

func TestParseFilterlog_CARPTail(t *testing.T) {
	line := `5,,,0,vtnet0,match,pass,out,4,0x0,,255,0,0,none,112,carp,36,10.0.0.1,224.0.0.18,TYPE_ADVERTISEMENT,255,1,2,0,1`
	rec, ok := parseFilterlog(testEnvelope(line), testSnapshot(t), nil)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true")
	}
	assertAttr(t, rec, "protocol", "carp")
	assertAttr(t, rec, "src.ip", "10.0.0.1")
	assertAttr(t, rec, "dst.ip", "224.0.0.18")
	assertNoAttr(t, rec, "src.port")
	assertNoAttr(t, rec, "icmp_extra")
}

func TestParseFilterlog_Malformed(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"empty", ""},
		{"short", "not,enough,fields"},
		{"header only", "117,,,0,vtnet0,match,pass,in,4"},
		{"bad ip version", "117,,,0,vtnet0,match,pass,in,9,a,b,c,d,e,f,g,h,i,j,k"},
		{"ipv4 body truncated", "117,,,0,vtnet0,match,pass,in,4,0x0,,64,42046,0,DF,6,tcp"},
		{"ipv6 body truncated", "10,,,0,vtnet1,match,block,in,6,0x00,0x00000,255,ipv6-icmp"},
		{"just commas", ",,,,,,,,,,,,,,,,,,,,"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			rec, ok := parseFilterlog(testEnvelope(tc.msg), testSnapshot(t), m.miss) // must not panic
			if ok {
				t.Fatalf("parseFilterlog(%q) = ok, want ok=false (record=%+v)", tc.msg, rec)
			}
		})
	}
}

func TestParseFilterlog_ShortTailStillShips(t *testing.T) {
	// A TCP row whose tail is truncated: we keep what is there and never panic.
	line := `117,,,0,vtnet0,match,pass,in,4,0x0,,64,42046,0,DF,6,tcp,60,10.0.0.6,10.0.0.114,57920`
	rec, ok := parseFilterlog(testEnvelope(line), testSnapshot(t), nil)
	if !ok {
		t.Fatalf("parseFilterlog(ok) = false, want true: a short protocol tail is not a malformed row")
	}
	assertAttr(t, rec, "src.port", "57920")
	assertNoAttr(t, rec, "dst.port")
	assertNoAttr(t, rec, "tcp.window")
	if got := attr(t, rec, "protocol"); got != "tcp" {
		t.Errorf("protocol = %q, want tcp", got)
	}
}

// The normalised opnsense.action must be set alongside — never instead of — the
// raw wire verb, which sample.go:25 and derive.go both read.
func TestParseFilterlog_SetsAttrAction(t *testing.T) {
	blocked, ok := parseFilterlog(testEnvelope(realIPv6ICMPLine), nil, nil)
	if !ok {
		t.Fatal("parse failed")
	}
	assertAttr(t, blocked, logship.AttrAction, logship.ActionBlock)
	if got := attr(t, blocked, "action"); got != "block" {
		t.Errorf(`raw "action" = %q, want "block"; sample.go:25 and derive.go:71 depend on it surviving`, got)
	}

	passed, ok := parseFilterlog(testEnvelope(realIPv4TCPLine), nil, nil)
	if !ok {
		t.Fatal("parse failed")
	}
	assertAttr(t, passed, logship.AttrAction, logship.ActionPass)
	if got := attr(t, passed, "action"); got != "pass" {
		t.Errorf(`raw "action" = %q, want "pass"`, got)
	}
}

// filterlog's action is a raw wire passthrough, so an unrecognised verb (NAT/rdr)
// must leave opnsense.action ABSENT rather than be guessed into "block".
func TestParseFilterlog_UnknownActionLeavesAttrActionUnset(t *testing.T) {
	// Same shape as realIPv4UDPLine but with pf's rdr verb in the action field.
	rdrLine := strings.Replace(realIPv4UDPLine, ",match,pass,out,", ",match,rdr,out,", 1)
	rec, ok := parseFilterlog(testEnvelope(rdrLine), nil, nil)
	if !ok {
		t.Fatal("parse failed")
	}
	if v, present := rec.Attributes[logship.AttrAction]; present {
		t.Errorf("opnsense.action = %q for an unrecognised verb; it must be absent, not guessed", v)
	}
	// The raw verb still ships.
	if got := attr(t, rec, "action"); got != "rdr" {
		t.Errorf(`raw "action" = %q, want "rdr"`, got)
	}
}
