package syslog

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

func unboundEnv(msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "unbound",
		Facility:  3,
		Severity:  6, // info
		Message:   msg,
	}
}

// unboundSnapshot: 10.0.0.141 is a known LAN client; 127.0.0.1 and IPv6 clients are
// not in it (an unknown client is normal and must not signal a miss).
func unboundSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		Hostnames: map[string]string{"10.0.0.141": "workstation"},
		MACs:      map[string]string{"10.0.0.141": "de:ad:be:ef:00:01"},
		LocalNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
}

func TestUnboundRegistered(t *testing.T) {
	if _, ok := parserFor("unbound"); !ok {
		t.Fatal("no parser registered for program unbound")
	}
}

// TestUnboundVerbatimLines covers the shapes captured verbatim from camden: IPv4
// and IPv6 clients, every observed qtype, and all three zone types.
func TestUnboundVerbatimLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "SRV transparent ipv4 (the dominant shape)",
			msg:  "[46775:2] info: example.com. transparent 10.0.0.141@51967 _ldap._tcp.dc._msdcs.example.com. SRV IN",
			want: map[string]string{
				"dns.query_name":   "_ldap._tcp.dc._msdcs.example.com.",
				"dns.query_type":   "SRV",
				"dns.query_class":  "IN",
				"dns.local_zone":   "example.com.",
				"dns.local_action": "transparent",
				"src.ip":           "10.0.0.141",
				"src.port":         "51967",
			},
		},
		{
			name: "PTR typetransparent reverse zone, loopback client",
			msg:  "[46775:0] info: 10.in-addr.arpa. typetransparent 127.0.0.1@7365 20.100.0.10.in-addr.arpa. PTR IN",
			want: map[string]string{
				"dns.query_name":   "20.100.0.10.in-addr.arpa.",
				"dns.query_type":   "PTR",
				"dns.local_zone":   "10.in-addr.arpa.",
				"dns.local_action": "typetransparent",
				"src.ip":           "127.0.0.1",
				"src.port":         "7365",
			},
		},
		{
			name: "PTR static reverse zone",
			msg:  "[46775:10] info: 16.172.in-addr.arpa. static 10.0.0.5@48801 33.0.16.172.in-addr.arpa. PTR IN",
			want: map[string]string{
				"dns.query_type":   "PTR",
				"dns.local_action": "static",
				"src.ip":           "10.0.0.5",
				"src.port":         "48801",
			},
		},
		{
			name: "AAAA ipv4 client",
			msg:  "[46775:9] info: example.com. transparent 10.0.0.5@44038 haos.example.com. AAAA IN",
			want: map[string]string{
				"dns.query_name": "haos.example.com.",
				"dns.query_type": "AAAA",
				"src.ip":         "10.0.0.5",
			},
		},
		{
			name: "PTR ipv6 client (colons in the address)",
			msg:  "[46775:1] info: example.com. transparent 2001:db8::105b@52824 lb._dns-sd._udp.example.com. PTR IN",
			want: map[string]string{
				"dns.query_name": "lb._dns-sd._udp.example.com.",
				"dns.query_type": "PTR",
				"src.ip":         "2001:db8::105b",
				"src.port":       "52824",
			},
		},
		{
			name: "SVCB static (resolver.arpa)",
			msg:  "[46775:11] info: resolver.arpa. static 10.0.0.5@62817 _dns.resolver.arpa. SVCB IN",
			want: map[string]string{
				"dns.query_name": "_dns.resolver.arpa.",
				"dns.query_type": "SVCB",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &missRecorder{}
			rec, ok := parseUnbound(unboundEnv(tc.msg), unboundSnapshot(), m.miss)
			if !ok {
				t.Fatalf("parseUnbound returned ok=false for %q", tc.msg)
			}
			if len(m.calls) != 0 {
				t.Fatalf("client lookups must never call miss(); got %v", m.calls)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message", rec.Body)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestUnboundClientEnrichment: a known client is enriched; the miss channel stays
// silent for an unknown one.
func TestUnboundClientEnrichment(t *testing.T) {
	rec, ok := parseUnbound(
		unboundEnv("[46775:2] info: example.com. transparent 10.0.0.141@51967 x.example.com. A IN"),
		unboundSnapshot(), func(string) {})
	if !ok {
		t.Fatal("ok=false")
	}
	assertAttrs(t, rec, map[string]string{
		"src.hostname": "workstation",
		"src.mac":      "de:ad:be:ef:00:01",
		"src.scope":    "local",
	})
}

// TestUnboundServfail: the SERVFAIL error shape (#334) is structured, both the
// "got SERVFAIL" and "upstream server timeout" details, and the root zone ".".
func TestUnboundServfail(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "forward servers failed, named zone, got SERVFAIL",
			msg:  "[46775:9] error: SERVFAIL <api.ipify.org.saga-turtle.ts.net. AAAA IN>: all the configured stub or forward servers failed, at zone saga-turtle.ts.net. from 100.100.100.100 got SERVFAIL",
			want: map[string]string{
				"dns.query_name":  "api.ipify.org.saga-turtle.ts.net.",
				"dns.query_type":  "AAAA",
				"dns.query_class": "IN",
				"dns.rcode":       "SERVFAIL",
				"dns.error_zone":  "saga-turtle.ts.net.",
				"dns.upstream":    "100.100.100.100",
				"dns.error":       "got SERVFAIL",
			},
		},
		{
			name: "root zone, upstream timeout",
			msg:  "[46775:6] error: SERVFAIL <res.dod.cdn.office.net. A IN>: all the configured stub or forward servers failed, at zone . from 162.159.36.20 upstream server timeout",
			want: map[string]string{
				"dns.query_name": "res.dod.cdn.office.net.",
				"dns.query_type": "A",
				"dns.rcode":      "SERVFAIL",
				"dns.error_zone": ".",
				"dns.upstream":   "162.159.36.20",
				"dns.error":      "upstream server timeout",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseUnbound(unboundEnv(tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseUnbound returned ok=false for %q", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestUnboundServfailCached: a cached negative answer being replayed (#641) is a
// different operational signal from a live resolution failure — the reused
// trailer is SHORTER than reUnboundServfail's ", at zone <z> from <upstream>
// <detail>" shape, so it needs its own branch, not a loosened live regex.
// Distinguished from the live shape via dns.cached, which is absent on a live
// SERVFAIL.
//
// Captured verbatim from a live box for #641, 2026-08-04:
//
//	[9284:5] error: SERVFAIL <wpad.saga-turtle.ts.net. A IN>: SERVFAIL in cache
//	[9284:6] error: SERVFAIL <wpad.saga-turtle.ts.net. AAAA IN>: SERVFAIL in cache
func TestUnboundServfailCached(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "cached SERVFAIL, A",
			msg:  "[9284:5] error: SERVFAIL <wpad.saga-turtle.ts.net. A IN>: SERVFAIL in cache",
			want: map[string]string{
				"dns.query_name":  "wpad.saga-turtle.ts.net.",
				"dns.query_type":  "A",
				"dns.query_class": "IN",
				"dns.rcode":       "SERVFAIL",
				"dns.cached":      "true",
			},
		},
		{
			name: "cached SERVFAIL, AAAA",
			msg:  "[9284:6] error: SERVFAIL <wpad.saga-turtle.ts.net. AAAA IN>: SERVFAIL in cache",
			want: map[string]string{
				"dns.query_name":  "wpad.saga-turtle.ts.net.",
				"dns.query_type":  "AAAA",
				"dns.query_class": "IN",
				"dns.rcode":       "SERVFAIL",
				"dns.cached":      "true",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseUnbound(unboundEnv(tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseUnbound returned ok=false for %q", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
			assertNoAttrs(t, rec, "dns.error_zone", "dns.upstream", "dns.error")
		})
	}
}

// TestUnboundNonQueryLinesDegrade: the remaining unbound chatter — the multi-line
// stats/histogram dump, unrecognized plugin status lines, and a bare startup line
// missing its [pid:thread] prefix — is deliberately NOT parsed. It returns ok=false
// so BuildRecord ships it as a generic record (still shipped, never dropped),
// exactly as sshd treats its non-auth chatter.
func TestUnboundNonQueryLinesDegrade(t *testing.T) {
	lines := []string{
		`Q-Feeds : skip invalid whitelist exclude pattern "*.notion.com"`,
		"[46775:0] notice: init module 0: iterator",
		// No [pid:thread] prefix — unlike the verbatim-captured lifecycle lines
		// (#631), this shape was never actually observed and must keep degrading.
		"start of service (unbound 1.19.3).",
		"[46775:3] info: server stats for thread 3: 1234 queries, 5 answers from cache",
		"[46775:3] info: histogram of recursion processing times",
		"[46775:3] info: [25%]=0.001 median[50%]=0.002 [75%]=0.004",
		"[46775:3] info: lower(secs) upper(secs) recursions",
		"[46775:3] info: average recursion processing time 0.123456 sec",
		"[46775:0] notice: Closing logger",
		"[46775:0] notice: Backgrounding unbound logging backend.",
		"[46775:0] notice: Database auto restore from /var/db/unbound.db",
		"",
	}
	for _, l := range lines {
		if _, ok := parseUnbound(unboundEnv(l), nil, func(string) {}); ok {
			t.Errorf("parseUnbound(%q) returned ok=true, want a generic-record fallthrough", l)
		}
	}
}

// TestUnboundDNSBL: the DNSBL/blocklist subsystem (#631), the single largest
// steady source of previously-unparsed volume on the box (~1550 entries over 8
// days). All lines except "blocklist parsing done" carry the standard
// [pid:thread] prefix; that one line does not, verbatim, and unbound.thread must
// be absent for it specifically.
func TestUnboundDNSBL(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "blocklist update starting",
			msg:  "[48126:7] info: dnsbl_module: updating blocklist.",
			want: map[string]string{
				"dnsbl.event":    "blocklist_updating",
				"unbound.thread": "7",
			},
		},
		{
			name: "blocklist loaded, entries reported",
			msg:  "[48126:7] info: dnsbl_module: blocklist loaded. length is 509328",
			want: map[string]string{
				"dnsbl.event":    "blocklist_loaded",
				"dnsbl.entries":  "509328",
				"unbound.thread": "7",
			},
		},
		{
			name: "blocklist parsing done - NO [pid:thread] prefix on this shape",
			msg:  "blocklist parsing done in 2.26 seconds (509328 records)",
			want: map[string]string{
				"dnsbl.event":                  "blocklist_parsed",
				"dnsbl.entries":                "509328",
				"dnsbl.parse_duration_seconds": "2.26",
			},
		},
		{
			name: "pipe opening",
			msg:  "[10176:8] info: dnsbl_module: attempting to open pipe",
			want: map[string]string{
				"dnsbl.event":    "pipe_opening",
				"unbound.thread": "8",
			},
		},
		{
			name: "pipe opened",
			msg:  "[10176:7] info: dnsbl_module: successfully opened pipe",
			want: map[string]string{
				"dnsbl.event":    "pipe_opened",
				"unbound.thread": "7",
			},
		},
		{
			name: "no logging backend",
			msg:  "[10176:8] info: dnsbl_module: no logging backend found.",
			want: map[string]string{
				"dnsbl.event":    "backend_missing",
				"unbound.thread": "8",
			},
		},
		{
			name: "logging backend closed pipe",
			msg:  "[92242:5] info: dnsbl_module: Logging backend closed connection. Closing pipe and continuing.",
			want: map[string]string{
				"dnsbl.event":    "pipe_closed",
				"unbound.thread": "5",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseUnbound(unboundEnv(tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseUnbound returned ok=false for %q", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
			if strings.Contains(tc.msg, "parsing done") {
				if _, ok := rec.Attributes["unbound.thread"]; ok {
					t.Errorf("unbound.thread must be absent on the unprefixed parsing-done line, got %v", rec.Attributes["unbound.thread"])
				}
			}
		})
	}
}

// TestUnboundServiceLifecycle: the start/stop pair (#631), also carrying the
// [pid:thread] prefix and the unbound version.
func TestUnboundServiceLifecycle(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "service started",
			msg:  "[10176:0] info: start of service (unbound 1.25.1).",
			want: map[string]string{
				"dns.event":      "service_started",
				"dns.version":    "1.25.1",
				"unbound.thread": "0",
			},
		},
		{
			name: "service stopped",
			msg:  "[53465:0] info: service stopped (unbound 1.25.1).",
			want: map[string]string{
				"dns.event":      "service_stopped",
				"dns.version":    "1.25.1",
				"unbound.thread": "0",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseUnbound(unboundEnv(tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseUnbound returned ok=false for %q", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// enablePerQueryRoute turns on the opt-in syslog per-query DNS route (#659) for one
// test and restores the previous state afterwards. The route is off by default, so
// without this every parse below correctly returns ok=false.
func enablePerQueryRoute(t *testing.T) {
	t.Helper()
	prev := perQueryRouteEnabled
	perQueryRouteEnabled = func() bool { return true }
	t.Cleanup(func() { perQueryRouteEnabled = prev })
}

// TestUnboundQueryReplyLog covers the log-queries/log-replies/log-tag-queryreply
// shapes frozen on #659. Each case comment states its provenance: "verbatim" ==
// captured verbatim in capture-010.ndjson (camden, 2026-08-07); "source-derived"
// == not captured, traced to a named upstream branch per the frozen spec.
func TestUnboundQueryReplyLog(t *testing.T) {
	enablePerQueryRoute(t)
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		// --- verbatim query: lines ---
		{
			name: "query, ipv4 loopback client (verbatim)",
			msg:  "[96463:4] query: 127.0.0.1 www.tleechreload.org. A IN",
			want: map[string]string{
				"dns.event":       "query",
				"dns.query_name":  "www.tleechreload.org.",
				"dns.query_type":  "A",
				"dns.query_class": "IN",
				"src.ip":          "127.0.0.1",
				"unbound.thread":  "4",
			},
		},
		{
			name: "query, ipv4 LAN client, AAAA (verbatim)",
			msg:  "[96463:9] query: 10.0.0.5 profiles-prod-023.grafana.net. AAAA IN",
			want: map[string]string{
				"dns.event":      "query",
				"dns.query_name": "profiles-prod-023.grafana.net.",
				"dns.query_type": "AAAA",
				"src.ip":         "10.0.0.5",
				"unbound.thread": "9",
			},
		},
		{
			name: "query, bare ipv6 client -- no brackets, no port (verbatim)",
			msg:  "[96463:0] query: fd6b:d9cd:7613:4c33:301f:7ada:8457:a679 www.msftconnecttest.com. A IN",
			want: map[string]string{
				"dns.event":      "query",
				"dns.query_name": "www.msftconnecttest.com.",
				"dns.query_type": "A",
				"src.ip":         "fd6b:d9cd:7613:4c33:301f:7ada:8457:a679",
				"unbound.thread": "0",
			},
		},

		// --- verbatim reply: lines ---
		{
			name: "reply, ipv4 loopback, from-cache=0, NOERROR (verbatim)",
			msg:  "[96463:8] reply: 127.0.0.1 tvchaosuk.com. AAAA IN NOERROR 0.012482 0 90",
			want: map[string]string{
				"dns.event":                "reply",
				"dns.query_name":           "tvchaosuk.com.",
				"dns.query_type":           "AAAA",
				"dns.query_class":          "IN",
				"dns.rcode":                "NOERROR",
				"dns.resolve_time_seconds": "0.012482",
				"dns.cached":               "false",
				"dns.response_size_bytes":  "90",
				"src.ip":                   "127.0.0.1",
				"unbound.thread":           "8",
			},
		},
		{
			name: "reply, bare ipv6 client (verbatim)",
			msg:  "[96463:0] reply: fd6b:d9cd:7613:4c33:301f:7ada:8457:a679 www.msftconnecttest.com. A IN NOERROR 0.010623 0 151",
			want: map[string]string{
				"dns.event":                "reply",
				"dns.query_name":           "www.msftconnecttest.com.",
				"dns.rcode":                "NOERROR",
				"dns.resolve_time_seconds": "0.010623",
				"dns.cached":               "false",
				"dns.response_size_bytes":  "151",
				"src.ip":                   "fd6b:d9cd:7613:4c33:301f:7ada:8457:a679",
			},
		},
		{
			name: "reply, from-cache=1, HTTPS qtype, resolve_time 0.000000 (verbatim)",
			msg:  "[96463:10] reply: 10.0.0.183 safebrowsing-proxy.g.aaplimg.com. HTTPS IN NOERROR 0.000000 1 110",
			want: map[string]string{
				"dns.event":                "reply",
				"dns.query_type":           "HTTPS",
				"dns.rcode":                "NOERROR",
				"dns.resolve_time_seconds": "0.000000",
				"dns.cached":               "true",
				"dns.response_size_bytes":  "110",
			},
		},
		{
			name: "reply, NXDOMAIN, SRV qtype (verbatim)",
			msg:  "[96463:5] reply: 10.0.0.199 _ldap._tcp.dc._msdcs.mgmt.rob-knight.net. SRV IN NXDOMAIN 0.000981 0 58",
			want: map[string]string{
				"dns.event":      "reply",
				"dns.query_type": "SRV",
				"dns.rcode":      "NXDOMAIN",
				"dns.cached":     "false",
			},
		},

		// --- source-derived qname edge cases (dname_str, util/data/dname.c) ---
		{
			name: "query, root/empty dname (source-derived: dname_str root branch, dname.c:643)",
			msg:  "[96463:4] query: 127.0.0.1 . A IN",
			want: map[string]string{
				"dns.event":      "query",
				"dns.query_name": ".",
				"dns.query_type": "A",
			},
		},
		{
			name: "query, '?'-escaped byte + TYPE%d/CLASS%d fallback (source-derived: dname.c:665 '?' branch; net_help.c:601 TYPE%d; net_help.c:608 CLASS%d)",
			msg:  "[96463:4] query: 127.0.0.1 ex?mple.com. TYPE65534 CLASS42",
			want: map[string]string{
				"dns.event":       "query",
				"dns.query_name":  "ex?mple.com.",
				"dns.query_type":  "TYPE65534",
				"dns.query_class": "CLASS42",
			},
		},
		{
			name: "query, MAX_DOMAINLEN truncation, '&', no trailing dot (source-derived: dname.c:653)",
			msg:  "[96463:4] query: 127.0.0.1 & A IN",
			want: map[string]string{
				"dns.event":      "query",
				"dns.query_name": "&",
				"dns.query_type": "A",
			},
		},
		{
			name: "query, label>63 bytes, '#', no trailing dot (source-derived: dname.c:659)",
			msg:  "[96463:4] query: 127.0.0.1 # A IN",
			want: map[string]string{
				"dns.event":      "query",
				"dns.query_name": "#",
				"dns.query_type": "A",
			},
		},

		// --- source-derived reply edge cases ---
		{
			name: "reply, FORMERR, all-dash placeholders mapped to absent (source-derived: msgreply.c:1046)",
			msg:  "[96463:8] reply: 10.0.0.5 - - - FORMERR - - -",
			want: map[string]string{
				"dns.event": "reply",
				"dns.rcode": "FORMERR",
				"src.ip":    "10.0.0.5",
			},
		},
		{
			name: "reply, null qname literal (source-derived: msgreply.c:1058)",
			msg:  "[96463:8] reply: 10.0.0.5 null A IN SERVFAIL 0.000000 0 0",
			want: map[string]string{
				"dns.event":                "reply",
				"dns.query_name":           "null",
				"dns.rcode":                "SERVFAIL",
				"dns.resolve_time_seconds": "0.000000",
				"dns.cached":               "false",
			},
		},
		{
			name: "reply, RCODE%d fallback (source-derived: sldns_wire2str_rcode_buf fallback)",
			msg:  "[96463:8] reply: 10.0.0.5 x. A IN RCODE23 0.000123 0 55",
			want: map[string]string{
				"dns.event": "reply",
				"dns.rcode": "RCODE23",
			},
		},
		{
			name: "reply, optional log-destaddr dest clause (source-derived: msgreply.c:1040)",
			msg:  "[96463:8] reply: 10.0.0.5 x. A IN NOERROR 0.012482 0 90 on udp 10.0.0.254 53",
			want: map[string]string{
				"dns.event":     "reply",
				"net.transport": "udp",
				"dst.ip":        "10.0.0.254",
				"dst.port":      "53",
			},
		},
		{
			name: "reply, tv_sec >= 1, NS qtype (source-derived: resolve time not always sub-second)",
			msg:  "[96463:8] reply: 10.0.0.5 x. NS IN NOERROR 1.234567 0 512",
			want: map[string]string{
				"dns.event":                "reply",
				"dns.query_type":           "NS",
				"dns.resolve_time_seconds": "1.234567",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &missRecorder{}
			rec, ok := parseUnbound(unboundEnv(tc.msg), unboundSnapshot(), m.miss)
			if !ok {
				t.Fatalf("parseUnbound returned ok=false for %q", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestUnboundReplyFormerrOmitsDashPlaceholders: a FORMERR reply's qname/qtype/
// qclass/resolve_time/response_size_bytes are all literal "-" on the wire and
// must never surface as the literal string "-" (set() only skips truly empty
// values, so "-" needs an explicit map-to-absent).
func TestUnboundReplyFormerrOmitsDashPlaceholders(t *testing.T) {
	enablePerQueryRoute(t)
	rec, ok := parseUnbound(
		unboundEnv("[96463:8] reply: 10.0.0.5 - - - FORMERR - - -"),
		nil, func(string) {})
	if !ok {
		t.Fatal("ok=false")
	}
	assertNoAttrs(t, rec,
		"dns.query_name", "dns.query_type", "dns.query_class",
		"dns.resolve_time_seconds", "dns.response_size_bytes")
}

// TestUnboundQueryReplyClientEnrichment: the query/reply lanes enrich src.ip
// exactly like the local-actions parser does.
func TestUnboundQueryReplyClientEnrichment(t *testing.T) {
	enablePerQueryRoute(t)
	rec, ok := parseUnbound(
		unboundEnv("[96463:4] query: 10.0.0.141 x.example.com. A IN"),
		unboundSnapshot(), func(string) {})
	if !ok {
		t.Fatal("ok=false")
	}
	assertAttrs(t, rec, map[string]string{
		"src.hostname": "workstation",
		"src.mac":      "de:ad:be:ef:00:01",
		"src.scope":    "local",
	})
}

// TestUnboundQueryReplyNegativeCases: lines that must NOT match the new
// query:/reply: patterns -- the existing local-actions and SERVFAIL parsers
// still own their shapes, and the deliberate fall-through set is unaffected.
// All real lines, from the archive or the existing suite above.
func TestUnboundQueryReplyNegativeCases(t *testing.T) {
	lines := []string{
		// local-actions info: line -- must route to reUnboundQuery, not the new
		// query: pattern (real, from TestUnboundVerbatimLines above).
		"[46775:2] info: example.com. transparent 10.0.0.141@51967 _ldap._tcp.dc._msdcs.example.com. SRV IN",
		// cached SERVFAIL -- must route to reUnboundServfailCached (real, #641).
		"[9284:5] error: SERVFAIL <wpad.saga-turtle.ts.net. A IN>: SERVFAIL in cache",
		// dnsbl chatter -- must route to the dnsbl_module parsers (real, #631).
		"[48126:7] info: dnsbl_module: blocklist loaded. length is 509328",
		// deliberate fall-through: multi-line stats dump (real, capture-010.ndjson).
		"[96463:0] info: server stats for thread 0: 6552 queries, 6310 answers from cache, 242 recursions, 18 prefetch, 0 rejected by ip ratelimiting",
	}
	for _, l := range lines {
		if m := reUnboundQueryLog.FindStringSubmatch(l); m != nil {
			t.Errorf("reUnboundQueryLog unexpectedly matched %q", l)
		}
		if m := reUnboundReplyLog.FindStringSubmatch(l); m != nil {
			t.Errorf("reUnboundReplyLog unexpectedly matched %q", l)
		}
		rec, ok := parseUnbound(unboundEnv(l), nil, func(string) {})
		if ok && (rec.Attributes["dns.event"] == "query" || rec.Attributes["dns.event"] == "reply") {
			t.Errorf("parseUnbound(%q) routed to the new query/reply shape, want its existing parser", l)
		}
	}
}

// TestUnboundThroughBuildRecord: exercised end-to-end via the dispatcher, the line
// is parsed (not generic) and carries subsystem=dns.
func TestUnboundThroughBuildRecord(t *testing.T) {
	env := unboundEnv("[46775:2] info: example.com. transparent 10.0.0.141@51967 host.example.com. A IN")
	rec, parsed := buildRecord(env, unboundSnapshot(), func(string) {})
	if !parsed {
		t.Fatal("buildRecord reported the unbound query line as unparsed")
	}
	assertAttrs(t, rec, map[string]string{
		"dns.query_type":      "A",
		logship.AttrSubsystem: "dns",
		"src.ip":              "10.0.0.141",
	})
}

// The route is opt-in, and OFF must mean "falls through to a generic record", never
// "dropped": an unparsed syslog line still ships (source.go), and the ~2 lines per
// query arrive from the firewall whether or not we structure them. A future edit that
// turned the gate into a drop would silently discard data the operator is paying to
// ingest, so this pins the distinction.
func TestUnboundPerQueryRouteDisabledFallsThroughRatherThanDropping(t *testing.T) {
	prev := perQueryRouteEnabled
	perQueryRouteEnabled = func() bool { return false }
	t.Cleanup(func() { perQueryRouteEnabled = prev })

	for _, msg := range []string{
		// verbatim, capture-010.ndjson (camden, 2026-08-07)
		"[96463:9] query: 10.0.0.5 profiles-prod-023.grafana.net. AAAA IN",
		"[96463:8] reply: 127.0.0.1 tvchaosuk.com. AAAA IN NOERROR 0.012482 0 90",
	} {
		if _, ok := parseUnbound(Envelope{Program: "unbound", Message: msg}, nil, nil); ok {
			t.Errorf("route disabled but parseUnbound claimed the line for %q; it must fall "+
				"through to a generic record", msg)
		}
	}
}

// The tag discriminator must key on `query:`/`reply:` and nothing else. Without
// log-tag-queryreply on the firewall unbound tags these lines `info:`, which is the
// local-actions parser's shape — blurring the two would both break that parser and
// make the opt-in gate swallow local-zone traffic.
func TestUnboundPerQueryTagDiscriminator(t *testing.T) {
	perQuery := []string{
		"[96463:9] query: 10.0.0.5 profiles-prod-023.grafana.net. AAAA IN",
		"[96463:8] reply: 127.0.0.1 tvchaosuk.com. AAAA IN NOERROR 0.012482 0 90",
	}
	notPerQuery := []string{
		// verbatim local-actions line: `info:` tag, @port client
		"[46775:2] info: example.com. transparent 10.0.0.141@51967 _ldap._tcp.dc._msdcs.example.com. SRV IN",
		// deliberate fall-through chatter (unbound.go:118-125), must stay untouched
		"[10176:0] info: start of service (unbound 1.25.1).",
		"blocklist parsing done in 2.26 seconds (509328 records)",
	}
	for _, msg := range perQuery {
		if !isUnboundPerQueryLine(msg) {
			t.Errorf("expected a per-query line: %q", msg)
		}
	}
	for _, msg := range notPerQuery {
		if isUnboundPerQueryLine(msg) {
			t.Errorf("must NOT be treated as a per-query line: %q", msg)
		}
	}
}
