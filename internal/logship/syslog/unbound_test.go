package syslog

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
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
