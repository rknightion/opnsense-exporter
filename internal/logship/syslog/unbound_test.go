package syslog

import (
	"net/netip"
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

// TestUnboundNonQueryLinesDegrade: DNSBL/plugin status chatter is deliberately NOT
// parsed — it returns ok=false so BuildRecord ships it as a generic record (still
// shipped, never dropped), exactly as sshd treats its non-auth chatter.
func TestUnboundNonQueryLinesDegrade(t *testing.T) {
	lines := []string{
		"[46775:9] info: dnsbl_module: updating blocklist.",
		"[46775:9] info: dnsbl_module: blocklist loaded. length is 414523",
		"blocklist parsing done in 1.41 seconds (414523 records)",
		`Q-Feeds : skip invalid whitelist exclude pattern "*.notion.com"`,
		"[46775:0] notice: init module 0: iterator",
		"start of service (unbound 1.19.3).",
		"",
	}
	for _, l := range lines {
		if _, ok := parseUnbound(unboundEnv(l), nil, func(string) {}); ok {
			t.Errorf("parseUnbound(%q) returned ok=true, want a generic-record fallthrough", l)
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
