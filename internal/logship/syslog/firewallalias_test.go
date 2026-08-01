package syslog

import (
	"testing"
	"time"
)

func firewallAliasEnv(t *testing.T, message string) Envelope {
	t.Helper()

	// The APP-NAME `firewall` here is OPNsense's alias/table maintenance logger
	// (filter_alias / update_alias code), NOT packet filtering — that is
	// `filterlog` (see filterlog.go). Envelope shape follows the house pattern
	// used by dpinger_test.go / miniupnpd_test.go.
	env, err := ParseEnvelope([]byte("<134>1 2026-07-26T16:14:24Z test-firewall firewall 6789 - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestFirewallAliasRegistered(t *testing.T) {
	if _, ok := parserFor("firewall"); !ok {
		t.Fatal("no parser registered for program firewall")
	}
}

// TestFirewallAliasCapturedLines pins all 13 verbatim lines observed on the
// real box for issue #631.
func TestFirewallAliasCapturedLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "resolving acme_dns",
			msg:  "resolving 4 hostnames (24 addresses) for acme_dns took 0.01 seconds",
			want: map[string]string{
				"alias.event":            "resolved",
				"alias.name":             "acme_dns",
				"alias.hostnames":        "4",
				"alias.addresses":        "24",
				"alias.duration_seconds": "0.01",
			},
		},
		{
			name: "resolving overaaisp",
			msg:  "resolving 24 hostnames (60 addresses) for overaaisp took 0.03 seconds",
			want: map[string]string{
				"alias.event":            "resolved",
				"alias.name":             "overaaisp",
				"alias.hostnames":        "24",
				"alias.addresses":        "60",
				"alias.duration_seconds": "0.03",
			},
		},
		{
			name: "resolving meraki_IPs_Core_web",
			msg:  "resolving 5 hostnames (8 addresses) for meraki_IPs_Core_web took 0.08 seconds",
			want: map[string]string{
				"alias.event":            "resolved",
				"alias.name":             "meraki_IPs_Core_web",
				"alias.hostnames":        "5",
				"alias.addresses":        "8",
				"alias.duration_seconds": "0.08",
			},
		},
		{
			name: "fetch alias url bytes - grafana",
			msg:  "fetch alias url https://allowlists.grafana.com/synthetics (bytes: 12921)",
			want: map[string]string{
				"alias.event": "fetched",
				"alias.url":   "https://allowlists.grafana.com/synthetics",
				"alias.bytes": "12921",
			},
		},
		{
			name: "fetch alias url bytes - aws ip ranges",
			msg:  "fetch alias url https://ip-ranges.amazonaws.com/ip-ranges.json (bytes: 2529294)",
			want: map[string]string{
				"alias.event": "fetched",
				"alias.url":   "https://ip-ranges.amazonaws.com/ip-ranges.json",
				"alias.bytes": "2529294",
			},
		},
		{
			name: "fetch alias url lines - dibdot doh",
			msg:  "fetch alias url https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt (lines: 1283)",
			want: map[string]string{
				"alias.event": "fetched",
				"alias.url":   "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt",
				"alias.lines": "1283",
			},
		},
		{
			name: "fetch alias url lines - uptimerobot",
			msg:  "fetch alias url https://uptimerobot.com/inc/files/ips/IPv4.txt (lines: 103)",
			want: map[string]string{
				"alias.event": "fetched",
				"alias.url":   "https://uptimerobot.com/inc/files/ips/IPv4.txt",
				"alias.lines": "103",
			},
		},
		{
			name: "processing alias url - grafana",
			msg:  "processing alias url https://allowlists.grafana.com/synthetics took 0.00s",
			want: map[string]string{
				"alias.event":            "processed",
				"alias.url":              "https://allowlists.grafana.com/synthetics",
				"alias.duration_seconds": "0.00",
			},
		},
		{
			name: "processing alias url - aws, pins 0.14s (no space, trailing s) vs the resolving form's ' seconds'",
			msg:  "processing alias url https://ip-ranges.amazonaws.com/ip-ranges.json took 0.14s",
			want: map[string]string{
				"alias.event":            "processed",
				"alias.url":              "https://ip-ranges.amazonaws.com/ip-ranges.json",
				"alias.duration_seconds": "0.14",
			},
		},
		{
			name: "processing alias url - dibdot doh",
			msg:  "processing alias url https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt took 0.02s",
			want: map[string]string{
				"alias.event":            "processed",
				"alias.url":              "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv6.txt",
				"alias.duration_seconds": "0.02",
			},
		},
		{
			name: "processing alias url - uptimerobot",
			msg:  "processing alias url https://uptimerobot.com/inc/files/ips/IPv4.txt took 0.00s",
			want: map[string]string{
				"alias.event":            "processed",
				"alias.url":              "https://uptimerobot.com/inc/files/ips/IPv4.txt",
				"alias.duration_seconds": "0.00",
			},
		},
		{
			name: "found zip format",
			msg:  "found .zip format, process",
			want: map[string]string{
				"alias.event": "archive_detected",
			},
		},
		{
			name: "geoip updated",
			msg:  "geoip updated (files: 502 lines: 1111384)",
			want: map[string]string{
				"alias.event": "geoip_updated",
				"geoip.files": "502",
				"geoip.lines": "1111384",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseFirewallAlias(firewallAliasEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseFirewallAlias(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestFirewallAliasResolvedNeverCarriesFetchOrProcessedKeys guards against the
// resolved/fetched/processed attribute sets bleeding into each other.
func TestFirewallAliasResolvedNeverCarriesFetchOrProcessedKeys(t *testing.T) {
	msg := "resolving 4 hostnames (24 addresses) for acme_dns took 0.01 seconds"
	rec, ok := parseFirewallAlias(firewallAliasEnv(t, msg), nil, func(string) {})
	if !ok {
		t.Fatalf("parseFirewallAlias(%q) returned ok=false", msg)
	}
	assertNoAttrs(t, rec, "alias.url", "alias.bytes", "alias.lines", "geoip.files", "geoip.lines")
}

// TestFirewallAliasFetchedEmitsOnlyPresentCount guards against a fetched
// record ever carrying both alias.bytes and alias.lines: the grammar reports
// exactly one of the two per line.
func TestFirewallAliasFetchedEmitsOnlyPresentCount(t *testing.T) {
	bytesMsg := "fetch alias url https://allowlists.grafana.com/synthetics (bytes: 12921)"
	rec, ok := parseFirewallAlias(firewallAliasEnv(t, bytesMsg), nil, func(string) {})
	if !ok {
		t.Fatalf("parseFirewallAlias(%q) returned ok=false", bytesMsg)
	}
	assertNoAttrs(t, rec, "alias.lines")

	linesMsg := "fetch alias url https://uptimerobot.com/inc/files/ips/IPv4.txt (lines: 103)"
	rec, ok = parseFirewallAlias(firewallAliasEnv(t, linesMsg), nil, func(string) {})
	if !ok {
		t.Fatalf("parseFirewallAlias(%q) returned ok=false", linesMsg)
	}
	assertNoAttrs(t, rec, "alias.bytes")
}

// TestFirewallAliasUnmatchedLineDegradesToGeneric ensures a firewall-program
// line that doesn't match any of the five known alias-maintenance grammars
// falls through to a generic record rather than being force-fit.
func TestFirewallAliasUnmatchedLineDegradesToGeneric(t *testing.T) {
	msg := "some entirely unrelated firewall program line we have never captured"
	env := firewallAliasEnv(t, msg)
	rec, parsed := buildRecord(env, nil, func(string) {})
	if parsed {
		t.Fatalf("buildRecord(%q) parsed an unsupported firewall-alias shape", msg)
	}
	if rec.Body != msg {
		t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
	}
	assertAttrs(t, rec, map[string]string{"program": "firewall"})
	assertNoAttrs(t, rec, "alias.event", "alias.name", "alias.url")
}
