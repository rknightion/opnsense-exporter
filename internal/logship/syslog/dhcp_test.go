package syslog

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// dhcpSnapshot is the enrichment fixture for the DHCP lane: the two VLAN devices
// the real captures came off, plus a lease for the address ISC/dnsmasq hand out.
func dhcpSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		IfaceNames: map[string]string{
			"vlan01": "IOT",
			"vlan02": "GUEST",
		},
		Hostnames: map[string]string{
			"172.16.30.100": "exporter-traffgen",
			"172.16.9.100":  "kea-client",
		},
		MACs: map[string]string{
			"172.16.30.100": "bc:24:11:eb:db:3d",
		},
		LocalNets: []netip.Prefix{
			netip.MustParsePrefix("172.16.0.0/16"),
		},
		SelfIPs: map[netip.Addr]bool{
			netip.MustParseAddr("172.16.30.1"): true,
		},
	}
}

func dhcpEnvelope(program, msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   program,
		PID:       "4242",
		Facility:  3,
		Severity:  6,
		Message:   msg,
	}
}

func wantDHCPAttrs(t *testing.T, rec logship.Record, want map[string]string) {
	t.Helper()
	for k, v := range want {
		got, ok := rec.Attributes[k]
		if !ok {
			t.Errorf("attribute %q missing (want %q)", k, v)
			continue
		}
		if got != v {
			t.Errorf("attribute %q = %q, want %q", k, got, v)
		}
	}
}

func wantNoDHCPAttrs(t *testing.T, rec logship.Record, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if got, ok := rec.Attributes[k]; ok {
			t.Errorf("attribute %q present (%q), want absent", k, got)
		}
	}
}

// TestParseDHCP_ISC covers the four VERBATIM lines captured from ISC dhcpd on a
// live OPNsense 26.7 box, including the hostname-absent DHCPDISCOVER and the
// server-identifier parenthetical unique to DHCPREQUEST.
func TestParseDHCP_ISC(t *testing.T) {
	snap := dhcpSnapshot()

	tests := []struct {
		name string
		msg  string
		want map[string]string
		none []string
	}{
		{
			name: "discover (no ip, no hostname)",
			msg:  "DHCPDISCOVER from bc:24:11:eb:db:3d via vlan02",
			want: map[string]string{
				"dhcp.action":    "discover",
				"dhcp.mac":       "bc:24:11:eb:db:3d",
				"interface":      "vlan02",
				"interface.name": "GUEST",
			},
			none: []string{"dhcp.ip", "dhcp.hostname", "dhcp.lease_seconds"},
		},
		{
			name: "offer",
			msg:  "DHCPOFFER on 172.16.30.100 to bc:24:11:eb:db:3d (exporter-traffgen) via vlan02",
			want: map[string]string{
				"dhcp.action":    "offer",
				"dhcp.ip":        "172.16.30.100",
				"dhcp.mac":       "bc:24:11:eb:db:3d",
				"dhcp.hostname":  "exporter-traffgen",
				"dhcp.scope":     "local",
				"interface":      "vlan02",
				"interface.name": "GUEST",
			},
		},
		{
			name: "request (server identifier in parens)",
			msg:  "DHCPREQUEST for 172.16.30.100 (172.16.30.1) from bc:24:11:eb:db:3d (exporter-traffgen) via vlan02",
			want: map[string]string{
				"dhcp.action":    "request",
				"dhcp.ip":        "172.16.30.100",
				"dhcp.server_ip": "172.16.30.1",
				"dhcp.mac":       "bc:24:11:eb:db:3d",
				"dhcp.hostname":  "exporter-traffgen",
				"interface":      "vlan02",
				"interface.name": "GUEST",
			},
		},
		{
			name: "ack",
			msg:  "DHCPACK on 172.16.30.100 to bc:24:11:eb:db:3d (exporter-traffgen) via vlan02",
			want: map[string]string{
				"dhcp.action":   "ack",
				"dhcp.ip":       "172.16.30.100",
				"dhcp.mac":      "bc:24:11:eb:db:3d",
				"dhcp.hostname": "exporter-traffgen",
				"interface":     "vlan02",
			},
		},
		{
			name: "ack without hostname",
			msg:  "DHCPACK on 172.16.30.100 to bc:24:11:eb:db:3d via vlan02",
			want: map[string]string{
				"dhcp.action": "ack",
				"dhcp.ip":     "172.16.30.100",
				"dhcp.mac":    "bc:24:11:eb:db:3d",
				// hostname is not in the line: the snapshot supplies it.
				"dhcp.hostname": "exporter-traffgen",
			},
		},
		{
			name: "nak",
			msg:  "DHCPNAK on 172.16.30.100 to bc:24:11:eb:db:3d via vlan02",
			want: map[string]string{
				"dhcp.action": "nak",
				"dhcp.ip":     "172.16.30.100",
				"dhcp.mac":    "bc:24:11:eb:db:3d",
			},
		},
		{
			name: "release",
			msg:  "DHCPRELEASE of 172.16.30.100 from bc:24:11:eb:db:3d (exporter-traffgen) via vlan02 (found)",
			want: map[string]string{
				"dhcp.action":   "release",
				"dhcp.ip":       "172.16.30.100",
				"dhcp.mac":      "bc:24:11:eb:db:3d",
				"dhcp.hostname": "exporter-traffgen",
				"interface":     "vlan02",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			env := dhcpEnvelope("dhcpd", tc.msg)
			rec, ok := parseDHCP(env, snap, m.miss)
			if !ok {
				t.Fatalf("parseDHCP(%q) ok=false, want true", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
			}
			if !rec.Timestamp.Equal(env.Timestamp) {
				t.Errorf("Timestamp = %v, want %v", rec.Timestamp, env.Timestamp)
			}
			wantDHCPAttrs(t, rec, tc.want)
			wantNoDHCPAttrs(t, rec, tc.none...)
			if len(m.calls) != 0 {
				t.Errorf("miss() called %v, want no calls (address lookups never signal a miss)", m.calls)
			}
		})
	}
}

// TestParseDHCP_Dnsmasq covers the four VERBATIM dnsmasq lines: the interface is
// parenthesised onto the action word and the hostname is an optional trailing
// token.
func TestParseDHCP_Dnsmasq(t *testing.T) {
	snap := dhcpSnapshot()

	tests := []struct {
		name string
		msg  string
		want map[string]string
		none []string
	}{
		{
			name: "discover",
			msg:  "DHCPDISCOVER(vlan01) bc:24:11:3c:79:6b",
			want: map[string]string{
				"dhcp.action":    "discover",
				"dhcp.mac":       "bc:24:11:3c:79:6b",
				"interface":      "vlan01",
				"interface.name": "IOT",
			},
			none: []string{"dhcp.ip", "dhcp.hostname"},
		},
		{
			name: "offer",
			msg:  "DHCPOFFER(vlan01) 172.16.20.117 bc:24:11:3c:79:6b",
			want: map[string]string{
				"dhcp.action":    "offer",
				"dhcp.ip":        "172.16.20.117",
				"dhcp.mac":       "bc:24:11:3c:79:6b",
				"dhcp.scope":     "local",
				"interface":      "vlan01",
				"interface.name": "IOT",
			},
			none: []string{"dhcp.hostname"},
		},
		{
			name: "request",
			msg:  "DHCPREQUEST(vlan01) 172.16.20.117 bc:24:11:3c:79:6b",
			want: map[string]string{
				"dhcp.action": "request",
				"dhcp.ip":     "172.16.20.117",
				"dhcp.mac":    "bc:24:11:3c:79:6b",
				"interface":   "vlan01",
			},
			none: []string{"dhcp.hostname"},
		},
		{
			name: "ack with trailing hostname",
			msg:  "DHCPACK(vlan01) 172.16.20.117 bc:24:11:3c:79:6b exporter-traffgen",
			want: map[string]string{
				"dhcp.action":    "ack",
				"dhcp.ip":        "172.16.20.117",
				"dhcp.mac":       "bc:24:11:3c:79:6b",
				"dhcp.hostname":  "exporter-traffgen",
				"interface":      "vlan01",
				"interface.name": "IOT",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			rec, ok := parseDHCP(dhcpEnvelope("dnsmasq", tc.msg), snap, m.miss)
			if !ok {
				t.Fatalf("parseDHCP(%q) ok=false, want true", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
			}
			wantDHCPAttrs(t, rec, tc.want)
			wantNoDHCPAttrs(t, rec, tc.none...)
			if len(m.calls) != 0 {
				t.Errorf("miss() called %v, want no calls", m.calls)
			}
		})
	}
}

// TestParseDHCP_Kea covers the VERBATIM Kea lines, including the lease duration
// in both its "4000 s" and "3869 seconds" spellings.
func TestParseDHCP_Kea(t *testing.T) {
	snap := dhcpSnapshot()

	tests := []struct {
		name string
		msg  string
		want map[string]string
		none []string
	}{
		{
			name: "lease alloc",
			msg:  "DHCP4_LEASE_ALLOC [hwtype=1 bc:24:11:a5:a6:34], cid=[no info], tid=0x8a1b2c3d: lease 172.16.9.100 has been allocated for 4000 s",
			want: map[string]string{
				"dhcp.action":        "alloc",
				"dhcp.ip":            "172.16.9.100",
				"dhcp.mac":           "bc:24:11:a5:a6:34",
				"dhcp.lease_seconds": "4000",
				"dhcp.hostname":      "kea-client",
				"dhcp.scope":         "local",
			},
			none: []string{"interface"},
		},
		{
			name: "lease offer (no duration)",
			msg:  "DHCP4_LEASE_OFFER [hwtype=1 bc:24:11:a5:a6:34], cid=[no info], tid=0x8a1b2c3d: lease 172.16.9.100 will be offered",
			want: map[string]string{
				"dhcp.action": "offer",
				"dhcp.ip":     "172.16.9.100",
				"dhcp.mac":    "bc:24:11:a5:a6:34",
			},
			none: []string{"dhcp.lease_seconds"},
		},
		{
			name: "lease reuse (seconds spelled out)",
			msg:  "DHCP4_LEASE_REUSE [hwtype=1 bc:24:11:a5:a6:34], cid=[no info], tid=0x8a1b2c3d: lease 172.16.9.100 has been reused for 3869 seconds",
			want: map[string]string{
				"dhcp.action":        "reuse",
				"dhcp.ip":            "172.16.9.100",
				"dhcp.mac":           "bc:24:11:a5:a6:34",
				"dhcp.lease_seconds": "3869",
			},
		},
		{
			name: "level word and logger prefix are stripped",
			msg:  "INFO  [kea-dhcp4.leases.0x4f1907869010] DHCP4_LEASE_ALLOC [hwtype=1 bc:24:11:a5:a6:34], cid=[no info], tid=0x8a1b2c3d: lease 172.16.9.100 has been allocated for 4000 s",
			want: map[string]string{
				"dhcp.action":        "alloc",
				"dhcp.ip":            "172.16.9.100",
				"dhcp.mac":           "bc:24:11:a5:a6:34",
				"dhcp.lease_seconds": "4000",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp4", tc.msg), snap, m.miss)
			if !ok {
				t.Fatalf("parseDHCP(%q) ok=false, want true", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the raw message verbatim", rec.Body)
			}
			wantDHCPAttrs(t, rec, tc.want)
			wantNoDHCPAttrs(t, rec, tc.none...)
			if len(m.calls) != 0 {
				t.Errorf("miss() called %v, want no calls", m.calls)
			}
		})
	}
}

// TestParseDHCP_NotALeaseEvent: control-plane chatter and garbage degrade to a
// generic record (ok=false) rather than being force-fitted into the lease shape.
func TestParseDHCP_NotALeaseEvent(t *testing.T) {
	snap := dhcpSnapshot()

	lines := []struct {
		name    string
		program string
		msg     string
	}{
		{
			name:    "kea COMMAND_RECEIVED is control plane",
			program: "kea-dhcp6",
			msg:     "INFO  [kea-dhcp6.commands.0x4f1907869010] COMMAND_RECEIVED Received command 'lease6-get-page'",
		},
		{
			name:    "kea message id we do not model",
			program: "kea-dhcp4",
			msg:     "DHCP4_STARTED Kea DHCPv4 server version 2.6.1 started",
		},
		{
			name:    "dnsmasq dns query line",
			program: "dnsmasq",
			msg:     "query[A] example.com from 172.16.20.117",
		},
		{
			name:    "dhcpd chatter",
			program: "dhcpd",
			msg:     "Wrote 3 leases to leases file.",
		},
		{
			name:    "unknown DHCP verb",
			program: "dhcpd",
			msg:     "DHCPLEASEQUERY from bc:24:11:eb:db:3d via vlan02",
		},
		{
			name:    "dhcrelay forward line",
			program: "dhcrelay",
			msg:     "forwarded BOOTREQUEST for bc:24:11:eb:db:3d to 172.16.9.1",
		},
		{
			name:    "action word but nothing to key on",
			program: "dhcpd",
			msg:     "DHCPACK",
		},
		{
			name:    "empty message",
			program: "dhcpd",
			msg:     "",
		},
		{
			name:    "garbage",
			program: "dhcpd",
			msg:     "\x00\x01 ))((( not a log line at all",
		},
	}

	for _, tc := range lines {
		t.Run(tc.name, func(t *testing.T) {
			var m missRecorder
			if _, ok := parseDHCP(dhcpEnvelope(tc.program, tc.msg), snap, m.miss); ok {
				t.Fatalf("parseDHCP(%q) ok=true, want false (should ship as a generic record)", tc.msg)
			}
			if len(m.calls) != 0 {
				t.Errorf("miss() called %v, want no calls", m.calls)
			}
		})
	}
}

// TestParseDHCP_NilSnapshot: a cold or absent snapshot yields an unenriched but
// complete record — never a panic.
func TestParseDHCP_NilSnapshot(t *testing.T) {
	msg := "DHCPACK on 172.16.30.100 to bc:24:11:eb:db:3d (exporter-traffgen) via vlan02"
	rec, ok := parseDHCP(dhcpEnvelope("dhcpd", msg), nil, nil)
	if !ok {
		t.Fatalf("parseDHCP ok=false, want true")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.action":   "ack",
		"dhcp.ip":       "172.16.30.100",
		"dhcp.mac":      "bc:24:11:eb:db:3d",
		"dhcp.hostname": "exporter-traffgen",
		"interface":     "vlan02",
	})
	wantNoDHCPAttrs(t, rec, "interface.name", "dhcp.scope")
}

// TestParseDHCP_Registered: every DHCP backend program dispatches to this lane,
// and BuildRecord tags the record with the coarse dhcp subsystem.
func TestParseDHCP_Registered(t *testing.T) {
	for _, prog := range []string{"dhcpd", "dnsmasq", "kea-dhcp4", "kea-dhcp6", "dhcrelay"} {
		if _, ok := parserFor(prog); !ok {
			t.Errorf("no parser registered for program %q", prog)
		}
	}

	env := dhcpEnvelope("dhcpd", "DHCPACK on 172.16.30.100 to bc:24:11:eb:db:3d (exporter-traffgen) via vlan02")
	rec := BuildRecord(env, dhcpSnapshot(), nil)
	wantDHCPAttrs(t, rec, map[string]string{
		"opnsense.subsystem": "dhcp",
		"dhcp.action":        "ack",
		"program":            "dhcpd",
	})

	// An unparsed line from a DHCP program still ships, verbatim, as a generic record.
	generic := BuildRecord(dhcpEnvelope("dhcpd", "Wrote 3 leases to leases file."), dhcpSnapshot(), nil)
	if generic.Body != "Wrote 3 leases to leases file." {
		t.Errorf("Body = %q, want the raw message", generic.Body)
	}
	wantNoDHCPAttrs(t, generic, "dhcp.action")
	wantDHCPAttrs(t, generic, map[string]string{"opnsense.subsystem": "dhcp"})
}
