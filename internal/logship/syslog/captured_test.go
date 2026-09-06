package syslog

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/capture"
)

// Sanitized examples from the complete Camden corpus (OPN-0104). These exercise
// dispatch and extracted meaning, rather than just matching a private string.
func TestCapturedOperationalEvents(t *testing.T) {
	cases := []struct {
		program, message string
		attrs            map[string]string
	}{
		{"/usr/sbin/cron", "(nobody) PARSE (bad minute)", map[string]string{"syslog.event": "cron_parse_failed", "cron.user": "nobody", "cron.error": "bad minute"}},
		{"configd.py", "Timeout (120) executing : zfs snapshot list", map[string]string{"syslog.event": "config_command_timeout", "config.timeout_seconds": "120", "config.command": "zfs snapshot list"}},
		{"configctl", "unable to connect to configd socket (@/var/run/configd.socket)", map[string]string{"syslog.event": "config_socket_failed"}},
		{"php", "error connecting to Google Drive", map[string]string{"syslog.event": "backup_connection_failed", "backup.provider": "Google Drive"}},
		{"dnsmasq", "query[A] example.com from 192.0.2.1", map[string]string{"syslog.event": "dns_query", "dns.query_name": "example.com", "dns.query_type": "A", "src.ip": "192.0.2.1"}},
		{"dnsmasq", "config example.com is NODATA", map[string]string{"syslog.event": "dns_config_answer", "dns.query_name": "example.com", "dns.answer": "NODATA"}},
		{"dnsmasq-dhcp", "Error sending DHCP packet to 192.0.2.1: Host is down", map[string]string{"syslog.event": "dhcp_send_failed", "dst.ip": "192.0.2.1", "error.message": "Host is down"}},
		{"dhclient", "ip length 328 disagrees with bytes received 332.", map[string]string{"syslog.event": "dhcp_packet_length_mismatch", "network.ip_length": "328", "network.received_bytes": "332"}},
		{"dhcp6c", "failed to remove an address on ixl0: Can't assign requested address", map[string]string{"syslog.event": "dhcp6_address_remove_failed", "interface": "ixl0"}},
		{"dhcp6c", "remove a site prefix 2001:db8:1::/48", map[string]string{"syslog.event": "dhcp6_prefix_removed", "dhcp6c.prefix": "2001:db8:1::/48"}},
		{"lldpd", "unable to send packet on real device for ixl0: No buffer space available", map[string]string{"syslog.event": "lldp_send_failed", "interface": "ixl0"}},
		{"firewall", "geoip update failed : Daily GeoIP database download limit reached [http_code: 429]", map[string]string{"syslog.event": "geoip_update_failed", "http.response.status_code": "429"}},
		{"kernel", "<6>[123] ixl0: link state changed to DOWN", map[string]string{"syslog.event": "interface_link_changed", "interface": "ixl0", "interface.link_state": "DOWN"}},
		{"kernel", "<6>[123] 12.345 [ 1] netmap_extra_free breaking with head abcd", map[string]string{"syslog.event": "netmap_free_diagnostic", "netmap.head": "abcd"}},
		{"devd", "Processing event '!system=IFNET subsystem=ixl0 type=LINK_DOWN'", map[string]string{"syslog.event": "interface_notification", "interface": "ixl0", "interface.notification": "LINK_DOWN"}},
		{"ntpd", "kernel reports TIME_ERROR: 0x41: Clock Unsynchronized", map[string]string{"syslog.event": "clock_unsynchronized", "ntp.status": "0x41"}},
		{"pkg-static", "example-package upgraded: 1.2.3 -> 1.2.4", map[string]string{"syslog.event": "package_upgraded", "package.name": "example-package", "package.version.previous": "1.2.3", "package.version": "1.2.4"}},
		{"audit", "[Firmware] User root executed a firmware update", map[string]string{"syslog.event": "firmware_update_executed", "audit.user": "root"}},
		{"shutdown", "reboot by root:", map[string]string{"syslog.event": "reboot_requested", "audit.user": "root"}},
		{"ppp", "[opt1_link0] LCP: Down event", map[string]string{"syslog.event": "ppp_protocol_event", "ppp.protocol": "LCP", "ppp.transition": "Down", "ppp.link": "opt1_link0"}},
		{"sshd-session", "Read error from remote host 192.0.2.1 port 45000: Operation timed out", map[string]string{"syslog.event": "ssh_transport_failed", "src.ip": "192.0.2.1", "src.port": "45000"}},
		{"syslog-ng", "Syslog connection failed; fd='27', server='AF_INET(192.0.2.1:5847)', error='Connection refused (61)', time_reopen='60'", map[string]string{"syslog.event": "syslog_connection_failed", "dst.ip": "192.0.2.1", "dst.port": "5847", "syslogng.time_reopen_seconds": "60"}},
	}
	for _, tc := range cases {
		t.Run(tc.program+"/"+tc.attrs["syslog.event"], func(t *testing.T) {
			rec, parsed := buildRecord(Envelope{Program: tc.program, Message: tc.message}, nil, nil)
			if !parsed {
				t.Fatalf("captured grammar was not parsed: %s", tc.message)
			}
			assertAttrs(t, rec, tc.attrs)
			if rec.Body != tc.message {
				t.Fatalf("body changed: %q", rec.Body)
			}
			sink := &fakeSink{}
			if observeDerived(sink, tc.program, rec.Attributes) {
				t.Fatal("log-only event unexpectedly derived a metric")
			}
		})
	}
}

func TestCapturedKnownPassThroughStillShipsAndNewFailuresCapture(t *testing.T) {
	dir := t.TempDir()
	cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newCaptureSource(t, cap)
	var records []logship.Record
	s.emit = func(r logship.Record) { records = append(records, r) }
	unknowns := 0
	s.unparsed = func(string) { unknowns++ }
	cases := []struct{ program, message, status string }{
		{"dhclient", "dhclient-script: Creating resolv.conf", "known"},
		{"dhclient", "dhclient-script: New Hostname (ixl0): firewall", "known"},
		{"syslog-ng", "Configuration reload finished;", "known"},
		{"configd.py", "generate template container OPNsense/Syslog", "known"},
		{"dhclient", "dhclient-script: Creating resolv.conf failed: permission denied", "unknown"},
		{"syslog-ng", "Configuration reload failed;", "unknown"},
		{"mystery-plugin", "Configuration reload finished;", "unknown"},
	}
	for _, tc := range cases {
		s.handle(syslogTestLine(tc.program, tc.message), netip.MustParseAddr("192.0.2.1"))
	}
	if err := cap.Close(); err != nil {
		t.Fatal(err)
	}
	if len(records) != len(cases) {
		t.Fatalf("shipped %d records, want %d", len(records), len(cases))
	}
	for i, tc := range cases {
		if records[i].Body != tc.message {
			t.Errorf("body changed for %s", tc.program)
		}
		assertAttrs(t, records[i], map[string]string{"syslog.parse_status": tc.status})
	}
	captured := readSyslogCaptures(t, dir)
	if len(captured) != 3 {
		t.Fatalf("captured %d records, want exactly three unknown shapes", len(captured))
	}
	if unknowns != 2 {
		t.Fatalf("coverage misses=%d, want two registered-program failures", unknowns)
	}
}

func TestCapturedBoundariesLeaveNewShapesUnknown(t *testing.T) {
	for _, tc := range []struct{ program, message string }{
		{"kernel", "[1] ixl0: Using 4 RX queues 4 TX queues failed"},
		{"kernel", "[1] panic: kernel boot failure"},
		{"kernel", "[1] ixl0: <Intel device> firmware failure"},
		{"devd", "Processing event '!system=IFNET subsystem=ixl0 type=NEW_FAILURE'"},
		{"configd.py", "generate template container OPNsense/Syslog failed"},
		{"opnsense", "/usr/local/etc/rc.newwanip: plugins_configure dns () failed"},
		{"unbound", "[12:0] query: new unknown grammar"},
		{"dnsmasq", "query[A] example.com from not-an-address"},
		{"dhcp6c", "remove a site prefix 2001:db8::/129"},
		{"sshd-session", "Read error from remote host 192.0.2.1 port 99999: Operation timed out"},
	} {
		t.Run(tc.program+"/"+tc.message, func(t *testing.T) {
			rec, parsed := buildRecord(Envelope{Program: tc.program, Message: tc.message}, nil, nil)
			if parsed || rec.Attributes["syslog.parse_status"] != "unknown" {
				t.Fatal("new or malformed grammar incorrectly classified")
			}
		})
	}
}

func TestCapturedUnboundOptInRemainsEffective(t *testing.T) {
	old := perQueryRouteEnabled
	t.Cleanup(func() { perQueryRouteEnabled = old })
	env := Envelope{Program: "unbound", Message: "[12:0] query: 192.0.2.1 example.com. A IN"}
	perQueryRouteEnabled = func() bool { return false }
	rec, parsed := buildRecord(env, nil, nil)
	if parsed {
		t.Fatal("disabled query route unexpectedly parsed")
	}
	assertAttrs(t, rec, map[string]string{"syslog.parse_status": "known", "syslog.parse_reason": "unbound_per_query_disabled"})
	perQueryRouteEnabled = func() bool { return true }
	rec, parsed = buildRecord(env, nil, nil)
	if !parsed {
		t.Fatal("enabled query route did not parse")
	}
	assertAttrs(t, rec, map[string]string{"dns.query_name": "example.com.", "dns.event": "query", "syslog.parse_status": "parsed"})
	if _, exists := rec.Attributes["syslog.parse_reason"]; exists {
		t.Fatal("parsed query still marked disabled")
	}
}
