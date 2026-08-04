package syslog

import "testing"

// TestDnsmasqDHCPProgramRegistered: the DHCP-server program name dnsmasq-dhcp
// dispatches to parseDHCP, and its DHCPREQUEST/DHCPACK lines parse as lease events.
func TestDnsmasqDHCPProgramRegistered(t *testing.T) {
	if _, ok := parserFor("dnsmasq-dhcp"); !ok {
		t.Fatal("no parser registered for program dnsmasq-dhcp")
	}
	rec, ok := parseDHCP(dhcpEnvelope("dnsmasq-dhcp", "DHCPREQUEST(ixl0_vlan50) 10.0.50.112 a8:9c:6c:24:b8:00"), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for a dnsmasq-dhcp DHCPREQUEST")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.action": "request",
		"interface":   "ixl0_vlan50",
		"dhcp.ip":     "10.0.50.112",
		"dhcp.mac":    "a8:9c:6c:24:b8:00",
	})
}

// TestKeaDHCP6PacketReceived: a DHCPv6 handshake packet is structured by DUID +
// transaction id + message type, with no address (Kea has not assigned one yet).
func TestKeaDHCP6PacketReceived(t *testing.T) {
	msg := "INFO  [kea-dhcp6.packets.0x41006dab1010] DHCP6_PACKET_RECEIVED duid=[00:01:00:01:31:e6:58:29:bc:24:11:c1:d5:12], [no hwaddr info], tid=0xe7ba05: RENEW"
	rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp6", msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for DHCP6_PACKET_RECEIVED")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.kea_event":    "packet_received",
		"dhcp.message_type": "RENEW",
		"dhcp.duid":         "00:01:00:01:31:e6:58:29:bc:24:11:c1:d5:12",
		"dhcp.tid":          "0xe7ba05",
	})
	assertNoAttrs(t, rec, "dhcp.ip", "dhcp.mac", "dhcp.action")
}

// TestKeaDHCP6CommandReceived: control-plane commands (the exporter's own lease
// polling) are labelled rather than left unparsed.
func TestKeaDHCP6CommandReceived(t *testing.T) {
	msg := "INFO  [kea-dhcp6.commands.0x41006da69010] COMMAND_RECEIVED Received command 'lease6-get-page'"
	rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp6", msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for COMMAND_RECEIVED")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.kea_event":   "command_received",
		"dhcp.kea_command": "lease6-get-page",
	})
}

// TestKeaDHCP6OtherPacketEvents: QUERY_LABEL and PACKET_SEND are packet-lifecycle
// events too — structured by DUID + tid + event kind, with no message type.
func TestKeaDHCP6OtherPacketEvents(t *testing.T) {
	cases := []struct {
		msg   string
		event string
		tid   string
	}{
		{"INFO  [kea-dhcp6.dhcp6.0x41006dab1010] DHCP6_QUERY_LABEL received query: duid=[00:01:00:01], tid=0xe7b", "query_label", "0xe7b"},
		{"INFO  [kea-dhcp6.packets.0x41006dab1010] DHCP6_PACKET_SEND duid=[00:01:00:01], tid=0xe7ba05: trying to send packet", "packet_send", "0xe7ba05"},
	}
	for _, tc := range cases {
		rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp6", tc.msg), nil, func(string) {})
		if !ok {
			t.Fatalf("parseDHCP ok=false for %q", tc.msg)
		}
		wantDHCPAttrs(t, rec, map[string]string{
			"dhcp.kea_event": tc.event,
			"dhcp.duid":      "00:01:00:01",
			"dhcp.tid":       tc.tid,
		})
		assertNoAttrs(t, rec, "dhcp.message_type")
	}
}

// TestKeaDHCP6LeaseAdvert: DHCP6_LEASE_ADVERT (#641) is a Kea DHCPv6 lease event
// like ALLOC/OFFER/REUSE/RENEW/EXPIRE, just an id the keaActions map did not yet
// carry — the highest-volume of the #641 gaps (41-125/day on the live box).
//
// Captured verbatim, address sanitized to the RFC 3849 documentation range
// (real prefix was a live delegated /64, replaced with 2001:db8:1f05::/64 —
// same shape, no real prefix):
//
//	INFO  [kea-dhcp6.leases.0x3fa9c347e810] DHCP6_LEASE_ADVERT duid=[00:03:00:01:b6:cf:62:d8:d6:84], [no hwaddr info], tid=0xb9c201: lease for address 2001:db8:1f05::10ad and iaid=0 will be advertised
func TestKeaDHCP6LeaseAdvert(t *testing.T) {
	msg := "INFO  [kea-dhcp6.leases.0x3fa9c347e810] DHCP6_LEASE_ADVERT duid=[00:03:00:01:b6:cf:62:d8:d6:84], [no hwaddr info], tid=0xb9c201: lease for address 2001:db8:1f05::10ad and iaid=0 will be advertised"
	rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp6", msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for DHCP6_LEASE_ADVERT")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.action": "advertise",
		"dhcp.ip":     "2001:db8:1f05::10ad",
	})
	assertNoAttrs(t, rec, "dhcp.mac", "dhcp.lease_seconds")
}

// TestKeaDHCP6ReleaseNAPair: DHCP6_RELEASE_NA / DHCP6_RELEASE_NA_EXPIRED (#641)
// fire as a PAIR for one real release, same tid, back to back — structurally
// like the ALLOC_ENGINE_V6_ALLOC_FAIL* burst (#546, see keaAllocFailV6RE). Both
// lines are shipped as structured records, but only DHCP6_RELEASE_NA sets
// dhcp.action, exactly the alloc_fail dedup pattern: a downstream counter gated
// on dhcp.action counts the release once, not twice. The corrected name is
// DHCP6_RELEASE_NA_EXPIRED — the tracking issue's "DHCP6_RELEASE_NA_EXP" does
// not match what the box actually emits.
//
// Captured verbatim, address sanitized to the RFC 3849 documentation range
// (real address was a live delegated address, replaced with 2001:db8:1f05::102a
// — same shape):
//
//	INFO  [kea-dhcp6.leases.0x3fa9c347e010] DHCP6_RELEASE_NA duid=[00:02:00:00:ab:11:dc:50:a3:d6:9c:1d:a7:32], [no hwaddr info], tid=0x3cfc48: binding for address 2001:db8:1f05::102a and iaid=3394439514 was released properly
//	INFO  [kea-dhcp6.leases.0x3fa9c347e010] DHCP6_RELEASE_NA_EXPIRED duid=[00:02:00:00:ab:11:dc:50:a3:d6:9c:1d:a7:32], [no hwaddr info], tid=0x3cfc48: binding for address 2001:db8:1f05::102a and iaid=3394439514 expired on release
func TestKeaDHCP6ReleaseNAPair(t *testing.T) {
	const duid = "00:02:00:00:ab:11:dc:50:a3:d6:9c:1d:a7:32"
	const addr = "2001:db8:1f05::102a"
	const tid = "0x3cfc48"

	released := "INFO  [kea-dhcp6.leases.0x3fa9c347e010] DHCP6_RELEASE_NA duid=[" + duid + "], [no hwaddr info], tid=" + tid + ": binding for address " + addr + " and iaid=3394439514 was released properly"
	expired := "INFO  [kea-dhcp6.leases.0x3fa9c347e010] DHCP6_RELEASE_NA_EXPIRED duid=[" + duid + "], [no hwaddr info], tid=" + tid + ": binding for address " + addr + " and iaid=3394439514 expired on release"

	t.Run("RELEASE_NA is the counted line", func(t *testing.T) {
		rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp6", released), nil, func(string) {})
		if !ok {
			t.Fatal("parseDHCP returned ok=false for DHCP6_RELEASE_NA")
		}
		wantDHCPAttrs(t, rec, map[string]string{
			"dhcp.action": "release",
			"dhcp.ip":     addr,
			"dhcp.duid":   duid,
			"dhcp.tid":    tid,
		})
	})

	t.Run("RELEASE_NA_EXPIRED ships but must not set dhcp.action", func(t *testing.T) {
		rec, ok := parseDHCP(dhcpEnvelope("kea-dhcp6", expired), nil, func(string) {})
		if !ok {
			t.Fatal("parseDHCP returned ok=false for DHCP6_RELEASE_NA_EXPIRED")
		}
		wantDHCPAttrs(t, rec, map[string]string{
			"dhcp.kea_event": "release_expired",
			"dhcp.ip":        addr,
			"dhcp.duid":      duid,
			"dhcp.tid":       tid,
		})
		// The whole point of the pairing dedup: the EXPIRED line must never carry
		// dhcp.action, or a downstream counter gated on it double-counts one release.
		assertNoAttrs(t, rec, "dhcp.action")
	})
}

// TestDnsmasqDHCPDeclineAndInform: DHCPDECLINE and DHCPINFORM (#641) already match
// dnsmasqLineRE and fell through only because the iscActions allowlist did not
// name them — verified against the parser, not assumed from the issue text.
// Adding the two map entries is the whole fix.
//
// Captured verbatim (trailing whitespace on the DHCPDECLINE line as captured is
// trimmed by parseDHCP's strings.TrimSpace before matching):
//
//	DHCPDECLINE(ixl0) 10.0.0.4 bc:d0:74:17:e7:cd
//	DHCPINFORM(ixl0_vlan50) 10.0.50.152 bc:24:11:bc:a1:2e
func TestDnsmasqDHCPDeclineAndInform(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "decline",
			msg:  "DHCPDECLINE(ixl0) 10.0.0.4 bc:d0:74:17:e7:cd",
			want: map[string]string{
				"dhcp.action": "decline",
				"dhcp.ip":     "10.0.0.4",
				"dhcp.mac":    "bc:d0:74:17:e7:cd",
				"interface":   "ixl0",
			},
		},
		{
			name: "inform",
			msg:  "DHCPINFORM(ixl0_vlan50) 10.0.50.152 bc:24:11:bc:a1:2e",
			want: map[string]string{
				"dhcp.action": "inform",
				"dhcp.ip":     "10.0.50.152",
				"dhcp.mac":    "bc:24:11:bc:a1:2e",
				"interface":   "ixl0_vlan50",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseDHCP(dhcpEnvelope("dnsmasq-dhcp", tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseDHCP(%q) returned ok=false", tc.msg)
			}
			wantDHCPAttrs(t, rec, tc.want)
		})
	}
}

// TestDnsmasqAbandoningLease: dnsmasq's standalone "abandoning lease to <mac> of
// <ip>" line (#641) — NOT the parenthesized DHCP<VERB>(iface) shape, a distinct
// sentence. Signals an address conflict, same as DHCPDECLINE; captured 2 seconds
// apart with the same MAC/IP/pid in the live box's log, though this parser does
// not attempt to correlate the pair itself.
//
// Captured verbatim:
//
//	abandoning lease to bc:d0:74:17:e7:cd of 10.0.0.4
func TestDnsmasqAbandoningLease(t *testing.T) {
	msg := "abandoning lease to bc:d0:74:17:e7:cd of 10.0.0.4"
	rec, ok := parseDHCP(dhcpEnvelope("dnsmasq-dhcp", msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP returned ok=false for an abandoning-lease line")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.action": "abandoned",
		"dhcp.mac":    "bc:d0:74:17:e7:cd",
		"dhcp.ip":     "10.0.0.4",
	})
}

// TestDnsmasqNameConflict: the recurring "not giving name … to the DHCP lease of …"
// warning is structured as a name_conflict event with the rejected name + address.
func TestDnsmasqNameConflict(t *testing.T) {
	msg := "not giving name garden.cam.rob-knight.net to the DHCP lease of 10.0.25.154 because the name exists in /var/etc/dnsmasq-hosts with address 10.0.0.31"
	rec, ok := parseDHCP(dhcpEnvelope("dnsmasq-dhcp", msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseDHCP ok=false for a dnsmasq name-conflict line")
	}
	wantDHCPAttrs(t, rec, map[string]string{
		"dhcp.action":   "name_conflict",
		"dhcp.hostname": "garden.cam.rob-knight.net",
		"dhcp.ip":       "10.0.25.154",
	})
}
