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
