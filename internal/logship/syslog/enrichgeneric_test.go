package syslog

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// enrichSnap is a snapshot that knows about one LAN host and the firewall itself.
func enrichSnap() *enrich.Snapshot {
	return &enrich.Snapshot{
		Hostnames:  map[string]string{"10.0.0.6": "robs-laptop"},
		MACs:       map[string]string{"10.0.0.6": "7c:10:c9:5e:84:86"},
		IfaceNames: map[string]string{"vtnet0": "LAN", "vtnet2": "TESTLAN"},
		LocalNets:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		SelfIPs:    map[netip.Addr]bool{netip.MustParseAddr("10.0.0.114"): true},
	}
}

// The whole point of #250: the SAME address that is fully enriched in a filterlog
// line was, before this, an opaque string in an sshd line.
func TestEnrichMessage_ResolvesAddressInAnyProgram(t *testing.T) {
	// A program with NO registered parser: this is the generic path, which is what
	// peer.* enrichment is for. (sshd/filterlog/dhcp have their own parsers and own
	// their addresses positionally as src.*/dst.*.)
	env := Envelope{
		Program:  "upsmon",
		Message:  "Poll UPS [10.0.0.6] failed - Protocol error",
		Severity: 3,
	}
	rec := BuildRecord(env, enrichSnap(), nil)
	a := rec.Attributes
	for k, want := range map[string]string{
		"peer.ip":            "10.0.0.6",
		"peer.hostname":      "robs-laptop",
		"peer.mac":           "7c:10:c9:5e:84:86",
		"peer.scope":         "local",
		"opnsense.subsystem": "ups",
	} {
		if a[k] != want {
			t.Errorf("attr %q = %q, want %q", k, a[k], want)
		}
	}
	// The body must survive verbatim -- enrichment adds context, it never rewrites.
	if !strings.Contains(rec.Body, "Poll UPS") {
		t.Errorf("body was mangled: %q", rec.Body)
	}
}

// Real charon line: two addresses on one line, neither positionally meaningful.
func TestEnrichMessage_MultipleAddresses(t *testing.T) {
	snap := enrichSnap()
	snap.Hostnames["10.0.0.114"] = "" // the firewall itself: resolvable by scope only
	env := Envelope{
		Program: "charon",
		Message: "sending packet: from 10.0.0.114[4500] to 10.0.0.6[4500] (80 bytes)",
	}
	rec := BuildRecord(env, snap, nil)
	a := rec.Attributes
	if a["peer.ip"] != "10.0.0.114" || a["peer.scope"] != "self" {
		t.Errorf("first address: ip=%q scope=%q, want 10.0.0.114/self", a["peer.ip"], a["peer.scope"])
	}
	if a["peer.2.ip"] != "10.0.0.6" || a["peer.2.hostname"] != "robs-laptop" {
		t.Errorf("second address: ip=%q host=%q", a["peer.2.ip"], a["peer.2.hostname"])
	}
	if a["opnsense.subsystem"] != "ipsec" {
		t.Errorf("subsystem = %q, want ipsec", a["opnsense.subsystem"])
	}
}

// A MAC address is colon-separated hex and would match a naive IPv6 regex. It must
// not be mistaken for an address.
func TestEnrichMessage_MACIsNotAnIP(t *testing.T) {
	// monit has no parser: the generic path. (dhcpd has its own parser now, #256.)
	env := Envelope{Program: "monit", Message: "host 10.0.0.6 at bc:24:11:eb:db:3d on vtnet0 failed"}
	rec := BuildRecord(env, enrichSnap(), nil)
	if got := rec.Attributes["peer.ip"]; got != "10.0.0.6" {
		t.Errorf("peer.ip = %q, want the real IP 10.0.0.6 (a MAC must never be read as an address)", got)
	}
	if got := rec.Attributes["peer.2.ip"]; got != "" {
		t.Errorf("a MAC was enriched as an address: peer.2.ip = %q", got)
	}
}

// Interface devices resolve in any program, not just filterlog.
func TestEnrichMessage_InterfaceInAnyProgram(t *testing.T) {
	env := Envelope{Program: "configd.py", Message: "New IPv6 on vtnet0"}
	rec := BuildRecord(env, enrichSnap(), nil)
	if rec.Attributes["interface.name"] != "LAN" {
		t.Errorf("interface.name = %q, want LAN", rec.Attributes["interface.name"])
	}
}

// An address we know nothing about (every WAN address) must not be echoed back as a
// peer attribute -- that would just duplicate the body for nothing.
func TestEnrichMessage_UnresolvableAddressIsNotEchoed(t *testing.T) {
	snap := &enrich.Snapshot{} // cold: no nets, no hosts -> Scope() returns ""
	env := Envelope{Program: "monit", Message: "Ping response for 8.8.8.8 timed out"}
	rec := BuildRecord(env, snap, nil)
	if got := rec.Attributes["peer.ip"]; got != "" {
		t.Errorf("an unresolvable address was echoed as peer.ip = %q", got)
	}
}

// A pathological line must not be able to inflate one record without bound.
func TestEnrichMessage_CapsEnrichedAddresses(t *testing.T) {
	snap := enrichSnap()
	var b strings.Builder
	for i := 1; i <= 20; i++ {
		b.WriteString("10.0.0.6 ")
		b.WriteString("10.0.0.")
		b.WriteString(string(rune('0' + i%10)))
		b.WriteString(" ")
	}
	rec := BuildRecord(Envelope{Program: "zebra", Message: b.String()}, snap, nil)
	if _, over := rec.Attributes["peer.4.ip"]; over {
		t.Error("more than maxEnrichedIPs addresses were enriched")
	}
}

// Enrichment must never drop a record, even with no snapshot at all.
func TestEnrichMessage_NilSnapshotStillShips(t *testing.T) {
	env := Envelope{Program: "upsmon", Message: "Poll UPS [testups@127.0.0.1:3493] failed"}
	rec := BuildRecord(env, nil, nil)
	if rec.Body != env.Message {
		t.Errorf("body = %q, want the message verbatim", rec.Body)
	}
	if rec.Attributes["opnsense.subsystem"] != "ups" {
		t.Errorf("subsystem = %q, want ups", rec.Attributes["opnsense.subsystem"])
	}
}

func TestSubsystemFor(t *testing.T) {
	for prog, want := range map[string]string{
		"filterlog":       "firewall",
		"sshd-session":    "auth",
		"audit":           "audit",
		"kea-dhcp6":       "dhcp",
		"charon":          "ipsec",
		"haproxy":         "proxy",
		"upsmon":          "ups",
		"openvpn_server1": "vpn", // per-instance program name: prefix match, not exact
		"openvpn_client2": "vpn",
		"kea-whatever":    "dhcp", // future kea component: prefix match
		"totally-unknown": "",     // no subsystem is fine; the record still ships
	} {
		if got := subsystemFor(prog); got != want {
			t.Errorf("subsystemFor(%q) = %q, want %q", prog, got, want)
		}
	}
}
