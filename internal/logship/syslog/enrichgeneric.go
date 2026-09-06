package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// Universal enrichment for records that have no positional structure.
//
// The filterlog parser knows which address is the source and which is the
// destination, so it emits src.*/dst.*. Every other program just mentions
// addresses somewhere in a sentence -- "Accepted publickey for root from 10.0.0.6",
// "sending packet: from 172.16.9.1[4500] to 172.16.9.99[4500]". We cannot know
// which is which, so those are emitted as peer.* : one or more addresses the line
// referred to, each resolved through the same snapshot filterlog uses.
//
// This matters more than it looks. On a real box, 71% of non-filterlog lines carry
// an address we can already resolve -- the same 10.0.0.6 that gets a hostname, a
// scope and a MAC in a firewall log line was, until this existed, an opaque string
// in an SSH login line.

const (
	// maxEnrichedIPs bounds how many addresses a single line can contribute. A
	// pathological message (a routing table dump, a traceroute) must not be able to
	// inflate one record's attribute set without limit.
	maxEnrichedIPs = 3
	// maxEnrichedDevices likewise bounds interface-name resolution per line.
	maxEnrichedDevices = 2
)

var (
	// ipRe matches IPv4 and IPv6 literals. It is deliberately conservative: it must
	// not fire on version strings ("26.1.11"), timestamps, or hex ids. IPv4 requires
	// four dotted octets; IPv6 requires at least two colons, which excludes MAC
	// addresses (five colons but hyphen/colon-separated pairs are two hex digits --
	// see macLikeRe, which we use to reject them).
	ipRe = regexp.MustCompile(`\b(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4})\b`)

	// macLikeRe rejects MAC addresses, which the IPv6 branch of ipRe would otherwise
	// happily match (bc:24:11:a5:a6:34 is syntactically colon-separated hex).
	macLikeRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)

	// deviceRe matches the raw interface device names OPNsense uses. Anchored to the
	// known driver prefixes so it cannot fire on arbitrary words.
	deviceRe = regexp.MustCompile(`\b(?:vtnet|igb|em|ix|ixl|re|bge|lagg|vlan|pppoe|ovpn[cs]|wg|bridge|enc|gif|gre|tun|tap)\d+\b`)
)

// enrichMessage resolves the addresses and interface devices mentioned anywhere in
// a record's message and writes them into attrs.
//
// It NEVER reports a miss: an address that is not in our tables is the normal case
// (every WAN address is), and treating it as a stale-cache signal would turn every
// internet-facing log line into a spurious refresh trigger. That is the opposite of
// the firewall rule id, whose absence really does mean the snapshot is behind.
//
// A nil or cold snapshot is fine: nothing resolves, and the record ships with only
// the addresses it already had in its body.
func enrichMessage(msg string, snap *enrich.Snapshot, set func(k, v string)) {
	if snap == nil || msg == "" {
		return
	}

	seen := make(map[string]bool, maxEnrichedIPs)
	n := 0
	for _, ip := range ipRe.FindAllString(msg, -1) {
		if n >= maxEnrichedIPs {
			break
		}
		if seen[ip] || macLikeRe.MatchString(ip) {
			continue
		}
		// Only surface an address we could actually say something about. Echoing an
		// unresolvable address back as a peer.N.ip attribute would just duplicate the
		// body and inflate the record for nothing.
		host, hasHost := snap.Hostname(ip)
		mac, hasMAC := snap.MAC(ip)
		scope := snap.Scope(ip)
		if !hasHost && !hasMAC && scope == "" {
			continue
		}
		seen[ip] = true

		p := peerKey(n)
		set(p+".ip", ip)
		if hasHost {
			set(p+".hostname", host)
		}
		if hasMAC {
			set(p+".mac", mac)
		}
		set(p+".scope", scope)
		n++
	}

	d := 0
	devSeen := make(map[string]bool, maxEnrichedDevices)
	for _, dev := range deviceRe.FindAllString(msg, -1) {
		if d >= maxEnrichedDevices || devSeen[dev] {
			continue
		}
		name, ok := snap.InterfaceName(dev)
		if !ok {
			continue
		}
		devSeen[dev] = true
		if d == 0 {
			set("interface", dev)
			set("interface.name", name)
		} else {
			set("interface.2", dev)
			set("interface.2.name", name)
		}
		d++
	}
}

// peerKey names the nth resolved address. The first is the common case and gets the
// unsuffixed key, so a query for peer.hostname does not have to know how many
// addresses happened to be on the line.
func peerKey(n int) string {
	switch n {
	case 0:
		return "peer"
	case 1:
		return "peer.2"
	default:
		return "peer.3"
	}
}
