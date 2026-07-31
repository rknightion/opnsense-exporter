package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// IPsec and OpenVPN both name their tunnel in the log as a bare UUID and nothing
// else:
//
//	charon:   10[IKE] <5e891b0c-ca13-4e38-a7c0-a2aa891c30b4|8> sending DPD request
//	openvpn:  MANAGEMENT: Client connected from /var/etc/openvpn/instance-6f86d5cd-….sock
//
// Nobody can read that. The exporter already fetches both inventories for its
// metrics collectors, so it can turn the UUID into the name the admin actually gave
// the tunnel — at no extra API cost. Verified against a live OPNsense 26.7 box: the
// UUID charon logs is exactly the `ikeid` from ipsec/sessions/search_phase1, and the
// UUID in the socket path is exactly the `uuid` from openvpn/instances/search.
//
// This is enrichment, not parsing: these programs have no fixed message grammar
// worth structuring, so the record still ships as generic with its body verbatim —
// it just gains a name for the thing it is talking about.

var uuidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// enrichTunnels resolves any IPsec-connection or OpenVPN-instance UUID mentioned in
// the message. A UUID that resolves in neither table is left alone: it may be a
// tunnel that has since been deleted, or an unrelated identifier (configd stamps its
// RPC lines with a task UUID), and inventing an attribute for it would be worse than
// silence.
func enrichTunnels(program, msg string, snap *enrich.Snapshot, set func(k, v string)) {
	if snap == nil || msg == "" {
		return
	}
	if subsystemFor(program) != "ipsec" && subsystemFor(program) != "vpn" {
		return
	}
	for _, id := range uuidRe.FindAllString(msg, 2) {
		if name, ok := snap.Tunnel(id); ok {
			set("ipsec.connection", name)
			set("ipsec.connection_id", id)
			return
		}
		if name, ok := snap.VPNInstance(id); ok {
			set("openvpn.instance", name)
			set("openvpn.instance_id", id)
			return
		}
	}
}
