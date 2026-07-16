package zenarmor

import (
	"net"
	"net/netip"
	"strconv"
)

// Zenarmor inspects the link our own listener sits on, so it reports the _bulk
// connection that is delivering its records to us — and we then ship a record about
// the connection carrying the records. Measured on a live box: 76% of the web family
// and ~15% of all volume (#278). It converges rather than runs away (one bulk carries
// many records), but it is never information: it exists only because we are
// measuring, and logs_zenarmor_bulk_requests_total already describes that connection
// far better than a flow record can.
//
// The match is deliberately (source address, destination PORT) and never the
// destination ADDRESS. In a container the exporter binds 0.0.0.0:9200 inside its own
// netns and has no idea what address the firewall dialled — the record says
// 10.0.0.5, the host's LAN address, which the process cannot enumerate. Comparing
// destination addresses would therefore silently never fire in exactly the
// deployment everyone actually runs.
//
// The residual false positive, stated rather than hidden: if the FIREWALL ITSELF
// opens a connection to a real Elasticsearch on the same port number we listen on,
// that record is dropped too. It needs the Zenarmor host specifically as the source —
// a LAN client talking to an Elasticsearch is unaffected — so this is narrow, and
// --logs.zenarmor.drop-self-traffic=false turns the whole thing off.

// listenPortOf extracts the TCP port from a listen address. It returns 0 for anything
// it cannot read, which disables the filter rather than guessing a port and dropping
// real traffic.
//
// Prefer the bound listener's own address over the configured one where possible: a
// configured ":0" means "any free port", and only the listener knows which it got.
func listenPortOf(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}

// isSelfTraffic reports whether a record describes the very connection that delivered
// it: sent by the peer currently streaming to us, addressed to the port we listen on.
//
// peer is the remote address of the request carrying this document, not a configured
// value — so it works whether or not --logs.zenarmor.allowed-peers is set.
func isSelfTraffic(attrs map[string]string, peer netip.Addr, listenPort int) bool {
	if listenPort == 0 || !peer.IsValid() {
		return false
	}

	dstPort, err := strconv.Atoi(attrs["ip_dst_port"])
	if err != nil || dstPort != listenPort {
		return false
	}

	src, err := netip.ParseAddr(attrs["ip_src_saddr"])
	if err != nil {
		return false
	}

	// Unmap both sides. A dual-stack listener reports an IPv4 peer as the 4-in-6
	// mapped ::ffff:10.0.0.254, while Zenarmor writes the plain dotted quad — so
	// comparing them unmapped never matches and the filter quietly does nothing.
	return src.Unmap() == peer.Unmap()
}
