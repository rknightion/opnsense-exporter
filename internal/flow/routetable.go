package flow

import (
	"net/netip"
	"strconv"
	"time"
)

// This file is the pf state table, reduced to the one question the repair stage
// asks of it: which interface did pf actually send this 5-tuple out of (#603).
//
// WHY PF AND NOT AN INFERENCE. ng_netflow's OUTPUT_SNMP is a FIB lookup, and
// OPNsense's multi-WAN policy routing happens in pf, which ng_netflow never sees.
// The obvious repair — join a pre-NAT record to its post-NAT copy on the shared
// destination — was costed against the live table and rejected: it is inferential,
// it has an ambiguity class (two LAN hosts to one destination over different WANs)
// that it would have to refuse, and it is blind to exactly the short flows the
// state table is blind to anyway. pf's own `route-to` is the routing decision
// itself, not evidence about it.
//
// WHY THE JOIN IS EXACT. pf keeps BOTH states for a NAT'd conversation, and the
// direction="in" state is the PRE-NAT view — the same 5-tuple the pre-NAT NetFlow
// record carries — and it already carries the route-to. Measured against the live
// production table on 2026-07-31: 3,232 direction="in" rows, ZERO duplicate 5-tuple
// keys, ZERO keys mapping to more than one egress device. So the lookup is a full
// exact match with no ambiguity class at all.
//
// WHAT IT CANNOT DO. A short flow may have no live state left by the time its
// NetFlow record arrives (the reference box runs inactiveTimeout=15, so a record
// can land 15-30s after the conversation ended). That is a genuine miss window, it
// is NOT something a shorter poll interval fixes, and the repair refuses and counts
// rather than guessing. The flows this bug actually hurts are long ones — state ages
// in the live table run to 36 hours — so the miss window and the damage do not
// overlap.

// StateRow is one pf state as the API reports it, in the API's own string shapes.
//
// Strings rather than parsed types because that is what
// api/diagnostics/firewall/query_states serves and because parsing is this file's
// job: a row it cannot key is counted, not dropped silently, and that count belongs
// with the table rather than with the fetch.
type StateRow struct {
	// Proto is pf's protocol name ("tcp", "udp", "icmp"), not a number.
	Proto string
	// Direction is "in" or "out". ONLY "in" rows are keyed: that is the pre-NAT
	// view, and the post-NAT row's tuple matches no pre-NAT NetFlow record. On the
	// live box the two halves' route-to can legitimately disagree, so keying both
	// would not merely be redundant, it would be wrong.
	Direction string

	SrcAddr string
	SrcPort string
	DstAddr string
	DstPort string

	// RouteToDevice is the device half of pf's "<gateway>@<device>", empty when the
	// state carries no route-to. Empty is a REAL ANSWER — it means the FIB decided,
	// which is precisely when OUTPUT_SNMP is already correct.
	RouteToDevice string
}

// RouteTableInput is everything BuildRouteTable needs, in the shape of the frozen
// IfMapInput seam next door: a plain struct so the caller does the API-to-flow
// translation and this package imports no API client.
type RouteTableInput struct {
	Rows  []StateRow
	Built time.Time
}

// routeKey is the pre-NAT directional 5-tuple, exactly as pf keys its own states.
// netip.Addr is comparable, so this is an allocation-free map key.
type routeKey struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
}

// RouteTableStats is the table's own accounting, published as self-metrics: a
// lookup structure nobody can size or age is one nobody will trust when it starts
// answering "no".
type RouteTableStats struct {
	// Entries is how many pre-NAT tuples the table can answer for.
	Entries int
	// PolicyRouted is the subset carrying a route-to, i.e. the states that can
	// actually change a record's egress. Zero on a single-WAN box is expected; zero
	// on a policy-routed box means the mechanism has nothing to work with.
	PolicyRouted int
	// Skipped counts rows the table could not key at all — an unmodelled protocol,
	// an unparseable address or port. They are counted rather than ignored because a
	// row that silently vanishes here reads downstream as a genuine miss.
	Skipped int
	// Conflicts counts direction="in" rows whose key was already taken. Measured
	// zero on the live table; a non-zero value means the key stopped being unique
	// upstream and every answer from it wants re-checking.
	Conflicts int
}

// RouteTable answers "which device did pf route this pre-NAT tuple out of".
//
// It is immutable after construction and REBUILT AND SWAPPED, never mutated, so any
// number of record-path readers may use one concurrently with no locking — the same
// contract as IfMap.
type RouteTable struct {
	byTuple map[routeKey]string
	built   time.Time
	stats   RouteTableStats
}

// protoNumbers maps pf's protocol names to their IANA numbers, which is what a
// NetFlow record carries.
//
// It is deliberately a short closed list rather than a full IANA table: an
// unmodelled protocol yields a SKIP, and a skipped state is only ever a missed
// correction, never a wrong one. Everything a policy-route rule can realistically
// carry over a WAN is here.
var protoNumbers = map[string]uint8{
	"icmp":      1,
	"igmp":      2,
	"ipencap":   4,
	"tcp":       6,
	"udp":       17,
	"gre":       47,
	"esp":       50,
	"ah":        51,
	"ipv6-icmp": 58,
	"icmpv6":    58,
	"ospf":      89,
	"sctp":      132,
}

// BuildRouteTable indexes the direction="in" states by their pre-NAT 5-tuple.
func BuildRouteTable(in RouteTableInput) *RouteTable {
	t := &RouteTable{
		byTuple: make(map[routeKey]string, len(in.Rows)),
		built:   in.Built,
	}
	for _, row := range in.Rows {
		if row.Direction != "in" {
			continue
		}
		key, ok := keyOfState(row)
		if !ok {
			t.stats.Skipped++
			continue
		}
		if _, taken := t.byTuple[key]; taken {
			// First row wins. A later duplicate must never move traffic: the whole
			// point of this mechanism over the destination-match design is that its
			// key cannot be ambiguous, so an ambiguous one is a signal, not an input.
			t.stats.Conflicts++
			continue
		}
		t.byTuple[key] = row.RouteToDevice
		if row.RouteToDevice != "" {
			t.stats.PolicyRouted++
		}
	}
	t.stats.Entries = len(t.byTuple)
	return t
}

func keyOfState(row StateRow) (routeKey, bool) {
	proto, ok := protoNumbers[row.Proto]
	if !ok {
		return routeKey{}, false
	}
	src, err := netip.ParseAddr(row.SrcAddr)
	if err != nil {
		return routeKey{}, false
	}
	dst, err := netip.ParseAddr(row.DstAddr)
	if err != nil {
		return routeKey{}, false
	}
	sport, err := strconv.ParseUint(row.SrcPort, 10, 16)
	if err != nil {
		return routeKey{}, false
	}
	dport, err := strconv.ParseUint(row.DstPort, 10, 16)
	if err != nil {
		return routeKey{}, false
	}
	return routeKey{
		proto: proto,
		src:   src.Unmap(),
		dst:   dst.Unmap(),
		sport: uint16(sport),
		dport: uint16(dport),
	}, true
}

// Egress reports the device pf routed this pre-NAT tuple out of.
//
// The two negatives are DIFFERENT and callers must keep them apart:
//
//   - ok == false: no state exists for this tuple. Either the flow ended and its
//     state expired (the miss window), or the record is not a pre-NAT egress copy
//     at all. Nothing may be concluded — refuse, do not guess.
//   - ok == true, device == "": a state exists and pf applied NO route-to, so the
//     FIB decided and OUTPUT_SNMP is already right. Nothing to do.
//
// Safe on a nil receiver: the table is late-bound and a record arriving before the
// first poll must not panic and must not be corrected.
func (t *RouteTable) Egress(proto uint8, src netip.Addr, sport uint16, dst netip.Addr, dport uint16) (string, bool) {
	if t == nil {
		return "", false
	}
	device, ok := t.byTuple[routeKey{
		proto: proto,
		src:   src.Unmap(),
		dst:   dst.Unmap(),
		sport: sport,
		dport: dport,
	}]
	return device, ok
}

// Stats reports the table's accounting. Nil-safe.
func (t *RouteTable) Stats() RouteTableStats {
	if t == nil {
		return RouteTableStats{}
	}
	return t.stats
}

// Age is how long ago the table was built. Nil-safe, and zero for a table built
// with no timestamp — the metric it backs treats absence as "no table", which is
// what the caller not publishing one means.
func (t *RouteTable) Age(now time.Time) time.Duration {
	if t == nil || t.built.IsZero() {
		return 0
	}
	if d := now.Sub(t.built); d > 0 {
		return d
	}
	return 0
}
