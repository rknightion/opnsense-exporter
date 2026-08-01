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
// WHAT IT CANNOT DO, AND THE HALF OF THAT WE FIXED (#620). The miss window is
// BIDIRECTIONAL, and #603 accounted for only one side of it:
//
//   - EXPIRED-BEFORE-THE-RECORD. The state was alive at a poll, then died before its
//     NetFlow record arrived (the reference box runs inactiveTimeout=15, so a record
//     can land 15-30s after the conversation ended). A rolling union closes this:
//     see BuildRouteTable's Previous/Retain, which keeps a tuple answerable for a
//     bounded time after it stops appearing in snapshots.
//   - CREATED-AFTER-THE-LAST-POLL. The state was born, used and closed entirely
//     between two snapshots, so it appears in NO snapshot and is refused, correctly,
//     every time. NOTHING closes this except a poll interval shorter than the state
//     lifetime, and no interval reaches the shortest states.
//
// #603 claimed the flows the bug hurts are long — "state ages run to 36 hours". That
// was WRONG, and it is the reason this file used to say a shorter poll buys nothing.
// Measured on the production box 2026-07-31, the policy-routed population is 19
// states of which EIGHTEEN are short: sub-90-second TCP connections, a new one about
// every ten seconds. Exactly one is long. So the second half of the window above is
// where the damage is, the poll interval does matter, and it was cut from five
// minutes to one (main.go's pfStateRefreshInterval). Short states still get refused
// and counted rather than guessed at; that is a floor, not a bug.

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

	// Previous is the table this build supersedes, or nil on the first build.
	// Entries it holds that are ABSENT from Rows are carried forward while they
	// are younger than Retain — the rolling union that closes the
	// expired-before-the-record half of the miss window (#620).
	//
	// Fresh rows always win. A tuple present in Rows takes its answer from Rows,
	// never from Previous, so a re-routed flow is corrected on the very next poll
	// rather than being pinned by its own history.
	Previous *RouteTable

	// Retain bounds how long a carried entry stays answerable after it was last
	// SEEN in a snapshot. Zero disables carrying entirely, which is exactly the
	// pre-#620 behaviour and what the tests that predate it assert.
	//
	// It is a bound on being WRONG, not just on memory. A carried entry is a claim
	// about a state that no longer exists, and the way it goes bad is a WAN
	// failover: pf re-routes, the old tuple stops appearing, and until it ages out
	// the table keeps naming the dead egress. Keeping Retain to a few poll
	// intervals is what makes that window short enough not to matter; a large
	// value would trade a real miss for a silent mislabel, which is the worse of
	// the two.
	Retain time.Duration
}

// routeEntry is one answerable tuple. LastSeen is when the tuple was last present
// in an actual snapshot — NOT when the table was built — so age-out measures the
// state's own absence rather than how many times we have rebuilt since.
type routeEntry struct {
	device   string
	lastSeen time.Time
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
	// Carried is the subset of Entries answered from a PREVIOUS snapshot rather
	// than from this one — states that have since expired but are still inside the
	// retention window (#620). It is the size of the rolling union's contribution,
	// and the number to watch: persistently zero means the union is doing nothing,
	// while a value that dwarfs the fresh count means states are expiring far
	// faster than we poll and the retention is carrying a mostly-dead picture.
	Carried int
}

// RouteTable answers "which device did pf route this pre-NAT tuple out of".
//
// It is immutable after construction and REBUILT AND SWAPPED, never mutated, so any
// number of record-path readers may use one concurrently with no locking — the same
// contract as IfMap.
type RouteTable struct {
	byTuple map[routeKey]routeEntry
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

// BuildRouteTable indexes the direction="in" states by their pre-NAT 5-tuple, then
// unions in whatever the previous table can still vouch for (#620).
func BuildRouteTable(in RouteTableInput) *RouteTable {
	t := &RouteTable{
		byTuple: make(map[routeKey]routeEntry, len(in.Rows)),
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
		t.byTuple[key] = routeEntry{device: row.RouteToDevice, lastSeen: in.Built}
		if row.RouteToDevice != "" {
			t.stats.PolicyRouted++
		}
	}

	// Carry forward states that have since expired but are still within the
	// retention window. Deliberately AFTER the fresh pass and guarded on the key
	// being untaken, so a fresh row always wins and a carried entry can only ever
	// answer where this snapshot has nothing to say.
	//
	// Conflicts is NOT incremented here: a tuple appearing in both the previous
	// and the current snapshot is the normal life of a long-lived state, not the
	// upstream-uniqueness failure that counter exists to surface.
	if in.Previous != nil && in.Retain > 0 {
		for key, prev := range in.Previous.byTuple {
			if _, taken := t.byTuple[key]; taken {
				continue
			}
			if in.Built.Sub(prev.lastSeen) > in.Retain {
				continue
			}
			t.byTuple[key] = prev
			t.stats.Carried++
			if prev.device != "" {
				t.stats.PolicyRouted++
			}
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
//   - ok == false: no state is answerable for this tuple. Either it was never in a
//     snapshot at all (born and died between two polls), or it expired and has now
//     aged past Retain, or the record is not a pre-NAT egress copy. Nothing may be
//     concluded — refuse, do not guess.
//   - ok == true, device == "": a state was seen and pf applied NO route-to, so the
//     FIB decided and OUTPUT_SNMP is already right. Nothing to do.
//
// A hit may come from the current snapshot or be CARRIED from a recent one (#620),
// and the caller deliberately cannot tell the two apart. Both are pf's own recorded
// decision for this exact 5-tuple; the only difference is that a carried answer
// describes a state that has since expired, and the retention window is what bounds
// how wrong that can be. Splitting the return value would push a judgement call onto
// every call site for a distinction none of them could act on — the aggregate is
// visible instead as pf_state_entries{kind="carried"}.
//
// Safe on a nil receiver: the table is late-bound and a record arriving before the
// first poll must not panic and must not be corrected.
func (t *RouteTable) Egress(proto uint8, src netip.Addr, sport uint16, dst netip.Addr, dport uint16) (string, bool) {
	if t == nil {
		return "", false
	}
	entry, ok := t.byTuple[routeKey{
		proto: proto,
		src:   src.Unmap(),
		dst:   dst.Unmap(),
		sport: sport,
		dport: dport,
	}]
	return entry.device, ok
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
