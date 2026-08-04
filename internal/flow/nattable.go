package flow

import (
	"net/netip"
	"strconv"
	"time"
)

// This file is the pf state table read for its SECOND fact: the NAT translation pf
// applied to a conversation (#623). routetable.go next door reads the same rows for
// `route-to`; this one reads `nat_addr`/`nat_port`.
//
// WHY IT EXISTS. ng_netflow captures per interface, so a NAT'd conversation crossing
// a captured LAN interface AND a captured WAN interface is exported TWICE: once
// pre-NAT on the LAN node and once post-NAT on the WAN node. They are the same bytes.
// Nothing in either record says so — the whole point of NAT is that the 5-tuples
// differ — so both were counted, and on the reference box the policy-routed WAN read
// 62.40 GB against 45.05 GB actual, +38.5%.
//
// The other WAN read +6.2%, which is ordinary overhead, and the asymmetry is NOT
// configuration: both WANs are set to egress_only. It is that the second WAN is a
// PPPoE link, and selecting a PPPoE interface for NetFlow capture is silently a no-op
// upstream — ng_netflow attaches to mpd's framing node rather than the ng_iface node,
// so the node exists in `ngctl list` and exports nothing. That WAN has no post-NAT
// copy and therefore cannot double-count. Any box with an ETHERNET WAN captured
// alongside its LAN has this, single-WAN or not.
//
// WHY PF AND NOT AN INFERENCE. The `direction="out"` row carries the pre-NAT endpoint
// in nat_addr/nat_port, so the pairing is pf's own translation stated verbatim, the
// same class of evidence repair 4 rests on. The obvious alternative — pair on the
// remote endpoint plus an identical byte count — was measured as viable but is an
// inference, and it was not needed: see the availability figure below.
//
// MEASURED ON A LIVE PRODUCTION BOX, 2026-08-01. 15 minutes, 4,257 export datagrams,
// 85,919 flow records, 14 one-minute pf snapshots, with a real 100 Mbit/s backup
// running over the policy-routed WAN:
//
//   - 425 true pairs. Also 1,009 records carrying a WAN address with NO private twin
//     at all — firewall-originated traffic, which is never translated and must never
//     be de-duplicated. Keying on "has a WAN address" instead of on pf's mapping
//     would have destroyed all 1,009.
//   - 399/399 pairs matched bytes AND packets EXACTLY. NAT does not change the size
//     of a packet, so volume is conserved and is the strongest evidence available.
//   - Only 244/399 (61%) also matched FIRST/LAST. The two copies are expired by two
//     INDEPENDENT ng_netflow nodes, so their flow timestamps differ by up to a second.
//     This is why natKey deliberately omits them where instanceKey includes them.
//   - Arrival gap between the copies: p50 20s, p90 49s, p99 60s, max 7m11s. That is
//     why the hold buffer is NOT the mechanism — vlanHoldWindow would pair 15.8% —
//     and why the de-dup table is: the existing 2-minute dedupeTTL pairs 99.7%.
//   - The pre-NAT copy arrived first in 356/399 (89.2%).
//   - The pf mapping was available AT THE POST-NAT COPY'S ARRIVAL in 420/425 (98.8%)
//     with the live 60-second poll and 3-minute retention. That is the number that
//     made the inferential fallback unnecessary, and it is much better than repair 4
//     manages (#624) for a structural reason: repair 4 needs the state when the
//     PRE-NAT copy lands, roughly 20 s earlier and often before the state has appeared
//     in any snapshot at all, while this needs it when the POST-NAT copy lands, by
//     which time the state has been through a poll.

// NATTableInput mirrors RouteTableInput exactly, including its retention semantics,
// because both tables are built from the SAME rows on the same poll and a divergence
// between their two windows would be a bug nobody could see.
type NATTableInput struct {
	Rows  []StateRow
	Built time.Time

	// Previous is the table this build supersedes, or nil on the first build.
	// Entries absent from Rows are carried forward while younger than Retain.
	Previous *NATTable

	// Retain bounds how long a carried mapping stays answerable. Zero disables
	// carrying.
	//
	// A stale mapping here is much less dangerous than a stale route-to next door.
	// The worst it can do is fail to recognise a duplicate (an over-count, which
	// shows up against the interface counter) or — only if a translation were reused
	// for a DIFFERENT conversation with a byte-and-packet-identical twin inside the
	// window — suppress one record. It never moves traffic between interfaces.
	Retain time.Duration
}

// natEntry is one answerable translation.
type natEntry struct {
	canon    routeKey
	lastSeen time.Time
}

// NATTableStats is the table's own accounting, published as self-metrics.
type NATTableStats struct {
	// Entries is how many post-NAT tuples the table can canonicalise. Each
	// translated state contributes TWO — the outbound form and its inbound reverse.
	Entries int
	// Skipped counts direction="out" rows carrying a translation the table could not
	// key: an unmodelled protocol, an unparseable address or port.
	Skipped int
	// Conflicts counts post-NAT tuples that were already mapped to a DIFFERENT
	// pre-NAT tuple within one build.
	//
	// A SMALL NON-ZERO VALUE IS NORMAL HERE, unlike RouteTable's conflict counter.
	// Measured across 14 consecutive one-minute snapshots of a live box: 6-14 per
	// build against ~7,000 entries, about 0.15%. A translation genuinely can be
	// reused inside the retention window.
	//
	// It fails SAFE. First writer wins, so a conflicted tuple canonicalises to the
	// wrong conversation — and that conversation's twin will not match on volume, so
	// the record is emitted rather than suppressed. A conflict costs a missed
	// de-duplication (an over-count, visible against the interface counter), never a
	// dropped record. What a LARGE value would mean is that the index is mostly
	// guessing and its suppressions want re-checking.
	Conflicts int
	// Carried is the subset answered from an EARLIER snapshot (the rolling union).
	Carried int
}

// NATTable answers "which conversation is this post-NAT tuple really part of".
//
// Immutable after construction and REBUILT AND SWAPPED, never mutated, so any number
// of record-path readers may use one concurrently with no locking — the same contract
// as IfMap and RouteTable.
type NATTable struct {
	byPost map[routeKey]natEntry
	// byPre is the set of PRE-NAT tuples this table knows a translation for — the
	// image of byPost, indexed for lookup.
	//
	// It exists so the record path can ask "could a record with THIS tuple ever have
	// a post-NAT twin?" before spending an entry remembering it (#636). Without it,
	// the conversation table would have to remember every record with one private
	// endpoint, which is nearly all of a box's traffic; with it, the population is
	// exactly the conversations pf says it translates.
	byPre map[routeKey]struct{}
	built time.Time
	stats NATTableStats
}

// BuildNATTable indexes every translated direction="out" state by BOTH directional
// forms of its post-NAT tuple, then unions in whatever the previous table can still
// vouch for.
//
// BOTH FORMS ARE REQUIRED. A NetFlow record is strictly unidirectional, so a
// conversation is two records on each node and the reverse half's post-NAT tuple is
// the out-row's tuple with the ends swapped. Indexing only the forward form would
// de-duplicate the upload of every conversation and leave the download doubled, which
// is a worse state than doubling both: it would look like an asymmetry in the traffic
// rather than like a bug.
func BuildNATTable(in NATTableInput) *NATTable {
	t := &NATTable{
		byPost: make(map[routeKey]natEntry, 2*len(in.Rows)),
		byPre:  make(map[routeKey]struct{}, 2*len(in.Rows)),
		built:  in.Built,
	}
	for _, row := range in.Rows {
		if row.Direction != "out" || row.NatAddr == "" || row.NatPort == "" {
			// An "in" row is the pre-NAT view and carries no translation; a row with no
			// nat_addr was never translated. Both are normal and neither is a skip.
			continue
		}
		proto, ok := protoNumbers[row.Proto]
		if !ok {
			t.stats.Skipped++
			continue
		}
		post, ok := parseTuple(proto, row.SrcAddr, row.SrcPort, row.DstAddr, row.DstPort)
		if !ok {
			t.stats.Skipped++
			continue
		}
		pre, ok := parseTuple(proto, row.NatAddr, row.NatPort, row.DstAddr, row.DstPort)
		if !ok {
			t.stats.Skipped++
			continue
		}
		if post == pre {
			// The translation did not change the endpoint (a pass-through NAT rule).
			// There is nothing to distinguish the two copies by, and equally nothing
			// to de-duplicate: one interface's copy is the other's.
			continue
		}
		t.put(post, pre, in.Built)
		t.put(reverseKey(post), reverseKey(pre), in.Built)
	}

	if in.Previous != nil && in.Retain > 0 {
		for key, prev := range in.Previous.byPost {
			if _, taken := t.byPost[key]; taken {
				continue
			}
			if in.Built.Sub(prev.lastSeen) > in.Retain {
				continue
			}
			t.byPost[key] = prev
			t.byPre[prev.canon] = struct{}{}
			t.stats.Carried++
		}
	}

	t.stats.Entries = len(t.byPost)
	return t
}

// put records one direction of one translation. First writer wins, on the same
// reasoning as BuildRouteTable: an ambiguous key is a signal, not an input.
func (t *NATTable) put(post, pre routeKey, at time.Time) {
	if existing, taken := t.byPost[post]; taken {
		if existing.canon != pre {
			t.stats.Conflicts++
		}
		return
	}
	t.byPost[post] = natEntry{canon: pre, lastSeen: at}
	t.byPre[pre] = struct{}{}
}

// IsTranslatedPre reports whether pre is the PRE-NAT side of a translation this
// table knows about — i.e. whether a record carrying this tuple could have a
// post-NAT twin at all.
//
// It is the gate on the conversation table (#636): a "yes" is what makes a record
// worth remembering as evidence that the LAN side of a translated conversation is
// being captured. A "no" is the common case and costs nothing.
//
// Nil-receiver safe, and a nil table answers no: before the first poll nothing is
// known to be translated, which makes the mechanism inert rather than wrong.
func (t *NATTable) IsTranslatedPre(pre routeKey) bool {
	if t == nil {
		return false
	}
	_, ok := t.byPre[pre]
	return ok
}

// Canonical maps a POST-NAT tuple to the pre-NAT tuple of the same conversation.
//
// It answers ONLY for tuples pf recorded as translated, which is what makes it safe:
// a pre-NAT record's own tuple is never a key here (the post form's local address is
// the firewall's own WAN address), and firewall-originated traffic — 1,009 of the
// 1,434 WAN-addressed records in the reference capture — is not translated and so is
// not answered for. A false answer here would suppress a real record.
//
// Nil-receiver safe: the window before the first poll makes the mechanism inert
// rather than failing.
func (t *NATTable) Canonical(post routeKey) (routeKey, bool) {
	if t == nil {
		return routeKey{}, false
	}
	e, ok := t.byPost[post]
	if !ok {
		return routeKey{}, false
	}
	return e.canon, true
}

// Stats reports the table's own accounting. Nil-receiver safe, and a nil table
// reports zeroes rather than being absent: "no mapping yet" is a real state an
// operator should be able to see.
func (t *NATTable) Stats() NATTableStats {
	if t == nil {
		return NATTableStats{}
	}
	return t.stats
}

// Age is how long ago the snapshot behind this table was taken.
func (t *NATTable) Age(now time.Time) time.Duration {
	if t == nil || t.built.IsZero() {
		return 0
	}
	return now.Sub(t.built)
}

// reverseKey swaps the two ends of a directional tuple.
func reverseKey(k routeKey) routeKey {
	return routeKey{proto: k.proto, src: k.dst, dst: k.src, sport: k.dport, dport: k.sport}
}

// parseTuple builds a routeKey from the API's string shapes, reporting failure rather
// than guessing — a tuple this cannot key is counted as Skipped, never silently
// dropped.
func parseTuple(proto uint8, srcAddr, srcPort, dstAddr, dstPort string) (routeKey, bool) {
	src, err := netip.ParseAddr(srcAddr)
	if err != nil {
		return routeKey{}, false
	}
	dst, err := netip.ParseAddr(dstAddr)
	if err != nil {
		return routeKey{}, false
	}
	sport, err := strconv.ParseUint(srcPort, 10, 16)
	if err != nil {
		return routeKey{}, false
	}
	dport, err := strconv.ParseUint(dstPort, 10, 16)
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
