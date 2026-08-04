package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// Repair 5 (#623): a NAT'd conversation is exported twice, and only the post-NAT
// copy may ever be suppressed.
//
// The topology these run against is the reference shape: a LAN interface and an
// ETHERNET WAN, both captured. A PPPoE WAN exports nothing at all, which is why the
// reference box's other WAN cannot double-count and is not modelled here.

const (
	natWANAddr = "198.51.100.6"
	natLANAddr = "10.0.0.6"
	natRemote  = "203.0.113.9"
)

func natTopology() *IfMap {
	return BuildIfMap(IfMapInput{
		Order: []string{"ixl0", "igb0"},
		Ifaces: []enrich.IfaceInfo{
			{Device: "ixl0", Name: "LAN", Identifier: "lan", Addrs: addrs("10.0.0.1")},
			{Device: "igb0", Name: "WAN2", Identifier: "opt5", IsWAN: true, Addrs: addrs(natWANAddr)},
		},
		Built: time.Unix(1700000000, 0),
	})
}

// natTable is the index built from one translated pf state.
func natTable(t *testing.T) *NATTable {
	t.Helper()
	return BuildNATTable(NATTableInput{
		Rows: []StateRow{{
			Proto: "tcp", Direction: "out",
			SrcAddr: natWANAddr, SrcPort: "42031",
			DstAddr: natRemote, DstPort: "8007",
			NatAddr: natLANAddr, NatPort: "36180",
		}},
		Built: time.Unix(1700000000, 0),
	})
}

// natRecord builds one unidirectional export. The two copies deliberately carry
// DIFFERENT timestamps: measured on a live box, 39% of real pairs disagree on
// first/last because the two ng_netflow nodes expire them independently. A key that
// included the timestamps would miss those pairs, so these tests would catch a
// regression that put them back.
func natRecord(src string, sport uint16, dst string, dport uint16, bytes uint64, at time.Time) *Record {
	return &Record{
		Proto:   6,
		SrcAddr: netip.MustParseAddr(src),
		DstAddr: netip.MustParseAddr(dst),
		SrcPort: sport,
		DstPort: dport,
		NF:      Counters{TxBytes: bytes, TxPackets: 15, Present: true},
		Start:   at,
		End:     at.Add(time.Second),
		In:      Iface{Device: "ixl0", Name: "LAN"},
		Out:     Iface{Device: "igb0", Name: "WAN2"},
	}
}

func newNATRepairer(t *testing.T) *Repairer {
	t.Helper()
	r := NewRepairer(0, 1000)
	r.SetNATTable(natTable(t))
	return r
}

func TestNATPairPostNATCopyIsSuppressedAfterThePreNATCopy(t *testing.T) {
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	pre := natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0)
	if v := r.Repair(pre, m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT copy verdict = %v, want RepairEmit", v)
	}

	// The post-NAT copy lands a median of 20 seconds later on a real box, with its
	// own timestamps, and carries the SAME bytes and packets because NAT does not
	// change a packet's size.
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 3048, t0.Add(2*time.Second))
	if v := r.Repair(post, m, nil, t0.Add(20*time.Second)); v != RepairDrop {
		t.Fatalf("post-NAT copy verdict = %v, want RepairDrop: these are the same bytes", v)
	}

	st := r.Stats()
	if st.NATDuplicatesDropped != 1 {
		t.Errorf("NATDuplicatesDropped = %d, want 1", st.NATDuplicatesDropped)
	}
	if st.NATLatePreNATCopies != 0 {
		t.Errorf("NATLatePreNATCopies = %d, want 0", st.NATLatePreNATCopies)
	}
}

func TestNATPairInboundHalfIsAlsoSuppressed(t *testing.T) {
	// Without the reversed form in the index the download of every conversation
	// would stay doubled while the upload was fixed.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	pre := natRecord(natRemote, 8007, natLANAddr, 36180, 8075, t0)
	if v := r.Repair(pre, m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT inbound verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natRemote, 8007, natWANAddr, 42031, 8075, t0.Add(3*time.Second))
	if v := r.Repair(post, m, nil, t0.Add(25*time.Second)); v != RepairDrop {
		t.Fatalf("post-NAT inbound verdict = %v, want RepairDrop", v)
	}
}

func TestNATPairPreNATCopyIsNEVERSuppressed(t *testing.T) {
	// The pre-NAT copy carries the LAN host's own 5-tuple and is the only copy that
	// can correlate with a Zenarmor conn document. Suppressing it would trade a
	// visible double count for an invisible hole in correlation coverage.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	post := natRecord(natWANAddr, 42031, natRemote, 8007, 3048, t0)
	if v := r.Repair(post, m, nil, t0); v != RepairEmit {
		t.Fatalf("lone post-NAT copy verdict = %v, want RepairEmit", v)
	}
	pre := natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0.Add(2*time.Second))
	if v := r.Repair(pre, m, nil, t0.Add(20*time.Second)); v != RepairEmit {
		t.Fatalf("late pre-NAT copy verdict = %v, want RepairEmit — it must survive", v)
	}

	st := r.Stats()
	if st.NATDuplicatesDropped != 0 {
		t.Errorf("NATDuplicatesDropped = %d, want 0", st.NATDuplicatesDropped)
	}
	if st.NATLatePreNATCopies != 1 {
		t.Errorf("NATLatePreNATCopies = %d, want 1 — the residual must be counted, not hidden", st.NATLatePreNATCopies)
	}
}

func TestNATPairDifferentVolumeStillPairsOnTheConversation(t *testing.T) {
	// This is the safety property #636 traded, stated explicitly so the trade is not
	// made twice by accident.
	//
	// Volume equality is what identifies one EXPORT: 399 of 399 real pairs matched
	// bytes and packets exactly. Before #636 a mismatch meant "different export,
	// therefore not proven a duplicate, therefore emit". It no longer does. The two
	// ng_netflow nodes do not always split a conversation into the same records — the
	// WAN node fragments where the LAN node does not — so a mismatched volume is at
	// least as likely to be a differently-sliced copy of bytes already counted as it
	// is to be new traffic. Once the conversation is PROVEN captured pre-NAT, every
	// post-NAT copy of it is redundant whatever its volume.
	//
	// What still protects a record is the conversation never having been seen at all:
	// see TestNATPairUnprovenConversationIsNeverSuppressed.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	if v := r.Repair(natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0), m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT copy verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 9999, t0.Add(2*time.Second))
	if v := r.Repair(post, m, nil, t0.Add(20*time.Second)); v != RepairDrop {
		t.Fatalf("verdict = %v, want RepairDrop: the conversation is proven captured pre-NAT", v)
	}
	st := r.Stats()
	if st.NATConversationDuplicates != 1 {
		t.Errorf("NATConversationDuplicates = %d, want 1", st.NATConversationDuplicates)
	}
	if st.NATDuplicatesDropped != 0 {
		t.Errorf("NATDuplicatesDropped = %d, want 0 — the volumes differ, so proof 1 cannot fire", st.NATDuplicatesDropped)
	}
}

func TestNATPairUnprovenConversationIsNeverSuppressed(t *testing.T) {
	// The mechanism can only ever subtract a copy whose twin it has evidence for. A
	// box that captures its WAN but NOT the LAN behind it has no double count to
	// remove, and suppressing anything there would be pure data loss.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	for i := range 3 {
		at := t0.Add(time.Duration(i) * time.Minute)
		post := natRecord(natWANAddr, 42031, natRemote, 8007, uint64(3048+i), at)
		if v := r.Repair(post, m, nil, at); v != RepairEmit {
			t.Fatalf("post-NAT copy %d verdict = %v, want RepairEmit with no pre-NAT copy ever seen", i, v)
		}
	}
	st := r.Stats()
	if st.NATDuplicatesDropped != 0 || st.NATConversationDuplicates != 0 {
		t.Errorf("suppressed exact=%d conversation=%d, want 0 and 0",
			st.NATDuplicatesDropped, st.NATConversationDuplicates)
	}
	if st.NATUnpaired != 3 {
		t.Errorf("NATUnpaired = %d, want 3 — the guard must see every unproven post-NAT copy", st.NATUnpaired)
	}
	if st.NATConversationEntries != 0 {
		t.Errorf("NATConversationEntries = %d, want 0 — a post-NAT copy is not evidence of pre-NAT capture",
			st.NATConversationEntries)
	}
}

func TestNATPairFirewallOriginatedTrafficIsUntouched(t *testing.T) {
	// 1,009 of the 1,434 WAN-addressed records in the reference capture were the
	// firewall's own traffic: never translated, no twin, and suppressing any of them
	// would be pure data loss.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	// Two DISTINCT exports of the firewall's own traffic — distinct timestamps, so
	// repair 1's instance de-dup has no opinion and repair 5 is the only thing that
	// could suppress either.
	for i := range 2 {
		at := t0.Add(time.Duration(i) * time.Minute)
		own := natRecord(natWANAddr, 53, natRemote, 53, 120, at)
		own.In = Iface{}
		if v := r.Repair(own, m, nil, at); v != RepairEmit {
			t.Fatalf("firewall-originated record %d verdict = %v, want RepairEmit", i, v)
		}
	}
	if got := r.Stats().NATDuplicatesDropped; got != 0 {
		t.Errorf("NATDuplicatesDropped = %d, want 0", got)
	}
}

func TestNATPairIsInertWithoutATable(t *testing.T) {
	// The window before the first pf poll, and every box whose state table records
	// no translations at all.
	r := NewRepairer(0, 1000)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	if v := r.Repair(natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0), m, nil, t0); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 3048, t0.Add(2*time.Second))
	if v := r.Repair(post, m, nil, t0.Add(20*time.Second)); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit with no table", v)
	}
	st := r.Stats()
	if st.NATDuplicatesDropped != 0 || st.NATSeenEntries != 0 {
		t.Errorf("a nil table must cost nothing: dropped=%d entries=%d", st.NATDuplicatesDropped, st.NATSeenEntries)
	}
}

func TestNATPairInternalTrafficIsNotRemembered(t *testing.T) {
	// Both ends private: no post-NAT twin can exist, so holding an identity for it
	// would only fill the table. Internal traffic is the bulk of most boxes' records.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	internal := natRecord("10.0.0.20", 5000, "10.0.0.30", 22, 700, t0)
	internal.Out = Iface{Device: "ixl0", Name: "LAN"}
	if v := r.Repair(internal, m, nil, t0); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit", v)
	}
	if got := r.Stats().NATSeenEntries; got != 0 {
		t.Errorf("NATSeenEntries = %d, want 0 for purely internal traffic", got)
	}
}

// TestNATPairSurvivesTheProductionArrivalGap pins the shape #636 was measured in.
//
// #623 sized the pairing window from a capture taken while a 100 Mbit/s backup ran
// over the policy-routed WAN: arrival gap p50 20s, p90 49s, p99 60s, so two minutes
// paired 99.7%. That measurement was taken under the one condition that hides the
// failure — the backup ITSELF is what put enough flows on the WAN node to keep its
// export datagrams filling promptly.
//
// Off that load the WAN node carries a handful of flows, its datagram does not fill,
// and it holds records until its own flush. Measured at the exporter's socket on the
// production box 2026-08-04 (tcpdump on udp/2055, v9 decoded, pairs matched on exact
// bytes AND packets): the LAN node exported one record every 324 s, promptly at each
// window's close, while the WAN node exported in BATCHES ~609 s apart, two windows at
// a time. The pre->post arrival gaps were 266.4 s and 590.9 s — 4 of 4 pairs past the
// 120 s TTL, which is why the mechanism suppressed nothing while VIRGIN read 1.79x
// the kernel's own byte counter.
//
// The gap is set by the WAN node's flow RATE, which nothing here controls and which
// falls as the box gets quieter, so this test uses the smaller of the two measured
// gaps: a fix that only just covers 266 s is not a fix.
func TestNATPairSurvivesTheProductionArrivalGap(t *testing.T) {
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	pre := natRecord(natLANAddr, 36180, natRemote, 8007, 4294901912, t0)
	if v := r.Repair(pre, m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT copy verdict = %v, want RepairEmit", v)
	}

	// Same bytes, same packets, same conversation, 4m26s later.
	late := t0.Add(266 * time.Second)
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 4294901912, t0.Add(time.Second))
	if v := r.Repair(post, m, nil, late); v != RepairDrop {
		t.Fatalf("post-NAT copy verdict = %v, want RepairDrop: the WAN node's export is "+
			"minutes behind the LAN node's, and these are the same bytes", v)
	}

	// The exact-export identity is long gone by 266 s, so it is proof 2 that catches
	// this — and the two counters are kept apart precisely so an operator can see
	// which one is carrying the box.
	st := r.Stats()
	if st.NATConversationDuplicates != 1 {
		t.Errorf("NATConversationDuplicates = %d, want 1", st.NATConversationDuplicates)
	}
	if st.NATDuplicatesDropped != 0 {
		t.Errorf("NATDuplicatesDropped = %d, want 0 — the exact identity expired at 120 s", st.NATDuplicatesDropped)
	}
	if st.NATUnpaired != 0 {
		t.Errorf("NATUnpaired = %d, want 0 — the copy was paired, just not exactly", st.NATUnpaired)
	}
}

func TestNATPairIdentityExpiresIntoTheConversationProof(t *testing.T) {
	// Past dedupeTTL the exact identity is gone, so proof 1 can no longer fire — but
	// the conversation is still answerable and proof 2 takes over. Before #636 this
	// case was an over-count, and on a quiet WAN it was EVERY case.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	if v := r.Repair(natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0), m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 3048, t0)
	late := t0.Add(dedupeTTL + time.Second)
	if v := r.Repair(post, m, nil, late); v != RepairDrop {
		t.Fatalf("verdict = %v, want RepairDrop once proof 2 covers it", v)
	}
	st := r.Stats()
	if st.NATConversationDuplicates != 1 || st.NATDuplicatesDropped != 0 {
		t.Errorf("conversation=%d exact=%d, want 1 and 0",
			st.NATConversationDuplicates, st.NATDuplicatesDropped)
	}
}

func TestNATPairConversationExpiresToo(t *testing.T) {
	// Proof 2 is not unbounded either: a conversation nothing has refreshed for
	// natConversationTTL stops being evidence. Past that the stage is back to
	// over-counting, which is visible against the interface counter, rather than
	// suppressing a record on the strength of an hour-old memory.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	if v := r.Repair(natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0), m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 3048, t0)
	late := t0.Add(natConversationTTL + time.Second)
	if v := r.Repair(post, m, nil, late); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit once the conversation has expired", v)
	}
	st := r.Stats()
	if st.NATDuplicatesDropped != 0 || st.NATConversationDuplicates != 0 {
		t.Errorf("suppressed exact=%d conversation=%d, want 0 and 0",
			st.NATDuplicatesDropped, st.NATConversationDuplicates)
	}
	if st.NATConversationEntries != 0 {
		t.Errorf("NATConversationEntries = %d, want 0 after the sweep", st.NATConversationEntries)
	}
}

func TestNATPairLongLivedConversationRefreshesItsEntry(t *testing.T) {
	// The production shape: a conversation whose LAN node exports every 324 s and
	// whose WAN node exports in batches ~609 s behind, for hours. Each pre-NAT copy
	// must refresh the conversation so the entry never ages out under it — otherwise
	// the fix would work for one window and then lapse.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	const windows = 12 // ~65 minutes, well past natConversationTTL
	for i := range windows {
		at := t0.Add(time.Duration(i) * 324 * time.Second)
		pre := natRecord(natLANAddr, 36180, natRemote, 8007, uint64(4294901912+i), at)
		if v := r.Repair(pre, m, nil, at); v != RepairEmit {
			t.Fatalf("pre-NAT copy %d verdict = %v, want RepairEmit", i, v)
		}
		// The WAN node's copy of the PREVIOUS window, 591 s behind — the worst gap
		// measured at the socket on the production box.
		if i == 0 {
			continue
		}
		post := natRecord(natWANAddr, 42031, natRemote, 8007, uint64(4294901912+i-1), at)
		postAt := t0.Add(time.Duration(i-1)*324*time.Second + 591*time.Second)
		if v := r.Repair(post, m, nil, postAt); v != RepairDrop {
			t.Fatalf("post-NAT copy %d verdict = %v, want RepairDrop at a 591 s gap", i, v)
		}
	}
	st := r.Stats()
	if got := st.NATDuplicatesDropped + st.NATConversationDuplicates; got != windows-1 {
		t.Errorf("suppressed %d of %d post-NAT copies", got, windows-1)
	}
	if st.NATConversationEntries != 1 {
		t.Errorf("NATConversationEntries = %d, want 1 — one conversation, refreshed", st.NATConversationEntries)
	}
}

func TestNATPairUntranslatedConversationsCostNoEntry(t *testing.T) {
	// The conversation table is gated on pf calling the tuple translated, which is
	// what keeps it to one entry per NAT'd conversation instead of one per record.
	// Traffic the box does not translate is the bulk of a LAN's records.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	untranslated := natRecord("10.0.0.77", 51000, natRemote, 443, 4096, t0)
	if v := r.Repair(untranslated, m, nil, t0); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit", v)
	}
	if got := r.Stats().NATConversationEntries; got != 0 {
		t.Errorf("NATConversationEntries = %d, want 0 — pf records no translation for this tuple", got)
	}
}
