package flow

import (
	"net/netip"
	"sync"
	"testing"
)

func rec(iface string, dir Direction, cat string, bytes, packets uint64) Record {
	return Record{
		Source: SourceZenarmor, Proto: 6,
		SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("198.51.100.1"),
		In: Iface{Name: iface}, Direction: dir, L7: L7{AppCategory: cat},
		Zen: Counters{TxBytes: bytes, TxPackets: packets, Present: true},
	}
}

func totals(es []RollupEntry) (b, p, f uint64) {
	for _, e := range es {
		b, p, f = b+e.Bytes, p+e.Packets, f+e.Flows
	}
	return b, p, f
}

func countOther(es []RollupEntry) int {
	n := 0
	for _, e := range es {
		if e.Key.Category == OtherLabel {
			n++
		}
	}
	return n
}

// Control 1: top-N bounds the OUTPUT, and the remainder folds so the group total
// stays exact. A dashboard summing the family must not change its answer because an
// operator retuned topN.
func TestRollup_TopNFoldsRemainderPreservingTotals(t *testing.T) {
	r := NewRollup(2, 1000)
	var wantB, wantP, wantF uint64
	for i, cat := range []string{"a", "b", "c", "d", "e"} {
		b, p := uint64((i+1)*100), uint64(i+1)
		r.Observe(rec("LAN", DirectionOutbound, cat, b, p))
		wantB, wantP, wantF = wantB+b, wantP+p, wantF+1
	}
	es := r.Snapshot()
	gotB, gotP, gotF := totals(es)
	if gotB != wantB || gotP != wantP || gotF != wantF {
		t.Fatalf("totals = %d/%d/%d, want %d/%d/%d (folding must preserve every counter)",
			gotB, gotP, gotF, wantB, wantP, wantF)
	}
	if n := countOther(es); n != 1 {
		t.Fatalf("expected exactly one __other__ entry, got %d", n)
	}
	if len(es) != 3 { // topN=2 plus the single folded remainder
		t.Fatalf("expected 3 entries (2 top + 1 other), got %d", len(es))
	}
}

// Control 2: the insert-time cap is a SEPARATE bound from topN. topN shapes the
// output at snapshot; this bounds the live map between snapshots. Without it a
// flood of unique keys grows the accumulator without limit — and phase 2's NetFlow
// listener is unauthenticated, so this is the attacker-reachable path.
func TestRollup_InsertCapFoldsWithoutLosingVolume(t *testing.T) {
	r := NewRollup(1000, 3)
	var want uint64
	for i := 0; i < 50; i++ {
		r.Observe(rec("LAN", DirectionOutbound, string(rune('a'+i)), 10, 2))
		want += 10
	}
	es := r.Snapshot()
	if gotB, gotP, gotF := totals(es); gotB != want || gotP != 100 || gotF != 50 {
		t.Fatalf("totals = %d/%d/%d, want %d/100/50 (the insert cap must fold, never drop)",
			gotB, gotP, gotF, want)
	}
	if len(es) > 4 { // 3 tracked keys + __other__
		t.Fatalf("live key set unbounded: %d entries", len(es))
	}
	if st := r.Stats(); st.Keys != 3 || st.Capped == 0 {
		t.Fatalf("Stats() = %+v, want Keys=3 and a non-zero Capped count", st)
	}
}

// Control 3: the label set is an explicit allowlist, in a fixed order. This is the
// guard that stops a future change adding an IP, port or app_name label.
func TestRollup_LabelNamesAreExactlyTheAllowlist(t *testing.T) {
	got := RollupLabelNames()
	want := []string{"interface", "direction", "transport", "category", "action", "source", "scope"}
	if len(got) != len(want) {
		t.Fatalf("label set changed: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("label set changed: got %v, want %v", got, want)
		}
	}
	// Values() must line up with the names positionally, or a label lands on the
	// wrong dimension with nothing failing.
	k := RollupKey{Interface: "i", Direction: "d", Transport: "t", Category: "c",
		Action: "a", Source: "s", Scope: "sc"}
	if v := k.Values(); len(v) != len(want) {
		t.Fatalf("Values() has %d entries, want %d", len(v), len(want))
	}
}

// THE regression test for the fold. The remainder must be monotone on bytes,
// packets AND records.
//
// Folding the tail's CUMULATIVE totals is monotone only for the sort key: for any
// N-subset S, sum_S bytes(t1) <= sum_topN bytes(t1) because topN maximises it, so
// the remainder never decreases. Packets and records ride along on a bytes-only
// ranking, where that argument does not hold — a high-packet/low-byte key crossing
// the boundary drops __other__ packets by millions in one interval and Prometheus
// reads it as a counter reset.
//
// The key that CHURNS has to be the packet-heavy one, or the test proves nothing:
// a high-packet key parked permanently in the tail keeps the remainder growing and
// the bug never fires. So "fat" carries a million packets per observation and
// alternates the byte increment with "mid", which puts fat itself on either side of
// the bytes-ranked top-N boundary every round while "anchor" holds slot one.
//
// Verified against the v1 implementation: folding cumulative tail totals sends
// __other__ packets from 1,000,000 to 2 on the first swap.
func TestRollup_OtherIsMonotoneOnAllThreeCountersUnderChurn(t *testing.T) {
	r := NewRollup(2, 100)
	var prevOther RollupEntry
	var haveOther bool

	for round := 0; round < 20; round++ {
		r.Observe(rec("LAN", DirectionOutbound, "anchor", 100_000, 1))
		if round%2 == 0 {
			r.Observe(rec("LAN", DirectionOutbound, "mid", 1_000, 1))
			r.Observe(rec("LAN", DirectionOutbound, "fat", 0, 1_000_000))
		} else {
			r.Observe(rec("LAN", DirectionOutbound, "fat", 1_100, 1_000_000))
		}

		for _, e := range r.Snapshot() {
			if e.Key.Category != OtherLabel {
				continue
			}
			if haveOther && (e.Bytes < prevOther.Bytes || e.Packets < prevOther.Packets || e.Flows < prevOther.Flows) {
				t.Fatalf("round %d: __other__ went backwards: %d/%d/%d -> %d/%d/%d",
					round, prevOther.Bytes, prevOther.Packets, prevOther.Flows, e.Bytes, e.Packets, e.Flows)
			}
			prevOther, haveOther = e, true
		}
	}
	if !haveOther {
		t.Fatal("the churn never produced a remainder; the test proves nothing")
	}
}

// A series that stays in top-N continuously must never go backwards either.
func TestRollup_ContinuouslyEmittedSeriesAreMonotone(t *testing.T) {
	r := NewRollup(2, 100)
	prev := map[RollupKey]RollupEntry{}
	present := map[RollupKey]int{}

	for round := 1; round <= 20; round++ {
		r.Observe(rec("LAN", DirectionOutbound, "anchor", 100_000, 1))
		if round%2 == 0 {
			r.Observe(rec("LAN", DirectionOutbound, "mid", 1_000, 7))
			r.Observe(rec("LAN", DirectionOutbound, "fat", 0, 1_000_000))
		} else {
			r.Observe(rec("LAN", DirectionOutbound, "fat", 1_100, 1_000_000))
		}

		for _, e := range r.Snapshot() {
			// Only a series emitted in the IMMEDIATELY preceding snapshot is
			// required to be monotone. One that fell out of top-N and came back
			// resumes from the delta accumulated while it was folded — a documented,
			// deliberate reset, pinned by TestRollup_ReEntryResumesFromTheFoldedDelta.
			if last, seen := present[e.Key]; seen && last == round-1 {
				p := prev[e.Key]
				if e.Bytes < p.Bytes || e.Packets < p.Packets || e.Flows < p.Flows {
					t.Fatalf("round %d: continuously-present series %+v went backwards: %+v -> %+v",
						round, e.Key, p, e)
				}
			}
			prev[e.Key], present[e.Key] = e, round
		}
	}
}

// The exactness invariant, asserted at EVERY snapshot rather than only the last:
// the sum over emitted series equals the true observed total. This is what lets a
// dashboard sum the family and get the right answer no matter how the bounds are
// tuned or how membership churns.
func TestRollup_SumOverEmittedSeriesAlwaysEqualsTrueTotal(t *testing.T) {
	r := NewRollup(3, 6)
	var trueB, trueP, trueF uint64
	obs := func(cat string, b, p uint64) {
		r.Observe(rec("LAN", DirectionOutbound, cat, b, p))
		trueB, trueP, trueF = trueB+b, trueP+p, trueF+1
	}
	for round := 0; round < 30; round++ {
		obs("steady", 5_000, 5)
		obs(string(rune('a'+round%12)), uint64(round*137%9_000), uint64(round%7))
		obs("fat", 1, 900_000)

		gotB, gotP, gotF := totals(r.Snapshot())
		if gotB != trueB || gotP != trueP || gotF != trueF {
			t.Fatalf("round %d: emitted %d/%d/%d != true total %d/%d/%d",
				round, gotB, gotP, gotF, trueB, trueP, trueF)
		}
	}
}

// The documented cost of the watermark scheme, pinned so it is a decision rather
// than a surprise: a key that leaves top-N and returns resumes from the volume it
// accumulated while folded, not from its lifetime total. The alternative — freezing
// a fallen-out series at its last value forever — is the failure mode that makes a
// top-K exporter lie indefinitely.
func TestRollup_ReEntryResumesFromTheFoldedDelta(t *testing.T) {
	r := NewRollup(1, 10)

	r.Observe(rec("LAN", DirectionOutbound, "small", 100, 1))
	if got := entryFor(r.Snapshot(), "small"); got == nil || got.Bytes != 100 {
		t.Fatalf("expected small=100 while it holds the single top-N slot, got %+v", got)
	}

	// A bigger key displaces it; "small" is folded into __other__ at 100 bytes.
	r.Observe(rec("LAN", DirectionOutbound, "big", 10_000, 1))
	if got := entryFor(r.Snapshot(), "small"); got != nil {
		t.Fatalf("small must not be emitted once it is outside top-N, got %+v", got)
	}

	// It comes back with a burst, and resumes from the burst, not from 100+burst.
	r.Observe(rec("LAN", DirectionOutbound, "small", 50_000, 1))
	got := entryFor(r.Snapshot(), "small")
	if got == nil {
		t.Fatal("small should have re-entered top-N")
	}
	if got.Bytes != 50_000 {
		t.Fatalf("re-entered series = %d bytes, want 50000 (the delta since it was folded)", got.Bytes)
	}
	// And the family still sums exactly, which is the invariant that matters.
	if b, _, _ := totals(r.Snapshot()); b != 60_100 {
		t.Fatalf("family total = %d, want 60100", b)
	}
}

func entryFor(es []RollupEntry, cat string) *RollupEntry {
	for i := range es {
		if es[i].Key.Category == cat {
			return &es[i]
		}
	}
	return nil
}

// __other__ collapses every dimension EXCEPT source. Once phase 2 lands the family
// holds two sources' measurement of the same traffic, so a query that does not pin
// source double-counts; collapsing source into the sentinel too would make the
// correct query impossible to write at all.
func TestRollup_OtherPreservesTheSourceLabel(t *testing.T) {
	r := NewRollup(1, 100)
	for _, cat := range []string{"a", "b", "c"} {
		zen := rec("LAN", DirectionOutbound, cat, 100, 1)
		r.Observe(zen)
		nf := zen
		nf.Source = SourceNetflow
		nf.Zen = Counters{}
		nf.NF = Counters{TxBytes: 200, TxPackets: 2, Present: true}
		r.Observe(nf)
	}
	var others []RollupEntry
	for _, e := range r.Snapshot() {
		if e.Key.Category == OtherLabel {
			others = append(others, e)
		}
	}
	if len(others) != 2 {
		t.Fatalf("expected one remainder per source, got %d: %+v", len(others), others)
	}
	seen := map[string]bool{}
	for _, e := range others {
		seen[e.Key.Source] = true
		if e.Key.Interface != OtherLabel || e.Key.Direction != OtherLabel || e.Key.Scope != OtherLabel {
			t.Fatalf("remainder must collapse every dimension but source: %+v", e.Key)
		}
	}
	if !seen["zenarmor"] || !seen["netflow"] {
		t.Fatalf("both sources must keep their own remainder, got %v", seen)
	}
}

// Saturation must be observable. At maxKeys every novel key folds into __other__
// forever, and an operator cannot otherwise distinguish "a few small categories
// folded" from "the map saturated weeks ago and everything new is invisible".
func TestRollup_ReportsSaturationStats(t *testing.T) {
	r := NewRollup(2, 4)
	if st := r.Stats(); st.MaxKeys != 4 || st.TopN != 2 || st.Keys != 0 || st.Capped != 0 {
		t.Fatalf("fresh Stats() = %+v, want TopN=2 MaxKeys=4 and zeroes", st)
	}
	for i := 0; i < 10; i++ {
		r.Observe(rec("LAN", DirectionOutbound, string(rune('a'+i)), 10, 1))
	}
	_ = r.Snapshot()
	st := r.Stats()
	if st.Keys != 4 {
		t.Fatalf("Keys = %d, want 4 (the insert cap)", st.Keys)
	}
	if st.Capped != 6 {
		t.Fatalf("Capped = %d, want 6 observations rejected at the cap", st.Capped)
	}
	if st.FoldedKeys != 2 {
		t.Fatalf("FoldedKeys = %d, want 2 (4 tracked, topN=2)", st.FoldedKeys)
	}
}

// An unstable tie-break makes top-N membership flap between scrapes, churning
// series and corrupting rate().
func TestRollup_TieBreakIsDeterministic(t *testing.T) {
	build := func() []RollupEntry {
		r := NewRollup(2, 1000)
		for _, cat := range []string{"a", "b", "c", "d"} {
			r.Observe(rec("LAN", DirectionOutbound, cat, 100, 1)) // all equal
		}
		return r.Snapshot()
	}
	first := build()
	for i := 0; i < 20; i++ {
		got := build()
		for j := range first {
			if got[j].Key != first[j].Key {
				t.Fatal("top-N membership is not deterministic under equal values")
			}
		}
	}
}

// Counters are cumulative: reading them must not reset them.
func TestRollup_SnapshotDoesNotReset(t *testing.T) {
	r := NewRollup(10, 100)
	r.Observe(rec("LAN", DirectionOutbound, "a", 100, 1))
	_ = r.Snapshot()
	r.Observe(rec("LAN", DirectionOutbound, "a", 50, 1))
	if b, _, f := totals(r.Snapshot()); b != 150 || f != 2 {
		t.Fatalf("counters must be cumulative across snapshots: got %d bytes / %d flows, want 150/2", b, f)
	}
}

// Zero means unbounded for both caps, so an operator who wants no bound gets none
// rather than a silently empty metric.
func TestRollup_ZeroBoundsMeanUnbounded(t *testing.T) {
	r := NewRollup(0, 0)
	for i := 0; i < 50; i++ {
		r.Observe(rec("LAN", DirectionOutbound, string(rune('a'+i)), 10, 1))
	}
	es := r.Snapshot()
	if len(es) != 50 {
		t.Fatalf("got %d entries, want all 50 emitted with no bound", len(es))
	}
	if countOther(es) != 0 {
		t.Fatal("nothing should fold when both bounds are unlimited")
	}
}

// SetBounds is safe against a concurrent Observe/Snapshot by construction — it
// takes the accumulator's own mutex and swaps no pointer — rather than by call
// ordering. An ordering-only fix would be a data race living in untested main.go
// wiring, which -race would never reach.
func TestRollup_SetBoundsIsRaceFreeAndPreservesTotals(t *testing.T) {
	r := NewRollup(1000, 5000)
	const n = 2000
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			r.Observe(rec("LAN", DirectionOutbound, "a", 1, 1))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = r.Snapshot()
			_ = r.Stats()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			r.SetBounds(1000+i%3, 5000+i%3)
		}
	}()
	wg.Wait()

	r.SetBounds(1000, 5000)
	if b, _, f := totals(r.Snapshot()); b != n || f != n {
		t.Fatalf("lost writes or discarded totals: got %d bytes / %d flows, want %d/%d", b, f, n, n)
	}
}

func TestRollup_TransportNamesAreBounded(t *testing.T) {
	for proto, want := range map[uint8]string{
		1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6", 132: "sctp",
		// A protocol number we do not name becomes "other", never its number: the
		// field is wire-derived and, on the phase-2 listener, attacker-controlled, so
		// echoing it verbatim would let a sender mint up to 256 label values.
		99: "other", 0: "other",
	} {
		if got := transportName(proto); got != want {
			t.Errorf("transportName(%d) = %q, want %q", proto, got, want)
		}
	}
}

// NetFlow and Zenarmor counters are never summed: they measure at different points
// and will legitimately disagree (#346 decision 3).
func TestRollup_VolumeNeverSumsTheTwoSources(t *testing.T) {
	both := rec("LAN", DirectionOutbound, "a", 0, 0)
	both.Zen = Counters{TxBytes: 100, TxPackets: 1, Present: true}
	both.NF = Counters{TxBytes: 900, TxPackets: 9, Present: true}
	b, p := volumeOf(both)
	if b != 900 || p != 9 {
		t.Fatalf("volumeOf = %d/%d, want the NetFlow view 900/9 — never the 1000/10 sum", b, p)
	}
	zenOnly := rec("LAN", DirectionOutbound, "a", 100, 1)
	if b, p := volumeOf(zenOnly); b != 100 || p != 1 {
		t.Fatalf("volumeOf = %d/%d, want the Zenarmor view 100/1", b, p)
	}
}
