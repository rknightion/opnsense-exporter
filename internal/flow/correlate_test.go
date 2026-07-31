package flow

import (
	"net/netip"
	"testing"
	"time"
)

// baseNF builds a minimal NetFlow-side record for a given community id, byte count and
// flow-end. The community id is passed verbatim rather than computed so a test can force
// two records onto the same key without constructing colliding tuples.
func baseNF(community string, bytes, packets uint64, end time.Time, observed time.Time) Record {
	return Record{
		Source:      SourceNetflow,
		CommunityID: community,
		Observed:    observed,
		Start:       end.Add(-time.Second),
		End:         end,
		Proto:       6,
		SrcAddr:     netip.MustParseAddr("192.0.2.10"),
		DstAddr:     netip.MustParseAddr("203.0.113.5"),
		SrcPort:     40000,
		DstPort:     443,
		NF:          Counters{TxBytes: bytes, TxPackets: packets, Present: true},
		In:          Iface{Device: "ixl0", Name: "LAN"},
		Out:         Iface{Device: "pppoe0", Name: "WAN1"},
		Direction:   DirectionOutbound,
	}
}

func baseZen(community string, bytes uint64, end time.Time, observed time.Time) Record {
	return Record{
		Source:      SourceZenarmor,
		CommunityID: community,
		Observed:    observed,
		End:         end,
		Zen:         Counters{TxBytes: bytes, Present: true},
		Verdict:     VerdictPass,
		L7:          L7{AppName: "google", AppCategory: "Web Browsing"},
	}
}

// collect is an emit sink that records everything the correlator hands it.
type collect struct{ recs []Record }

func (c *collect) emit(r Record) { c.recs = append(c.recs, r) }

func newCorr(t *testing.T, enabled bool, window time.Duration, maxEntries int) (*Correlator, *collect) {
	t.Helper()
	sink := &collect{}
	return NewCorrelator(CorrelatorConfig{Enabled: enabled, Window: window, MaxEntries: maxEntries}, sink.emit), sink
}

// A connection that fragments into several NetFlow records must emit ONCE, on expiry,
// with the bytes summed and the fragment count preserved. If the accumulator ever
// emitted per fragment (the bug the correlator exists to prevent) this sees 3 records.
func TestCorrelator_CollapsesFragmentsIntoOneEmit(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Observe(baseNF("cid-A", 200, 2, t0, t0.Add(time.Second)))
	c.Observe(baseNF("cid-A", 300, 3, t0, t0.Add(2*time.Second)))

	if len(sink.recs) != 0 {
		t.Fatalf("emitted %d records before expiry; the correlator must hold fragments", len(sink.recs))
	}
	c.Expire(t0.Add(4 * time.Minute))

	if len(sink.recs) != 1 {
		t.Fatalf("want exactly 1 emitted record after expiry, got %d", len(sink.recs))
	}
	got := sink.recs[0]
	if got.Source != SourceNetflow {
		t.Errorf("source = %v, want netflow (no Zenarmor arrived)", got.Source)
	}
	if got.NF.Bytes() != 600 {
		t.Errorf("summed bytes = %d, want 600", got.NF.Bytes())
	}
	if got.NF.Packets() != 6 {
		t.Errorf("summed packets = %d, want 6", got.NF.Packets())
	}
	if got.Fragments != 3 {
		t.Errorf("fragments = %d, want 3", got.Fragments)
	}
}

// #585: one conversation arrives as a mean of 3.75 NetFlow records — the two
// directions are separate records, and a long flow is re-reported per inactive
// timeout — so the flag bits of a single connection are SPREAD ACROSS fragments.
// Taking the first fragment's byte (the sample record's own value) would report "SYN"
// on almost every TCP flow and make the attribute useless for the question it exists
// to answer: a refused connection (client SYN, server RST) would be indistinguishable
// from a scan that got no reply at all.
//
// OR-ing is not an invention here: a NetFlow record already reports the union of the
// flags across its own packets, so extending that union across the fragments of one
// connection-window keeps the field meaning exactly one thing.
func TestCorrelator_UnionsTCPFlagsAcrossFragments(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	syn := baseNF("cid-A", 60, 1, t0, t0)
	syn.TCPFlags = 0x02 // client -> server: SYN
	c.Observe(syn)
	rstAck := baseNF("cid-A", 40, 1, t0, t0.Add(time.Second))
	rstAck.TCPFlags = 0x14 // server -> client: RST,ACK — the peer refused
	c.Observe(rstAck)

	c.Expire(t0.Add(4 * time.Minute))
	if len(sink.recs) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
	}
	if got := sink.recs[0].TCPFlags; got != 0x16 {
		t.Errorf("TCPFlags = %#02x, want 0x16 (SYN|RST|ACK across both fragments)", got)
	}
	if got := sink.recs[0].LogAttributes()["netflow.tcp_flags"]; got != "SYN,RST,ACK" {
		t.Errorf("rendered flags = %q, want SYN,RST,ACK", got)
	}
}

// #585: Zenarmor's encryption verdict reaches the merged record only because it rides
// inside L7, which finalize copies wholesale. A sibling field on Record would need its
// own line in finalize and would otherwise be dropped on every merged record — the
// only kind of record carrying both a Zenarmor verdict and NetFlow volume, and so the
// only one that answers "which hosts still send cleartext to the internet".
func TestCorrelator_MergedRecordCarriesZenarmorEncryption(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 500, 5, t0, t0))
	zen := baseZen("cid-A", 480, t0, t0.Add(time.Second))
	zen.L7.Encryption = "Clear"
	c.Observe(zen)

	c.Expire(t0.Add(4 * time.Minute))
	if len(sink.recs) != 1 {
		t.Fatalf("want 1 merged record, got %d", len(sink.recs))
	}
	if got := sink.recs[0].L7.Encryption; got != "Clear" {
		t.Errorf("L7.Encryption = %q, want Clear", got)
	}
}

// Fragments whose flow-ends land in different windows are different keys, so each
// window emits its own partial — the mechanism that bounds emit latency for a flow
// that never ends.
func TestCorrelator_DifferentWindowsEmitSeparately(t *testing.T) {
	window := 3 * time.Minute
	c, sink := newCorr(t, true, window, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Observe(baseNF("cid-A", 200, 2, t0.Add(2*window), t0.Add(2*window)))

	c.Expire(t0.Add(10 * window))
	if len(sink.recs) != 2 {
		t.Fatalf("want 2 emitted records (two windows), got %d", len(sink.recs))
	}
}

// A NetFlow entry with a matching Zenarmor conn document emits ONE merged record
// carrying the NetFlow repaired interfaces AND the Zenarmor L7. Remove the merge and
// the record is source=netflow with no category.
func TestCorrelator_MergesZenarmorEnrichment(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 500, 5, t0, t0))
	c.Observe(baseZen("cid-A", 480, t0, t0.Add(time.Second)))

	if len(sink.recs) != 0 {
		t.Fatalf("Zenarmor arrival must not emit; the conn lane already ships it (got %d)", len(sink.recs))
	}
	c.Expire(t0.Add(4 * time.Minute))

	if len(sink.recs) != 1 {
		t.Fatalf("want 1 merged record, got %d", len(sink.recs))
	}
	got := sink.recs[0]
	if got.Source != SourceMerged {
		t.Fatalf("source = %v, want merged", got.Source)
	}
	if got.L7.AppCategory != "Web Browsing" {
		t.Errorf("category = %q, want the Zenarmor value", got.L7.AppCategory)
	}
	if got.Verdict != VerdictPass {
		t.Errorf("verdict = %v, want pass from Zenarmor", got.Verdict)
	}
	if got.NF.Bytes() != 500 || got.Zen.Bytes() != 480 {
		t.Errorf("NF/Zen bytes = %d/%d, want 500/480 (never summed)", got.NF.Bytes(), got.Zen.Bytes())
	}
	if got.Out.Name != "WAN1" {
		t.Errorf("egress = %q, want the NetFlow repaired interface", got.Out.Name)
	}
	if st := c.Stats(); st.Matched != 1 {
		t.Errorf("Matched = %d, want 1", st.Matched)
	}
}

// Enrichment order is not guaranteed: a Zenarmor document arriving BEFORE any NetFlow
// fragment must still merge once the fragment lands.
func TestCorrelator_ZenarmorBeforeNetflowStillMerges(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseZen("cid-A", 480, t0, t0))
	c.Observe(baseNF("cid-A", 500, 5, t0, t0.Add(time.Second)))
	c.Expire(t0.Add(4 * time.Minute))

	if len(sink.recs) != 1 || sink.recs[0].Source != SourceMerged {
		t.Fatalf("want 1 merged record regardless of arrival order, got %d", len(sink.recs))
	}
}

// #590 finding: when a Zenarmor document creates the entry FIRST, the corrEntry it
// gets has no sample (observeZenarmorLocked never sets one) - and the old
// observeNetflowLocked only ever wrote e.sample inside its "e == nil" branch, so an
// entry that already existed from Zenarmor never received one from the NetFlow
// fragment that landed afterwards. finalize() then emitted e.sample's ZERO VALUE:
// an empty CommunityID, an invalid SrcAddr/DstAddr, and an empty Out interface -
// not merely "took the first fragment's dimensions" as the issue described, but
// "took no fragment's dimensions at all". This is worse than the described
// staleness and is what fixed the entry's sample being set on whichever call is
// the ENTRY's first NetFlow fragment, not just the call that created the entry.
func TestCorrelator_ZenarmorFirstStillCarriesNetflowSample(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseZen("cid-A", 480, t0, t0))
	c.Observe(baseNF("cid-A", 500, 5, t0, t0.Add(time.Second)))
	c.Expire(t0.Add(4 * time.Minute))

	if len(sink.recs) != 1 {
		t.Fatalf("want 1 merged record, got %d", len(sink.recs))
	}
	got := sink.recs[0]
	if got.CommunityID != "cid-A" {
		t.Errorf("CommunityID = %q, want cid-A (the NetFlow fragment's sample was never applied)", got.CommunityID)
	}
	if !got.SrcAddr.IsValid() {
		t.Errorf("SrcAddr = %v, want the NetFlow fragment's address, not the zero value", got.SrcAddr)
	}
	if got.Out.Name != "WAN1" {
		t.Errorf("Out.Name = %q, want WAN1 from the NetFlow fragment", got.Out.Name)
	}
	if got.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound from the NetFlow fragment", got.Direction)
	}
	if !got.Start.Equal(t0.Add(-time.Second)) || !got.End.Equal(t0) {
		t.Errorf("start=%v end=%v, want the NetFlow fragment's window, not the zero value", got.Start, got.End)
	}
}

// A second Zenarmor conn document for the same key OVERWRITES the first entirely
// (#590) rather than merging: e.zen is replaced wholesale, so whatever the first
// document carried that the second doesn't repeat is gone. This is the observable
// side of that loss - the metric this test drives is the whole point of #590.
func TestCorrelator_SecondZenarmorDocOverwritesAndIsCounted(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 500, 5, t0, t0))

	first := baseZen("cid-A", 100, t0, t0.Add(time.Second))
	first.L7.AppCategory = "first-doc"
	c.Observe(first)

	if st := c.Stats(); st.EnrichmentOverwrites != 0 {
		t.Fatalf("EnrichmentOverwrites = %d, want 0 before any overwrite happens", st.EnrichmentOverwrites)
	}

	second := baseZen("cid-A", 380, t0, t0.Add(2*time.Second))
	second.L7.AppCategory = "second-doc"
	c.Observe(second)

	if st := c.Stats(); st.EnrichmentOverwrites != 1 {
		t.Fatalf("EnrichmentOverwrites = %d, want 1", st.EnrichmentOverwrites)
	}

	c.Expire(t0.Add(4 * time.Minute))
	if len(sink.recs) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
	}
	if got := sink.recs[0].L7.AppCategory; got != "second-doc" {
		t.Errorf("L7.AppCategory = %q, want second-doc: the second document must win (overwrite, "+
			"not a silent merge)", got)
	}
}

// A later NetFlow fragment reporting a DIFFERENT egress interface than the sample
// finalize() will emit is exactly the silent loss #590 exists to surface: the
// dimension the merged record carries is frozen to the first fragment, and every
// later disagreement vanishes with no trace today.
func TestCorrelator_FragmentDisagreementCounted(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0)) // Out.Name == "WAN1"

	disagree := baseNF("cid-A", 200, 2, t0, t0.Add(time.Second))
	disagree.Out.Name = "WAN2"
	c.Observe(disagree)

	if st := c.Stats(); st.FragmentDisagreements != 1 {
		t.Fatalf("FragmentDisagreements = %d, want 1", st.FragmentDisagreements)
	}

	c.Expire(t0.Add(4 * time.Minute))
	if len(sink.recs) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
	}
	// The counter observes the loss; it does not change what is emitted. The first
	// fragment's interface is still what wins, exactly as before this issue.
	if got := sink.recs[0].Out.Name; got != "WAN1" {
		t.Errorf("Out.Name = %q, want WAN1 (the first fragment still wins; only the disagreement "+
			"is now counted)", got)
	}
}

// #585 added TCP-flag OR-union accumulation across fragments in this same
// accumulator. That is a MERGE - the field is explicitly designed to combine every
// fragment's bits - and must never be counted as a fragment disagreement, which
// exists to flag dimensions that are silently DROPPED, not combined.
func TestCorrelator_TCPFlagUnionNotCountedAsFragmentDisagreement(t *testing.T) {
	c, _ := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	syn := baseNF("cid-A", 60, 1, t0, t0)
	syn.TCPFlags = 0x02
	c.Observe(syn)

	rstAck := baseNF("cid-A", 40, 1, t0, t0.Add(time.Second))
	rstAck.TCPFlags = 0x14 // differs from the first fragment's flags on purpose
	c.Observe(rstAck)

	if st := c.Stats(); st.FragmentDisagreements != 0 {
		t.Fatalf("FragmentDisagreements = %d, want 0: differing TCPFlags is a union (#585), not a "+
			"dropped dimension", st.FragmentDisagreements)
	}
}

// A Zenarmor document that never gains a NetFlow fragment emits NOTHING: the conn lane
// owns it, so emitting here would double-ship the Zenarmor side.
func TestCorrelator_ZenarmorOnlyNeverEmits(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseZen("cid-A", 480, t0, t0))
	c.Expire(t0.Add(4 * time.Minute))
	c.Flush()
	if len(sink.recs) != 0 {
		t.Fatalf("Zenarmor-only must never emit, got %d", len(sink.recs))
	}
}

// Pass-through (correlation disabled): NetFlow emits raw and immediately, one per
// fragment, with no accumulation; Zenarmor is dropped.
func TestCorrelator_PassThroughEmitsNetflowRawDropsZenarmor(t *testing.T) {
	c, sink := newCorr(t, false, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Observe(baseNF("cid-A", 200, 2, t0, t0))
	c.Observe(baseZen("cid-A", 50, t0, t0))

	if len(sink.recs) != 2 {
		t.Fatalf("pass-through must emit each NetFlow record raw and drop Zenarmor; got %d", len(sink.recs))
	}
	if sink.recs[0].NF.Bytes() != 100 || sink.recs[1].NF.Bytes() != 200 {
		t.Errorf("pass-through must not accumulate: got %d,%d", sink.recs[0].NF.Bytes(), sink.recs[1].NF.Bytes())
	}
}

// At capacity, a novel NetFlow key force-emits the oldest entry rather than dropping
// it, and the eviction is counted. Removing the eviction path either grows the map
// past the cap or silently loses the oldest flow.
func TestCorrelator_OverflowForceEmitsOldest(t *testing.T) {
	c, sink := newCorr(t, true, 1*time.Hour, 2)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Observe(baseNF("cid-B", 100, 1, t0, t0.Add(time.Second)))
	// Third novel key at cap=2 forces the oldest (cid-A) out.
	c.Observe(baseNF("cid-C", 100, 1, t0, t0.Add(2*time.Second)))

	if len(sink.recs) != 1 {
		t.Fatalf("overflow must force-emit exactly one (the oldest), got %d", len(sink.recs))
	}
	if sink.recs[0].CommunityID != "cid-A" {
		t.Errorf("evicted %q, want the oldest cid-A", sink.recs[0].CommunityID)
	}
	st := c.Stats()
	if st.Evicted != 1 {
		t.Errorf("Evicted = %d, want 1", st.Evicted)
	}
	if st.Entries != 2 {
		t.Errorf("Entries = %d, want the map held at the cap of 2", st.Entries)
	}
}

// Flush drains every pending NetFlow entry at shutdown, whatever the window says.
func TestCorrelator_FlushEmitsPending(t *testing.T) {
	c, sink := newCorr(t, true, 1*time.Hour, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Observe(baseNF("cid-B", 100, 1, t0, t0))
	c.Flush()
	if len(sink.recs) != 2 {
		t.Fatalf("flush must emit both pending entries, got %d", len(sink.recs))
	}
	if st := c.Stats(); st.Entries != 0 {
		t.Errorf("Entries after flush = %d, want 0", st.Entries)
	}
}

// Expire before the window has elapsed emits nothing: an entry must be held for its
// full window.
func TestCorrelator_ExpireBeforeWindowHoldsEntry(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Expire(t0.Add(2 * time.Minute)) // still inside the window
	if len(sink.recs) != 0 {
		t.Fatalf("entry emitted before its window elapsed, got %d", len(sink.recs))
	}
	c.Expire(t0.Add(4 * time.Minute))
	if len(sink.recs) != 1 {
		t.Fatalf("entry not emitted after its window elapsed, got %d", len(sink.recs))
	}
}

// mirrorNF is baseNF's reverse half: the same conversation reported from the other
// direction, exactly as ng_netflow exports it. Endpoints swapped, interfaces
// swapped, direction inverted — and the same community id, because CanonicalTuple
// is direction-independent by design (record.go:258) and that is what makes the
// correlator work at all.
func mirrorNF(community string, bytes, packets uint64, end time.Time, observed time.Time) Record {
	r := baseNF(community, bytes, packets, end, observed)
	r.SrcAddr, r.DstAddr = r.DstAddr, r.SrcAddr
	r.SrcPort, r.DstPort = r.DstPort, r.SrcPort
	r.In, r.Out = r.Out, r.In
	r.Direction = DirectionInbound
	r.Enrich.SrcScope, r.Enrich.DstScope = "remote", "lan"
	return r
}

// #605: the two unidirectional halves of one conversation share a corrKey BY
// DESIGN, and their In/Out/Direction are necessarily mirror images. Counting that
// as a disagreement fired on ordinary bidirectional traffic by construction — 48.6%
// of every fragment the counter could examine on prod — which made it useless for
// the job #590 added it for.
//
// Same precedent as the TCPFlags exclusion: a field that differs by design is not a
// disagreement.
func TestCorrelator_MirrorHalfIsNotADisagreement(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	c.Observe(mirrorNF("cid-A", 200, 2, t0, t0.Add(time.Second)))
	c.Expire(t0.Add(4 * time.Minute))

	st := c.Stats()
	if st.FragmentDisagreements != 0 {
		t.Errorf("FragmentDisagreements = %d, want 0: the reverse half is the expected case, not an anomaly", st.FragmentDisagreements)
	}
	if st.FragmentMirrored != 1 {
		t.Errorf("FragmentMirrored = %d, want 1: the excluded case must still be counted", st.FragmentMirrored)
	}
	if len(sink.recs) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
	}
	if got := sink.recs[0].NF.Bytes(); got != 300 {
		t.Errorf("bytes = %d, want 300: both halves' volume still counts", got)
	}
}

// A fragment that genuinely disagrees — same orientation, different egress — must
// still be counted. Without this the fix above would be indistinguishable from
// deleting the counter.
func TestCorrelator_SameOrientationDisagreementStillCounts(t *testing.T) {
	c, _ := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)
	c.Observe(baseNF("cid-A", 100, 1, t0, t0))
	odd := baseNF("cid-A", 200, 2, t0, t0.Add(time.Second))
	odd.Out = Iface{Device: "ixl1", Name: "WAN2"}
	c.Observe(odd)

	if st := c.Stats(); st.FragmentDisagreements != 1 {
		t.Errorf("FragmentDisagreements = %d, want 1: a same-orientation egress disagreement is the real anomaly", st.FragmentDisagreements)
	}
}

// #605, the headline: the emitted dimensions must be the SAME whichever half
// arrived first. Before the fix, finalize() emitted whichever fragment landed
// first, so 22.5% of merged records on prod described the conversation backwards —
// public source address, inverted interfaces, inverted direction.
//
// Rule 2 of the recorded decision decides this pair: both halves have the same
// Start here, so rule 3 (prefer the local->remote half) settles it.
func TestCorrelator_OrientationIsIndependentOfArrivalOrder(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)

	run := func(t *testing.T, forwardFirst bool) Record {
		t.Helper()
		c, sink := newCorr(t, true, 3*time.Minute, 0)
		fwd := baseNF("cid-A", 100, 1, t0, t0)
		fwd.Enrich.SrcScope, fwd.Enrich.DstScope = "lan", "remote"
		rev := mirrorNF("cid-A", 200, 2, t0, t0.Add(time.Second))
		if forwardFirst {
			c.Observe(fwd)
			c.Observe(rev)
		} else {
			c.Observe(rev)
			c.Observe(fwd)
		}
		c.Expire(t0.Add(4 * time.Minute))
		if len(sink.recs) != 1 {
			t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
		}
		return sink.recs[0]
	}

	a := run(t, true)
	b := run(t, false)

	for _, tc := range []struct {
		name string
		got  Record
	}{{"forward arrived first", a}, {"reverse arrived first", b}} {
		if tc.got.SrcAddr.String() != "192.0.2.10" {
			t.Errorf("%s: SrcAddr = %v, want the local end 192.0.2.10", tc.name, tc.got.SrcAddr)
		}
		if tc.got.Out.Name != "WAN1" {
			t.Errorf("%s: Out.Name = %q, want WAN1", tc.name, tc.got.Out.Name)
		}
		if tc.got.In.Name != "LAN" {
			t.Errorf("%s: In.Name = %q, want LAN", tc.name, tc.got.In.Name)
		}
		if tc.got.Direction != DirectionOutbound {
			t.Errorf("%s: Direction = %v, want outbound", tc.name, tc.got.Direction)
		}
	}
	if a.NF.Bytes() != b.NF.Bytes() || a.NF.Bytes() != 300 {
		t.Errorf("bytes differ by arrival order: %d vs %d, want 300 both ways", a.NF.Bytes(), b.NF.Bytes())
	}
}

// Rule 2 outranks rule 3: the half that STARTED first is the initiator's, so an
// inbound-initiated conversation (a port-forwarded service) must stay inbound
// rather than being flipped outbound by the locality tiebreak. This is the case
// the naive "always orient local->remote" rule would get wrong.
func TestCorrelator_EarliestStartWinsOverLocality(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	// The remote end opened the connection: its half starts a second earlier.
	rev := mirrorNF("cid-A", 200, 2, t0, t0)
	rev.Start = t0.Add(-5 * time.Second)
	fwd := baseNF("cid-A", 100, 1, t0, t0.Add(time.Second))
	fwd.Enrich.SrcScope, fwd.Enrich.DstScope = "lan", "remote"

	c.Observe(fwd) // local half arrives FIRST, and would win on arrival order
	c.Observe(rev)
	c.Expire(t0.Add(4 * time.Minute))

	if len(sink.recs) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
	}
	got := sink.recs[0]
	if got.Direction != DirectionInbound {
		t.Errorf("Direction = %v, want inbound: the remote half started first, so it initiated", got.Direction)
	}
	if got.SrcAddr.String() != "203.0.113.5" {
		t.Errorf("SrcAddr = %v, want the initiator 203.0.113.5", got.SrcAddr)
	}
}

// Rule 1 outranks rule 2: Zenarmor is the only connection-oriented source here, so
// when it states a direction the half matching it wins even against an earlier
// Start. NetFlow's FIRST_SWITCHED is initiation evidence by inference; a conn
// document is initiation evidence by construction.
func TestCorrelator_ZenarmorDirectionPicksTheHalf(t *testing.T) {
	c, sink := newCorr(t, true, 3*time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	rev := mirrorNF("cid-A", 200, 2, t0, t0)
	rev.Start = t0.Add(-5 * time.Second) // would win rule 2
	fwd := baseNF("cid-A", 100, 1, t0, t0.Add(time.Second))
	fwd.Enrich.SrcScope, fwd.Enrich.DstScope = "lan", "remote"

	c.Observe(rev)
	c.Observe(fwd)

	zen := baseZen("cid-A", 480, t0, t0.Add(2*time.Second))
	zen.Direction = DirectionOutbound
	c.Observe(zen)

	c.Expire(t0.Add(4 * time.Minute))
	if len(sink.recs) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(sink.recs))
	}
	got := sink.recs[0]
	if got.Source != SourceMerged {
		t.Fatalf("source = %v, want merged", got.Source)
	}
	if got.Direction != DirectionOutbound {
		t.Errorf("Direction = %v, want outbound: Zenarmor stated it", got.Direction)
	}
	if got.Out.Name != "WAN1" {
		t.Errorf("Out.Name = %q, want WAN1 from the half Zenarmor's direction selected", got.Out.Name)
	}
}
