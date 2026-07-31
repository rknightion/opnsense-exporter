package flow

import (
	"net/netip"
	"testing"
	"time"
)

// baseNFRev is baseNF's mirror: the same conversation seen from the other end.
// A NetFlow record is strictly unidirectional, so this is a SEPARATE export, and
// before #617 both halves were summed into the same Tx accumulator.
func baseNFRev(community string, bytes, packets uint64, end, observed time.Time) Record {
	r := baseNF(community, bytes, packets, end, observed)
	r.SrcAddr, r.DstAddr = r.DstAddr, r.SrcAddr
	r.SrcPort, r.DstPort = r.DstPort, r.SrcPort
	r.In, r.Out = r.Out, r.In
	r.Direction = DirectionInbound
	return r
}

// #617: a merged record used to report a 2 GB download as 2 GB transmitted and
// nothing received. The forward half's volume belongs in Tx and the mirror's in Rx.
func TestCorrelator_SplitsTheTwoHalvesIntoTxAndRx(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	// The forward half starts first, so orientation rule 2 picks it.
	fwd := baseNF("cid-A", 1_000, 10, t0, t0)
	fwd.Start = t0.Add(-10 * time.Second)
	rev := baseNFRev("cid-A", 9_000, 20, t0, t0)
	rev.Start = t0.Add(-5 * time.Second)

	c.Observe(fwd)
	c.Observe(rev)
	c.Flush()

	if len(sink.recs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(sink.recs))
	}
	got := sink.recs[0].NF
	if got.TxBytes != 1_000 {
		t.Errorf("TxBytes = %d, want 1000 (the chosen orientation's volume)", got.TxBytes)
	}
	if got.RxBytes != 9_000 {
		t.Errorf("RxBytes = %d, want 9000 (the mirror's volume)", got.RxBytes)
	}
	if got.TxPackets != 10 || got.RxPackets != 20 {
		t.Errorf("packets = %d/%d, want 10/20", got.TxPackets, got.RxPackets)
	}
	// The whole point of splitting rather than re-basing: the TOTAL is unchanged, so
	// opnsense_flow_bytes_total (which sums Tx+Rx) does not move for any consumer.
	if got.Bytes() != 10_000 {
		t.Errorf("Bytes() = %d, want 10000 — the total must not move", got.Bytes())
	}
	if got.Packets() != 30 {
		t.Errorf("Packets() = %d, want 30", got.Packets())
	}
}

// #605's property, extended to volume: the split must be the same whichever half
// arrived first. Before #605 there was nothing to split into, because "the forward
// direction" was decided by datagram scheduling.
func TestCorrelator_TheSplitIsIndependentOfArrivalOrder(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	run := func(first, second Record) Counters {
		c, sink := newCorr(t, true, time.Minute, 0)
		c.Observe(first)
		c.Observe(second)
		c.Flush()
		if len(sink.recs) != 1 {
			t.Fatalf("emitted %d records, want 1", len(sink.recs))
		}
		return sink.recs[0].NF
	}

	fwd := baseNF("cid-A", 1_000, 10, t0, t0)
	fwd.Start = t0.Add(-10 * time.Second)
	rev := baseNFRev("cid-A", 9_000, 20, t0, t0)
	rev.Start = t0.Add(-5 * time.Second)

	a := run(fwd, rev)
	b := run(rev, fwd)
	if a != b {
		t.Fatalf("split depends on arrival order: %+v vs %+v", a, b)
	}
	if a.TxBytes != 1_000 || a.RxBytes != 9_000 {
		t.Fatalf("Tx/Rx = %d/%d, want 1000/9000 either way", a.TxBytes, a.RxBytes)
	}
}

// Fragments of the SAME half accumulate into that half. A long flow is re-reported
// per inactive timeout, so this is the ordinary case, not an edge one.
func TestCorrelator_AccumulatesFragmentsWithinEachHalf(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	fwd1 := baseNF("cid-A", 100, 1, t0, t0)
	fwd1.Start = t0.Add(-10 * time.Second)
	fwd2 := baseNF("cid-A", 200, 2, t0, t0.Add(time.Second))
	fwd2.Start = t0.Add(-9 * time.Second)
	rev := baseNFRev("cid-A", 700, 7, t0, t0.Add(2*time.Second))
	rev.Start = t0.Add(-5 * time.Second)

	c.Observe(fwd1)
	c.Observe(fwd2)
	c.Observe(rev)
	c.Flush()

	got := sink.recs[0].NF
	if got.TxBytes != 300 || got.RxBytes != 700 {
		t.Fatalf("Tx/Rx = %d/%d, want 300/700", got.TxBytes, got.RxBytes)
	}
	if got.Bytes() != 1000 {
		t.Fatalf("Bytes() = %d, want 1000", got.Bytes())
	}
}

// A conversation with only one half seen keeps behaving exactly as before: all of
// its volume is Tx, because that is all NetFlow reported.
func TestCorrelator_OneSidedConversationKeepsAllVolumeInTx(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	c.Observe(baseNF("cid-A", 500, 5, t0, t0))
	c.Flush()

	got := sink.recs[0].NF
	if got.TxBytes != 500 || got.RxBytes != 0 {
		t.Fatalf("Tx/Rx = %d/%d, want 500/0", got.TxBytes, got.RxBytes)
	}
}

// A NetFlow record's own RxBytes are always zero on this export (processor.go
// documents it), but if that ever changed the reverse volume must not be silently
// discarded — it rides with the half that reported it.
func TestCorrelator_KeepsAFragmentsOwnRxWithItsOwnHalf(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	fwd := baseNF("cid-A", 100, 1, t0, t0)
	fwd.NF.RxBytes = 7
	fwd.NF.RxPackets = 1
	c.Observe(fwd)
	c.Flush()

	got := sink.recs[0].NF
	if got.Bytes() != 107 {
		t.Fatalf("Bytes() = %d, want 107 — no volume may be dropped", got.Bytes())
	}
}

var _ = netip.Addr{}
