package flow

import (
	"testing"
	"time"
)

// #604 problem 2: a connection longer than the correlator window emits one record
// per window carrying only THAT window's NetFlow bytes, while the single Zenarmor
// conn document carries the WHOLE connection's counters and merges into whichever
// bucket its End falls in. The resulting ratio reads "Zenarmor counted 75x more
// bytes than crossed the wire", which is impossible — it is a partial total against
// a complete one, and it accounted for 3.2% of merged records and 12.3% of the
// default WAN's on the reference box. The byte and packet figures below are one of
// the live examples recorded on #604 verbatim (nf=210 nfp=3 zen=15718 zenp=239,
// ratio 0.013), not a synthesised shape.
func TestDeltaRatio_ExcludesWindowPartialRecords(t *testing.T) {
	d := NewDeltaRatio()

	partial := Record{
		Source: SourceMerged,
		NF:     Counters{TxBytes: 210, TxPackets: 3, Present: true},
		Zen:    Counters{TxBytes: 15718, TxPackets: 239, Present: true},
		Out:    Iface{Device: "pppoe0", Name: "WAN1"},
		// Direction drives which side interfaceLabel reads.
		Direction: DirectionOutbound,
		Repairs:   Repairs{WindowPartial: true},
	}
	d.Observe(partial)

	if got := len(d.Snapshot()); got != 0 {
		t.Fatalf("Snapshot has %d interfaces, want 0 — a window-partial record must not be observed", got)
	}
	if got := d.Excluded(); got != 1 {
		t.Fatalf("Excluded = %d, want 1 — exclusions must be counted, never silent", got)
	}

	whole := partial
	whole.Repairs.WindowPartial = false
	d.Observe(whole)
	if got := d.Snapshot()["WAN1"].Count; got != 1 {
		t.Fatalf("whole-connection record: Count = %d, want 1", got)
	}
	if got := d.Excluded(); got != 1 {
		t.Fatalf("Excluded = %d, want 1 unchanged", got)
	}
}

// #604 problem 1: the payload-vs-wire basis is NOT excluded — it is marked. Roughly
// half of all Zenarmor flow records fall back to payload bytes, and dropping them
// would delete the population the metric is most often asked about. The record
// carries the basis instead, so a consumer can tell wire-vs-wire from payload-vs-wire.
//
// The numbers are the measured shape from the live box, not invented: a 2-packet UDP
// flow where the NetFlow-minus-Zenarmor gap is exactly 28 bytes per packet, the IPv4
// IP+UDP header. 184 - 128 = 56 = 2 x 28.
func TestDeltaRatio_KeepsPayloadBasisRecordsButTheyAreMarked(t *testing.T) {
	d := NewDeltaRatio()
	rec := Record{
		Source:    SourceMerged,
		NF:        Counters{TxBytes: 184, TxPackets: 2, Present: true},
		Zen:       Counters{TxBytes: 128, TxPackets: 2, Present: true},
		Out:       Iface{Device: "pppoe0", Name: "WAN1"},
		Direction: DirectionOutbound,
		Repairs:   Repairs{ZenBytesArePayload: true},
	}
	d.Observe(rec)

	if got := d.Snapshot()["WAN1"].Count; got != 1 {
		t.Fatalf("Count = %d, want 1 — a payload-basis record still belongs in the histogram", got)
	}
	if got := d.Excluded(); got != 0 {
		t.Fatalf("Excluded = %d, want 0", got)
	}
}

// The correlator is what knows a record is a window partial, because only it holds
// the bucket arithmetic. The discriminator is the ZENARMOR side's own span: a conn
// document whose [Start, End] crosses a window boundary describes a connection the
// NetFlow side is bucketed across, so this bucket's NetFlow total cannot be the
// whole of it.
func TestCorrelator_MarksAWindowPartialMerge(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	c.Observe(baseNF("cid-A", 210, 3, t0, t0))
	// The conn document opened 90 seconds earlier and closed now: with a 60s window
	// its span crosses at least one boundary, so the NetFlow side in this bucket
	// carries only part of what the conn document counts.
	zen := baseZen("cid-A", 15718, t0, t0)
	zen.Start = t0.Add(-90 * time.Second)
	c.Observe(zen)
	c.Flush()

	if len(sink.recs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(sink.recs))
	}
	if sink.recs[0].Source != SourceMerged {
		t.Fatalf("Source = %v, want merged", sink.recs[0].Source)
	}
	if !sink.recs[0].Repairs.WindowPartial {
		t.Error("Repairs.WindowPartial = false on a conn document spanning more than one window")
	}
}

func TestCorrelator_DoesNotMarkAWholeConnectionMerge(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	c.Observe(baseNF("cid-A", 1000, 8, t0, t0))
	zen := baseZen("cid-A", 900, t0, t0)
	zen.Start = t0.Add(-2 * time.Second)
	c.Observe(zen)
	c.Flush()

	if len(sink.recs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(sink.recs))
	}
	if sink.recs[0].Repairs.WindowPartial {
		t.Error("Repairs.WindowPartial = true on a connection wholly inside one window")
	}
}

// The Zenarmor lane sets PayloadByteFallback on its own record, but finalize()
// builds the merged record from a NETFLOW half — so without carrying it explicitly
// the basis marker is lost on precisely the record the ratio is computed from.
func TestCorrelator_CarriesTheZenarmorByteBasisOntoTheMerge(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	c.Observe(baseNF("cid-A", 184, 2, t0, t0))
	zen := baseZen("cid-A", 128, t0, t0)
	zen.Start = t0
	zen.Repairs.PayloadByteFallback = true
	c.Observe(zen)
	c.Flush()

	if len(sink.recs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(sink.recs))
	}
	if !sink.recs[0].Repairs.ZenBytesArePayload {
		t.Error("Repairs.ZenBytesArePayload = false; the merged record must state its own byte basis")
	}
}

// A repair applied to ONE fragment must survive the merge. finalize() takes
// every non-volume dimension from the chosen orientation, so a marker set on the
// other half — or on a later fragment of the same half — vanished silently. That
// is the same class of loss #604 fixed for the byte basis, and it hit the
// policy-route marker (#603) on any conversation whose corrected fragment was not
// the one orientation() picked.
func TestCorrelator_UnionsRepairMarkersAcrossFragments(t *testing.T) {
	c, sink := newCorr(t, true, time.Minute, 0)
	t0 := time.Unix(1_700_000_000, 0)

	// The chosen orientation (earlier Start) carries NO marker.
	fwd := baseNF("cid-A", 100, 1, t0, t0)
	fwd.Start = t0.Add(-10 * time.Second)
	c.Observe(fwd)

	// A later fragment of the same conversation was policy-route corrected.
	other := baseNF("cid-A", 200, 2, t0, t0.Add(time.Second))
	other.Start = t0.Add(-5 * time.Second)
	other.Repairs.PolicyRouteCorrected = true
	other.Repairs.VLANSubnetAttributed = true
	c.Observe(other)

	c.Flush()
	if len(sink.recs) != 1 {
		t.Fatalf("emitted %d records, want 1", len(sink.recs))
	}
	got := sink.recs[0].Repairs
	if !got.PolicyRouteCorrected {
		t.Error("PolicyRouteCorrected lost at merge; a repair nobody can observe is a repair nobody will trust")
	}
	if !got.VLANSubnetAttributed {
		t.Error("VLANSubnetAttributed lost at merge")
	}
}
