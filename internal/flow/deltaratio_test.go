package flow

import "testing"

// merged builds a merged record with both sources present, on a named interface via
// its In device (interfaceLabel falls back to the device when no friendly name).
func merged(iface string, nfBytes, zenBytes uint64) Record {
	return Record{
		Source: SourceMerged,
		In:     Iface{Device: iface},
		NF:     Counters{TxBytes: nfBytes, Present: true},
		Zen:    Counters{TxBytes: zenBytes, Present: true},
	}
}

func TestDeltaRatioIgnoresSingleSource(t *testing.T) {
	d := NewDeltaRatio()
	// NetFlow-only: no Zenarmor side, so no disagreement to measure.
	d.Observe(Record{Source: SourceNetflow, In: Iface{Device: "wan"}, NF: Counters{TxBytes: 100, Present: true}})
	// Zenarmor-only: likewise.
	d.Observe(Record{Source: SourceZenarmor, In: Iface{Device: "wan"}, Zen: Counters{TxBytes: 100, Present: true}})

	if got := d.Snapshot(); len(got) != 0 {
		t.Fatalf("single-source records must not be observed, got %v", got)
	}
}

func TestDeltaRatioAgreementBucket(t *testing.T) {
	d := NewDeltaRatio()
	d.Observe(merged("lan", 1000, 1000)) // ratio exactly 1.0

	h := d.Snapshot()["lan"]
	if h.Count != 1 {
		t.Fatalf("count = %d, want 1", h.Count)
	}
	if h.Sum != 1.0 {
		t.Fatalf("sum = %v, want 1.0", h.Sum)
	}
	// 1.0 is a finite bound, so it is counted at and above le=1, and at every larger
	// bound, but NOT at le=0.9.
	if h.Buckets[0.9] != 0 {
		t.Errorf("le=0.9 = %d, want 0", h.Buckets[0.9])
	}
	if h.Buckets[1] != 1 {
		t.Errorf("le=1 = %d, want 1", h.Buckets[1])
	}
	if h.Buckets[100] != 1 {
		t.Errorf("le=100 (top finite) = %d, want 1", h.Buckets[100])
	}
}

func TestDeltaRatioZeroZenIsOverflow(t *testing.T) {
	d := NewDeltaRatio()
	// Zenarmor present but zero bytes: total blindness, must land in +Inf only.
	d.Observe(merged("wan", 5000, 0))

	h := d.Snapshot()["wan"]
	if h.Count != 1 {
		t.Fatalf("count = %d, want 1", h.Count)
	}
	// Every finite bucket must be empty; the observation shows up only as Count (the
	// implicit +Inf bucket).
	for _, b := range deltaRatioBounds {
		if h.Buckets[b] != 0 {
			t.Errorf("finite le=%v = %d, want 0 (overflow rides in +Inf only)", b, h.Buckets[b])
		}
	}
}

func TestDeltaRatioBucketsAreCumulative(t *testing.T) {
	d := NewDeltaRatio()
	d.Observe(merged("lan", 1000, 1000))  // 1.0  -> le>=1
	d.Observe(merged("lan", 2000, 1000))  // 2.0  -> le>=2
	d.Observe(merged("lan", 40000, 1000)) // 40.0 -> le>=100

	h := d.Snapshot()["lan"]
	if h.Count != 3 {
		t.Fatalf("count = %d, want 3", h.Count)
	}
	// Cumulative: le=1 holds the one ratio<=1; le=2 holds two; le=100 holds all three.
	if h.Buckets[1] != 1 {
		t.Errorf("le=1 = %d, want 1", h.Buckets[1])
	}
	if h.Buckets[2] != 2 {
		t.Errorf("le=2 = %d, want 2", h.Buckets[2])
	}
	if h.Buckets[5] != 2 {
		t.Errorf("le=5 = %d, want 2 (40.0 not yet included)", h.Buckets[5])
	}
	if h.Buckets[100] != 3 {
		t.Errorf("le=100 = %d, want 3", h.Buckets[100])
	}
}

func TestDeltaRatioSeparatesInterfaces(t *testing.T) {
	d := NewDeltaRatio()
	d.Observe(merged("lan", 1000, 1000))
	d.Observe(merged("wan", 3000, 1000))

	got := d.Snapshot()
	if len(got) != 2 {
		t.Fatalf("want 2 interfaces, got %d", len(got))
	}
	if got["lan"].Count != 1 || got["wan"].Count != 1 {
		t.Fatalf("each interface should hold its own single observation: %v", got)
	}
}
