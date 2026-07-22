package flow

import (
	"net/netip"
	"testing"
)

// talkerRec builds a Zenarmor-sourced record from src to dst with the given scopes,
// direction and Zenarmor byte volume.
func talkerRec(src, dst, srcScope, dstScope string, dir Direction, zenBytes uint64) Record {
	return Record{
		Source:    SourceZenarmor,
		SrcAddr:   netip.MustParseAddr(src),
		DstAddr:   netip.MustParseAddr(dst),
		Direction: dir,
		Zen:       Counters{TxBytes: zenBytes, Present: true},
		Enrich:    Enrichment{SrcScope: srcScope, DstScope: dstScope},
	}
}

func TestTopTalkersDisabledIsNoop(t *testing.T) {
	tt := NewTopTalkers() // never Configure'd → disabled
	tt.Observe(talkerRec("10.0.0.5", "1.1.1.1", "local", "remote", DirectionOutbound, 500))
	if got := tt.Snapshot(); len(got) != 0 {
		t.Fatalf("disabled accumulator emitted %v", got)
	}
}

func TestTopTalkersHostSelection(t *testing.T) {
	tt := NewTopTalkers()
	tt.Configure(true, SourceZenarmor)

	// Outbound: local source is the talker.
	tt.Observe(talkerRec("10.0.0.5", "1.1.1.1", "local", "remote", DirectionOutbound, 500))
	// Inbound: remote source, local destination → the destination is the talker.
	tt.Observe(talkerRec("8.8.8.8", "10.0.0.6", "remote", "local", DirectionInbound, 700))
	// Transit: neither end local → no talker, skipped.
	tt.Observe(talkerRec("8.8.8.8", "1.1.1.1", "remote", "remote", DirectionUnknown, 900))

	hosts := map[string]uint64{}
	for _, e := range tt.Snapshot() {
		hosts[e.Host] = e.Bytes
	}
	if hosts["10.0.0.5"] != 500 {
		t.Errorf("outbound talker 10.0.0.5 = %d, want 500", hosts["10.0.0.5"])
	}
	if hosts["10.0.0.6"] != 700 {
		t.Errorf("inbound talker 10.0.0.6 = %d, want 700", hosts["10.0.0.6"])
	}
	if _, ok := hosts["8.8.8.8"]; ok {
		t.Errorf("transit flow must not credit a remote host, got %v", hosts)
	}
}

func TestTopTalkersPrimarySourceGuard(t *testing.T) {
	tt := NewTopTalkers()
	tt.Configure(true, SourceZenarmor) // count only Zenarmor

	tt.Observe(talkerRec("10.0.0.5", "1.1.1.1", "local", "remote", DirectionOutbound, 500))
	// A NetFlow record for the same host must be ignored, else the host double-counts.
	nf := talkerRec("10.0.0.5", "1.1.1.1", "local", "remote", DirectionOutbound, 0)
	nf.Source = SourceNetflow
	nf.Zen = Counters{}
	nf.NF = Counters{TxBytes: 500, Present: true}
	tt.Observe(nf)

	for _, e := range tt.Snapshot() {
		if e.Host == "10.0.0.5" && e.Bytes != 500 {
			t.Fatalf("cross-source double-count: 10.0.0.5 = %d, want 500", e.Bytes)
		}
	}
}

func TestTopTalkersFoldExactness(t *testing.T) {
	tt := NewTopTalkers()
	tt.Configure(true, SourceZenarmor)
	tt.topN = 2 // force folding

	// Four outbound hosts with distinct volumes; only the top 2 emit individually.
	tt.Observe(talkerRec("10.0.0.1", "1.1.1.1", "local", "remote", DirectionOutbound, 1000))
	tt.Observe(talkerRec("10.0.0.2", "1.1.1.1", "local", "remote", DirectionOutbound, 800))
	tt.Observe(talkerRec("10.0.0.3", "1.1.1.1", "local", "remote", DirectionOutbound, 600))
	tt.Observe(talkerRec("10.0.0.4", "1.1.1.1", "local", "remote", DirectionOutbound, 400))

	var total uint64
	var other uint64
	named := 0
	for _, e := range tt.Snapshot() {
		total += e.Bytes
		if e.Host == OtherLabel {
			other = e.Bytes
			if e.Direction != "outbound" {
				t.Errorf("__other__ lost its direction: %q", e.Direction)
			}
		} else {
			named++
		}
	}
	if total != 2800 {
		t.Errorf("sum over all series = %d, want 2800 (folding must preserve the total)", total)
	}
	if named != 2 {
		t.Errorf("named series = %d, want 2 (top-N)", named)
	}
	if other != 600+400 {
		t.Errorf("__other__ = %d, want 1000 (the two folded hosts)", other)
	}
}

func TestTopTalkersFoldMonotoneAcrossSnapshots(t *testing.T) {
	tt := NewTopTalkers()
	tt.Configure(true, SourceZenarmor)
	tt.topN = 1

	tt.Observe(talkerRec("10.0.0.1", "1.1.1.1", "local", "remote", DirectionOutbound, 1000))
	tt.Observe(talkerRec("10.0.0.2", "1.1.1.1", "local", "remote", DirectionOutbound, 500))

	first := otherBytes(tt.Snapshot())
	// No new observations: the remainder must not grow on a second snapshot (the
	// watermark must stop the tail folding twice).
	second := otherBytes(tt.Snapshot())
	if first != 500 || second != 500 {
		t.Fatalf("__other__ not stable: first=%d second=%d, want 500 both", first, second)
	}
}

func otherBytes(entries []TalkerEntry) uint64 {
	for _, e := range entries {
		if e.Host == OtherLabel {
			return e.Bytes
		}
	}
	return 0
}
