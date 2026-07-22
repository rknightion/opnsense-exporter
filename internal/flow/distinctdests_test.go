package flow

import (
	"net/netip"
	"testing"
)

// destRec builds a record on interface iface (via In device) to a destination IP.
func destRec(iface, dst string) Record {
	return Record{In: Iface{Device: iface}, DstAddr: netip.MustParseAddr(dst)}
}

func TestDistinctDestsCountsUnique(t *testing.T) {
	d := NewDistinctDests()
	d.Observe(destRec("lan", "1.1.1.1"))
	d.Observe(destRec("lan", "1.1.1.1")) // duplicate: no change
	d.Observe(destRec("lan", "2.2.2.2"))

	if got := d.Snapshot()["lan"]; got != 2 {
		t.Fatalf("distinct = %d, want 2", got)
	}
}

func TestDistinctDestsFoldsMappedV6(t *testing.T) {
	d := NewDistinctDests()
	// ::ffff:1.2.3.4 and 1.2.3.4 are the same host; Unmap must collapse them.
	d.Observe(destRec("lan", "1.2.3.4"))
	d.Observe(destRec("lan", "::ffff:1.2.3.4"))

	if got := d.Snapshot()["lan"]; got != 1 {
		t.Fatalf("mapped v6 duplicate not folded: distinct = %d, want 1", got)
	}
}

func TestDistinctDestsSeparatesInterfaces(t *testing.T) {
	d := NewDistinctDests()
	d.Observe(destRec("lan", "1.1.1.1"))
	d.Observe(destRec("wan", "1.1.1.1")) // same IP, different interface

	got := d.Snapshot()
	if got["lan"] != 1 || got["wan"] != 1 {
		t.Fatalf("per-interface counts wrong: %v", got)
	}
}

func TestDistinctDestsSkipsUnlabelled(t *testing.T) {
	d := NewDistinctDests()
	// No interface resolvable: nothing to attribute the destination to.
	d.Observe(Record{DstAddr: netip.MustParseAddr("1.1.1.1")})
	if len(d.Snapshot()) != 0 {
		t.Fatalf("record with no interface label must not be counted")
	}
}

func TestDistinctDestsCapStopsInserting(t *testing.T) {
	d := NewDistinctDests()
	// Fill exactly to the cap, then one past it.
	for i := range distinctDestsPerIfaceCap {
		d.Observe(destRec("lan", netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()))
	}
	over := d.Snapshot()["lan"]
	if over != distinctDestsPerIfaceCap {
		t.Fatalf("at cap = %d, want %d", over, distinctDestsPerIfaceCap)
	}
	// A brand-new destination beyond the cap is refused; the count holds at the cap.
	d.Observe(destRec("lan", "203.0.113.99"))
	if got := d.Snapshot()["lan"]; got != distinctDestsPerIfaceCap {
		t.Fatalf("cap breached: %d, want %d", got, distinctDestsPerIfaceCap)
	}
}
