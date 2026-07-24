package flow

import (
	"net/netip"
	"testing"
	"time"
)

func lastSeenRec(src Source, in, out string) Record {
	return Record{
		Source: src, Proto: 6,
		SrcAddr: netip.MustParseAddr("192.0.2.1"), DstAddr: netip.MustParseAddr("198.51.100.1"),
		Direction: DirectionOutbound,
		In:        Iface{Name: in}, Out: Iface{Name: out},
	}
}

func TestLastSeenRecordsArrivalPerInterface(t *testing.T) {
	l := NewLastSeen()
	t0 := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

	l.Observe(lastSeenRec(SourceNetflow, "LAN", "AAISP"), t0)
	l.Observe(lastSeenRec(SourceNetflow, "LAN", "VIRGIN"), t0.Add(30*time.Second))

	got := l.Snapshot()
	if len(got) != 2 {
		t.Fatalf("Snapshot has %d interfaces, want 2: %v", len(got), got)
	}
	if !got["AAISP"].Equal(t0) {
		t.Errorf("AAISP last seen = %v, want %v", got["AAISP"], t0)
	}
	if !got["VIRGIN"].Equal(t0.Add(30 * time.Second)) {
		t.Errorf("VIRGIN last seen = %v, want %v", got["VIRGIN"], t0.Add(30*time.Second))
	}
}

// The label must be the one the volume metrics carry, or the two cannot be joined
// and "this interface is exporting nothing" cannot be lined up against its bytes.
func TestLastSeenUsesTheSameLabelAsTheRollup(t *testing.T) {
	l := NewLastSeen()
	now := time.Now()
	r := lastSeenRec(SourceNetflow, "LAN", "AAISP")

	l.Observe(r, now)

	want := interfaceLabel(r)
	if _, ok := l.Snapshot()[want]; !ok {
		t.Fatalf("Snapshot keyed on %v, want the rollup's label %q", l.Snapshot(), want)
	}
}

// THE load-bearing rule. Zenarmor and NetFlow are independent lanes over the same
// traffic, so a Zenarmor record for an interface would keep its timestamp fresh
// while its ng_netflow hook exports nothing — masking the exact fault this exists
// to surface (#366).
func TestLastSeenIgnoresNonNetflowSources(t *testing.T) {
	l := NewLastSeen()
	now := time.Now()

	l.Observe(lastSeenRec(SourceZenarmor, "LAN", "AAISP"), now)

	if got := l.Snapshot(); len(got) != 0 {
		t.Fatalf("a Zenarmor record registered as a NetFlow sighting: %v", got)
	}
}

// A Zenarmor record must not REFRESH an existing NetFlow timestamp either — the
// masking is the same whether it creates the entry or updates it.
func TestLastSeenZenarmorDoesNotRefreshAnExistingEntry(t *testing.T) {
	l := NewLastSeen()
	t0 := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

	l.Observe(lastSeenRec(SourceNetflow, "LAN", "AAISP"), t0)
	l.Observe(lastSeenRec(SourceZenarmor, "LAN", "AAISP"), t0.Add(time.Hour))

	if got := l.Snapshot()["AAISP"]; !got.Equal(t0) {
		t.Errorf("AAISP last seen = %v after a Zenarmor record, want the NetFlow time %v", got, t0)
	}
}

// An unlabelled record proves nothing about any interface, so it must not create
// an empty-string series.
func TestLastSeenSkipsUnlabelledRecords(t *testing.T) {
	l := NewLastSeen()

	l.Observe(lastSeenRec(SourceNetflow, "", ""), time.Now())

	if got := l.Snapshot(); len(got) != 0 {
		t.Fatalf("an unlabelled record produced %v, want nothing", got)
	}
}

// The interface set comes from the ifIndex map and is small, but the NetFlow
// socket is unauthenticated, so the map is bounded rather than trusted. Crucially
// the cap must never block an UPDATE to an interface already tracked: freezing a
// live interface's timestamp would invent exactly the fault this detects.
func TestLastSeenCapsNewInterfacesButAlwaysUpdatesKnownOnes(t *testing.T) {
	l := NewLastSeen()
	t0 := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

	for i := 0; i < lastSeenIfaceCap+50; i++ {
		l.Observe(lastSeenRec(SourceNetflow, "", "iface"+itoa(i)), t0)
	}
	if got := len(l.Snapshot()); got != lastSeenIfaceCap {
		t.Fatalf("tracked %d interfaces, want the cap %d", got, lastSeenIfaceCap)
	}

	// iface0 was admitted before the cap was reached; its timestamp must still move.
	l.Observe(lastSeenRec(SourceNetflow, "", "iface0"), t0.Add(time.Hour))
	if got := l.Snapshot()["iface0"]; !got.Equal(t0.Add(time.Hour)) {
		t.Errorf("iface0 last seen = %v, want %v; the cap froze a known interface",
			got, t0.Add(time.Hour))
	}
}

// Snapshot hands out a copy: a caller mutating it must not corrupt the tracker.
func TestLastSeenSnapshotIsACopy(t *testing.T) {
	l := NewLastSeen()
	t0 := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	l.Observe(lastSeenRec(SourceNetflow, "", "AAISP"), t0)

	snap := l.Snapshot()
	delete(snap, "AAISP")

	if _, ok := l.Snapshot()["AAISP"]; !ok {
		t.Fatal("mutating a Snapshot mutated the tracker")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
