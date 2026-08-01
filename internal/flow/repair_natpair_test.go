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

func TestNATPairDifferentVolumeIsNotADuplicate(t *testing.T) {
	// Volume is the evidence: 399 of 399 real pairs matched bytes AND packets
	// exactly. A record that does not match is a different export and must survive.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	if v := r.Repair(natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0), m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT copy verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 9999, t0.Add(2*time.Second))
	if v := r.Repair(post, m, nil, t0.Add(20*time.Second)); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit: never drop what is not PROVEN a duplicate", v)
	}
	if got := r.Stats().NATDuplicatesDropped; got != 0 {
		t.Errorf("NATDuplicatesDropped = %d, want 0", got)
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

func TestNATPairIdentityExpiresPastTheDedupeTTL(t *testing.T) {
	// The arrival gap between the two copies is p99 60s and the TTL is two minutes,
	// which pairs 99.7% of them. Past that the pair is missed — an over-count, which
	// is visible against the interface counter, rather than a wrong drop.
	r := newNATRepairer(t)
	m := natTopology()
	t0 := time.Unix(1700000000, 0)

	if v := r.Repair(natRecord(natLANAddr, 36180, natRemote, 8007, 3048, t0), m, nil, t0); v != RepairEmit {
		t.Fatalf("pre-NAT verdict = %v, want RepairEmit", v)
	}
	post := natRecord(natWANAddr, 42031, natRemote, 8007, 3048, t0)
	late := t0.Add(dedupeTTL + time.Second)
	if v := r.Repair(post, m, nil, late); v != RepairEmit {
		t.Fatalf("verdict = %v, want RepairEmit once the identity has expired", v)
	}
	if got := r.Stats().NATDuplicatesDropped; got != 0 {
		t.Errorf("NATDuplicatesDropped = %d, want 0", got)
	}
}
