package flow

// These tests replay the committed golden fixture
// internal/flow/netflow/testdata/replay-v9.bin — a curated, anonymised subset of a
// REAL production capture (811,234 records, #346), produced by cmd/flowanon — through
// the real decoder + ifmap + repair stage. Where repair_test.go drives the repair
// logic with hand-built records, these prove the three repairs against real box
// bytes: the VLAN/parent de-duplication, the policy-routed WAN-egress correction, and
// the multi-fragment community-id that the phase-3 correlator folds on.
//
// The ifIndex map is the one VERIFIED LIVE on the box (#346), reproduced here so the
// anonymised addresses in the fixture resolve to the interfaces they really crossed.
// The one anonymisation-dependent value is WAN2's address: the anonymiser pins the
// box's real WAN2 NAT address (198.51.100.106) to 198.51.100.6, so the map's igb0 must
// own that.

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/flow/netflow"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

const (
	replayFixturePath = "netflow/testdata/replay-v9.bin"
	// wan2AnonAddr is what cmd/flowanon pins the box's real WAN2 (igb0) NAT address to.
	// The egress-correction case turns on the replay ifmap owning it.
	wan2AnonAddr = "198.51.100.6"
)

// replayIfaces reproduces the live #346 ifIndex enumeration (see ifmap_test.go's
// liveIfaces), with igb0/WAN2 owning the fixture's anonymised WAN2 address so
// WANFor resolves the mislabelled flows.
func replayIfaces() []enrich.IfaceInfo {
	return []enrich.IfaceInfo{
		{Device: "ixl0", Name: "LAN", Identifier: "lan", Addrs: addrs("10.0.0.114")}, // 1
		{Device: "ixl1"}, // 2
		{Device: "ixl2"}, // 3
		{Device: "ixl3"}, // 4
		{Device: "igb0", Name: "WAN2", Identifier: "opt5", IsWAN: true, // 5
			Addrs: addrs(wan2AnonAddr)},
		{Device: "igb1"}, // 6
		{Device: "lo0", Name: "loopback", Addrs: addrs("127.0.0.1")}, // 7
		{Device: "enc0"},    // 8
		{Device: "pflog0"},  // 9
		{Device: "pfsync0"}, // 10
		{Device: "ixl0_vlan100", Name: "MGMT", Identifier: "opt1", // 11
			VlanTag: "100", VlanParent: "ixl0", Addrs: addrs("10.100.0.1")},
		{Device: "ixl0_vlan25", Name: "CAM", Identifier: "opt2", // 12
			VlanTag: "25", VlanParent: "ixl0", Addrs: addrs("10.25.0.1")},
		{Device: "ixl0_vlan50", Name: "IOT", Identifier: "opt3", // 13
			VlanTag: "50", VlanParent: "ixl0", Addrs: addrs("10.50.0.1")},
		{Device: "pppoe0", Name: "WAN1", Identifier: "wan", IsWAN: true, // 14
			Addrs: addrs("198.51.100.42")},
	}
}

func replayIfMap() *IfMap {
	return BuildIfMap(IfMapInput{Order: devicesOf(replayIfaces()), Ifaces: replayIfaces(), Built: time.Unix(1700000000, 0)})
}

// readReplayDatagrams decodes every fixture datagram in file order with one decoder,
// so the template cache warms exactly as it would on the wire.
func readReplayDatagrams(t *testing.T) []*netflow.Datagram {
	t.Helper()
	raw, err := os.ReadFile(replayFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	d := netflow.New()
	var dgs []*netflow.Datagram
	off := 0
	for off+13 <= len(raw) {
		nanos := int64(binary.BigEndian.Uint64(raw[off : off+8]))
		alen := int(raw[off+8])
		addr, _ := netip.AddrFromSlice(raw[off+9 : off+9+alen])
		plen := int(binary.BigEndian.Uint32(raw[off+9+alen : off+9+alen+4]))
		start := off + 9 + alen + 4
		if start+plen > len(raw) {
			break
		}
		dg, err := d.Decode(raw[start:start+plen], addr.Unmap(), time.Unix(0, nanos))
		if err != nil {
			t.Fatalf("decode fixture datagram at %d: %v", off, err)
		}
		dgs = append(dgs, dg)
		off = start + plen
	}
	if len(dgs) == 0 {
		t.Fatal("fixture decoded to no datagrams")
	}
	return dgs
}

// runReplayPipeline feeds every fixture datagram through a real Processor + Repairer
// and returns the emitted records and the repair accounting.
func runReplayPipeline(t *testing.T) ([]Record, RepairStats, ProcessorStats) {
	t.Helper()
	dgs := readReplayDatagrams(t)
	sink := &captureSink{}
	rep := NewRepairer(0, 1000)
	p := NewProcessor(sink, rep, nil)
	p.SetIfMap(replayIfMap())
	now := time.Unix(1700000000, 0)
	for _, dg := range dgs {
		p.ObserveDatagram(dg, now)
	}
	// Every datagram is fed at the SAME instant, so nothing ages out of the hold buffer
	// during the run and the whole fixture is resolved by topology rather than by the
	// clock — which is what makes this deterministic. The closing flush is the
	// shutdown path (main.go stopNetflow), and without it a held record would read as a
	// dropped one.
	p.Flush(now)
	return sink.recs, rep.Stats(), p.Stats()
}

// dedupKey is the instance identity the repair keys on: the DIRECTIONAL tuple, the
// flow's own First/Last, and its volume (repair.go instanceKey). Two records with this
// key on a parent and its VLAN child are the duplicate pair ng_netflow exports for
// every tagged packet.
//
// The direction and the volume are what stop the two HALVES of one conversation — same
// canonical tuple, same timestamps, different bytes — from being mistaken for two
// copies of one export (#357).
type dedupKey struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
	first, last  int64
	bytes, pkts  uint64
}

func replayKey(r Record) dedupKey {
	bytes, pkts := volumeOf(r)
	return dedupKey{
		proto: r.Proto,
		src:   r.SrcAddr.Unmap(), dst: r.DstAddr.Unmap(),
		sport: r.SrcPort, dport: r.DstPort,
		first: r.Start.UnixNano(), last: r.End.UnixNano(),
		bytes: bytes, pkts: pkts,
	}
}

// The fixture retains a real VLAN-duplicate pair: one 5-tuple exported with identical
// FIRST/LAST on both ixl0 (the trunk) and one of its VLAN children. The repair must
// drop exactly one copy — the byte total is otherwise inflated ~4% (#346) and the
// traffic is misattributed to the parent interface. This first proves the case is
// genuinely present in the fixture (not vacuously passing), then proves the pipeline
// suppresses it.
func TestReplayRepair_VLANParentDuplicateSuppressed(t *testing.T) {
	m := replayIfMap()
	now := time.Unix(1700000000, 0)

	// Discovery pass: normalize every record WITHOUT repair and COUNT the copies of
	// each instance per device. Counts, not a set: how many copies an instance has on
	// each device is exactly what decides how many may survive, and collapsing that to
	// "seen here" is what made this test pick unassertable candidates.
	byKey := map[dedupKey]map[string]int{}
	for _, dg := range readReplayDatagrams(t) {
		for _, nr := range dg.Records {
			rec, ok := normalizeNetflow(nr, now)
			if !ok {
				continue
			}
			rec.In, rec.Out = m.Iface(nr.InIfIndex), m.Iface(nr.OutIfIndex)
			k := replayKey(rec)
			if byKey[k] == nil {
				byKey[k] = map[string]int{}
			}
			byKey[k][rec.In.Device]++
		}
	}

	// The case this test models is an instance exported EXACTLY TWICE: once on the
	// trunk and once on one of its VLAN children, and nowhere else. Restricting to that
	// shape is what makes "exactly one survivor" a sound assertion.
	//
	// Selecting any instance merely *seen* on ixl0 and some child — as this test did
	// until #350's follow-up — also admitted shapes whose survivor count is legitimately
	// greater than one, so the assertion held for only some candidates and the test
	// failed ~40% of runs on Go's randomized map iteration. Under the #357 key those
	// shapes largely stop colliding in the first place (the two halves of a conversation
	// no longer share a key), but the restriction stays: it is what the assertion below
	// is sound for.
	var pairs []dedupKey
	for k, devs := range byKey {
		if len(devs) != 2 || devs["ixl0"] != 1 {
			continue
		}
		for dev, n := range devs {
			if dev == "ixl0" {
				continue
			}
			if p, ok := m.ParentOf(dev); ok && p == "ixl0" && n == 1 {
				pairs = append(pairs, k)
			}
		}
	}
	if len(pairs) == 0 {
		t.Fatal("fixture no longer retains a VLAN parent/child duplicate pair — the case was lost")
	}

	// Repaired pass: EVERY such instance must survive exactly once, ON THE VLAN CHILD.
	//
	// Which copy survives is the whole of #357. Asserting only the COUNT — as this test
	// did until then — passes just as happily with the trunk copy kept, which is what
	// let the attribution be wrong for as long as it was. On this fixture the trunk copy
	// arrives first in every one of these pairs (the trunk hook and the child hook flush
	// in separate consecutive datagrams), so a first-seen-wins rule fails this outright.
	recs, rstats, pstats := runReplayPipeline(t)
	survivors := map[dedupKey][]Record{}
	for _, r := range recs {
		k := replayKey(r)
		survivors[k] = append(survivors[k], r)
	}
	for _, pair := range pairs {
		got := survivors[pair]
		if len(got) != 1 {
			t.Errorf("VLAN-duplicated instance survived %d times, want exactly 1 (one copy must be dropped); "+
				"instance first=%d last=%d", len(got), pair.first, pair.last)
			continue
		}
		if parent, ok := m.ParentOf(got[0].In.Device); !ok || parent != "ixl0" {
			t.Errorf("VLAN-duplicated instance survived on %q, want the ixl0 VLAN child: keeping the "+
				"trunk copy attributes the VLAN's traffic to the trunk (#357); instance first=%d last=%d",
				got[0].In.Device, pair.first, pair.last)
		}
	}
	if rstats.VLANDuplicatesDropped == 0 {
		t.Fatal("VLANDuplicatesDropped = 0, want > 0")
	}
	if rstats.VLANChildPreferred == 0 {
		t.Fatal("VLANChildPreferred = 0: every pair in this fixture arrives parent-first, so the " +
			"child copy must have replaced a held parent copy at least once")
	}
	if pstats.RecordsDropped != rstats.VLANDuplicatesDropped {
		t.Fatalf("processor dropped %d but repair counted %d VLAN duplicates; they must agree",
			pstats.RecordsDropped, rstats.VLANDuplicatesDropped)
	}
	if pstats.RecordsHeld != 0 {
		t.Fatalf("RecordsHeld = %d after the closing flush, want 0", pstats.RecordsHeld)
	}
}

// The fixture retains the policy-routed WAN mislabel: flows whose source is WAN2's
// (igb0) NAT address but whose OUTPUT_SNMP names pppoe0 (WAN1), because ng_netflow's
// egress comes from a FIB lookup that OPNsense's pf policy routing bypasses (#346).
// The repair must rewrite the egress to WAN2 from the source-address evidence, and
// mark it Corrected so the fix is observable.
func TestReplayRepair_WANEgressCorrected(t *testing.T) {
	recs, rstats, _ := runReplayPipeline(t)
	wan2 := netip.MustParseAddr(wan2AnonAddr)

	corrected := 0
	for _, r := range recs {
		if r.SrcAddr != wan2 {
			continue
		}
		if !r.Out.Corrected {
			t.Errorf("WAN2-sourced flow to %s:%d left egress uncorrected (out=%q)", r.DstAddr, r.DstPort, r.Out.Device)
			continue
		}
		if r.Out.Device != "igb0" || r.Out.Name != "WAN2" {
			t.Errorf("corrected egress = %q/%q, want igb0/WAN2", r.Out.Device, r.Out.Name)
		}
		if r.Direction != DirectionOutbound {
			t.Errorf("WAN2-sourced flow direction = %v, want outbound (its egress is a WAN)", r.Direction)
		}
		corrected++
	}
	if corrected == 0 {
		t.Fatal("fixture no longer retains a WAN2-sourced flow — the egress-mislabel case was lost")
	}
	if rstats.EgressCorrected == 0 {
		t.Fatal("EgressCorrected = 0, want > 0")
	}
}

// The fixture retains a multi-fragment connection: a single conversation exported as
// three or more interim (active-timeout) records. All fragments canonicalise to one
// community-id, which is exactly what lets the phase-3 correlator fold them into one
// flow record. Asserted on the normalized records (before de-dup), because the
// fragment signal is a property of the export, not of the repair.
func TestReplayRepair_MultiFragmentSharesCommunityID(t *testing.T) {
	now := time.Unix(1700000000, 0)
	byCID := map[string]int{}
	for _, dg := range readReplayDatagrams(t) {
		for _, nr := range dg.Records {
			if rec, ok := normalizeNetflow(nr, now); ok {
				byCID[rec.CommunityID]++
			}
		}
	}
	best := 0
	for _, n := range byCID {
		if n > best {
			best = n
		}
	}
	if best < 3 {
		t.Fatalf("largest community-id group = %d records, want >= 3 (the multi-fragment case)", best)
	}
}

// A whole-pipeline sanity check: every input record is accounted for, and the
// fixture exercises real volume, not a single record.
func TestReplayRepair_EveryRecordAccountedFor(t *testing.T) {
	_, _, pstats := runReplayPipeline(t)
	if pstats.RecordsIn < 100 {
		t.Fatalf("RecordsIn = %d, want the fixture's full record volume (>100)", pstats.RecordsIn)
	}
	//nolint:gosec // RecordsHeld is zero here (the pipeline flushed); the identity needs one type
	sum := pstats.RecordsEmitted + pstats.RecordsDropped + pstats.RecordsNoAddr + uint64(pstats.RecordsHeld)
	if sum != pstats.RecordsIn {
		t.Fatalf("emitted(%d)+dropped(%d)+noaddr(%d)+held(%d) = %d, want RecordsIn = %d — every record must land in one bucket",
			pstats.RecordsEmitted, pstats.RecordsDropped, pstats.RecordsNoAddr, pstats.RecordsHeld, sum, pstats.RecordsIn)
	}
}

// The volume the fixture emits, pinned exactly.
//
// #357 changed it, and the acceptance criterion it was filed with ("byte totals
// unchanged") was wrong — the de-duplication was inaccurate in BOTH directions, so
// correcting it moves the total. Every byte of the move is accounted for here, and the
// point of pinning the number is that any FUTURE change to the de-dup rule has to
// explain itself the same way rather than quietly shifting what the exporter reports.
//
// Against the pre-#357 pipeline (118 records, 1,898,159 bytes, 2,123 packets):
//
//	+558 B, +7 pkt   10.0.0.16:8080 -> 10.0.0.15:52231 on ixl0 -> ixl0_vlan50.
//	                 A REAL record, destroyed as a "VLAN duplicate" because the old
//	                 canonical-tuple key folded it onto the 4,907-byte reverse-direction
//	                 record of the same conversation.
//	 -69 B, -1 pkt   10.0.0.5:41302 -> 10.0.0.19:161, and
//	-142 B, -2 pkt   10.0.0.5:50767 -> 10.0.0.20:161.
//	                 Each exported twice with IDENTICAL in/out ifIndex (an inter-VLAN
//	                 flow, where both hooks report trunk -> child), so the old rule
//	                 could not see them as a pair and counted both.
//
// Net +347 B, +4 pkt, and one record fewer.
func TestReplayRepair_EmittedVolumeIsPinned(t *testing.T) {
	const (
		wantRecords = 117
		wantBytes   = 1898506
		wantPackets = 2127
	)

	recs, _, _ := runReplayPipeline(t)
	var bytes, packets uint64
	for _, r := range recs {
		b, p := volumeOf(r)
		bytes += b
		packets += p
	}

	if len(recs) != wantRecords {
		t.Errorf("emitted %d records, want %d", len(recs), wantRecords)
	}
	if bytes != wantBytes {
		t.Errorf("emitted %d bytes, want %d (delta %+d) — the de-dup rule changed what this "+
			"exporter reports; account for every byte before re-pinning this",
			bytes, wantBytes, int64(bytes)-int64(wantBytes))
	}
	if packets != wantPackets {
		t.Errorf("emitted %d packets, want %d (delta %+d)", packets, wantPackets, int64(packets)-int64(wantPackets))
	}
}

// The record the old key destroyed, asserted by identity rather than by a total.
//
// It is the 558-byte half of a conversation whose other half (4,907 bytes, the opposite
// direction, identical First/Last) sits on the VLAN child. Folding the two onto one
// canonical-tuple key made the second one look like the trunk copy of the first, and
// the de-dup dropped it. A NetFlow record is unidirectional: these are two exports, not
// two copies of one.
func TestReplayRepair_OppositeDirectionsAreNotDuplicates(t *testing.T) {
	recs, _, _ := runReplayPipeline(t)

	var forward, reverse int
	for _, r := range recs {
		switch {
		case r.SrcAddr.String() == "10.0.0.15" && r.DstAddr.String() == "10.0.0.16":
			forward++
			if got, _ := volumeOf(r); got != 4907 {
				t.Errorf("forward half = %d bytes, want 4907", got)
			}
		case r.SrcAddr.String() == "10.0.0.16" && r.DstAddr.String() == "10.0.0.15":
			reverse++
			if got, _ := volumeOf(r); got != 558 {
				t.Errorf("reverse half = %d bytes, want 558", got)
			}
		}
	}
	if forward != 1 || reverse != 1 {
		t.Errorf("emitted %d forward and %d reverse records for 10.0.0.15 <-> 10.0.0.16, want 1 of each: "+
			"the two directions of one conversation are two exports, not a duplicate pair", forward, reverse)
	}
}

// The other half of the de-dup's inaccuracy: an inter-VLAN flow whose two copies name
// the SAME ingress and egress ifIndex, because both hooks saw it cross trunk -> child.
// They are indistinguishable by interface, so a rule that requires a trunk/child pair
// cannot see them and counts the bytes twice.
func TestReplayRepair_IdenticalCopiesOnOneInterfacePairCollapse(t *testing.T) {
	recs, _, _ := runReplayPipeline(t)

	counts := map[string]int{}
	for _, r := range recs {
		if r.SrcAddr.String() != "10.0.0.5" {
			continue
		}
		if r.In.Device == "ixl0" && r.Out.Device == "ixl0_vlan100" {
			counts[r.DstAddr.String()]++
		}
	}
	if len(counts) == 0 {
		t.Fatal("fixture no longer retains an inter-VLAN flow exported twice on one interface pair")
	}
	for dst, n := range counts {
		if n != 1 {
			t.Errorf("10.0.0.5 -> %s survived %d times on ixl0 -> ixl0_vlan100, want 1: "+
				"two records identical in tuple, timestamps, volume AND both ifIndexes are one export twice", dst, n)
		}
	}
}
