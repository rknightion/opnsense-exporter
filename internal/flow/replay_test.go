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
// box's real WAN2 NAT address (86.31.203.106) to 198.51.100.6, so the map's igb0 must
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
	return BuildIfMap(replayIfaces(), nil, time.Unix(1700000000, 0))
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
	rep := NewRepairer(0)
	p := NewProcessor(sink, rep, nil)
	p.SetIfMap(replayIfMap())
	now := time.Unix(1700000000, 0)
	for _, dg := range dgs {
		p.ObserveDatagram(dg, now)
	}
	return sink.recs, rep.Stats(), p.Stats()
}

// dedupKey is the instance identity the repair keys on: canonical tuple + the flow's
// own First/Last. Two records with this key on a parent and its VLAN child are the
// duplicate pair ng_netflow exports for every tagged packet.
type dedupKey struct {
	tuple       Tuple
	first, last int64
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
			rec.In = m.Iface(nr.InIfIndex)
			k := dedupKey{rec.CanonicalTuple(), rec.Start.UnixNano(), rec.End.UnixNano()}
			if byKey[k] == nil {
				byKey[k] = map[string]int{}
			}
			byKey[k][rec.In.Device]++
		}
	}

	// The case this test models is an instance exported EXACTLY TWICE: once on the
	// trunk and once on one of its VLAN children, and nowhere else. Restricting to
	// that shape is what makes "exactly one survivor" a sound assertion, and the
	// fixture holds 9 such instances.
	//
	// Selecting any instance merely *seen* on ixl0 and some child — as this test did
	// until #350's follow-up — also admits three shapes whose survivor count is
	// legitimately greater than one, so the assertion held for only 9 of 13
	// candidates and the test failed ~40% of runs on Go's randomized map iteration:
	//   - an instance with several copies on the trunk itself (two in this fixture):
	//     same-device copies are not a parent/child pair, so the de-dup rule does not
	//     touch them and all of them correctly survive;
	//   - an instance ALSO exported on an unrelated interface (pppoe0, two here):
	//     that third copy is not proven a duplicate and is correctly kept.
	// Both are correct pipeline behaviour, so the fix is to assert the modelled shape
	// rather than to loosen the count.
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

	// Repaired pass: EVERY such instance must survive exactly once. Asserting over all
	// of them rather than one arbitrary pick is both deterministic and strictly
	// stronger than the single random assertion it replaces.
	recs, rstats, pstats := runReplayPipeline(t)
	survivors := map[dedupKey]int{}
	for _, r := range recs {
		survivors[dedupKey{r.CanonicalTuple(), r.Start.UnixNano(), r.End.UnixNano()}]++
	}
	for _, pair := range pairs {
		if n := survivors[pair]; n != 1 {
			t.Errorf("VLAN-duplicated instance survived %d times, want exactly 1 (one copy must be dropped); "+
				"instance first=%d last=%d", n, pair.first, pair.last)
		}
	}
	if rstats.VLANDuplicatesDropped == 0 {
		t.Fatal("VLANDuplicatesDropped = 0, want > 0")
	}
	if pstats.RecordsDropped != rstats.VLANDuplicatesDropped {
		t.Fatalf("processor dropped %d but repair counted %d VLAN duplicates; they must agree",
			pstats.RecordsDropped, rstats.VLANDuplicatesDropped)
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
	sum := pstats.RecordsEmitted + pstats.RecordsDropped + pstats.RecordsNoAddr
	if sum != pstats.RecordsIn {
		t.Fatalf("emitted(%d)+dropped(%d)+noaddr(%d) = %d, want RecordsIn = %d — every record must land in one bucket",
			pstats.RecordsEmitted, pstats.RecordsDropped, pstats.RecordsNoAddr, sum, pstats.RecordsIn)
	}
}
