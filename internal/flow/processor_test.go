package flow

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/flow/netflow"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

type captureSink struct{ recs []Record }

func (c *captureSink) Observe(r Record) { c.recs = append(c.recs, r) }

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

// The reference box's interface table (#346), in ifinfo enumeration order, so the
// derived ifIndexes match the live mapping: 1=ixl0, 5=igb0(WAN2), 13=ixl0_vlan50.
func testIfaces() []enrich.IfaceInfo {
	blank := func(n int) []enrich.IfaceInfo {
		out := make([]enrich.IfaceInfo, n)
		return out
	}
	ifs := []enrich.IfaceInfo{{Device: "ixl0", Name: "LAN", Identifier: "lan"}}
	ifs = append(ifs, blank(3)...) // indices 2-4: unassigned rows still occupy a slot
	ifs = append(ifs, enrich.IfaceInfo{
		Device: "igb0", Name: "WAN2", Identifier: "opt6", IsWAN: true,
		Addrs: []netip.Addr{netip.MustParseAddr("86.31.203.106")},
	})
	ifs = append(ifs, blank(7)...) // indices 6-12
	ifs = append(ifs, enrich.IfaceInfo{
		Device: "ixl0_vlan50", Name: "IOT", Identifier: "opt3",
		VlanTag: "50", VlanParent: "ixl0",
	})
	return ifs
}

func testSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		IfaceNames: map[string]string{"ixl0": "LAN", "igb0": "WAN2", "ixl0_vlan50": "IOT"},
		LocalNets: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		SelfIPs: map[netip.Addr]bool{netip.MustParseAddr("10.0.0.254"): true},
	}
}

func TestNormalizeNetflow_MapsVolumeOntoTheNetFlowCountersOnly(t *testing.T) {
	nr := netflow.Record{
		Proto: 6, Bytes: 24935, Packets: 20,
		SrcAddr: mustAddr(t, "10.0.50.4"), DstAddr: mustAddr(t, "10.0.0.5"),
		SrcPort: 5432, DstPort: 44554,
		First: time.Unix(1784652000, 0), Last: time.Unix(1784652010, 0),
	}
	got, ok := normalizeNetflow(nr, time.Unix(1784652020, 0))
	if !ok {
		t.Fatal("normalize rejected a well-formed record")
	}
	if got.Source != SourceNetflow {
		t.Errorf("Source = %v, want netflow", got.Source)
	}
	// A NetFlow record is unidirectional: all volume is Tx, and Rx staying zero is
	// NOT a claim that the reverse direction carried nothing.
	if got.NF.TxBytes != 24935 || got.NF.RxBytes != 0 || got.NF.TxPackets != 20 || !got.NF.Present {
		t.Errorf("NF counters = %+v, want tx 24935/20, rx 0, present", got.NF)
	}
	if got.Zen.Present {
		t.Error("Zen counters marked present on a NetFlow record")
	}
}

// End defaulting to Start matters for the de-dup, which keys on (tuple, First, Last):
// a zero Last would collapse unrelated instances onto one key.
func TestNormalizeNetflow_EndDefaultsToStart(t *testing.T) {
	nr := netflow.Record{
		SrcAddr: mustAddr(t, "10.0.0.1"), DstAddr: mustAddr(t, "10.0.0.2"),
		First: time.Unix(1784652000, 0),
	}
	got, _ := normalizeNetflow(nr, time.Now())
	if !got.End.Equal(got.Start) {
		t.Errorf("End = %v, want it defaulted to Start %v", got.End, got.Start)
	}
}

func TestNormalizeNetflow_RejectsRecordsWithNoEndpoints(t *testing.T) {
	if _, ok := normalizeNetflow(netflow.Record{DstAddr: mustAddr(t, "10.0.0.2")}, time.Now()); ok {
		t.Error("accepted a record with no source address")
	}
	if _, ok := normalizeNetflow(netflow.Record{SrcAddr: mustAddr(t, "10.0.0.1")}, time.Now()); ok {
		t.Error("accepted a record with no destination address")
	}
}

// A v4-mapped IPv6 address and its plain v4 form are the same host. If they
// canonicalise differently, the correlator misses every join involving one.
func TestNormalizeNetflow_UnmapsSoTheJoinKeyAgrees(t *testing.T) {
	plain, _ := normalizeNetflow(netflow.Record{
		Proto: 6, SrcAddr: mustAddr(t, "10.0.0.1"), DstAddr: mustAddr(t, "10.0.0.2"),
		SrcPort: 1234, DstPort: 443,
	}, time.Now())
	mapped, _ := normalizeNetflow(netflow.Record{
		Proto: 6, SrcAddr: mustAddr(t, "::ffff:10.0.0.1"), DstAddr: mustAddr(t, "::ffff:10.0.0.2"),
		SrcPort: 1234, DstPort: 443,
	}, time.Now())
	if plain.CommunityID != mapped.CommunityID {
		t.Errorf("community id differs for the same host pair:\n plain  %s\n mapped %s",
			plain.CommunityID, mapped.CommunityID)
	}
}

// Tag 0 means UNTAGGED, not "VLAN zero". The de-dup keys off a non-empty tag, so
// rendering 0 as "0" would make every untagged record look like a VLAN record.
func TestNormalizeNetflow_CarriesTheVLANTagAndTreatsZeroAsUntagged(t *testing.T) {
	tagged, _ := normalizeNetflow(netflow.Record{
		SrcAddr: mustAddr(t, "10.0.50.4"), DstAddr: mustAddr(t, "10.0.0.5"), VLANID: 50,
	}, time.Now())
	if tagged.VLANID != "50" {
		t.Errorf("VLANID = %q, want \"50\" — the VLAN de-dup cannot work without it", tagged.VLANID)
	}
	untagged, _ := normalizeNetflow(netflow.Record{
		SrcAddr: mustAddr(t, "10.0.0.4"), DstAddr: mustAddr(t, "10.0.0.5"), VLANID: 0,
	}, time.Now())
	if untagged.VLANID != "" {
		t.Errorf("VLANID = %q for an untagged record, want empty", untagged.VLANID)
	}
}

// The label names the WAN-FACING side, which is what makes per-WAN volume — and
// therefore the policy-routing repair — answerable at all.
func TestInterfaceLabel_NamesTheWANFacingSide(t *testing.T) {
	lan := Iface{Device: "ixl0", Name: "LAN"}
	iot := Iface{Device: "ixl0_vlan50", Name: "IOT"}
	wan := Iface{Device: "igb0", Name: "WAN2"}

	for _, tc := range []struct {
		name string
		rec  Record
		want string
	}{
		{"outbound uses the egress interface", Record{Direction: DirectionOutbound, In: iot, Out: wan}, "WAN2"},
		{"inbound uses the ingress interface", Record{Direction: DirectionInbound, In: wan, Out: lan}, "WAN2"},
		{"internal falls back to egress", Record{Direction: DirectionInternal, In: iot, Out: lan}, "LAN"},
		{"unknown direction still names something", Record{Direction: DirectionUnknown, In: iot}, "IOT"},
		// Phase 1's Zenarmor records set only In, and must keep their old meaning.
		{"zenarmor record is unchanged", Record{Source: SourceZenarmor, Direction: DirectionOutbound, In: iot}, "IOT"},
		{"inbound with no ingress falls back to egress", Record{Direction: DirectionInbound, Out: wan}, "WAN2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := interfaceLabel(tc.rec); got != tc.want {
				t.Errorf("interfaceLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProcessor_EmitsRecordsAndCountsThem(t *testing.T) {
	sink := &captureSink{}
	p := NewProcessor(sink, NewRepairer(100, 1000), nil)
	p.SetIfMap(BuildIfMap(testIfaces(), nil, time.Now()))

	p.ObserveDatagram(&netflow.Datagram{
		Version: netflow.V9,
		Records: []netflow.Record{
			{
				Proto: 6, Bytes: 1000, Packets: 10,
				SrcAddr: mustAddr(t, "10.0.0.5"), DstAddr: mustAddr(t, "93.184.216.34"),
				SrcPort: 40000, DstPort: 443,
				InIfIndex: 1, OutIfIndex: 5,
				First: time.Unix(1784652000, 0), Last: time.Unix(1784652005, 0),
			},
		},
	}, time.Unix(1784652010, 0))

	// The record entered on ixl0, which is a trunk with a VLAN child, so the repair
	// stage HOLDS it: a copy on ixl0_vlan50 could still arrive and beat it (#357). It
	// is accounted for the whole time — held is the fourth term of the identity, not a
	// gap in it.
	if len(sink.recs) != 0 {
		t.Fatalf("sink saw %d records before the hold window elapsed, want 0", len(sink.recs))
	}
	if st := p.Stats(); st.RecordsHeld != 1 || st.RecordsEmitted != 0 {
		t.Fatalf("stats = %+v, want the record held and nothing emitted yet", st)
	}

	p.ReleaseDue(time.Unix(1784652010, 0).Add(vlanHoldWindow))

	if len(sink.recs) != 1 {
		t.Fatalf("sink saw %d records after the hold window, want 1", len(sink.recs))
	}
	st := p.Stats()
	if st.Datagrams != 1 || st.RecordsIn != 1 || st.RecordsEmitted != 1 {
		t.Errorf("stats = %+v, want 1/1/1", st)
	}
	if st.RecordsHeld != 0 {
		t.Errorf("RecordsHeld = %d after the release, want 0", st.RecordsHeld)
	}
	got := sink.recs[0]
	if got.In.Device != "ixl0" || got.Out.Device != "igb0" {
		t.Errorf("interfaces = in %q / out %q, want ixl0 / igb0 — the ifIndex map did not resolve",
			got.In.Device, got.Out.Device)
	}
}

// A record naming no trunk cannot be beaten by a more specific copy, so it must not
// pay the hold window at all: this is what keeps the added latency confined to the
// interfaces that actually have VLAN children.
func TestProcessor_RecordOnNoTrunkEmitsImmediately(t *testing.T) {
	sink := &captureSink{}
	p := NewProcessor(sink, NewRepairer(100, 1000), nil)
	p.SetIfMap(BuildIfMap(testIfaces(), nil, time.Now()))

	p.ObserveDatagram(&netflow.Datagram{
		Version: netflow.V9,
		Records: []netflow.Record{
			{
				Proto: 6, Bytes: 1000, Packets: 10,
				SrcAddr: mustAddr(t, "93.184.216.34"), DstAddr: mustAddr(t, "10.0.0.5"),
				SrcPort: 443, DstPort: 40000,
				InIfIndex: 5, OutIfIndex: 13, // igb0 -> ixl0_vlan50: neither is a trunk
				First: time.Unix(1784652000, 0), Last: time.Unix(1784652005, 0),
			},
		},
	}, time.Unix(1784652010, 0))

	if len(sink.recs) != 1 {
		t.Fatalf("sink saw %d records, want 1 emitted straight away", len(sink.recs))
	}
	if st := p.Stats(); st.RecordsHeld != 0 || st.RecordsEmitted != 1 {
		t.Errorf("stats = %+v, want nothing held and one emitted", st)
	}
}

// The pipeline must not emit a record the repair stage discarded: a VLAN/parent
// duplicate that reaches the sink is counted twice, which is the ~4%-of-bytes bug
// the repair exists to remove.
func TestProcessor_DoesNotEmitWhatTheRepairStageDrops(t *testing.T) {
	sink := &captureSink{}
	p := NewProcessor(sink, NewRepairer(100, 1000), nil)
	p.SetIfMap(BuildIfMap(testIfaces(), nil, time.Now()))

	// A record tagged VLAN 50 but sitting on the PARENT device (ifIndex 1 = ixl0) is
	// by construction the duplicate copy of one captured on ixl0_vlan50.
	p.ObserveDatagram(&netflow.Datagram{
		Records: []netflow.Record{{
			Proto: 6, Bytes: 24935, Packets: 20,
			SrcAddr: mustAddr(t, "10.0.50.4"), DstAddr: mustAddr(t, "10.0.0.5"),
			SrcPort: 5432, DstPort: 44554, VLANID: 50,
			InIfIndex: 1, OutIfIndex: 1,
			First: time.Unix(1784652000, 0), Last: time.Unix(1784652010, 0),
		}},
	}, time.Unix(1784652020, 0))

	if len(sink.recs) != 0 {
		t.Fatalf("sink saw %d records, want 0 — a parent-interface duplicate reached the rollup",
			len(sink.recs))
	}
	if st := p.Stats(); st.RecordsDropped != 1 || st.RecordsEmitted != 0 {
		t.Errorf("stats = %+v, want 1 dropped / 0 emitted", st)
	}
}

func TestProcessor_CountsRecordsWithNoUsableEndpoints(t *testing.T) {
	sink := &captureSink{}
	p := NewProcessor(sink, NewRepairer(100, 1000), nil)
	p.ObserveDatagram(&netflow.Datagram{Records: []netflow.Record{{Proto: 6}}}, time.Now())
	if st := p.Stats(); st.RecordsNoAddr != 1 || st.RecordsEmitted != 0 {
		t.Errorf("stats = %+v, want 1 no-address / 0 emitted", st)
	}
	if len(sink.recs) != 0 {
		t.Error("emitted a record with no endpoints")
	}
}

// A nil map is the pre-first-refresh state, and a nil snapshot is a cold cache.
// Neither may panic, and neither may stop records being counted: an exporter that
// drops flow data until enrichment warms up loses exactly the traffic burst that
// made someone look.
func TestProcessor_SurvivesAColdIfMapAndSnapshot(t *testing.T) {
	sink := &captureSink{}
	p := NewProcessor(sink, NewRepairer(100, 1000), nil)
	p.ObserveDatagram(&netflow.Datagram{
		Records: []netflow.Record{{
			Proto: 17, Bytes: 100, Packets: 1,
			SrcAddr: mustAddr(t, "10.0.0.5"), DstAddr: mustAddr(t, "1.1.1.1"), DstPort: 53,
		}},
	}, time.Now())
	if len(sink.recs) != 1 {
		t.Fatalf("sink saw %d records with no ifmap/snapshot, want 1", len(sink.recs))
	}
	if lbl := sink.recs[0].In.Label(); lbl != "" {
		t.Errorf("interface = %q with no map, want empty — a guessed name is worse than none", lbl)
	}
}

func TestEnrichRecord_ResolvesNamesScopeAndService(t *testing.T) {
	r := Record{
		SrcAddr: mustAddr(t, "10.0.0.5"), DstAddr: mustAddr(t, "93.184.216.34"),
		DstPort: 443, Proto: 6,
		In: Iface{Device: "ixl0_vlan50"},
	}
	enrichRecord(&r, testSnapshot(), nil, time.Time{})

	if r.In.Name != "IOT" {
		t.Errorf("In.Name = %q, want IOT", r.In.Name)
	}
	if r.Enrich.SrcScope != "local" {
		t.Errorf("SrcScope = %q, want local", r.Enrich.SrcScope)
	}
	if r.Enrich.DstScope != "remote" {
		t.Errorf("DstScope = %q, want remote", r.Enrich.DstScope)
	}
	if r.Enrich.DstService != "https" {
		t.Errorf("DstService = %q, want https", r.Enrich.DstService)
	}
}

func TestEnrichRecord_DNSCacheResolvesDomain(t *testing.T) {
	now := time.Unix(1784224500, 0)
	cache := NewDNSCache(100, time.Hour)
	client := mustAddr(t, "10.0.0.5")
	answer := mustAddr(t, "93.184.216.34")
	cache.Put(client, answer, "example.com", now)

	r := Record{SrcAddr: client, DstAddr: answer, DstPort: 443, Proto: 6}
	// A cold snapshot: the domain must still resolve, since the DNS lookup does not
	// depend on the enrichment snapshot.
	enrichRecord(&r, nil, cache, now)

	if r.Enrich.DstDomain != "example.com" {
		t.Fatalf("DstDomain = %q, want example.com", r.Enrich.DstDomain)
	}
}

func TestEnrichRecord_DNSCacheMissLeavesDomainEmpty(t *testing.T) {
	now := time.Unix(1784224500, 0)
	cache := NewDNSCache(100, time.Hour)
	r := Record{SrcAddr: mustAddr(t, "10.0.0.5"), DstAddr: mustAddr(t, "1.2.3.4")}
	enrichRecord(&r, testSnapshot(), cache, now)
	if r.Enrich.DstDomain != "" {
		t.Fatalf("DstDomain = %q, want empty on cache miss", r.Enrich.DstDomain)
	}
}
