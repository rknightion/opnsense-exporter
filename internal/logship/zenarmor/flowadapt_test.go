package zenarmor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/flow"
	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// Flow fixtures. Unlike the documents in fixtures_test.go — which are verbatim
// production records captured before this rule existed — these are ANONYMISED. Each
// is derived from a real bucket of the 2026-07-21 capture (20,476 conn documents),
// with every address rewritten into RFC 5737 / RFC 3849 documentation space and
// hostnames/MACs stripped. The raw corpus stays in ~/flow-captures and is never
// committed: it is a real home network's addressing.
//
// Field shapes, byte/packet values and the is_local/direction/vlanid combinations
// are preserved exactly, because those are what the assertions turn on.
//
// flowSnapshot below declares 192.0.2.0/24 as the LAN, 198.18.50.0/24 as the IOT
// VLAN and 2001:db8:1::/64 as the LAN's IPv6 prefix, so "local" and "remote" come
// out of the firewall's own topology rather than out of any real address.

// Bucket (is_local=0, src local, dst remote) — 5,398 of 20,476. The ordinary case.
const flowLANToInternet = `{"transport_proto":"TCP","interface":"ixl0","vlanid":"0","direction":"out","is_local":0,"ip_src_saddr":"192.0.2.50","ip_src_port":49812,"src_dir":"EGRESS","ip_dst_saddr":"203.0.113.12","ip_dst_port":443,"dst_dir":"INGRESS","is_blocked":0,"src_npackets":12,"src_nbytes":1804,"src_pbytes":940,"dst_npackets":18,"dst_nbytes":23110,"dst_pbytes":21430,"start_time":1784656700000,"end_time":1784656707000,"app_proto":"HTTPS","app_name":"Secure Web Browsing","app_category":"Secure Web Browsing","community_id":"1:aaaaaaaaaaaaaaaaaaaaaaaaaaa="}`

// Bucket (is_local=1, src REMOTE, dst local) — 556 of 20,476, and the reason
// #346 comment 2's "is_local==1 means internal" rule is wrong. This is inbound
// traffic from the internet, tagged "Local Bound" because it is bound FOR a local
// host.
const flowInternetToLAN = `{"transport_proto":"TCP","interface":"ixl0","vlanid":"0","direction":"in","is_local":1,"ip_src_saddr":"203.0.113.99","ip_src_port":36971,"src_dir":"INGRESS","ip_dst_saddr":"192.0.2.5","ip_dst_port":6881,"dst_dir":"EGRESS","is_blocked":0,"src_npackets":1,"src_nbytes":66,"src_pbytes":0,"dst_npackets":3,"dst_nbytes":802,"dst_pbytes":604,"start_time":1784656706000,"end_time":1784656707000,"app_proto":"HTTPS","app_name":"BitTorrent","app_category":"File Transfer","tags":["Local Bound"]}`

// Bucket (is_local=1, both local) — 10,846 of 20,476. The destination is the
// firewall itself, so its scope is "self", which is NOT remote: a LAN host querying
// the box's own resolver is internal traffic, and v1's scope logic called it
// outbound.
const flowLANToSelf = `{"transport_proto":"UDP","interface":"ixl0","vlanid":"0","direction":"out","is_local":1,"ip_src_saddr":"192.0.2.114","ip_src_port":55309,"ip_dst_saddr":"192.0.2.254","ip_dst_port":53,"is_blocked":0,"src_npackets":1,"src_nbytes":94,"src_pbytes":66,"dst_npackets":1,"dst_nbytes":150,"dst_pbytes":122,"start_time":1784656700000,"end_time":1784656701000,"app_proto":"DNS","app_name":"DNS","app_category":"Network Management"}`

// A VLAN-tagged flow: interface is the PARENT device (it is "ixl0" on all 20,476
// documents) and the tag lives in vlanid. 2,906 documents carry vlanid=50.
const flowVLANTagged = `{"transport_proto":"TCP","interface":"ixl0","vlanid":"50","direction":"out","is_local":0,"ip_src_saddr":"198.18.50.7","ip_src_port":51200,"ip_dst_saddr":"203.0.113.20","ip_dst_port":443,"is_blocked":0,"src_npackets":9,"src_nbytes":1200,"src_pbytes":700,"dst_npackets":11,"dst_nbytes":9400,"dst_pbytes":8800,"start_time":1784656700000,"end_time":1784656705000,"app_proto":"HTTPS","app_name":"Microsoft","app_category":"Cloud Services"}`

// Bucket (is_local=1, src local, dst "remote") — 538 documents, all of them a local
// host talking to a multicast group. The destination is not in any configured
// subnet, so scope alone calls it remote; it never leaves the L2 domain.
const flowMulticastSSDP = `{"transport_proto":"UDP","interface":"ixl0","vlanid":"50","direction":"out","is_local":1,"ip_src_saddr":"198.18.50.144","ip_src_port":49155,"ip_dst_saddr":"239.255.255.250","ip_dst_port":1900,"is_blocked":0,"src_npackets":2,"src_nbytes":0,"src_pbytes":344,"dst_npackets":0,"dst_nbytes":0,"dst_pbytes":0,"start_time":1784656700000,"end_time":1784656700000,"app_proto":"SSDP","app_name":"SSDP","app_category":"Network Management"}`

// nbytes==0 with packets>0: 10,682 of 38,722 flow-sides (27.6%), exclusively UDP at
// one or two packets. Without the payload-byte fallback this document reports zero
// bytes while records_total counts it.
const flowZeroNBytes = `{"transport_proto":"UDP","interface":"ixl0","vlanid":"0","direction":"out","is_local":0,"ip_src_saddr":"192.0.2.50","ip_src_port":40404,"ip_dst_saddr":"203.0.113.53","ip_dst_port":53,"is_blocked":0,"src_npackets":1,"src_nbytes":0,"src_pbytes":74,"dst_npackets":1,"dst_nbytes":0,"dst_pbytes":90,"start_time":1784656700000,"end_time":1784656700000,"app_proto":"DNS","app_name":"DNS","app_category":"Network Management"}`

// transport_proto "TCP6" — 1,465 documents, plus 1,871 "UDP6". 16.3% of the corpus.
// is_local is 0 here even though the source is a LAN host, because Zenarmor's local
// networks are RFC1918 only and miss the LAN's IPv6 prefix entirely — 3,137
// documents. The firewall's own LocalNets do know it.
const flowTCP6GUA = `{"transport_proto":"TCP6","interface":"ixl0","vlanid":"0","direction":"out","is_local":0,"ip_src_saddr":"2001:db8:1::1038","ip_src_port":52000,"ip_dst_saddr":"2001:db8:ffff::10","ip_dst_port":443,"is_blocked":0,"src_npackets":20,"src_nbytes":3000,"src_pbytes":1800,"dst_npackets":40,"dst_nbytes":58000,"dst_pbytes":55000,"start_time":1784656700000,"end_time":1784656710000,"app_proto":"HTTPS","app_name":"Claude","app_category":"Web Browsing"}`

// DELIBERATELY SYNTHETIC: is_blocked was 0 on all 20,476 captured documents, so no
// real blocked conn record exists to anonymise. This pins parser behaviour, not a
// captured payload.
const flowBlockedSynthetic = `{"transport_proto":"UDP","interface":"ixl0","vlanid":"0","direction":"out","is_local":0,"ip_src_saddr":"192.0.2.60","ip_src_port":33333,"ip_dst_saddr":"203.0.113.66","ip_dst_port":123,"is_blocked":1,"src_npackets":1,"src_nbytes":90,"src_pbytes":48,"start_time":1784656700000,"end_time":1784656700000,"app_proto":"NTP","app_name":"NTP","app_category":"Network Management"}`

// flowSnapshot is the firewall topology the fixtures are read against. Everything
// in it is documentation-range, so the local/remote split is a property of this
// table rather than of any real network.
func flowSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		IfaceNames: map[string]string{
			"ixl0":         "LAN",
			"ixl0_vlan50":  "IOT",
			"ixl0_vlan100": "MGMT",
		},
		LocalNets: []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("198.18.50.0/24"),
			netip.MustParsePrefix("2001:db8:1::/64"),
		},
		SelfIPs: map[netip.Addr]bool{netip.MustParseAddr("192.0.2.254"): true},
	}
}

func flowDoc(t *testing.T, family, doc string) *zenDoc {
	t.Helper()
	_, d, parsed := parseDocFull(family, []byte(doc), nil)
	if !parsed || d == nil {
		t.Fatalf("fixture did not decode: %s", doc)
	}
	return d
}

func mustFlow(t *testing.T, doc string) flow.Record {
	t.Helper()
	r, ok := flowFromDoc("flow", flowDoc(t, "flow", doc), flowSnapshot(), nil, time.Unix(1784656800, 0))
	if !ok {
		t.Fatal("a well-formed conn document must produce a flow record")
	}
	return r
}

func TestFlowFromDoc_MapsCountersBothDirections(t *testing.T) {
	r := mustFlow(t, flowLANToInternet)
	if !r.Zen.Present {
		t.Fatal("Zen counters must be marked Present")
	}
	if r.Zen.TxBytes != 1804 || r.Zen.RxBytes != 23110 {
		t.Fatalf("bytes = tx %d rx %d, want 1804/23110", r.Zen.TxBytes, r.Zen.RxBytes)
	}
	if r.Zen.TxPackets != 12 || r.Zen.RxPackets != 18 {
		t.Fatalf("packets = tx %d rx %d, want 12/18", r.Zen.TxPackets, r.Zen.RxPackets)
	}
	if r.NF.Present {
		t.Fatal("NetFlow counters must be absent on a Zenarmor-only record")
	}
	if r.Source != flow.SourceZenarmor {
		t.Fatalf("Source = %v, want zenarmor", r.Source)
	}
	if !r.End.Equal(time.UnixMilli(1784656707000)) {
		t.Fatalf("End = %v, want the document's end_time", r.End)
	}
	if !r.Observed.Equal(time.Unix(1784656800, 0)) {
		t.Fatalf("Observed = %v, want the arrival time passed in", r.Observed)
	}
}

// The family guard. flowFromDoc applied to all six families would inflate
// records_total by ~64% and roll up documents that carry no byte fields at all.
func TestFlowFromDoc_OnlyAcceptsTheFlowFamily(t *testing.T) {
	for _, family := range []string{"dns", "tls", "web", "ids", "voip", ""} {
		d := flowDoc(t, family, flowLANToInternet) // shape is irrelevant; the family is the gate
		if _, ok := flowFromDoc(family, d, flowSnapshot(), nil, time.Now()); ok {
			t.Fatalf("family %q must not produce a flow record", family)
		}
	}
}

func TestFlowFromDoc_RejectsUnusableInput(t *testing.T) {
	if _, ok := flowFromDoc("flow", nil, flowSnapshot(), nil, time.Now()); ok {
		t.Fatal("a nil document must not produce a flow record")
	}
	// A document with no parseable endpoints is not a flow; emitting one would put a
	// zero-address series into the rollup.
	noEndpoints := flowDoc(t, "flow", `{"transport_proto":"TCP","interface":"ixl0"}`)
	if _, ok := flowFromDoc("flow", noEndpoints, flowSnapshot(), nil, time.Now()); ok {
		t.Fatal("a document with no addresses must not produce a flow record")
	}
	halfEndpoints := flowDoc(t, "flow", `{"transport_proto":"TCP","ip_src_saddr":"192.0.2.1"}`)
	if _, ok := flowFromDoc("flow", halfEndpoints, flowSnapshot(), nil, time.Now()); ok {
		t.Fatal("a document with only one address must not produce a flow record")
	}
}

// THE correction from the live corpus. Zenarmor's is_local is 1 on this document
// and #346 comment 2 bound that to mean "internal", but it is inbound traffic from
// the internet: is_local means "bound to or from a local host", and 1,094 of 11,940
// is_local=1 documents have a non-local endpoint.
func TestFlowFromDoc_DirectionInternetToLANIsInboundNotInternal(t *testing.T) {
	r := mustFlow(t, flowInternetToLAN)
	if r.Direction != flow.DirectionInbound {
		t.Fatalf("Direction = %v, want inbound — is_local=1 does NOT mean internal", r.Direction)
	}
	if r.Enrich.SrcScope != "remote" || r.Enrich.DstScope != "local" {
		t.Fatalf("scopes = %q -> %q, want remote -> local", r.Enrich.SrcScope, r.Enrich.DstScope)
	}
}

func TestFlowFromDoc_DirectionCases(t *testing.T) {
	for _, c := range []struct {
		name string
		doc  string
		want flow.Direction
	}{
		{"lan to internet", flowLANToInternet, flow.DirectionOutbound},
		{"internet to lan", flowInternetToLAN, flow.DirectionInbound},
		// The firewall itself is "self", not "remote": a LAN host querying the box's
		// resolver is internal. v1's scope logic labelled this outbound.
		{"lan to firewall", flowLANToSelf, flow.DirectionInternal},
		// Never leaves the L2 domain, even though the group address is in no subnet.
		{"lan to multicast", flowMulticastSSDP, flow.DirectionInternal},
		// Zenarmor says is_local=0 because its local nets are RFC1918 only; the
		// firewall's own LocalNets know the LAN's IPv6 prefix, so the source is local
		// and the direction still resolves to outbound.
		{"ipv6 gua to internet", flowTCP6GUA, flow.DirectionOutbound},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := mustFlow(t, c.doc).Direction; got != c.want {
				t.Fatalf("Direction = %v, want %v", got, c.want)
			}
		})
	}
}

// With no snapshot there is no topology, so "internal" cannot be established and
// the record falls back to Zenarmor's stated direction rather than guessing.
func TestFlowFromDoc_DirectionWithoutSnapshotFallsBackToZenarmor(t *testing.T) {
	r, ok := flowFromDoc("flow", flowDoc(t, "flow", flowLANToSelf), nil, nil, time.Now())
	if !ok {
		t.Fatal("a nil snapshot must not prevent a record")
	}
	if r.Direction != flow.DirectionOutbound {
		t.Fatalf("Direction = %v, want outbound from the document's own field", r.Direction)
	}
	if r.Enrich.SrcScope != "" || r.In.Name != "" {
		t.Fatal("no snapshot means no enrichment, not invented enrichment")
	}
}

// A document stating no direction at all, with no topology to fall back on, must
// stay unknown rather than being assigned one.
func TestFlowFromDoc_DirectionUnknownWhenNothingStatesIt(t *testing.T) {
	d := flowDoc(t, "flow", `{"transport_proto":"TCP","ip_src_saddr":"203.0.113.1","ip_src_port":1,"ip_dst_saddr":"203.0.113.2","ip_dst_port":2}`)
	r, ok := flowFromDoc("flow", d, nil, nil, time.Now())
	if !ok {
		t.Fatal("expected a record")
	}
	if r.Direction != flow.DirectionUnknown {
		t.Fatalf("Direction = %v, want unknown", r.Direction)
	}
}

// Zenarmor reports the PARENT device on every conn document and puts the tag in a
// separate field, so enriching on `interface` alone resolves 20.5% of flows to the
// parent's name and makes the label single-valued.
func TestFlowFromDoc_SynthesisesTheVLANChildDevice(t *testing.T) {
	r := mustFlow(t, flowVLANTagged)
	if r.In.Device != "ixl0_vlan50" {
		t.Fatalf("In.Device = %q, want ixl0_vlan50", r.In.Device)
	}
	if r.In.Name != "IOT" {
		t.Fatalf("In.Name = %q, want IOT — the child device must resolve, not the parent", r.In.Name)
	}
	if r.In.Label() != "IOT" {
		t.Fatalf("Label() = %q, want IOT", r.In.Label())
	}
	if r.VLANID != "50" {
		t.Fatalf("VLANID = %q, want 50", r.VLANID)
	}
	// An untagged flow keeps the parent device and the parent's name.
	if r := mustFlow(t, flowLANToInternet); r.In.Device != "ixl0" || r.In.Name != "LAN" {
		t.Fatalf("untagged flow = %q/%q, want ixl0/LAN", r.In.Device, r.In.Name)
	}
}

// An unmapped device yields no name rather than a guessed one: a wrong interface
// label is worse than a missing one.
func TestFlowFromDoc_UnknownDeviceYieldsNoName(t *testing.T) {
	snap := flowSnapshot()
	delete(snap.IfaceNames, "ixl0_vlan50")
	r, _ := flowFromDoc("flow", flowDoc(t, "flow", flowVLANTagged), snap, nil, time.Now())
	if r.In.Name != "" {
		t.Fatalf("In.Name = %q, want empty for an unmapped device", r.In.Name)
	}
	if r.In.Label() != "ixl0_vlan50" {
		t.Fatalf("Label() = %q, want the raw device", r.In.Label())
	}
}

// nbytes is wire bytes and wins where it is present, but Zenarmor leaves it at zero
// on short UDP flows. Without the fallback, 1,756 of 20,476 documents (8.6%) report
// zero bytes while records_total counts them.
func TestFlowFromDoc_FallsBackToPayloadBytesWhenNBytesIsZero(t *testing.T) {
	r := mustFlow(t, flowZeroNBytes)
	if r.Zen.TxBytes != 74 || r.Zen.RxBytes != 90 {
		t.Fatalf("bytes = %d/%d, want the payload counts 74/90", r.Zen.TxBytes, r.Zen.RxBytes)
	}
	if !r.Repairs.PayloadByteFallback {
		t.Fatal("the fallback must be flagged so it can be counted; a silent repair is untrustworthy")
	}
	// nbytes wins wherever it is present, and the fallback is NOT flagged.
	full := mustFlow(t, flowLANToInternet)
	if full.Zen.TxBytes != 1804 {
		t.Fatalf("bytes = %d, want the wire count 1804, not the payload count", full.Zen.TxBytes)
	}
	if full.Repairs.PayloadByteFallback {
		t.Fatal("the fallback must not be flagged when nbytes was present")
	}
	// One side falling back is enough to flag the record: flowInternetToLAN has
	// src_nbytes=66 with src_pbytes=0, and dst_nbytes=802 — no side is zero-with-
	// payload, so this must NOT flag.
	if mustFlow(t, flowInternetToLAN).Repairs.PayloadByteFallback {
		t.Fatal("a side with nbytes>0 and pbytes==0 is not a fallback")
	}
}

// A genuinely empty side (no bytes and no payload either) stays zero and triggers
// no fallback, while the other side of the same document falls back normally.
func TestFlowFromDoc_EmptySideStaysZeroWhileTheOtherFallsBack(t *testing.T) {
	r := mustFlow(t, flowMulticastSSDP)
	if r.Zen.TxBytes != 344 || r.Zen.RxBytes != 0 {
		t.Fatalf("bytes = %d/%d, want 344/0", r.Zen.TxBytes, r.Zen.RxBytes)
	}
	if !r.Repairs.PayloadByteFallback {
		t.Fatal("the src side fell back from nbytes=0 to pbytes=344 and must be flagged")
	}
}

// transport_proto carries TCP6 and UDP6 on 16.3% of documents. Missing them puts
// every IPv6 flow on transport="other".
func TestFlowFromDoc_ProtocolNames(t *testing.T) {
	for in, want := range map[string]uint8{
		"TCP": 6, "tcp": 6, "TCP6": 6, "tcp6": 6,
		"UDP": 17, "UDP6": 17,
		"ICMP": 1, "ICMP6": 58, "ICMPV6": 58, "IPV6-ICMP": 58,
		"GRE": 47, "ESP": 50, "SCTP": 132,
		"": 0, "nonsense": 0,
	} {
		if got := protoNumber(in); got != want {
			t.Errorf("protoNumber(%q) = %d, want %d", in, got, want)
		}
	}
	if got := mustFlow(t, flowTCP6GUA).Proto; got != 6 {
		t.Fatalf("TCP6 fixture gave proto %d, want 6", got)
	}
}

// Absent is_blocked means UNKNOWN, never "pass" — the same rule parse.go:95-98
// already applies to the shipped log attribute. Claiming a disposition the document
// never stated would corrupt the action label.
func TestFlowFromDoc_VerdictFollowsTheAbsentMeansUnknownRule(t *testing.T) {
	unstated := flowDoc(t, "flow", `{"transport_proto":"TCP","ip_src_saddr":"192.0.2.1","ip_src_port":1,"ip_dst_saddr":"203.0.113.1","ip_dst_port":443}`)
	r, _ := flowFromDoc("flow", unstated, flowSnapshot(), nil, time.Now())
	if r.Verdict != flow.VerdictUnknown {
		t.Fatalf("Verdict = %v, want unknown", r.Verdict)
	}
	if got := r.Verdict.String(); got != "" {
		t.Fatalf("unknown verdict renders %q, want an empty action label", got)
	}
	if got := mustFlow(t, flowLANToInternet).Verdict; got != flow.VerdictPass {
		t.Fatalf("Verdict = %v, want pass", got)
	}
	if got := mustFlow(t, flowBlockedSynthetic).Verdict; got != flow.VerdictBlock {
		t.Fatalf("Verdict = %v, want block", got)
	}
}

// Zenarmor's byte fields are signed in the JSON; a negative would wrap through
// uint64 into the rollup as an astronomical value.
func TestFlowFromDoc_ClampsNegativeCounters(t *testing.T) {
	d := flowDoc(t, "flow", `{"transport_proto":"TCP","ip_src_saddr":"192.0.2.1","ip_src_port":1,"ip_dst_saddr":"203.0.113.1","ip_dst_port":443,"src_nbytes":-5,"src_pbytes":-9,"src_npackets":-3,"dst_nbytes":-1,"dst_npackets":-1}`)
	r, _ := flowFromDoc("flow", d, flowSnapshot(), nil, time.Now())
	if r.Zen.Bytes() != 0 || r.Zen.Packets() != 0 {
		t.Fatalf("negative counters must clamp to zero, got %d bytes / %d packets", r.Zen.Bytes(), r.Zen.Packets())
	}
}

func TestFlowFromDoc_EnrichesServiceAndCommunityID(t *testing.T) {
	r := mustFlow(t, flowLANToInternet)
	if r.Enrich.DstService != "https" {
		t.Fatalf("DstService = %q, want https", r.Enrich.DstService)
	}
	if r.CommunityID == "" {
		t.Fatal("CommunityID must be computed for the phase-3 join")
	}
	// Ours, not Zenarmor's: the fixture's community_id field is a placeholder and a
	// sweep of all 65,536 seeds against five real documents matched none of them, so
	// Zenarmor's value is neither trusted nor compared against.
	if r.CommunityID == "1:aaaaaaaaaaaaaaaaaaaaaaaaaaa=" {
		t.Fatal("CommunityID must be computed, not copied from the document")
	}
	if r.L7.AppCategory != "Secure Web Browsing" || r.L7.AppName != "Secure Web Browsing" {
		t.Fatalf("L7 = %+v, want the document's app fields", r.L7)
	}
}

// flowEncrypted / flowCleartext isolate ONE field. Both are flowLANToInternet with
// `encryption` restored: the anonymiser dropped it from the shared fixtures, but the
// real corpus carries it on every conn document (see connDoc in fixtures_test.go), and
// "Clear" / "TLS-Encrypted" are the two values it was observed with. Nothing else in
// the document differs, so a failure here is about the copy and not about parsing.
const flowEncrypted = `{"transport_proto":"TCP","interface":"ixl0","vlanid":"0","direction":"out","is_local":0,"ip_src_saddr":"192.0.2.50","ip_src_port":49812,"ip_dst_saddr":"203.0.113.12","ip_dst_port":443,"is_blocked":0,"src_npackets":12,"src_nbytes":1804,"dst_npackets":18,"dst_nbytes":23110,"start_time":1784656700000,"end_time":1784656707000,"encryption":"TLS-Encrypted","app_proto":"HTTPS","app_name":"Secure Web Browsing","app_category":"Secure Web Browsing"}`

const flowCleartext = `{"transport_proto":"TCP","interface":"ixl0","vlanid":"0","direction":"out","is_local":0,"ip_src_saddr":"192.0.2.50","ip_src_port":49813,"ip_dst_saddr":"203.0.113.12","ip_dst_port":80,"is_blocked":0,"src_npackets":12,"src_nbytes":1804,"dst_npackets":18,"dst_nbytes":23110,"start_time":1784656700000,"end_time":1784656707000,"encryption":"Clear","app_proto":"HTTP","app_name":"Web Browsing","app_category":"Web Browsing"}`

// #585: the parser has read `encryption` since the Zenarmor lane existed and the flow
// adapter never copied it, so it reached the conn record only and could not be joined
// against NetFlow volume. It rides on L7 because that is the struct the correlator
// copies wholesale onto a merged record; a document that states nothing must leave the
// field empty rather than claiming cleartext, which would read as a finding.
func TestFlowFromDoc_CarriesEncryption(t *testing.T) {
	if got := mustFlow(t, flowEncrypted).L7.Encryption; got != "TLS-Encrypted" {
		t.Errorf("Encryption = %q, want TLS-Encrypted", got)
	}
	if got := mustFlow(t, flowCleartext).L7.Encryption; got != "Clear" {
		t.Errorf("Encryption = %q, want Clear", got)
	}
	// The shared fixtures carry no encryption field at all — an absent field must not
	// become a stated verdict.
	if got := mustFlow(t, flowLANToInternet).L7.Encryption; got != "" {
		t.Errorf("Encryption = %q on a document that stated none, want empty", got)
	}
}

// The [F9] regression test, and the whole reason the hook lives in process rather
// than parseDoc: parseDoc runs UPSTREAM of the self-traffic drop, which is on by
// default and removes the exporter's own ingest link — about 11% of the flow
// family. Rolling up there would make our own bookkeeping the operator's top
// talker, scaling with how much they log.
func TestProcess_DoesNotRollUpTrafficItDrops(t *testing.T) {
	const listenPort = 9200
	peer := netip.MustParseAddr("192.0.2.9")
	selfDoc := `{"transport_proto":"TCP","interface":"ixl0","vlanid":"0","direction":"out","ip_src_saddr":"192.0.2.9","ip_src_port":40000,"ip_dst_saddr":"192.0.2.1","ip_dst_port":9200,"is_blocked":0,"src_npackets":10,"src_nbytes":900000,"dst_npackets":1,"dst_nbytes":80,"end_time":1784656707000,"app_category":"Network Management"}`

	sink := &countingFlowSink{}
	p := newDocProcessor(logship.Deps{Registerer: prometheus.NewRegistry(), FlowSink: sink}, Config{
		DropSelfTraffic: true,
	})
	p.process("flow", []byte(selfDoc), peer, []int{listenPort}, func(logship.Record) {})
	if sink.n != 0 {
		t.Fatalf("the rollup saw %d records about our own ingest link; it must see none", sink.n)
	}

	// Real traffic on the same processor still reaches the rollup, so the test above
	// is not passing merely because nothing is wired.
	p.process("flow", []byte(flowLANToInternet), peer, []int{listenPort}, func(logship.Record) {})
	if sink.n != 1 {
		t.Fatalf("the rollup saw %d real records, want 1", sink.n)
	}
}

// An excluded record is real traffic the operator merely does not want STORED, so
// its volume must still reach the counters — which outlive both the exclusion and
// Loki's retention. Same reasoning that already puts observeDerived before the
// exclusion (source.go:232-237).
func TestProcess_StillRollsUpExcludedRecords(t *testing.T) {
	rules, err := parseExcludeRules([]string{"app_category=~^Secure Web Browsing$"})
	if err != nil {
		t.Fatalf("exclude rule did not parse: %v", err)
	}
	sink := &countingFlowSink{}
	p := newDocProcessor(logship.Deps{Registerer: prometheus.NewRegistry(), FlowSink: sink}, Config{
		Excludes: rules,
	})
	emitted := 0
	p.process("flow", []byte(flowLANToInternet), netip.Addr{}, nil, func(logship.Record) { emitted++ })
	if emitted != 0 {
		t.Fatalf("the record should have been excluded from shipping, emitted=%d", emitted)
	}
	if sink.n != 1 {
		t.Fatalf("an excluded record must still be counted, sink saw %d", sink.n)
	}
}

// Only the flow family reaches the sink, and a nil sink is a no-op rather than a
// panic.
func TestProcess_RollsUpOnlyTheFlowFamily(t *testing.T) {
	sink := &countingFlowSink{}
	p := newDocProcessor(logship.Deps{Registerer: prometheus.NewRegistry(), FlowSink: sink}, Config{})
	p.process("dns", []byte(dnsDoc), netip.Addr{}, nil, func(logship.Record) {})
	p.process("tls", []byte(tlsDoc), netip.Addr{}, nil, func(logship.Record) {})
	if sink.n != 0 {
		t.Fatalf("non-flow families must not reach the rollup, sink saw %d", sink.n)
	}

	nilSink := newDocProcessor(logship.Deps{Registerer: prometheus.NewRegistry()}, Config{})
	nilSink.process("flow", []byte(flowLANToInternet), netip.Addr{}, nil, func(logship.Record) {})
}

// A document that does not decode must not reach the rollup — but must still ship,
// which the existing debugcapture test already asserts.
func TestProcess_DoesNotRollUpUndecodableDocuments(t *testing.T) {
	sink := &countingFlowSink{}
	p := newDocProcessor(logship.Deps{Registerer: prometheus.NewRegistry(), FlowSink: sink}, Config{})
	emitted := 0
	p.process("flow", []byte("this is not json"), netip.Addr{}, nil, func(logship.Record) { emitted++ })
	if sink.n != 0 {
		t.Fatalf("an undecodable document must not reach the rollup, sink saw %d", sink.n)
	}
	if emitted != 1 {
		t.Fatalf("an undecodable document must still ship with its raw body, emitted=%d", emitted)
	}
}

type countingFlowSink struct {
	n    int
	last flow.Record
}

func (s *countingFlowSink) Observe(r flow.Record) {
	s.n++
	s.last = r
}

var _ flow.Sink = (*countingFlowSink)(nil)
