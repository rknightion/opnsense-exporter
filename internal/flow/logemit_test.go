package flow

import (
	"net/netip"
	"testing"
)

func sampleMerged() Record {
	return Record{
		Source:      SourceMerged,
		Proto:       6,
		SrcAddr:     netip.MustParseAddr("192.0.2.10"),
		DstAddr:     netip.MustParseAddr("203.0.113.5"),
		SrcPort:     40000,
		DstPort:     443,
		CommunityID: "1:abcdef=",
		NF:          Counters{TxBytes: 1000, TxPackets: 8, Present: true},
		Zen:         Counters{TxBytes: 980, TxPackets: 8, Present: true},
		In:          Iface{Device: "ixl0", Name: "LAN"},
		Out:         Iface{Device: "igb0", Name: "WAN2", Corrected: true},
		Direction:   DirectionOutbound,
		Verdict:     VerdictBlock,
		L7:          L7{AppName: "google", AppCategory: "Web Browsing"},
		Enrich:      Enrichment{DstScope: "remote", DstDomain: "google.com"},
	}
}

// The attribute map must carry the high-cardinality identity as METADATA and must
// never be summed across sources. A missing nf/zen split here is a data-loss bug.
func TestLogAttributes_CarriesBothSourcesUnsummed(t *testing.T) {
	a := sampleMerged().LogAttributes()
	if a["flow.nf.bytes"] != "1000" || a["flow.zen.bytes"] != "980" {
		t.Fatalf("nf/zen bytes = %q/%q, want 1000/980 kept separate", a["flow.nf.bytes"], a["flow.zen.bytes"])
	}
	if a["src.ip"] != "192.0.2.10" || a["dst.port"] != "443" {
		t.Errorf("endpoints wrong: %q %q", a["src.ip"], a["dst.port"])
	}
	if a["flow.community_id"] != "1:abcdef=" {
		t.Errorf("community_id missing: %q", a["flow.community_id"])
	}
	if a["app.category"] != "Web Browsing" {
		t.Errorf("category missing: %q", a["app.category"])
	}
	if a["dst.domain"] != "google.com" {
		t.Errorf("domain missing: %q", a["dst.domain"])
	}
	if a["flow.egress_corrected"] != "true" {
		t.Errorf("egress correction not recorded on the record: %q", a["flow.egress_corrected"])
	}
	if a["flow.action"] != "block" {
		t.Errorf("verdict = %q, want block", a["flow.action"])
	}
}

// #465: a record whose interface was deduced from the address's subnet says so, for the
// same reason the egress correction does — an operator comparing this against a switch
// port needs to know the exporter deduced it rather than ng_netflow reporting it. And
// the flag must be ABSENT, not "false", on a record nothing was deduced for.
func TestLogAttributes_RecordsVLANSubnetAttribution(t *testing.T) {
	r := sampleMerged()
	if _, present := r.LogAttributes()["flow.vlan_subnet_attributed"]; present {
		t.Error("flow.vlan_subnet_attributed present on a record that was not reattributed")
	}

	r.Repairs.VLANSubnetAttributed = true
	if got := r.LogAttributes()["flow.vlan_subnet_attributed"]; got != "true" {
		t.Errorf("flow.vlan_subnet_attributed = %q, want true", got)
	}
}

// Absent information must not appear as an empty attribute: a NetFlow-only record has
// no L7 and no Zenarmor counters, and shipping empty keys would misread in Loki.
func TestLogAttributes_OmitsAbsentFields(t *testing.T) {
	r := Record{
		Source:  SourceNetflow,
		Proto:   17,
		SrcAddr: netip.MustParseAddr("192.0.2.1"),
		DstAddr: netip.MustParseAddr("192.0.2.2"),
		NF:      Counters{TxBytes: 5, Present: true},
	}
	a := r.LogAttributes()
	for _, k := range []string{"app.name", "app.category", "flow.zen.bytes", "dst.domain", "flow.action"} {
		if _, ok := a[k]; ok {
			t.Errorf("key %q present on a bare NetFlow record; absent fields must be omitted", k)
		}
	}
	if a["flow.nf.bytes"] != "5" {
		t.Errorf("nf bytes missing: %q", a["flow.nf.bytes"])
	}
}

// The flag set is rendered in a FIXED wire-bit order (LSB first), so one flag
// combination has exactly one spelling and `netflow.tcp_flags="SYN,ACK"` is a usable
// Loki matcher. An order derived from a map, or from the order bits happen to be
// tested in, would give the same flow two spellings and make every exact-match query
// miss a share of its records — silently, since both spellings look right.
func TestTCPFlagsString_StableWireOrder(t *testing.T) {
	cases := []struct {
		flags uint8
		want  string
	}{
		{0x00, ""},                // nothing reported
		{0x02, "SYN"},             // the opening SYN of a scan with no reply
		{0x12, "SYN,ACK"},         // the peer accepted
		{0x04, "RST"},             // the peer refused
		{0x14, "RST,ACK"},         // refused, acknowledging the SYN
		{0x18, "PSH,ACK"},         // mid-session data
		{0x1b, "FIN,SYN,PSH,ACK"}, // a complete short session, folded
		{0xff, "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR"}, // every bit, in wire order
	}
	for _, c := range cases {
		if got := tcpFlagsString(c.flags); got != c.want {
			t.Errorf("tcpFlagsString(%#02x) = %q, want %q", c.flags, got, c.want)
		}
	}
}

// #585: the flag byte is decoded and was then dropped before the log record, which is
// what makes a port scan (SYN, no reply) indistinguishable from a refused service
// (RST) on a WAN burst. Zenarmor's verdict is the FIREWALL's answer, not the peer's,
// so nothing else in the pipeline carries this.
func TestLogAttributes_CarriesTCPFlags(t *testing.T) {
	r := sampleMerged()
	r.TCPFlags = 0x14
	if got := r.LogAttributes()["netflow.tcp_flags"]; got != "RST,ACK" {
		t.Errorf("netflow.tcp_flags = %q, want RST,ACK", got)
	}
}

// A flow with no flags reported — every UDP record, and any v5/v9 export that leaves
// element 6 at zero — must emit NO key at all rather than an empty one. An empty
// attribute on every UDP line is pure per-line ingest cost across the whole flow
// stream, and Loki reads "absent" and "" differently, so the empty value would also
// make `netflow.tcp_flags=""` match records that reported nothing.
//
// Zero needs no separate presence bit to mean this: no legal TCP segment carries an
// empty flag byte, so "the exporter reported 0" and "the exporter reported nothing"
// are the same fact.
func TestLogAttributes_OmitsTCPFlagsWhenNoneReported(t *testing.T) {
	r := Record{
		Source:  SourceNetflow,
		Proto:   17,
		SrcAddr: netip.MustParseAddr("192.0.2.1"),
		DstAddr: netip.MustParseAddr("192.0.2.2"),
		NF:      Counters{TxBytes: 5, Present: true},
	}
	if v, ok := r.LogAttributes()["netflow.tcp_flags"]; ok {
		t.Errorf("netflow.tcp_flags = %q on a record that reported no flags; the key must be absent", v)
	}
}

// #585: Zenarmor parses `encryption` and the adapter dropped it, so "which internal
// hosts still send cleartext to the internet" could not be answered against NetFlow
// volume on one record. Absent must stay absent — a NetFlow-only flow has no Zenarmor
// side and must not claim one.
func TestLogAttributes_CarriesZenarmorEncryption(t *testing.T) {
	r := sampleMerged()
	if v, ok := r.LogAttributes()["zenarmor.encryption"]; ok {
		t.Errorf("zenarmor.encryption = %q on a record Zenarmor stated nothing for", v)
	}

	r.L7.Encryption = "TLS-Encrypted"
	if got := r.LogAttributes()["zenarmor.encryption"]; got != "TLS-Encrypted" {
		t.Errorf("zenarmor.encryption = %q, want TLS-Encrypted", got)
	}
}

func TestLogBody_Summary(t *testing.T) {
	got := sampleMerged().LogBody()
	want := "192.0.2.10:40000 -> 203.0.113.5:443 tcp google block"
	if got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestLogSeverityBlocked(t *testing.T) {
	if !sampleMerged().LogSeverityBlocked() {
		t.Error("blocked flow must report blocked severity")
	}
	r := sampleMerged()
	r.Verdict = VerdictPass
	if r.LogSeverityBlocked() {
		t.Error("passed flow must not report blocked severity")
	}
}
