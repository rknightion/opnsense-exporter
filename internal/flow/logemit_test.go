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
