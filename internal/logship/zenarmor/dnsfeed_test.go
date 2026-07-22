package zenarmor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/flow"
)

func TestFeedDNSCachePutsAnswers(t *testing.T) {
	cache := flow.NewDNSCache(100, time.Hour)
	now := time.Unix(1784224459, 0)

	// A resolved dns document: client 10.0.25.136 asked for time.windows.com, got 10.0.0.2.
	feedDNSCache(cache, &zenDoc{SrcIP: "10.0.25.136", Query: "time.windows.com", Answers: "10.0.0.2"}, now)

	dom, ok := cache.Lookup(netip.MustParseAddr("10.0.25.136"), netip.MustParseAddr("10.0.0.2"), now)
	if !ok || dom != "time.windows.com" {
		t.Fatalf("Lookup = (%q,%v), want (time.windows.com,true)", dom, ok)
	}
}

func TestFeedDNSCacheMultipleAnswersAndNonIP(t *testing.T) {
	cache := flow.NewDNSCache(100, time.Hour)
	now := time.Unix(1784224459, 0)

	// A record with two A answers plus a CNAME-style non-IP token, comma-separated.
	feedDNSCache(cache, &zenDoc{
		SrcIP:   "10.0.25.136",
		Query:   "cdn.example.net",
		Answers: "cdn.example.net.akamai.net, 93.184.216.34, 93.184.216.35",
	}, now)

	for _, ip := range []string{"93.184.216.34", "93.184.216.35"} {
		if dom, ok := cache.Lookup(netip.MustParseAddr("10.0.25.136"), netip.MustParseAddr(ip), now); !ok || dom != "cdn.example.net" {
			t.Errorf("answer %s: Lookup = (%q,%v), want (cdn.example.net,true)", ip, dom, ok)
		}
	}
	// The non-IP token must not have created an entry, and must not have crashed.
	if s := cache.Stats(); s.Entries != 2 {
		t.Errorf("entries = %d, want 2 (non-IP answer token skipped)", s.Entries)
	}
}

func TestFeedDNSCacheSkipsRequestOnly(t *testing.T) {
	cache := flow.NewDNSCache(100, time.Hour)
	now := time.Unix(1784224414, 0)
	// A request-only document (is_request=1, no response): empty answers, nothing to cache.
	feedDNSCache(cache, &zenDoc{SrcIP: "10.0.50.152", Query: "WINSRV", Answers: ""}, now)
	if s := cache.Stats(); s.Entries != 0 {
		t.Fatalf("entries = %d, want 0 (no answers to cache)", s.Entries)
	}
}

func TestFlowFromDocResolvesDstDomain(t *testing.T) {
	cache := flow.NewDNSCache(100, time.Hour)
	now := time.Unix(1784224500, 0)
	feedDNSCache(cache, &zenDoc{SrcIP: "10.0.25.136", Query: "time.windows.com", Answers: "10.0.0.2"}, now)

	// A conn flow from the same client to the resolved address recovers the domain.
	conn := &zenDoc{SrcIP: "10.0.25.136", DstIP: "10.0.0.2", TransportProto: "TCP", DstPort: 443}
	r, ok := flowFromDoc("flow", conn, nil, cache, now)
	if !ok {
		t.Fatal("flowFromDoc returned not-ok for a valid conn document")
	}
	if r.Enrich.DstDomain != "time.windows.com" {
		t.Fatalf("DstDomain = %q, want time.windows.com", r.Enrich.DstDomain)
	}
}

func TestAddFlowAttrsStampsNormalizedFields(t *testing.T) {
	attrs := map[string]string{}
	fr := flow.Record{
		CommunityID: "1:abc=",
		Direction:   flow.DirectionOutbound,
		In:          flow.Iface{Device: "ixl0_vlan50", Name: "IOT"},
		Enrich:      flow.Enrichment{DstDomain: "time.windows.com"},
	}
	addFlowAttrs(attrs, fr)

	want := map[string]string{
		"flow.community_id": "1:abc=",
		"flow.direction":    "outbound",
		"flow.interface":    "IOT",
		"dst.domain":        "time.windows.com",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attrs[%q] = %q, want %q", k, attrs[k], v)
		}
	}
}

func TestAddFlowAttrsSkipsUnknownDirectionAndEmptyDomain(t *testing.T) {
	attrs := map[string]string{}
	fr := flow.Record{CommunityID: "1:xyz=", Direction: flow.DirectionUnknown, In: flow.Iface{Device: "ixl0"}}
	addFlowAttrs(attrs, fr)

	if _, ok := attrs["flow.direction"]; ok {
		t.Error("unknown direction must not be stamped")
	}
	if _, ok := attrs["dst.domain"]; ok {
		t.Error("empty domain must not be stamped")
	}
	if attrs["flow.community_id"] != "1:xyz=" || attrs["flow.interface"] != "ixl0" {
		t.Errorf("expected community_id and interface stamped, got %v", attrs)
	}
}
