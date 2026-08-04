package opnsense

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// liveStatisticsFixture is the real payload shape from the reference box, trimmed
// to the rows that matter. Two things it has to exercise: the per-ADDRESS rows,
// which outnumber the AF_LINK rows three to one and must be filtered out, and the
// post-reconnect inversion where pppoe0 holds 15 while appearing after tailscale0.
const liveStatisticsFixture = `{"statistics":{
 "[LAN] (ixl0) / 98:b7:85:21:af:f2":{"name":"ixl0","network":"<Link#1>","received-bytes":5},
 "[LAN] (ixl0) / 10.0.0.254":{"name":"ixl0","network":"10.0.0.0/24","received-bytes":3},
 "[LAN] (ixl0) / fe80::1%ixl0":{"name":"ixl0","network":"fe80::%ixl0/64","received-bytes":1},
 "(ixl2)":{"name":"ixl2","network":"<Link#3>"},
 "(pfsync0)":{"name":"pfsync0","network":"<Link#10>"},
 "[tailscale] (tailscale0)":{"name":"tailscale0","network":"<Link#16>"},
 "[AAISP] (pppoe0)":{"name":"pppoe0","network":"<Link#15>"}
}}`

func indexClient(t *testing.T, body string, status int) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(srv.URL, "http://"),
		APIKey: "k", APISecret: "s",
	}, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestFetchInterfaceIndexesReadsTheKernelIndex(t *testing.T) {
	c := indexClient(t, liveStatisticsFixture, http.StatusOK)
	got, err := c.FetchInterfaceIndexes()
	if err != nil {
		t.Fatalf("FetchInterfaceIndexes: %v", err)
	}

	want := map[string]uint32{
		"ixl0": 1, "ixl2": 3, "pfsync0": 10, "tailscale0": 16, "pppoe0": 15,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d devices, want %d: %v", len(got), len(want), got)
	}
	for dev, idx := range want {
		if got[dev] != idx {
			t.Errorf("index for %q = %d, want %d", dev, got[dev], idx)
		}
	}
	// pfsync0 is the whole reason this endpoint was chosen: every other source
	// either omits it or has no index, and it sits mid-range so omitting it
	// shifts everything above.
	if _, ok := got["pfsync0"]; !ok {
		t.Error("pfsync0 missing; it is the device the other endpoints drop")
	}
}

// The per-address rows carry a prefix in the same field. Counting one as an
// interface would invent a device and shift every rank after it.
func TestFetchInterfaceIndexesIgnoresAddressRows(t *testing.T) {
	c := indexClient(t, liveStatisticsFixture, http.StatusOK)
	got, _ := c.FetchInterfaceIndexes()
	if n := len(got); n != 5 {
		t.Fatalf("parsed %d devices from a fixture with 5 AF_LINK rows and 2 address rows: %v", n, got)
	}
}

// Every failure mode of this parse — a libxo rename, a netstat format change —
// looks identical: no row matches. Returning an empty map would let a caller
// derive an enumeration from nothing, so it must be an error.
func TestFetchInterfaceIndexesRefusesAResponseWithNoLinkRows(t *testing.T) {
	c := indexClient(t, `{"statistics":{"(ixl0) / 10.0.0.1":{"name":"ixl0","network":"10.0.0.0/24"}}}`, http.StatusOK)
	if _, err := c.FetchInterfaceIndexes(); err == nil {
		t.Fatal("accepted a response with no <Link#N> rows; want an error")
	}
}

// A device reported twice with different indices means the response contradicts
// itself and nothing derived from it can be trusted.
func TestFetchInterfaceIndexesRefusesContradictoryIndexes(t *testing.T) {
	c := indexClient(t, `{"statistics":{
	 "a":{"name":"ixl0","network":"<Link#1>"},
	 "b":{"name":"ixl0","network":"<Link#7>"}}}`, http.StatusOK)
	if _, err := c.FetchInterfaceIndexes(); err == nil {
		t.Fatal("accepted a device with two different kernel indexes; want an error")
	}
}

// The same device repeated with the SAME index is just netstat listing it twice
// and is not a contradiction.
func TestFetchInterfaceIndexesToleratesADuplicateAgreeingRow(t *testing.T) {
	c := indexClient(t, `{"statistics":{
	 "a":{"name":"ixl0","network":"<Link#1>"},
	 "b":{"name":"ixl0","network":"<Link#1>"}}}`, http.StatusOK)
	got, err := c.FetchInterfaceIndexes()
	if err != nil {
		t.Fatalf("FetchInterfaceIndexes: %v", err)
	}
	if got["ixl0"] != 1 {
		t.Errorf("index for ixl0 = %d, want 1", got["ixl0"])
	}
}

// liveInterfaceStatisticsFixture is trimmed verbatim from the prod box
// (OPNsense 26.1, api/diagnostics/interface/get_interface_statistics). It keeps
// the three shapes that matter: the AF_LINK row, which is the ONLY row carrying
// mtu/errors/collisions/dropped-packets; the per-address rows, which carry their
// own counters; and a device (tailscale0) that the traffic/interface endpoint
// omits entirely, which is where the only non-zero dropped-packets on any
// observed box lives.
const liveInterfaceStatisticsFixture = `{"statistics":{
 "[LAN] (ixl0) / 98:b7:85:21:af:f2":{"name":"ixl0","flags":"0x8943","mtu":1500,"network":"<Link#1>","address":"98:b7:85:21:af:f2","received-packets":419866764,"received-errors":50,"dropped-packets":0,"received-bytes":383093557281,"sent-packets":381907348,"send-errors":0,"sent-bytes":316537354094,"collisions":0},
 "[LAN] (ixl0) / 10.0.0.254":{"name":"ixl0","flags":"0x8943","network":"10.0.0.0/24","address":"10.0.0.254","received-packets":15603611,"received-bytes":2369675284,"sent-packets":25173485,"sent-bytes":23846528514},
 "[LAN] (ixl0) / fe80::9ab7:85ff:fe21:aff2%ixl0":{"name":"ixl0","flags":"0x8943","network":"fe80::%ixl0/64","address":"fe80::9ab7:85ff:fe21:aff2%ixl0","received-packets":214444,"received-bytes":18089655,"sent-packets":257888,"sent-bytes":21509007},
 "[LAN] (ixl0) / 2001:db8::1":{"name":"ixl0","flags":"0x8943","network":"2001:db8::/64","address":"2001:db8::1","received-packets":8658484,"received-bytes":1614698995,"sent-packets":188695,"sent-bytes":27324379},
 "[tailscale] (tailscale0)":{"name":"tailscale0","flags":"0x8051","mtu":1280,"network":"<Link#16>","address":"","received-packets":1000,"received-errors":0,"dropped-packets":8,"received-bytes":2000,"sent-packets":3000,"send-errors":0,"sent-bytes":4000,"collisions":0}
}}`

func TestFetchInterfaceStatistics_SplitsTrafficByAddressFamily(t *testing.T) {
	c := indexClient(t, liveInterfaceStatisticsFixture, http.StatusOK)
	got, err := c.FetchInterfaceStatistics()
	if err != nil {
		t.Fatalf("FetchInterfaceStatistics: %v", err)
	}

	type key struct{ dev, fam string }
	fam := make(map[key]InterfaceFamilyTraffic, len(got.Families))
	for _, f := range got.Families {
		fam[key{f.Device, f.Family}] = f
	}

	v4 := fam[key{"ixl0", "ipv4"}]
	if v4.ReceivedPackets != 15603611 || v4.SentBytes != 23846528514 {
		t.Errorf("ixl0 ipv4 = %+v", v4)
	}
	// The two IPv6 addresses on ixl0 must be summed, not emitted per address:
	// an address is a churning label and is deliberately not carried.
	v6 := fam[key{"ixl0", "ipv6"}]
	if v6.ReceivedPackets != 214444+8658484 {
		t.Errorf("ixl0 ipv6 received packets = %v, want %v", v6.ReceivedPackets, float64(214444+8658484))
	}
	if v6.ReceivedBytes != 18089655+1614698995 {
		t.Errorf("ixl0 ipv6 received bytes = %v", v6.ReceivedBytes)
	}
	if len(got.Families) != 2 {
		t.Errorf("got %d family rows, want 2: %+v", len(got.Families), got.Families)
	}
}

// The AF_LINK row's address is a MAC, which contains colons and would classify
// as IPv6 on a naive test. It must be excluded by its network column instead.
func TestFetchInterfaceStatistics_LinkRowIsNotAnAddressFamily(t *testing.T) {
	c := indexClient(t, liveInterfaceStatisticsFixture, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()
	for _, f := range got.Families {
		if f.ReceivedPackets == 419866764 {
			t.Fatalf("the AF_LINK row was counted as an address family row: %+v", f)
		}
	}
}

func TestFetchInterfaceStatistics_ReadsOutputQueueDrops(t *testing.T) {
	c := indexClient(t, liveInterfaceStatisticsFixture, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()

	links := make(map[string]InterfaceLinkStats, len(got.Links))
	for _, l := range got.Links {
		links[l.Device] = l
	}
	if len(got.Links) != 2 {
		t.Fatalf("got %d link rows, want 2: %+v", len(got.Links), got.Links)
	}
	if !links["tailscale0"].OutputQueueDropsPresent || links["tailscale0"].OutputQueueDrops != 8 {
		t.Errorf("tailscale0 link stats = %+v, want drops 8 present", links["tailscale0"])
	}
	// A genuine zero must still be emitted; suppressing it would make a healthy
	// interface indistinguishable from an unreported one.
	if !links["ixl0"].OutputQueueDropsPresent || links["ixl0"].OutputQueueDrops != 0 {
		t.Errorf("ixl0 link stats = %+v, want drops 0 present", links["ixl0"])
	}
}

// An address row carries no dropped-packets key at all, so absence must be
// distinguished from zero rather than fabricating a boot-time 0.
func TestFetchInterfaceStatistics_AbsentDropsAreNotZero(t *testing.T) {
	c := indexClient(t, `{"statistics":{
	 "(vtnet0)":{"name":"vtnet0","network":"<Link#1>","address":"52:54:00:11:22:33","received-packets":1,"sent-packets":1}
	}}`, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()
	if len(got.Links) != 1 {
		t.Fatalf("got %d link rows, want 1", len(got.Links))
	}
	if got.Links[0].OutputQueueDropsPresent {
		t.Errorf("absent dropped-packets reported as present: %+v", got.Links[0])
	}
}

func TestFetchInterfaceStatistics_ResultsAreSorted(t *testing.T) {
	c := indexClient(t, liveInterfaceStatisticsFixture, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()
	for i := 1; i < len(got.Families); i++ {
		a, b := got.Families[i-1], got.Families[i]
		if a.Device > b.Device || (a.Device == b.Device && a.Family > b.Family) {
			t.Fatalf("Families not sorted at %d: %+v then %+v", i, a, b)
		}
	}
	for i := 1; i < len(got.Links); i++ {
		if got.Links[i-1].Device > got.Links[i].Device {
			t.Fatalf("Links not sorted at %d", i)
		}
	}
}

func TestFetchInterfaceStatistics_ServerError(t *testing.T) {
	c := indexClient(t, `boom`, http.StatusInternalServerError)
	if _, err := c.FetchInterfaceStatistics(); err == nil {
		t.Fatal("expected an error on a 500")
	}
}

// TestFetchInterfaceStatistics_ReadsErrorAndCollisionCounters covers #642:
// received-errors/send-errors/collisions are decoded from the AF_LINK row
// alongside dropped-packets, using the liveInterfaceStatisticsFixture above
// (real captured shape, already carrying these keys — they were simply
// discarded before this change).
func TestFetchInterfaceStatistics_ReadsErrorAndCollisionCounters(t *testing.T) {
	c := indexClient(t, liveInterfaceStatisticsFixture, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()

	links := make(map[string]InterfaceLinkStats, len(got.Links))
	for _, l := range got.Links {
		links[l.Device] = l
	}

	ixl0 := links["ixl0"]
	if !ixl0.InputErrorsPresent || ixl0.InputErrors != 50 {
		t.Errorf("ixl0 InputErrors = %+v, want 50 present", ixl0)
	}
	if !ixl0.OutputErrorsPresent || ixl0.OutputErrors != 0 {
		t.Errorf("ixl0 OutputErrors = %+v, want 0 present (genuine zero, not absence)", ixl0)
	}
	if !ixl0.CollisionsPresent || ixl0.Collisions != 0 {
		t.Errorf("ixl0 Collisions = %+v, want 0 present", ixl0)
	}
	if ixl0.ReceivedBytes != 383093557281 || ixl0.SentBytes != 316537354094 {
		t.Errorf("ixl0 bytes = %+v", ixl0)
	}
	if !ixl0.ReceivedPacketsPresent || ixl0.ReceivedPackets != 419866764 {
		t.Errorf("ixl0 ReceivedPackets = %+v, want 419866764 present (plausible)", ixl0)
	}
	if !ixl0.SentPacketsPresent || ixl0.SentPackets != 381907348 {
		t.Errorf("ixl0 SentPackets = %+v, want 381907348 present (plausible)", ixl0)
	}

	ts := links["tailscale0"]
	if !ts.InputErrorsPresent || ts.InputErrors != 0 {
		t.Errorf("tailscale0 InputErrors = %+v, want 0 present", ts)
	}
	if !ts.CollisionsPresent || ts.Collisions != 0 {
		t.Errorf("tailscale0 Collisions = %+v, want 0 present", ts)
	}
}

// An address row (and any row lacking the keys) must not report these
// counters as present — presence must come only from the AF_LINK row
// actually carrying the key, never a fabricated zero.
func TestFetchInterfaceStatistics_AbsentErrorCountersAreNotZero(t *testing.T) {
	c := indexClient(t, `{"statistics":{
	 "(vtnet0)":{"name":"vtnet0","network":"<Link#1>","address":"52:54:00:11:22:33","received-packets":1,"received-bytes":100,"sent-packets":1,"sent-bytes":100}
	}}`, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()
	if len(got.Links) != 1 {
		t.Fatalf("got %d link rows, want 1", len(got.Links))
	}
	l := got.Links[0]
	if l.InputErrorsPresent || l.OutputErrorsPresent || l.CollisionsPresent {
		t.Errorf("absent error/collision keys reported as present: %+v", l)
	}
}

// TestFetchInterfaceStatistics_ImplausiblePacketCountSuppressed pins #642's
// live ixl2 case verbatim: received-packets = 281,475,478,389,769
// (0x100001de95031, exactly 2^48 plus a plausible count — bit 48 stuck high)
// against received-bytes = 393,185,547,668 is ~0.0014 bytes/packet, far below
// the 20 bytes/packet floor (below the minimum Ethernet frame). The packet
// series must be suppressed; the byte series (which is NOT implausible) and
// the healthy sent-packets figure on the SAME row must not be affected.
func TestFetchInterfaceStatistics_ImplausiblePacketCountSuppressed(t *testing.T) {
	c := indexClient(t, `{"statistics":{
	 "[ixl2] / 98:b7:85:21:af:f4":{"name":"ixl2","network":"<Link#3>","address":"98:b7:85:21:af:f4","received-packets":281475478389769,"received-errors":0,"dropped-packets":0,"received-bytes":393185547668,"sent-packets":561408322,"send-errors":0,"sent-bytes":537868820722,"collisions":0}
	}}`, http.StatusOK)
	got, _ := c.FetchInterfaceStatistics()
	if len(got.Links) != 1 {
		t.Fatalf("got %d link rows, want 1", len(got.Links))
	}
	l := got.Links[0]
	if l.ReceivedPacketsPresent {
		t.Errorf("implausible received-packets (2^48 case) was not suppressed: %+v", l)
	}
	if l.ReceivedBytes != 393185547668 {
		t.Errorf("received-bytes must still be published: got %v", l.ReceivedBytes)
	}
	if !l.SentPacketsPresent || l.SentPackets != 561408322 {
		t.Errorf("the healthy sent-packets figure on the same row was wrongly affected: %+v", l)
	}
	if !l.SentPacketsPresent {
		t.Fatal("sent-packets wrongly suppressed")
	}
}

// TestPacketCountImplausible pins the exact predicate: below 20 bytes/packet
// is implausible, packets<=0 is never flagged (division-by-zero guard, #642
// point 4 — an idle device legitimately reports 0/0 and must not be
// suppressed), and the boundary is inclusive of 20 (only STRICTLY less than
// 20 is implausible).
func TestPacketCountImplausible(t *testing.T) {
	cases := []struct {
		name           string
		packets, bytes float64
		want           bool
	}{
		{"ixl2 live capture", 281475478389769, 393185547668, true},
		{"healthy ratio", 1000, 1400000, false},
		{"zero packets, zero bytes (idle device)", 0, 0, false},
		{"zero packets, nonzero bytes (nonsensical but not our call)", 0, 100, false},
		{"exactly at the 20 bytes/packet floor", 100, 2000, false},
		{"just under the floor", 100, 1999, true},
		{"negative packets (should never occur, must not panic/flag oddly)", -1, 100, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := packetCountImplausible(tc.packets, tc.bytes); got != tc.want {
				t.Errorf("packetCountImplausible(%v, %v) = %v, want %v", tc.packets, tc.bytes, got, tc.want)
			}
		})
	}
}
