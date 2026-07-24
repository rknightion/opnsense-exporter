package opnsense

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
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
