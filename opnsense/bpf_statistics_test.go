package opnsense

import (
	"net/http"
	"testing"
)

const bpfStatisticsNormalFixture = `{
  "bpf-statistics": {
    "bpf-entry": [
      {"pid": 12706, "interface-name": "igb0_vlan50", "direction": "bidirectional",
       "received-packets": 11442, "dropped-packets": 11424, "filter-packets": 11442,
       "store-buffer-length": 4028, "hold-buffer-length": 3236, "process": "dnsmasq"},
      {"pid": 28395, "interface-name": "igb0", "direction": "bidirectional",
       "received-packets": 987654321, "dropped-packets": 0, "filter-packets": 987654321,
       "store-buffer-length": 32768, "hold-buffer-length": 32768, "process": "dhcpd"},
      {"pid": 99999, "interface-name": "igb0_vlan50", "direction": "bidirectional",
       "received-packets": 100, "dropped-packets": 10, "filter-packets": 100,
       "store-buffer-length": 512, "hold-buffer-length": 256, "process": "dnsmasq"}
    ]
  }
}`

const bpfStatisticsEmptyFixture = `{"bpf-statistics":{"bpf-entry":[]}}`

const bpfStatisticsSingleFixture = `{
  "bpf-statistics": {
    "bpf-entry": {
      "pid": 12706, "interface-name": "igb0_vlan50", "direction": "bidirectional",
      "received-packets": 500, "dropped-packets": 5, "filter-packets": 500,
      "store-buffer-length": 2048, "hold-buffer-length": 1024, "process": "dnsmasq"
    }
  }
}`

func TestFetchBPFStatistics_Normal(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bpfStatisticsNormalFixture))
	})
	defer server.Close()

	data, err := client.FetchBPFStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 raw entries
	if data.ListenersTotal != 3 {
		t.Errorf("expected ListenersTotal=3, got %d", data.ListenersTotal)
	}

	// 2 aggregated listeners (dnsmasq/igb0_vlan50 is summed, dhcpd/igb0 is alone)
	if len(data.Listeners) != 2 {
		t.Fatalf("expected 2 aggregated listeners, got %d: %+v", len(data.Listeners), data.Listeners)
	}

	// Sorted by process then interface: dhcpd/igb0 first, dnsmasq/igb0_vlan50 second
	dhcpd := data.Listeners[0]
	dnsmasq := data.Listeners[1]

	if dhcpd.Process != "dhcpd" || dhcpd.Interface != "igb0" {
		t.Errorf("expected dhcpd/igb0 first, got %+v", dhcpd)
	}
	if dhcpd.ReceivedPackets != 987654321 || dhcpd.DroppedPackets != 0 ||
		dhcpd.MatchedPackets != 987654321 || dhcpd.StoreBufferBytes != 32768 ||
		dhcpd.HoldBufferBytes != 32768 {
		t.Errorf("dhcpd listener wrong: %+v", dhcpd)
	}

	if dnsmasq.Process != "dnsmasq" || dnsmasq.Interface != "igb0_vlan50" {
		t.Errorf("expected dnsmasq/igb0_vlan50 second, got %+v", dnsmasq)
	}
	// dnsmasq entries summed: received=11442+100=11542, dropped=11424+10=11434,
	// matched=11442+100=11542, store=4028+512=4540, hold=3236+256=3492
	if dnsmasq.ReceivedPackets != 11542 || dnsmasq.DroppedPackets != 11434 ||
		dnsmasq.MatchedPackets != 11542 || dnsmasq.StoreBufferBytes != 4540 ||
		dnsmasq.HoldBufferBytes != 3492 {
		t.Errorf("dnsmasq aggregated listener wrong: %+v", dnsmasq)
	}
}

func TestFetchBPFStatistics_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bpfStatisticsEmptyFixture))
	})
	defer server.Close()

	data, err := client.FetchBPFStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ListenersTotal != 0 {
		t.Errorf("expected ListenersTotal=0, got %d", data.ListenersTotal)
	}
	if len(data.Listeners) != 0 {
		t.Errorf("expected 0 aggregated listeners, got %d", len(data.Listeners))
	}
}

func TestFetchBPFStatistics_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchBPFStatistics()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.ListenersTotal != 0 || len(data.Listeners) != 0 {
		t.Errorf("expected empty data on 404, got: %+v", data)
	}
}

func TestFetchBPFStatistics_SingleEntryAsObject(t *testing.T) {
	// Defensive: some FreeBSD/PHP paths serialize a single bpf-entry as an object
	// instead of a one-element array. Verify the decoder handles it gracefully.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bpfStatisticsSingleFixture))
	})
	defer server.Close()

	data, err := client.FetchBPFStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ListenersTotal != 1 {
		t.Errorf("expected ListenersTotal=1, got %d", data.ListenersTotal)
	}
	if len(data.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(data.Listeners))
	}
	if data.Listeners[0].ReceivedPackets != 500 {
		t.Errorf("expected 500 received packets, got %v", data.Listeners[0].ReceivedPackets)
	}
}

// liveBPFDirectionFixture is trimmed verbatim from the prod box (OPNsense 26.1,
// api/diagnostics/interface/get_bpf_statistics). lldpd holds a separate
// input-only descriptor per physical port while filterlog holds one
// bidirectional descriptor on pflog0 — the split the (process, interface)
// aggregate erased. dhclient appears twice on one interface in two directions,
// which is the case that proves direction is part of the key and not a
// property of the pair.
const liveBPFDirectionFixture = `{
  "bpf-statistics": {
    "bpf-entry": [
      {"pid": 2759, "interface-name": "pflog0", "header-complete": true, "direction": "bidirectional",
       "received-packets": 648272, "dropped-packets": 0, "filter-packets": 648272,
       "store-buffer-length": 13452, "hold-buffer-length": 0, "process": "filterlog"},
      {"pid": 59070, "interface-name": "igb1", "immediate": true, "header-complete": true,
       "direction": "input", "locked": true,
       "received-packets": 11, "dropped-packets": 1, "filter-packets": 7,
       "store-buffer-length": 0, "hold-buffer-length": 0, "process": "lldpd"},
      {"pid": 59070, "interface-name": "ixl1", "direction": "input",
       "received-packets": 22, "dropped-packets": 2, "filter-packets": 14,
       "store-buffer-length": 0, "hold-buffer-length": 0, "process": "lldpd"},
      {"pid": 41000, "interface-name": "ixl1", "direction": "input",
       "received-packets": 100, "dropped-packets": 3, "filter-packets": 50,
       "store-buffer-length": 0, "hold-buffer-length": 0, "process": "dhclient"},
      {"pid": 41001, "interface-name": "ixl1", "direction": "bidirectional",
       "received-packets": 200, "dropped-packets": 4, "filter-packets": 60,
       "store-buffer-length": 0, "hold-buffer-length": 0, "process": "dhclient"}
    ]
  }
}`

func TestFetchBPFStatistics_KeepsDirection(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(liveBPFDirectionFixture))
	})
	defer server.Close()

	data, err := client.FetchBPFStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.ByDirection) != 5 {
		t.Fatalf("got %d direction rows, want 5: %+v", len(data.ByDirection), data.ByDirection)
	}

	type key struct{ process, iface, dir string }
	got := make(map[key]BPFDirectionListener, len(data.ByDirection))
	for _, d := range data.ByDirection {
		got[key{d.Process, d.Interface, d.Direction}] = d
	}

	// dhclient on ixl1 must NOT collapse: two rows, one per direction.
	in := got[key{"dhclient", "ixl1", "input"}]
	bi := got[key{"dhclient", "ixl1", "bidirectional"}]
	if in.ReceivedPackets != 100 || in.DroppedPackets != 3 || in.MatchedPackets != 50 {
		t.Errorf("dhclient/ixl1/input = %+v", in)
	}
	if bi.ReceivedPackets != 200 || bi.DroppedPackets != 4 || bi.MatchedPackets != 60 {
		t.Errorf("dhclient/ixl1/bidirectional = %+v", bi)
	}
	if in.Listeners != 1 || bi.Listeners != 1 {
		t.Errorf("listener counts = %d/%d, want 1/1", in.Listeners, bi.Listeners)
	}

	// The existing (process, interface) aggregate must still sum both.
	for _, l := range data.Listeners {
		if l.Process == "dhclient" && l.Interface == "ixl1" {
			if l.ReceivedPackets != 300 || l.DroppedPackets != 7 {
				t.Errorf("aggregated dhclient/ixl1 = %+v; the aggregate must be unchanged", l)
			}
		}
	}
}

func TestFetchBPFStatistics_DirectionRowsAreSorted(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(liveBPFDirectionFixture))
	})
	defer server.Close()

	data, _ := client.FetchBPFStatistics()
	for i := 1; i < len(data.ByDirection); i++ {
		a, b := data.ByDirection[i-1], data.ByDirection[i]
		if a.Process > b.Process ||
			(a.Process == b.Process && a.Interface > b.Interface) ||
			(a.Process == b.Process && a.Interface == b.Interface && a.Direction > b.Direction) {
			t.Fatalf("ByDirection not sorted at %d: %+v then %+v", i, a, b)
		}
	}
}

// A descriptor with no direction still has to produce a series; dropping it
// would silently lose a listener from the breakdown.
func TestFetchBPFStatistics_MissingDirectionIsLabelledUnknown(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"bpf-statistics":{"bpf-entry":[
		 {"interface-name":"igb0","received-packets":5,"dropped-packets":0,"filter-packets":5,"process":"tcpdump"}
		]}}`))
	})
	defer server.Close()

	data, _ := client.FetchBPFStatistics()
	if len(data.ByDirection) != 1 {
		t.Fatalf("got %d direction rows, want 1: %+v", len(data.ByDirection), data.ByDirection)
	}
	if data.ByDirection[0].Direction != "unknown" {
		t.Errorf("direction = %q, want %q", data.ByDirection[0].Direction, "unknown")
	}
}
