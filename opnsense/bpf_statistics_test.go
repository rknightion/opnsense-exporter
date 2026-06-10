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
