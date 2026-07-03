package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestInterfacesCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"device": "igb0",
					"driver": "igb",
					"index": "1",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "0",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "up",
					"vhid": "",
					"datalen": "176",
					"mtu": "1500",
					"metric": "0",
					"line rate": "1000000000",
					"packets received": "123456",
					"packets transmitted": "654321",
					"bytes received": "1000000",
					"bytes transmitted": "2000000",
					"output errors": "0",
					"input errors": "1",
					"collisions": "0",
					"multicasts received": "100",
					"multicasts transmitted": "50",
					"input queue drops": "0",
					"packets for unknown protocol": "0",
					"HW offload capabilities": "",
					"uptime at attach or stat reset": "",
					"name": "LAN"
				}
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 16 metrics per interface (mtu, bytesReceived, bytesTransmitted, multicastsReceived,
	// multicastsTransmitted, inputErrors, outputErrors, collisions, receivedPackets,
	// transmittedPackets, sendQueueLength, sendQueueMaxLength, sendQueueDrops,
	// inputQueueDrops, linkState, lineRate)
	expectedCount := 16
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestInterfacesCollector_Update_MultipleInterfaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"device": "igb0",
					"driver": "igb",
					"index": "1",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "0",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "up",
					"vhid": "",
					"datalen": "176",
					"mtu": "1500",
					"metric": "0",
					"line rate": "1000000000",
					"packets received": "100",
					"packets transmitted": "200",
					"bytes received": "1000",
					"bytes transmitted": "2000",
					"output errors": "0",
					"input errors": "0",
					"collisions": "0",
					"multicasts received": "10",
					"multicasts transmitted": "5",
					"input queue drops": "0",
					"packets for unknown protocol": "0",
					"HW offload capabilities": "",
					"uptime at attach or stat reset": "",
					"name": "LAN"
				},
				"igb1": {
					"device": "igb1",
					"driver": "igb",
					"index": "2",
					"flags": "0x8843",
					"promiscuous listeners": "0",
					"send queue length": "0",
					"send queue max length": "50",
					"send queue drops": "0",
					"type": "Ethernet",
					"address length": "6",
					"header length": "14",
					"link state": "down",
					"vhid": "",
					"datalen": "176",
					"mtu": "1500",
					"metric": "0",
					"line rate": "0",
					"packets received": "0",
					"packets transmitted": "0",
					"bytes received": "0",
					"bytes transmitted": "0",
					"output errors": "0",
					"input errors": "0",
					"collisions": "0",
					"multicasts received": "0",
					"multicasts transmitted": "0",
					"input queue drops": "0",
					"packets for unknown protocol": "0",
					"HW offload capabilities": "",
					"uptime at attach or stat reset": "",
					"name": "WAN"
				}
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 16 metrics per interface * 2 interfaces = 32
	expectedCount := 32
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestInterfacesCollector_LinkStateUnknownNotDown guards #86: an interface whose
// kernel link state is "0" (unknown — e.g. a healthy PPPoE WAN) must not be
// emitted as link_state==0 (down).
func TestInterfacesCollector_LinkStateUnknownNotDown(t *testing.T) {
	cases := []struct {
		name      string
		linkState string
		want      float64
	}{
		{"unknown is not down", "0", 2},
		{"genuine down preserved", "1", 0},
		{"up preserved", "2", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"interfaces":{"pppoe0":{"device":"pppoe0","name":"WAN","type":"PPPoE","link state":"` + tc.linkState + `","mtu":"1492","line rate":"0","bytes received":"0","bytes transmitted":"0","packets received":"0","packets transmitted":"0","multicasts received":"0","multicasts transmitted":"0","input errors":"0","output errors":"0","collisions":"0","send queue length":"0","send queue max length":"0","send queue drops":"0","input queue drops":"0"}}}`))
			}))
			defer server.Close()

			client := newCollectorTestClient(t, server)
			c := &interfacesCollector{subsystem: InterfacesSubsystem}
			c.Register(namespace, "test", promslog.NewNopLogger())

			metrics := collectMetrics(t, c, client)

			found := false
			for _, m := range metrics {
				if !strings.Contains(m.Desc().String(), "link_state") {
					continue
				}
				found = true
				if got := getMetricValue(m); got != tc.want {
					t.Errorf("link state %q: emitted link_state=%v, want %v", tc.linkState, got, tc.want)
				}
			}
			if !found {
				t.Fatal("no link_state series emitted")
			}
		})
	}
}

func TestInterfacesCollector_Name(t *testing.T) {
	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	if c.Name() != InterfacesSubsystem {
		t.Errorf("expected %s, got %s", InterfacesSubsystem, c.Name())
	}
}

func TestInterfacesCollector_Update_OverviewMetrics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"ixl0": {
					"device": "ixl0", "driver": "ixl", "index": "1", "flags": "0x8843",
					"promiscuous listeners": "0", "send queue length": "0",
					"send queue max length": "50", "send queue drops": "0",
					"type": "Ethernet", "address length": "6", "header length": "14",
					"link state": "2", "vhid": "", "datalen": "176", "mtu": "1500",
					"metric": "0", "line rate": "10000000000 bit/s",
					"packets received": "123456", "packets transmitted": "654321",
					"bytes received": "1000000", "bytes transmitted": "2000000",
					"output errors": "0", "input errors": "1", "collisions": "0",
					"multicasts received": "100", "multicasts transmitted": "50",
					"input queue drops": "0", "packets for unknown protocol": "0",
					"HW offload capabilities": "", "uptime at attach or stat reset": "",
					"name": "LAN"
				}
			}
		}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2, "rowCount": 2, "current": 1,
			"rows": [
				{
					"device": "ixl0", "identifier": "lan", "description": "LAN",
					"status": "up", "flags": ["up", "broadcast", "running"],
					"media": "10Gbase-SR <full-duplex>", "link_type": "static",
					"vlan_tag": null, "is_physical": true
				},
				{
					"device": "ixl0_vlan100", "identifier": "opt3", "description": "MGMT",
					"status": "up", "flags": ["broadcast"],
					"media": "10Gbase-SR <full-duplex>", "link_type": "static",
					"vlan_tag": "100",
					"vlan": {"tag": "100", "proto": "802.1q", "pcp": "7", "parent": "ixl0"},
					"is_physical": false
				}
			]
		}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	// 16 traffic metrics for ixl0 + (admin_up + info) × 2 overview rows = 20
	if expected := 20; len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	adminVals := map[string]float64{}
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), `fqName: "opnsense_interfaces_admin_up"`) {
			labels := getMetricLabels(m)
			adminVals[labels["device"]] = getMetricValue(m)
			if labels["interface"] == "" {
				t.Error("expected interface label on admin_up")
			}
		}
	}
	if adminVals["ixl0"] != 1 {
		t.Errorf("expected admin_up=1 for ixl0, got %v", adminVals["ixl0"])
	}
	if adminVals["ixl0_vlan100"] != 0 {
		t.Errorf("expected admin_up=0 for ixl0_vlan100, got %v", adminVals["ixl0_vlan100"])
	}

	foundVlanInfo := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), `fqName: "opnsense_interfaces_info"`) {
			continue
		}
		if getMetricValue(m) != 1 {
			t.Errorf("expected info value 1, got %v", getMetricValue(m))
		}
		labels := getMetricLabels(m)
		if labels["device"] == "ixl0_vlan100" {
			foundVlanInfo = true
			want := map[string]string{
				"interface": "MGMT", "identifier": "opt3",
				"media": "10Gbase-SR <full-duplex>", "link_type": "static",
				"vlan_tag": "100", "vlan_parent": "ixl0", "physical": "false",
			}
			for k, v := range want {
				if labels[k] != v {
					t.Errorf("info label %s: expected %q, got %q", k, v, labels[k])
				}
			}
		}
	}
	if !foundVlanInfo {
		t.Error("expected info metric for ixl0_vlan100")
	}
}
