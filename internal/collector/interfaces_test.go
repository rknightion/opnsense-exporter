package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
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

// TestInterfacesCollector_OverviewFailureSurfaced covers #123: when the secondary
// interfaces-overview fetch fails but the base fetch succeeds, the failure must be
// surfaced through the standard collector error path (endpoint_errors_total +
// scrape_collector_success=0) instead of being silently swallowed with a nil return,
// while the base traffic metrics are still emitted (partial tolerance preserved).
func TestInterfacesCollector_OverviewFailureSurfaced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"ixl0": {
					"device": "ixl0", "driver": "ixl", "index": "1", "flags": "0x8843",
					"send queue length": "0", "send queue max length": "50", "send queue drops": "0",
					"type": "Ethernet", "link state": "2", "mtu": "1500", "line rate": "10000000000 bit/s",
					"packets received": "123456", "packets transmitted": "654321",
					"bytes received": "1000000", "bytes transmitted": "2000000",
					"output errors": "0", "input errors": "1", "collisions": "0",
					"multicasts received": "100", "multicasts transmitted": "50",
					"input queue drops": "0", "name": "LAN"
				}
			}
		}`))
	})
	// Overview endpoint fails while the base traffic endpoint above succeeds.
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	ic := &interfacesCollector{subsystem: InterfacesSubsystem}
	ic.Register(namespace, "test", promslog.NewNopLogger())

	c := newScrapeTestCollector(t, client, ic)
	ch := make(chan prometheus.Metric, 128)
	c.execute(context.Background(), ic, client, ch)
	close(ch)

	var trafficSeen bool
	var successVal *float64
	for m := range ch {
		desc := m.Desc().String()
		if strings.Contains(desc, `fqName: "opnsense_interfaces_received_bytes_total"`) {
			trafficSeen = true
		}
		if strings.Contains(desc, "scrape_collector_success") {
			v := getMetricValue(m)
			successVal = &v
		}
	}

	if !trafficSeen {
		t.Error("base traffic metrics should still be emitted despite the overview failure")
	}
	if successVal == nil {
		t.Error("scrape_collector_success was not emitted")
	} else if *successVal != 0 {
		t.Errorf("scrape_collector_success{collector=interfaces} = %v, want 0", *successVal)
	}
	if got := counterValue(t, c.endpointErrors.WithLabelValues("api/interfaces/overview/interfaces_info", "test")); got != 1 {
		t.Errorf(`endpoint_errors_total{endpoint="api/interfaces/overview/interfaces_info"} = %v, want 1`, got)
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

// TestInterfacesCollector_Update_LaggBridgeSFP covers #214: LAGG member
// state, bridge membership and SFP/DOM optics all come from the same
// interfaces_info payload already fetched above. It exercises one row of
// each kind (LACP lagg, bridge, DOM-capable SFP) and asserts both the
// populated series AND that no DOM series are invented for a copper SFP with
// no DOM fields (absent, never zero).
func TestInterfacesCollector_Update_LaggBridgeSFP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces": {}}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 4, "rowCount": 4, "current": 1,
			"rows": [
				{
					"device": "lagg0", "identifier": "lan", "description": "LAN",
					"status": "up", "flags": ["up"], "media": "Ethernet autoselect",
					"link_type": "static", "vlan_tag": null, "is_physical": true,
					"laggproto": "lacp", "lagghash": "l2,l3,l4",
					"laggstatistics": {"active ports": "1", "flapping": "2"},
					"laggport": {
						"ix0": {"flags": ["active"], "state": ["active", "collecting", "distributing"]},
						"ix1": {"flags": [], "state": [""]}
					}
				},
				{
					"device": "bridge0", "identifier": "opt5", "description": "GUESTBRIDGE",
					"status": "up", "flags": ["up"], "media": "Ethernet autoselect",
					"link_type": "static", "vlan_tag": null, "is_physical": false,
					"members": {
						"ix2": {"flags": ["learning"]}
					}
				},
				{
					"device": "ixl2", "identifier": "opt6", "description": "SFPCOPPER",
					"status": "up", "flags": ["up"], "media": "SFP/SFP+/SFP28 1000BASE-T <full-duplex>",
					"link_type": "static", "vlan_tag": null, "is_physical": true,
					"sfp": {
						"plugged": "SFP/SFP+/SFP28 1000BASE-T (Unknown)",
						"vendor": "UBNT", "part_number": " UF-RJ45-1G",
						"serial_number": "X00000000002", "manufacturing_date": "2021-04-07"
					}
				},
				{
					"device": "ix0", "identifier": "opt7", "description": "SFPOPTICAL",
					"status": "up", "flags": ["up"], "media": "10Gbase-SR <full-duplex>",
					"link_type": "static", "vlan_tag": null, "is_physical": true,
					"sfp": {
						"plugged": "SFP+ 10GBASE-SR", "vendor": "FS",
						"part_number": "SFP-10GSR-85", "serial_number": "G2129012345",
						"manufacturing_date": "2021-01-01",
						"temperature": "32.79 C", "voltage": "3.30 ",
						"lane_1_rx_power": "-2.32 dBm (0.59 mW)", "lane_1_tx_bias": "6.02 mA"
					}
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

	byName := map[string][]prometheus.Metric{}
	for _, m := range metrics {
		desc := m.Desc().String()
		for _, name := range []string{
			"opnsense_interfaces_lagg_info", "opnsense_interfaces_lagg_active_ports",
			"opnsense_interfaces_lagg_flapping_total", "opnsense_interfaces_lagg_port_active",
			"opnsense_interfaces_lagg_port_collecting", "opnsense_interfaces_lagg_port_distributing",
			"opnsense_interfaces_bridge_member", "opnsense_interfaces_sfp_info",
			"opnsense_interfaces_sfp_temperature_celsius", "opnsense_interfaces_sfp_voltage_volts",
			"opnsense_interfaces_sfp_lane_rx_power_dbm", "opnsense_interfaces_sfp_lane_tx_bias_milliamps",
		} {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				byName[name] = append(byName[name], m)
			}
		}
	}

	if got := len(byName["opnsense_interfaces_lagg_info"]); got != 1 {
		t.Errorf("expected 1 lagg_info series, got %d", got)
	} else {
		labels := getMetricLabels(byName["opnsense_interfaces_lagg_info"][0])
		if labels["device"] != "lagg0" || labels["protocol"] != "lacp" || labels["hash"] != "l2,l3,l4" {
			t.Errorf("unexpected lagg_info labels: %+v", labels)
		}
	}
	if got := len(byName["opnsense_interfaces_lagg_active_ports"]); got != 1 {
		t.Errorf("expected 1 lagg_active_ports series, got %d", got)
	} else if v := getMetricValue(byName["opnsense_interfaces_lagg_active_ports"][0]); v != 1 {
		t.Errorf("expected lagg_active_ports=1, got %v", v)
	}
	if got := len(byName["opnsense_interfaces_lagg_flapping_total"]); got != 1 {
		t.Errorf("expected 1 lagg_flapping_total series, got %d", got)
	} else if v := getMetricValue(byName["opnsense_interfaces_lagg_flapping_total"][0]); v != 2 {
		t.Errorf("expected lagg_flapping_total=2, got %v", v)
	}
	if got := len(byName["opnsense_interfaces_lagg_port_active"]); got != 2 {
		t.Errorf("expected 2 lagg_port_active series (ix0+ix1), got %d", got)
	}
	// ix1's state carries a single empty-string entry — mirroring PHP's
	// explode(",", "") quirk for an empty "state=<>" clause — so StatePresent
	// is still true but Collecting/Distributing are false. Both ix0 (true)
	// and ix1 (false) therefore emit a collecting/distributing series; a
	// device whose laggport carries no "state=" clause at all (failover/
	// loadbalance) emits neither, covered at the opnsense layer by
	// TestFetchInterfacesOverview_LaggFailoverNoLACPState.
	if got := len(byName["opnsense_interfaces_lagg_port_collecting"]); got != 2 {
		t.Errorf("expected 2 lagg_port_collecting series (state clause present on both), got %d", got)
	}

	if got := len(byName["opnsense_interfaces_bridge_member"]); got != 1 {
		t.Errorf("expected 1 bridge_member series, got %d", got)
	} else {
		labels := getMetricLabels(byName["opnsense_interfaces_bridge_member"][0])
		if labels["device"] != "bridge0" || labels["member"] != "ix2" {
			t.Errorf("unexpected bridge_member labels: %+v", labels)
		}
	}

	if got := len(byName["opnsense_interfaces_sfp_info"]); got != 2 {
		t.Errorf("expected 2 sfp_info series (copper + optical), got %d", got)
	}

	// The copper SFP (ixl2) must never emit DOM series; only the optical one
	// (ix0) does. Assert exactly one DOM series per DOM metric, and that it
	// belongs to ix0.
	for _, name := range []string{
		"opnsense_interfaces_sfp_temperature_celsius",
		"opnsense_interfaces_sfp_voltage_volts",
		"opnsense_interfaces_sfp_lane_rx_power_dbm",
		"opnsense_interfaces_sfp_lane_tx_bias_milliamps",
	} {
		got := byName[name]
		if len(got) != 1 {
			t.Errorf("%s: expected exactly 1 series (optical only, none for copper), got %d", name, len(got))
			continue
		}
		if labels := getMetricLabels(got[0]); labels["device"] != "ix0" {
			t.Errorf("%s: expected device=ix0, got %+v", name, labels)
		}
	}
	if v := getMetricValue(byName["opnsense_interfaces_sfp_temperature_celsius"][0]); v != 32.79 {
		t.Errorf("expected temperature 32.79, got %v", v)
	}
	if v := getMetricValue(byName["opnsense_interfaces_sfp_voltage_volts"][0]); v != 3.30 {
		t.Errorf("expected voltage 3.30, got %v", v)
	}
	if v := getMetricValue(byName["opnsense_interfaces_sfp_lane_rx_power_dbm"][0]); v != -2.32 {
		t.Errorf("expected lane rx power -2.32, got %v", v)
	}
	if v := getMetricValue(byName["opnsense_interfaces_sfp_lane_tx_bias_milliamps"][0]); v != 6.02 {
		t.Errorf("expected lane tx bias 6.02, got %v", v)
	}
}
