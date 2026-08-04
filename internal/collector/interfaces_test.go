package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

	// 17 metrics per interface (mtu, bytesReceived, bytesTransmitted, multicastsReceived,
	// multicastsTransmitted, inputErrors, outputErrors, collisions, receivedPackets,
	// transmittedPackets, sendQueueLength, sendQueueMaxLength, sendQueueDrops,
	// inputQueueDrops, linkState, lineRate, unknownProtocolPackets). The attach/reset
	// marker gauge is NOT counted here: this fixture's marker is "" (invalid), so it is
	// presence-gated out (#375).
	expectedCount := 17
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

	// 17 metrics per interface * 2 interfaces = 34 (see TestInterfacesCollector_Update
	// for the per-interface breakdown; both fixtures' marker is "" so neither emits
	// the attach/reset gauge).
	expectedCount := 34
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

// TestInterfacesCollector_UnknownProtocolPackets covers #375: the
// unknown-protocol-packets counter is always emitted (CounterValue), following
// the tolerant safeAtoi convention (0 on missing/malformed), unlike the
// presence-gated attach/reset marker covered separately below.
func TestInterfacesCollector_UnknownProtocolPackets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces":{"igb0":{"device":"igb0","name":"LAN","type":"Ethernet","link state":"2","mtu":"1500","packets for unknown protocol":"13852362"}}}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	assertMetricsAreCounters(t, metrics, "opnsense_interfaces_unknown_protocol_packets_total")

	found := false
	for _, m := range metrics {
		if !hasFqName(m, "opnsense_interfaces_unknown_protocol_packets_total") {
			continue
		}
		found = true
		if got := getMetricValue(m); got != 13852362 {
			t.Errorf("expected unknown_protocol_packets_total=13852362, got %v", got)
		}
		labels := getMetricLabels(m)
		if labels["interface"] != "LAN" || labels["device"] != "igb0" || labels["type"] != "Ethernet" {
			t.Errorf("unexpected labels: %+v", labels)
		}
	}
	if !found {
		t.Fatal("expected an opnsense_interfaces_unknown_protocol_packets_total series")
	}
}

// TestInterfacesCollector_AttachOrStatResetMarker covers #375's presence-gated
// gauge: emitted (GaugeValue) only when the wire marker parsed, and a genuine
// "0" must still be emitted with value 0 — never dropped as if it were absent.
func TestInterfacesCollector_AttachOrStatResetMarker(t *testing.T) {
	cases := []struct {
		name       string
		markerJSON string // raw JSON fragment for the field, including trailing comma, or "" to omit
		wantSeries bool
		wantValue  float64
	}{
		{"non-zero marker emits gauge", `"uptime at attach or stat reset":"18",`, true, 18},
		{"genuine zero marker still emits gauge", `"uptime at attach or stat reset":"0",`, true, 0},
		{"missing marker emits nothing", ``, false, 0},
		{"malformed marker emits nothing", `"uptime at attach or stat reset":"not-a-number",`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"interfaces":{"igb0":{"device":"igb0","name":"LAN","type":"Ethernet","link state":"2","mtu":"1500",` + tc.markerJSON + `"packets for unknown protocol":"0"}}}`))
			}))
			defer server.Close()

			client := newCollectorTestClient(t, server)
			c := &interfacesCollector{subsystem: InterfacesSubsystem}
			c.Register(namespace, "test", promslog.NewNopLogger())
			metrics := collectMetrics(t, c, client)

			var series []prometheus.Metric
			for _, m := range metrics {
				if hasFqName(m, "opnsense_interfaces_attach_or_statistics_reset_uptime_seconds") {
					series = append(series, m)
				}
			}
			if tc.wantSeries {
				if len(series) != 1 {
					t.Fatalf("expected exactly 1 attach/reset series, got %d", len(series))
				}
				d := &dto.Metric{}
				_ = series[0].Write(d)
				if d.Gauge == nil {
					t.Error("expected attach/reset marker to be emitted as GaugeValue")
				}
				if got := getMetricValue(series[0]); got != tc.wantValue {
					t.Errorf("expected value %v, got %v", tc.wantValue, got)
				}
			} else if len(series) != 0 {
				t.Errorf("expected no attach/reset series, got %d", len(series))
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
	c.pollOnce(context.Background(), ic) // partial success: base traffic ok, overview 500
	ch := make(chan prometheus.Metric, 128)
	c.collect(context.Background(), ch, nil)
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
					"vlan_tag": null, "is_physical": true, "enabled": true
				},
				{
					"device": "ixl0_vlan100", "identifier": "opt3", "description": "MGMT",
					"status": "up", "flags": ["broadcast"],
					"media": "10Gbase-SR <full-duplex>", "link_type": "static",
					"vlan_tag": "100",
					"vlan": {"tag": "100", "proto": "802.1q", "pcp": "7", "parent": "ixl0"},
					"is_physical": false, "enabled": false
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

	// 17 traffic metrics for ixl0 (marker is "" so no attach/reset gauge) +
	// (admin_up + admin_enabled + info) × 2 overview rows = 23
	if expected := 23; len(metrics) != expected {
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

	// #584: admin_enabled is the config-level flag (fixture: ixl0 enabled=true,
	// ixl0_vlan100 enabled=false), independent of admin_up above -- both rows
	// here have admin_up derived purely from their "flags" array.
	adminEnabledVals := map[string]float64{}
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), `fqName: "opnsense_interfaces_admin_enabled"`) {
			labels := getMetricLabels(m)
			adminEnabledVals[labels["device"]] = getMetricValue(m)
			if labels["interface"] == "" {
				t.Error("expected interface label on admin_enabled")
			}
		}
	}
	if adminEnabledVals["ixl0"] != 1 {
		t.Errorf("expected admin_enabled=1 for ixl0, got %v", adminEnabledVals["ixl0"])
	}
	if adminEnabledVals["ixl0_vlan100"] != 0 {
		t.Errorf("expected admin_enabled=0 for ixl0_vlan100, got %v", adminEnabledVals["ixl0_vlan100"])
	}

	foundVlanInfo := false
	foundIxl0Info := false
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
				// ixl0_vlan100 has no entry in the traffic-endpoint fetch above
				// (only "ixl0" does), so the driver/offload join must degrade to
				// empty labels rather than erroring or borrowing another device's.
				"driver": "", "hw_offload_capabilities": "",
			}
			for k, v := range want {
				if labels[k] != v {
					t.Errorf("info label %s: expected %q, got %q", k, v, labels[k])
				}
			}
		}
		if labels["device"] == "ixl0" {
			foundIxl0Info = true
			// ixl0 IS present in the traffic-endpoint fetch ("driver": "ixl",
			// "HW offload capabilities": ""), so its info row must carry that
			// driver name and an empty (not missing) offload-capabilities label.
			if labels["driver"] != "ixl" {
				t.Errorf("info label driver: expected %q, got %q", "ixl", labels["driver"])
			}
			if labels["hw_offload_capabilities"] != "" {
				t.Errorf("info label hw_offload_capabilities: expected empty, got %q", labels["hw_offload_capabilities"])
			}
		}
	}
	if !foundIxl0Info {
		t.Error("expected info metric for ixl0")
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
						"lane_1_rx_power": "0.59 mW (-2.32 dBm)", "lane_1_tx_bias": "6.02 mA"
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
			"opnsense_interfaces_sfp_lane_rx_power_milliwatts", "opnsense_interfaces_sfp_lane_rx_power_dbm",
			"opnsense_interfaces_sfp_lane_tx_bias_milliamps",
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
		"opnsense_interfaces_sfp_lane_rx_power_milliwatts",
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
		t.Errorf("expected lane rx power -2.32 dBm, got %v", v)
	}
	if v := getMetricValue(byName["opnsense_interfaces_sfp_lane_rx_power_milliwatts"][0]); v != 0.59 {
		t.Errorf("expected lane rx power 0.59 mW, got %v", v)
	}
	if v := getMetricValue(byName["opnsense_interfaces_sfp_lane_tx_bias_milliamps"][0]); v != 6.02 {
		t.Errorf("expected lane tx bias 6.02, got %v", v)
	}
}

// TestInterfacesCollector_Update_SFPRXPowerPartial covers #456's per-series
// presence gating at the collector layer: when only one half of a lane's
// rx_power reading parses, exactly that series is emitted — the other metric
// name gets no series at all (never a zero-substituted one) for that lane.
func TestInterfacesCollector_Update_SFPRXPowerPartial(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces": {}}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 1, "rowCount": 1, "current": 1,
			"rows": [
				{
					"device": "ix0", "identifier": "opt1", "description": "SFP1",
					"status": "up", "flags": ["up"], "media": "10Gbase-SR <full-duplex>",
					"link_type": "static", "vlan_tag": null, "is_physical": true,
					"sfp": {
						"plugged": "SFP+ 10GBASE-SR", "vendor": "FS",
						"part_number": "SFP-10GSR-85", "serial_number": "G2129012345",
						"manufacturing_date": "2021-01-01",
						"lane_1_rx_power": "0.48 mW (N/A)",
						"lane_2_rx_power": "N/A (-3.16 dBm)"
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

	var mwSeries, dbmSeries []prometheus.Metric
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, `fqName: "opnsense_interfaces_sfp_lane_rx_power_milliwatts"`) {
			mwSeries = append(mwSeries, m)
		}
		if strings.Contains(desc, `fqName: "opnsense_interfaces_sfp_lane_rx_power_dbm"`) {
			dbmSeries = append(dbmSeries, m)
		}
	}

	if len(mwSeries) != 1 {
		t.Fatalf("expected exactly 1 rx_power_milliwatts series (lane 1 only), got %d", len(mwSeries))
	}
	if labels := getMetricLabels(mwSeries[0]); labels["lane"] != "1" {
		t.Errorf("expected mW series for lane 1, got %+v", labels)
	}
	if v := getMetricValue(mwSeries[0]); v != 0.48 {
		t.Errorf("expected mW=0.48, got %v", v)
	}

	if len(dbmSeries) != 1 {
		t.Fatalf("expected exactly 1 rx_power_dbm series (lane 2 only), got %d", len(dbmSeries))
	}
	if labels := getMetricLabels(dbmSeries[0]); labels["lane"] != "2" {
		t.Errorf("expected dBm series for lane 2, got %+v", labels)
	}
	if v := getMetricValue(dbmSeries[0]); v != -3.16 {
		t.Errorf("expected dBm=-3.16, got %v", v)
	}
}

// #544 item 4: get_interface_statistics was decoded for the kernel index only.
// Its per-address rows carry the only obtainable per-family split, and its
// AF_LINK row the only oqdrops figure for devices the traffic endpoint omits.
func TestInterfacesCollector_AddressFamilyAndOutputQueueDrops(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"interfaces":{}}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_interface_statistics", func(w http.ResponseWriter, _ *http.Request) {
		// Trimmed from the prod box, plus tailscale0 from a dev box — the only
		// device on any observed box with a non-zero oqdrops, and one the
		// traffic endpoint does not report at all.
		w.Write([]byte(`{"statistics":{
		 "[LAN] (ixl0) / 98:b7:85:21:af:f2":{"name":"ixl0","network":"<Link#1>","address":"98:b7:85:21:af:f2","received-packets":419866764,"dropped-packets":0,"received-bytes":383093557281,"sent-packets":381907348,"sent-bytes":316537354094},
		 "[LAN] (ixl0) / 10.0.0.254":{"name":"ixl0","network":"10.0.0.0/24","address":"10.0.0.254","received-packets":15603611,"received-bytes":2369675284,"sent-packets":25173485,"sent-bytes":23846528514},
		 "[LAN] (ixl0) / fe80::1%ixl0":{"name":"ixl0","network":"fe80::%ixl0/64","address":"fe80::1%ixl0","received-packets":214444,"received-bytes":18089655,"sent-packets":257888,"sent-bytes":21509007},
		 "[tailscale] (tailscale0)":{"name":"tailscale0","network":"<Link#16>","address":"","dropped-packets":8,"received-packets":1,"received-bytes":2,"sent-packets":3,"sent-bytes":4}
		}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	fam := map[string]float64{}
	drops := map[string]float64{}
	for _, m := range collectMetrics(t, c, client) {
		l := getMetricLabels(m)
		switch {
		case hasFqName(m, "opnsense_interfaces_address_family_received_packets_total"):
			fam["rxp|"+l["device"]+"|"+l["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_interfaces_address_family_received_bytes_total"):
			fam["rxb|"+l["device"]+"|"+l["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_interfaces_address_family_sent_packets_total"):
			fam["txp|"+l["device"]+"|"+l["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_interfaces_address_family_sent_bytes_total"):
			fam["txb|"+l["device"]+"|"+l["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_interfaces_output_queue_drops_total"):
			drops[l["device"]] = getMetricValue(m)
		}
	}

	if fam["rxp|ixl0|ipv4"] != 15603611 {
		t.Errorf("ixl0 ipv4 rx packets = %v", fam["rxp|ixl0|ipv4"])
	}
	if fam["rxp|ixl0|ipv6"] != 214444 {
		t.Errorf("ixl0 ipv6 rx packets = %v", fam["rxp|ixl0|ipv6"])
	}
	if fam["txb|ixl0|ipv4"] != 23846528514 {
		t.Errorf("ixl0 ipv4 tx bytes = %v", fam["txb|ixl0|ipv4"])
	}
	// The AF_LINK row must not become a family row; its address is a MAC.
	if fam["rxp|ixl0|ipv6"] == 419866764 {
		t.Error("AF_LINK row classified as an address family row")
	}
	if drops["tailscale0"] != 8 {
		t.Errorf("tailscale0 output queue drops = %v, want 8", drops["tailscale0"])
	}
	if _, ok := drops["ixl0"]; !ok {
		t.Error("ixl0 output_queue_drops missing; a healthy zero must still be emitted")
	}
}

// TestInterfacesCollector_WrappedQueueDropsAreAbsent pins the emit side of #548:
// a queue-drop figure that has wrapped through an unsigned 32-bit field must
// produce NO series for that interface, not a clamped 0. ixl1 carries the real
// captured prod value; ixl0 alongside it proves the suppression is per-interface
// and does not blank the family for the healthy ones.
func TestInterfacesCollector_WrappedQueueDropsAreAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"ixl0": {
					"device": "ixl0", "name": "LAN", "type": "Ethernet", "link state": "2",
					"mtu": "1500", "input queue drops": "7", "send queue drops": "0"
				},
				"ixl1": {
					"device": "ixl1", "name": "WAN", "type": "Ethernet", "link state": "2",
					"mtu": "1500", "input queue drops": "4294958080", "send queue drops": "0"
				}
			}
		}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	ic := &interfacesCollector{subsystem: InterfacesSubsystem}
	ic.Register(namespace, "test", promslog.NewNopLogger())

	devices := map[string]float64{}
	for _, m := range collectMetrics(t, ic, newCollectorTestClient(t, server)) {
		if !hasFqName(m, "opnsense_interfaces_input_queue_drops_total") {
			continue
		}
		devices[getMetricLabels(m)["device"]] = getMetricValue(m)
	}

	if got, ok := devices["ixl0"]; !ok || got != 7 {
		t.Errorf("ixl0 input_queue_drops = %v (present=%v), want 7", got, ok)
	}
	if got, ok := devices["ixl1"]; ok {
		t.Errorf("ixl1 published a wrapped input_queue_drops of %v; the series must be absent", got)
	}
}

// TestInterfacesCollector_LineRateSuppressedForCarrierlessDevice covers #644:
// a device the kernel reports as LinkStateUnknown ("0" wire link state —
// PPPoE, tun/tailscale, similar overlays) must emit NO line_rate_bits series,
// since the kernel value there is a placeholder, not a real negotiated rate
// (pppoe0 reads exactly 64000 on the reference box). An Ethernet device in
// the same scrape must be unaffected.
func TestInterfacesCollector_LineRateSuppressedForCarrierlessDevice(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"pppoe0": {
					"device": "pppoe0", "name": "WAN", "type": "PPPoE", "link state": "0",
					"mtu": "1492", "line rate": "64000 bit/s"
				},
				"ixl0": {
					"device": "ixl0", "name": "LAN", "type": "Ethernet", "link state": "2",
					"mtu": "1500", "line rate": "1000000000 bit/s"
				}
			}
		}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	rates := map[string]float64{}
	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		if !hasFqName(m, "opnsense_interfaces_line_rate_bits") {
			continue
		}
		rates[getMetricLabels(m)["device"]] = getMetricValue(m)
	}

	if _, ok := rates["pppoe0"]; ok {
		t.Errorf("pppoe0 published a line_rate_bits series; the placeholder value must be suppressed, got %v", rates["pppoe0"])
	}
	if got, ok := rates["ixl0"]; !ok || got != 1000000000 {
		t.Errorf("ixl0 line_rate_bits = %v (present=%v), want 1000000000", got, ok)
	}
}

// TestInterfacesCollector_StatisticsGapFill_NoDoubleSource covers #642's
// critical requirement: a device the traffic endpoint ALREADY covers must
// never also get counters from the get_interface_statistics gap-fill branch,
// or the two independently-drifting sources would make rate() nonsense. ixl0
// is assigned (covered by the traffic endpoint) and also appears in the
// statistics response with DIFFERENT figures — if gap-fill fired for it, the
// mismatched values below would prove the double-source bug. ixl2 is NOT in
// the traffic endpoint's response at all (mirrors the real unassigned-port
// case from #642) and must be filled in from statistics alone.
func TestInterfacesCollector_StatisticsGapFill_NoDoubleSource(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/traffic/interface", func(w http.ResponseWriter, r *http.Request) {
		// ixl0 is ASSIGNED and gets its counters from here. ixl2 is absent —
		// exactly like the live #642 case (OPNsense restricts this endpoint
		// to interfaces with a config identifier).
		w.Write([]byte(`{
			"interfaces": {
				"ixl0": {
					"device": "ixl0", "name": "LAN", "type": "Ethernet", "link state": "2",
					"mtu": "1500", "bytes received": "1000000", "bytes transmitted": "2000000",
					"packets received": "123456", "packets transmitted": "654321",
					"input errors": "1", "output errors": "2", "collisions": "0"
				}
			}
		}`))
	})
	mux.HandleFunc("/api/interfaces/overview/interfaces_info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"device":"ixl2","identifier":"","description":"Unassigned Interface ixl2","is_physical":true}
		]}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_interface_statistics", func(w http.ResponseWriter, r *http.Request) {
		// ixl0's statistics-endpoint figures are DELIBERATELY DIFFERENT from
		// the traffic-endpoint figures above: if the gap-fill branch ever
		// emitted for a traffic-covered device, these mismatched numbers
		// would appear as a second series and the test would catch it.
		// ixl2 carries the real live #642 payload verbatim.
		w.Write([]byte(`{"statistics":{
		 "[LAN] (ixl0) / 98:b7:85:21:af:f2":{"name":"ixl0","network":"<Link#1>","address":"98:b7:85:21:af:f2","received-packets":999999999,"received-errors":999,"dropped-packets":0,"received-bytes":999999999,"sent-packets":999999999,"send-errors":999,"sent-bytes":999999999,"collisions":999},
		 "[ixl2] / 98:b7:85:21:af:f4":{"name":"ixl2","network":"<Link#3>","address":"98:b7:85:21:af:f4","received-packets":281475478389769,"received-errors":0,"dropped-packets":0,"received-bytes":393185547668,"sent-packets":561408322,"send-errors":0,"sent-bytes":537868820722,"collisions":0}
		}}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &interfacesCollector{subsystem: InterfacesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	type series struct {
		count int
		last  float64
	}
	byNameDevice := map[string]series{}
	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		name := ""
		switch {
		case hasFqName(m, "opnsense_interfaces_received_bytes_total"):
			name = "received_bytes"
		case hasFqName(m, "opnsense_interfaces_transmitted_bytes_total"):
			name = "transmitted_bytes"
		case hasFqName(m, "opnsense_interfaces_received_packets_total"):
			name = "received_packets"
		case hasFqName(m, "opnsense_interfaces_transmitted_packets_total"):
			name = "transmitted_packets"
		case hasFqName(m, "opnsense_interfaces_input_errors_total"):
			name = "input_errors"
		case hasFqName(m, "opnsense_interfaces_output_errors_total"):
			name = "output_errors"
		case hasFqName(m, "opnsense_interfaces_collisions_total"):
			name = "collisions"
		default:
			continue
		}
		key := name + "|" + getMetricLabels(m)["device"]
		e := byNameDevice[key]
		e.count++
		e.last = getMetricValue(m)
		byNameDevice[key] = e
	}

	// ixl0: exactly ONE series per metric, and it must be the TRAFFIC-endpoint
	// value (1000000), never the statistics-endpoint decoy (999999999) and
	// never both (which would show count==2).
	if e := byNameDevice["received_bytes|ixl0"]; e.count != 1 || e.last != 1000000 {
		t.Errorf("ixl0 received_bytes_total: count=%d value=%v, want exactly 1 series at 1000000 (traffic endpoint must win, no double-source)", e.count, e.last)
	}
	if e := byNameDevice["input_errors|ixl0"]; e.count != 1 || e.last != 1 {
		t.Errorf("ixl0 input_errors_total: count=%d value=%v, want exactly 1 series at 1", e.count, e.last)
	}

	// ixl2: absent from the traffic endpoint entirely, so gap-fill must be
	// the ONLY source. Bytes and sent-packets are plausible and must be
	// published; received-packets is the live #642 2^48 case and must be
	// suppressed (absent), not published as either 0 or the corrupt figure.
	if e := byNameDevice["received_bytes|ixl2"]; e.count != 1 || e.last != 393185547668 {
		t.Errorf("ixl2 received_bytes_total: count=%d value=%v, want exactly 1 series at 393185547668 (gap-filled)", e.count, e.last)
	}
	if e := byNameDevice["transmitted_bytes|ixl2"]; e.count != 1 || e.last != 537868820722 {
		t.Errorf("ixl2 transmitted_bytes_total: count=%d value=%v, want exactly 1 series at 537868820722", e.count, e.last)
	}
	if e := byNameDevice["transmitted_packets|ixl2"]; e.count != 1 || e.last != 561408322 {
		t.Errorf("ixl2 transmitted_packets_total: count=%d value=%v, want exactly 1 series at 561408322", e.count, e.last)
	}
	if e, ok := byNameDevice["received_packets|ixl2"]; ok {
		t.Errorf("ixl2 received_packets_total published despite the implausible 2^48 value: count=%d value=%v", e.count, e.last)
	}
	if e := byNameDevice["input_errors|ixl2"]; e.count != 1 || e.last != 0 {
		t.Errorf("ixl2 input_errors_total: count=%d value=%v, want exactly 1 series at 0 (genuine zero, gap-filled)", e.count, e.last)
	}
	if e := byNameDevice["collisions|ixl2"]; e.count != 1 || e.last != 0 {
		t.Errorf("ixl2 collisions_total: count=%d value=%v, want exactly 1 series at 0", e.count, e.last)
	}

	// ixl2's "interface" label must come from the overview description
	// (there is no traffic-endpoint name for it), not be left empty.
	for _, m := range collectMetrics(t, c, newCollectorTestClient(t, server)) {
		if hasFqName(m, "opnsense_interfaces_received_bytes_total") && getMetricLabels(m)["device"] == "ixl2" {
			if got := getMetricLabels(m)["interface"]; got != "Unassigned Interface ixl2" {
				t.Errorf("ixl2 interface label = %q, want the overview description", got)
			}
		}
	}
}
