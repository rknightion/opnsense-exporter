package collector

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestNetworkDiagCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/interface/get_netisr_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"netisr": {
				"protocol": [
					{"name": "ip", "protocol": 1, "queue-limit": 256, "policy": "flow"},
					{"name": "arp", "protocol": 2, "queue-limit": 128, "policy": "source"}
				],
				"workstream": [
					{
						"work": [
							{
								"workstream": 0, "cpu": 0, "name": "ip",
								"length": 3, "watermark": 8,
								"dispatched": 100, "hybrid-dispatched": 10,
								"queue-drops": 1, "queued": 50, "handled": 99
							},
							{
								"workstream": 0, "cpu": 0, "name": "arp",
								"length": 1, "watermark": 2,
								"dispatched": 20, "hybrid-dispatched": 2,
								"queue-drops": 0, "queued": 10, "handled": 20
							}
						]
					}
				]
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/interface/get_socket_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"statistics": {
				"Active Internet connections": {
					"tcp4/[10.0.0.1:80-10.0.0.2:1234]": {},
					"tcp4/[10.0.0.1:443-10.0.0.3:5678]": {},
					"udp4/[10.0.0.1:53-*:*]": {}
				},
				"Active UNIX domain sockets": {
					"fffff8001d757280 - /var/run/log.sock": {}
				}
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/interface/get_routes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"proto": "IPv4"},
			{"proto": "IPv4"},
			{"proto": "IPv6"}
		]`))
	})

	mux.HandleFunc("/api/diagnostics/interface/get_pfsync_nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{"creatorid": "node1", "this": 1},
				{"creatorid": "node2", "this": 0}
			]
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	// per-CPU series off here so this stays a test of the aggregate shape;
	// they have their own tests below.
	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: false}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 protocols * 8 aggregate netisr metrics = 16
	// 2 protocols * (1 protocol_info + 4 derived summaries) = 10
	// 3 socket types (tcp4, udp4, unix) active = 3
	// 1 unix total = 1
	// 2 route protos (IPv4, IPv6) = 2
	// route breakdowns from a fixture whose rows carry no netif/flags: 2 per-interface
	//   + 2 per-flags + 2 default_route_present (always one per family) = 6
	// 1 pfsync nodes total + 2 pfsync node info = 3
	// Total: 16 + 10 + 3 + 1 + 2 + 6 + 3 = 41
	expectedCount := 41
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify some specific metrics
	found := false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if labels["protocol"] == "ip" {
			desc := m.Desc().String()
			// Check dispatched total for ip
			if containsString(desc, "netisr_dispatched_total") {
				val := getMetricValue(m)
				if val != 100 {
					t.Errorf("ip dispatched = %v; want 100", val)
				}
				found = true
			}
		}
	}
	if !found {
		t.Error("could not find ip netisr_dispatched_total metric")
	}
}

func TestNetworkDiagCollector_Name(t *testing.T) {
	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem}
	if c.Name() != NetworkDiagSubsystem {
		t.Errorf("expected %s, got %s", NetworkDiagSubsystem, c.Name())
	}
}

// --- netisr per-CPU exposure (#539) ---

// netisrProdFixture is the real OPNsense 26.1 netisr payload captured from the
// production firewall: 8 protocols x 12 workstreams. Only 4 of the 12 CPUs
// carry ip/ip6 work, cpu0's ip6 watermark is pinned at its 1000 queue-limit,
// and all 683 ip6 drops landed on cpu0 — the CPU-affinity condition #539 exists
// to make visible.
func netisrProdFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "opnsense", "testdata", "netisr", "prod_26.1.json"))
	if err != nil {
		t.Fatalf("read netisr fixture: %v", err)
	}
	return b
}

// newNetisrOnlyServer serves the netisr payload and empty responses for the
// collector's other three endpoints, so a test can assert on netisr series
// alone.
func newNetisrOnlyServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/get_netisr_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	mux.HandleFunc("/api/diagnostics/interface/get_socket_statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"statistics": {}}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_routes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_pfsync_nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})
	return httptest.NewServer(mux)
}

// netisrSeries indexes collected metrics by metric name, keeping the label sets
// and values so a test can look up one protocol/cpu combination.
type netisrSeries struct {
	labels map[string]string
	value  float64
}

func collectNetisr(t *testing.T, c *networkDiagCollector, server *httptest.Server) map[string][]netisrSeries {
	t.Helper()
	client := newCollectorTestClient(t, server)

	// The shared collectMetrics helper buffers 500 metrics; the prod netisr
	// capture alone produces 776 (8 aggregate + 5 derived per protocol, plus
	// 7 x 96 per-CPU series), which would deadlock it. Drain concurrently
	// instead of guessing a bigger buffer.
	ch := make(chan prometheus.Metric)
	var collected []prometheus.Metric
	done := make(chan struct{})
	go func() {
		for m := range ch {
			collected = append(collected, m)
		}
		close(done)
	}()
	if err := c.Update(context.Background(), client, ch); err != nil {
		close(ch)
		<-done
		t.Fatalf("Update returned error: %v", err)
	}
	close(ch)
	<-done

	out := make(map[string][]netisrSeries)
	for _, m := range collected {
		desc := m.Desc().String()
		for _, name := range []string{
			"netisr_protocol_info",
			"netisr_active_workstreams",
			"netisr_workstreams_at_limit",
			"netisr_queue_imbalance_ratio",
			"netisr_drop_concentration_ratio",
			"netisr_cpu_dispatched_total",
			"netisr_cpu_hybrid_dispatched_total",
			"netisr_cpu_queued_total",
			"netisr_cpu_handled_total",
			"netisr_cpu_queue_drops_total",
			"netisr_cpu_queue_length",
			"netisr_cpu_queue_watermark",
		} {
			if containsString(desc, `fqName: "opnsense_network_diag_`+name+`"`) {
				out[name] = append(out[name], netisrSeries{labels: getMetricLabels(m), value: getMetricValue(m)})
			}
		}
	}
	return out
}

func TestNetworkDiagCollector_NetisrPerCPU(t *testing.T) {
	server := newNetisrOnlyServer(t, netisrProdFixture(t))
	defer server.Close()

	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: true}
	c.Register(namespace, "test", promslog.NewNopLogger())
	got := collectNetisr(t, c, server)

	// 8 protocols x 12 workstreams, including entirely idle CPUs.
	for _, name := range []string{
		"netisr_cpu_dispatched_total",
		"netisr_cpu_hybrid_dispatched_total",
		"netisr_cpu_queued_total",
		"netisr_cpu_handled_total",
		"netisr_cpu_queue_drops_total",
		"netisr_cpu_queue_length",
		"netisr_cpu_queue_watermark",
	} {
		if len(got[name]) != 96 {
			t.Errorf("%s: got %d series; want 96 (8 protocols x 12 workstreams, idle rows included)", name, len(got[name]))
		}
	}

	// Every per-CPU series carries both the workstream index and the CPU.
	for _, s := range got["netisr_cpu_handled_total"] {
		if s.labels["protocol"] == "" || s.labels["cpu"] == "" || s.labels["workstream"] == "" {
			t.Fatalf("per-CPU series missing a label: %v", s.labels)
		}
	}

	find := func(name, proto, cpu string) (netisrSeries, bool) {
		for _, s := range got[name] {
			if s.labels["protocol"] == proto && s.labels["cpu"] == cpu {
				return s, true
			}
		}
		return netisrSeries{}, false
	}

	// cpu0 owns every ip6 drop; cpu1 has none. This is the whole point.
	if s, ok := find("netisr_cpu_queue_drops_total", "ip6", "0"); !ok || s.value != 683 {
		t.Errorf("ip6 cpu0 queue drops = %v (found=%v); want 683", s.value, ok)
	}
	if s, ok := find("netisr_cpu_queue_drops_total", "ip6", "1"); !ok || s.value != 0 {
		t.Errorf("ip6 cpu1 queue drops = %v (found=%v); want 0", s.value, ok)
	}
	// cpu0's ip6 watermark is pinned at the 1000 queue limit.
	if s, ok := find("netisr_cpu_queue_watermark", "ip6", "0"); !ok || s.value != 1000 {
		t.Errorf("ip6 cpu0 watermark = %v (found=%v); want 1000", s.value, ok)
	}
	// cpu11 is entirely idle for ip6 and must still be emitted as zero.
	if s, ok := find("netisr_cpu_handled_total", "ip6", "11"); !ok || s.value != 0 {
		t.Errorf("ip6 cpu11 handled = %v (found=%v); want an explicit 0 series", s.value, ok)
	}
}

func TestNetworkDiagCollector_NetisrDerivedSummaries(t *testing.T) {
	server := newNetisrOnlyServer(t, netisrProdFixture(t))
	defer server.Close()

	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: true}
	c.Register(namespace, "test", promslog.NewNopLogger())
	got := collectNetisr(t, c, server)

	value := func(name, proto string) (float64, bool) {
		for _, s := range got[name] {
			if s.labels["protocol"] == proto {
				return s.value, true
			}
		}
		return 0, false
	}

	tests := []struct {
		name  string
		proto string
		want  float64
	}{
		{"netisr_active_workstreams", "ip6", 4},
		{"netisr_active_workstreams", "ip", 4},
		{"netisr_active_workstreams", "ether", 12},
		{"netisr_workstreams_at_limit", "ip6", 1},
		{"netisr_workstreams_at_limit", "ip", 0},
		{"netisr_queue_imbalance_ratio", "ip6", 1000.0 / (2852.0 / 4.0)},
		{"netisr_queue_imbalance_ratio", "rtsock", 0},
		{"netisr_drop_concentration_ratio", "ip6", 1},
		{"netisr_drop_concentration_ratio", "ip", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.proto, func(t *testing.T) {
			v, ok := value(tt.name, tt.proto)
			if !ok {
				t.Fatalf("%s{protocol=%q} not emitted", tt.name, tt.proto)
			}
			if math.Abs(v-tt.want) > 1e-9 {
				t.Errorf("%s{protocol=%q} = %v; want %v", tt.name, tt.proto, v, tt.want)
			}
		})
	}

	// Summary metrics are always on and cover all 8 protocols.
	for _, name := range []string{
		"netisr_active_workstreams",
		"netisr_workstreams_at_limit",
		"netisr_queue_imbalance_ratio",
		"netisr_drop_concentration_ratio",
		"netisr_protocol_info",
	} {
		if len(got[name]) != 8 {
			t.Errorf("%s: got %d series; want 8", name, len(got[name]))
		}
	}
}

func TestNetworkDiagCollector_NetisrProtocolInfo(t *testing.T) {
	server := newNetisrOnlyServer(t, netisrProdFixture(t))
	defer server.Close()

	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: true}
	c.Register(namespace, "test", promslog.NewNopLogger())
	got := collectNetisr(t, c, server)

	byProto := make(map[string]netisrSeries)
	for _, s := range got["netisr_protocol_info"] {
		byProto[s.labels["protocol"]] = s
	}

	tests := []struct {
		proto      string
		protocolID string
		policy     string
		policyType string
		flags      string
	}{
		{"ip", "1", "hybrid", "cpu", "C--"},
		{"ip6", "6", "hybrid", "cpu", "C--"},
		{"ether", "5", "direct", "cpu", "C--"},
		// source-policy protocols are single-lane BY DESIGN — an imbalance
		// alert must be able to exclude them, which is what policy_type is for.
		{"igmp", "2", "default", "source", "---"},
		{"rtsock", "3", "default", "source", "---"},
		{"arp", "4", "default", "source", "---"},
		{"ip_direct", "9", "hybrid", "cpu", "C--"},
		{"ip6_direct", "10", "hybrid", "cpu", "C--"},
	}
	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			s, ok := byProto[tt.proto]
			if !ok {
				t.Fatalf("netisr_protocol_info{protocol=%q} not emitted", tt.proto)
			}
			if s.value != 1 {
				t.Errorf("value = %v; want 1", s.value)
			}
			if s.labels["protocol_id"] != tt.protocolID {
				t.Errorf("protocol_id = %q; want %q", s.labels["protocol_id"], tt.protocolID)
			}
			if s.labels["policy"] != tt.policy {
				t.Errorf("policy = %q; want %q", s.labels["policy"], tt.policy)
			}
			if s.labels["policy_type"] != tt.policyType {
				t.Errorf("policy_type = %q; want %q", s.labels["policy_type"], tt.policyType)
			}
			if s.labels["flags"] != tt.flags {
				t.Errorf("flags = %q; want %q", s.labels["flags"], tt.flags)
			}
		})
	}
}

func TestNetworkDiagCollector_NetisrPerCPUOptOut(t *testing.T) {
	server := newNetisrOnlyServer(t, netisrProdFixture(t))
	defer server.Close()

	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: true}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetNetisrPerCPUEnabled(false)
	got := collectNetisr(t, c, server)

	for _, name := range []string{
		"netisr_cpu_dispatched_total",
		"netisr_cpu_hybrid_dispatched_total",
		"netisr_cpu_queued_total",
		"netisr_cpu_handled_total",
		"netisr_cpu_queue_drops_total",
		"netisr_cpu_queue_length",
		"netisr_cpu_queue_watermark",
	} {
		if len(got[name]) != 0 {
			t.Errorf("%s: got %d series with per-CPU disabled; want 0", name, len(got[name]))
		}
	}

	// The derived summaries and the info metric are NOT gated by the opt-out —
	// they are what the alerts read.
	for _, name := range []string{
		"netisr_protocol_info",
		"netisr_active_workstreams",
		"netisr_workstreams_at_limit",
		"netisr_queue_imbalance_ratio",
		"netisr_drop_concentration_ratio",
	} {
		if len(got[name]) != 8 {
			t.Errorf("%s: got %d series with per-CPU disabled; want 8 (not gated)", name, len(got[name]))
		}
	}
}

// TestNetworkDiagCollector_NetisrPerCPUDefaultsOn guards the exact mistake the
// zero value invites: a bare `bool` field defaults to false, which would ship
// the per-CPU series silently switched off.
func TestNetworkDiagCollector_NetisrPerCPUDefaultsOn(t *testing.T) {
	var found *networkDiagCollector
	for _, ci := range collectorInstances {
		if c, ok := ci.(*networkDiagCollector); ok {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("networkDiagCollector not registered in collectorInstances")
	}
	if !found.netisrPerCPU {
		t.Error("netisrPerCPU must default to true in the init() registration")
	}
}

// TestNetworkDiagCollector_DescribeCoversNetisr asserts Describe() emits every
// new Desc regardless of the per-CPU toggle.
func TestNetworkDiagCollector_DescribeCoversNetisr(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: enabled}
		c.Register(namespace, "test", promslog.NewNopLogger())

		ch := make(chan *prometheus.Desc, 64)
		c.Describe(ch)
		close(ch)
		seen := make(map[string]bool)
		for d := range ch {
			seen[d.String()] = true
		}

		for _, name := range []string{
			"netisr_protocol_info",
			"netisr_active_workstreams",
			"netisr_workstreams_at_limit",
			"netisr_queue_imbalance_ratio",
			"netisr_drop_concentration_ratio",
			"netisr_cpu_dispatched_total",
			"netisr_cpu_hybrid_dispatched_total",
			"netisr_cpu_queued_total",
			"netisr_cpu_handled_total",
			"netisr_cpu_queue_drops_total",
			"netisr_cpu_queue_length",
			"netisr_cpu_queue_watermark",
		} {
			hit := false
			for d := range seen {
				if containsString(d, `fqName: "opnsense_network_diag_`+name+`"`) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("netisrPerCPU=%v: Describe() omitted %s", enabled, name)
			}
		}
	}
}

// #544 item 2: the whole routing table collapsed to routes_total{proto}. This
// fixture is trimmed from the prod box and keeps the default route on each
// family, a VLAN child whose netif differs from its description, and a
// blackhole route.
const routesCollectorFixture = `[
 {"proto":"ipv4","destination":"default","gateway":"81.187.81.187","flags":"UGS","netif":"pppoe0","intf_description":"AAISP"},
 {"proto":"ipv4","destination":"10.0.100.0/24","gateway":"link#5","flags":"U","netif":"ixl0_vlan100","intf_description":"MGMT"},
 {"proto":"ipv4","destination":"192.0.2.0/24","gateway":"127.0.0.1","flags":"USB","netif":"lo0","intf_description":"Loopback"},
 {"proto":"ipv6","destination":"default","gateway":"fe80::1%pppoe0","flags":"UGS","netif":"pppoe0","intf_description":"AAISP"}
]`

func routesOnlyCollector(t *testing.T, body string) []prometheus.Metric {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/get_netisr_statistics", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"netisr":{"protocol":[],"workstream":[]}}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_socket_statistics", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"statistics":{}}`))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_routes", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(body))
	})
	mux.HandleFunc("/api/diagnostics/interface/get_pfsync_nodes", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := newCollectorTestClient(t, server)
	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem, netisrPerCPU: false}
	c.Register(namespace, "test", promslog.NewNopLogger())
	return collectMetrics(t, c, client)
}

func TestNetworkDiagCollector_RoutesPerInterfaceAndFlags(t *testing.T) {
	metrics := routesOnlyCollector(t, routesCollectorFixture)

	perInterface := map[string]float64{}
	perFlags := map[string]float64{}
	for _, m := range metrics {
		l := getMetricLabels(m)
		switch {
		case hasFqName(m, "opnsense_network_diag_interface_routes"):
			perInterface[l["proto"]+"|"+l["device"]+"|"+l["interface"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_network_diag_routes_by_flags"):
			perFlags[l["proto"]+"|"+l["flags"]] = getMetricValue(m)
		}
	}

	wantIface := map[string]float64{
		"ipv4|pppoe0|AAISP":      1,
		"ipv4|ixl0_vlan100|MGMT": 1,
		"ipv4|lo0|Loopback":      1,
		"ipv6|pppoe0|AAISP":      1,
	}
	if len(perInterface) != len(wantIface) {
		t.Fatalf("got %d per-interface series, want %d: %v", len(perInterface), len(wantIface), perInterface)
	}
	for k, v := range wantIface {
		if perInterface[k] != v {
			t.Errorf("interface_routes[%s] = %v, want %v", k, perInterface[k], v)
		}
	}
	if perFlags["ipv4|USB"] != 1 {
		t.Errorf("routes_by_flags[ipv4|USB] = %v, want 1 (the blackhole route)", perFlags["ipv4|USB"])
	}
	if perFlags["ipv4|UGS"] != 1 || perFlags["ipv6|UGS"] != 1 {
		t.Errorf("routes_by_flags default-route flags = %v", perFlags)
	}
}

func TestNetworkDiagCollector_DefaultRoutePresence(t *testing.T) {
	metrics := routesOnlyCollector(t, routesCollectorFixture)

	present := map[string]float64{}
	info := map[string]float64{}
	for _, m := range metrics {
		l := getMetricLabels(m)
		switch {
		case hasFqName(m, "opnsense_network_diag_default_route_present"):
			present[l["proto"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_network_diag_default_route_info"):
			info[l["proto"]+"|"+l["device"]+"|"+l["interface"]+"|"+l["gateway"]] = getMetricValue(m)
		}
	}

	if present["ipv4"] != 1 || present["ipv6"] != 1 {
		t.Errorf("default_route_present = %v, want both 1", present)
	}
	if info["ipv4|pppoe0|AAISP|81.187.81.187"] != 1 {
		t.Errorf("ipv4 default_route_info missing: %v", info)
	}
	if info["ipv6|pppoe0|AAISP|fe80::1%pppoe0"] != 1 {
		t.Errorf("ipv6 default_route_info missing: %v", info)
	}
}

// Losing the default route is a total outage with no other signal, so the
// series must be emitted as 0 rather than disappearing — an absent series
// cannot be alerted on without an `absent()` rule nobody writes.
func TestNetworkDiagCollector_DefaultRouteAbsentIsZeroNotMissing(t *testing.T) {
	metrics := routesOnlyCollector(t, `[{"proto":"ipv4","destination":"10.0.0.0/24","gateway":"link#1","flags":"U","netif":"ixl0","intf_description":"LAN"}]`)

	present := map[string]float64{}
	infoCount := 0
	for _, m := range metrics {
		if hasFqName(m, "opnsense_network_diag_default_route_present") {
			present[getMetricLabels(m)["proto"]] = getMetricValue(m)
		}
		if hasFqName(m, "opnsense_network_diag_default_route_info") {
			infoCount++
		}
	}
	if len(present) != 2 {
		t.Fatalf("got %d default_route_present series, want one per family: %v", len(present), present)
	}
	if present["ipv4"] != 0 || present["ipv6"] != 0 {
		t.Errorf("default_route_present = %v, want both 0", present)
	}
	if infoCount != 0 {
		t.Errorf("got %d default_route_info series with no default route", infoCount)
	}
}
