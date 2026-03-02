package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
			"tcp4/[10.0.0.1:80-10.0.0.2:1234]": {},
			"tcp4/[10.0.0.1:443-10.0.0.3:5678]": {},
			"udp4/[10.0.0.1:53-*:*]": {},
			"unix/[/var/run/log.sock]": {}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/interface/get_routes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"proto": "IPv4"},
			{"proto": "IPv4"},
			{"proto": "IPv6"}
		]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &networkDiagCollector{subsystem: NetworkDiagSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 protocols * 8 netisr metrics = 16
	// 3 socket types (tcp4, udp4, unix) active = 3
	// 1 unix total = 1
	// 2 route protos (IPv4, IPv6) = 2
	// Total: 16 + 3 + 1 + 2 = 22
	expectedCount := 22
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
