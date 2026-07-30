package opnsense

import (
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchNetisrStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"netisr": {
				"protocol": [
					{"name": "ip", "protocol": 1, "queue-limit": 256, "policy": "flow"},
					{"name": "arp", "protocol": 2, "queue-limit": 512, "policy": "source"}
				],
				"workstream": [
					{
						"work": [
							{
								"workstream": 0, "cpu": 0, "name": "ip",
								"length": 5, "watermark": 10,
								"dispatched": 100, "hybrid-dispatched": 10,
								"queue-drops": 1, "queued": 50, "handled": 99
							},
							{
								"workstream": 0, "cpu": 0, "name": "arp",
								"length": 2, "watermark": 4,
								"dispatched": 30, "hybrid-dispatched": 3,
								"queue-drops": 0, "queued": 15, "handled": 30
							}
						]
					},
					{
						"work": [
							{
								"workstream": 1, "cpu": 1, "name": "ip",
								"length": 3, "watermark": 12,
								"dispatched": 200, "hybrid-dispatched": 20,
								"queue-drops": 2, "queued": 80, "handled": 198
							},
							{
								"workstream": 1, "cpu": 1, "name": "arp",
								"length": 1, "watermark": 3,
								"dispatched": 20, "hybrid-dispatched": 2,
								"queue-drops": 1, "queued": 10, "handled": 19
							}
						]
					}
				]
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchNetisrStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) != 2 {
		t.Fatalf("expected 2 protocols, got %d", len(data))
	}

	// Check ip: sums across 2 workstreams
	ip := data["ip"]
	if ip.Dispatched != 300 {
		t.Errorf("ip.Dispatched = %d; want 300", ip.Dispatched)
	}
	if ip.HybridDispatched != 30 {
		t.Errorf("ip.HybridDispatched = %d; want 30", ip.HybridDispatched)
	}
	if ip.QueueDrops != 3 {
		t.Errorf("ip.QueueDrops = %d; want 3", ip.QueueDrops)
	}
	if ip.Queued != 130 {
		t.Errorf("ip.Queued = %d; want 130", ip.Queued)
	}
	if ip.Handled != 297 {
		t.Errorf("ip.Handled = %d; want 297", ip.Handled)
	}
	// max length: max(5, 3) = 5
	if ip.Length != 5 {
		t.Errorf("ip.Length = %d; want 5", ip.Length)
	}
	// max watermark: max(10, 12) = 12
	if ip.Watermark != 12 {
		t.Errorf("ip.Watermark = %d; want 12", ip.Watermark)
	}
	// queue-limit from protocol array
	if ip.QueueLimit != 256 {
		t.Errorf("ip.QueueLimit = %d; want 256", ip.QueueLimit)
	}

	// Check arp
	arp := data["arp"]
	if arp.Dispatched != 50 {
		t.Errorf("arp.Dispatched = %d; want 50", arp.Dispatched)
	}
	if arp.HybridDispatched != 5 {
		t.Errorf("arp.HybridDispatched = %d; want 5", arp.HybridDispatched)
	}
	if arp.QueueDrops != 1 {
		t.Errorf("arp.QueueDrops = %d; want 1", arp.QueueDrops)
	}
	if arp.Queued != 25 {
		t.Errorf("arp.Queued = %d; want 25", arp.Queued)
	}
	if arp.Handled != 49 {
		t.Errorf("arp.Handled = %d; want 49", arp.Handled)
	}
	// max length: max(2, 1) = 2
	if arp.Length != 2 {
		t.Errorf("arp.Length = %d; want 2", arp.Length)
	}
	// max watermark: max(4, 3) = 4
	if arp.Watermark != 4 {
		t.Errorf("arp.Watermark = %d; want 4", arp.Watermark)
	}
	if arp.QueueLimit != 512 {
		t.Errorf("arp.QueueLimit = %d; want 512", arp.QueueLimit)
	}
}

func TestFetchNetisrStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNetisrStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchSocketStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"statistics": {
				"Active Internet connections": {
					"tcp4/[10.0.0.1:80-10.0.0.2:1234]": {},
					"tcp4/[10.0.0.1:443-10.0.0.3:5678]": {},
					"udp4/[10.0.0.1:53-*:*]": {}
				},
				"Active UNIX domain sockets": {
					"fffff8001d757280 - /var/run/log.sock": {},
					"fffff80020f24000": {}
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchSocketStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ByType["tcp4"] != 2 {
		t.Errorf("tcp4 count = %d; want 2", data.ByType["tcp4"])
	}
	if data.ByType["udp4"] != 1 {
		t.Errorf("udp4 count = %d; want 1", data.ByType["udp4"])
	}
	if data.ByType["unix"] != 2 {
		t.Errorf("unix count = %d; want 2", data.ByType["unix"])
	}
	if data.UnixTotal != 2 {
		t.Errorf("UnixTotal = %d; want 2", data.UnixTotal)
	}
}

func TestFetchSocketStatistics_EmptySection(t *testing.T) {
	// OPNsense (PHP) serializes an empty section as [] rather than {}.
	// This must not fail the whole decode.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"statistics": {
				"Active Internet connections": {
					"tcp4/[10.0.0.1:80-10.0.0.2:1234]": {}
				},
				"Active UNIX domain sockets": []
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchSocketStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ByType["tcp4"] != 1 {
		t.Errorf("tcp4 count = %d; want 1", data.ByType["tcp4"])
	}
	if data.UnixTotal != 0 {
		t.Errorf("UnixTotal = %d; want 0", data.UnixTotal)
	}
}

func TestFetchSocketStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchSocketStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchRouteStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`[
			{"proto": "IPv4"},
			{"proto": "IPv4"},
			{"proto": "IPv4"},
			{"proto": "IPv6"},
			{"proto": "IPv6"}
		]`))
	})
	defer server.Close()

	data, err := client.FetchRouteStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.ByProto["IPv4"] != 3 {
		t.Errorf("IPv4 count = %d; want 3", data.ByProto["IPv4"])
	}
	if data.ByProto["IPv6"] != 2 {
		t.Errorf("IPv6 count = %d; want 2", data.ByProto["IPv6"])
	}
}

func TestFetchRouteStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchRouteStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchPFSyncNodes_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{"creatorid": "ab12cd34", "this": 1},
				{"creatorid": "ef56gh78", "this": 0}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchPFSyncNodes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.Total != 2 {
		t.Errorf("expected Total=2, got %d", data.Total)
	}
	if len(data.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(data.Nodes))
	}

	n1 := data.Nodes[0]
	if n1.CreatorID != "ab12cd34" {
		t.Errorf("expected CreatorID 'ab12cd34', got %q", n1.CreatorID)
	}
	if !n1.IsLocal {
		t.Error("expected first node IsLocal=true")
	}

	n2 := data.Nodes[1]
	if n2.CreatorID != "ef56gh78" {
		t.Errorf("expected CreatorID 'ef56gh78', got %q", n2.CreatorID)
	}
	if n2.IsLocal {
		t.Error("expected second node IsLocal=false")
	}
}

func TestFetchPFSyncNodes_EmptyRows(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rowCount": 0,
			"current": 1,
			"rows": []
		}`))
	})
	defer server.Close()

	data, err := client.FetchPFSyncNodes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Total != 0 {
		t.Errorf("expected Total=0, got %d", data.Total)
	}
	if len(data.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(data.Nodes))
	}
}

func TestFetchPFSyncNodes_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchPFSyncNodes()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// --- netisr per-CPU / derived-summary tests (#539) ---

// loadNetisrFixture serves a captured netisr payload from testdata.
func loadNetisrFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "netisr", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// TestFetchNetisrStatistics_ProdCapture pins the derived netisr summaries against
// a real OPNsense 26.1 capture from the production firewall (12 workstreams,
// 8 protocols). The ip6 numbers are the known-firing CPU-affinity condition that
// motivated #539: only 4 of 12 CPUs carry netisr work, cpu0 sits at its
// queue-limit, and every single drop landed on cpu0.
func TestFetchNetisrStatistics_ProdCapture(t *testing.T) {
	body := loadNetisrFixture(t, "prod_26.1.json")
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})
	defer server.Close()

	data, err := client.FetchNetisrStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 8 {
		t.Fatalf("expected 8 protocols, got %d", len(data))
	}

	// Protocol metadata must survive the aggregation.
	ip6 := data["ip6"]
	if ip6.Protocol != 6 {
		t.Errorf("ip6.Protocol = %d; want 6", ip6.Protocol)
	}
	if ip6.Policy != "hybrid" {
		t.Errorf("ip6.Policy = %q; want %q", ip6.Policy, "hybrid")
	}
	if ip6.PolicyType != "cpu" {
		t.Errorf("ip6.PolicyType = %q; want %q", ip6.PolicyType, "cpu")
	}
	if ip6.Flags != "C--" {
		t.Errorf("ip6.Flags = %q; want %q", ip6.Flags, "C--")
	}
	if got := len(ip6.Workstreams); got != 12 {
		t.Fatalf("ip6 workstream rows = %d; want 12 (idle rows must NOT be dropped)", got)
	}

	// Single-lane-by-design protocols keep their source policy type.
	if got := data["arp"].PolicyType; got != "source" {
		t.Errorf("arp.PolicyType = %q; want %q", got, "source")
	}

	tests := []struct {
		proto       string
		active      int
		atLimit     int
		imbalance   float64
		dropConcRat float64
	}{
		// cpu0 at wmark 1000 == queue-limit 1000, all 683 drops on cpu0.
		{"ip6", 4, 1, 1000.0 / (2852.0 / 4.0), 1.0},
		// Same 4-CPU skew, but limit 3000 is not reached and nothing drops.
		{"ip", 4, 0, 1263.0 / (4565.0 / 4.0), 0.0},
		// Every CPU dispatches ether/arp directly, watermarks all zero →
		// mean 0 → imbalance defined as 0.
		{"ether", 12, 0, 0.0, 0.0},
		{"arp", 12, 0, 0.0, 0.0},
		// 3 active rows but all watermarks zero.
		{"igmp", 3, 0, 0.0, 0.0},
		// Single active workstream → imbalance is meaningless, emit 0.
		{"rtsock", 1, 0, 0.0, 0.0},
		// Entirely idle protocols.
		{"ip_direct", 0, 0, 0.0, 0.0},
		{"ip6_direct", 0, 0, 0.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			s := data[tt.proto]
			if got := s.ActiveWorkstreams(); got != tt.active {
				t.Errorf("ActiveWorkstreams() = %d; want %d", got, tt.active)
			}
			if got := s.WorkstreamsAtLimit(); got != tt.atLimit {
				t.Errorf("WorkstreamsAtLimit() = %d; want %d", got, tt.atLimit)
			}
			if got := s.QueueImbalanceRatio(); math.Abs(got-tt.imbalance) > 1e-9 {
				t.Errorf("QueueImbalanceRatio() = %v; want %v", got, tt.imbalance)
			}
			if got := s.DropConcentrationRatio(); math.Abs(got-tt.dropConcRat) > 1e-9 {
				t.Errorf("DropConcentrationRatio() = %v; want %v", got, tt.dropConcRat)
			}
		})
	}

	// The pre-existing aggregate behaviour must be byte-for-byte unchanged:
	// counters summed, length/watermark maxed, queue-limit from the protocol array.
	var wantHandled int64
	var wantDrops int64
	wantWatermark := 0
	for _, w := range ip6.Workstreams {
		wantHandled += w.Handled
		wantDrops += w.QueueDrops
		if w.Watermark > wantWatermark {
			wantWatermark = w.Watermark
		}
	}
	if ip6.Handled != wantHandled {
		t.Errorf("ip6.Handled = %d; want %d (sum over workstreams)", ip6.Handled, wantHandled)
	}
	if ip6.QueueDrops != wantDrops {
		t.Errorf("ip6.QueueDrops = %d; want %d", ip6.QueueDrops, wantDrops)
	}
	if ip6.Watermark != wantWatermark {
		t.Errorf("ip6.Watermark = %d; want %d (max over workstreams)", ip6.Watermark, wantWatermark)
	}
	if ip6.QueueLimit != 1000 {
		t.Errorf("ip6.QueueLimit = %d; want 1000", ip6.QueueLimit)
	}
}

// TestNetisrProtocolStats_DerivedEdgeCases covers the guards that the prod
// capture cannot exercise on its own.
func TestNetisrProtocolStats_DerivedEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		stats       NetisrProtocolStats
		active      int
		atLimit     int
		imbalance   float64
		dropConcRat float64
	}{
		{
			name: "zero queue limit never counts as at-limit",
			stats: NetisrProtocolStats{
				QueueLimit: 0,
				Workstreams: []NetisrWorkstreamStats{
					{Workstream: 0, CPU: 0, Watermark: 500, Handled: 10},
					{Workstream: 1, CPU: 1, Watermark: 0, Handled: 10},
				},
			},
			active: 2, atLimit: 0, imbalance: 2.0, dropConcRat: 0,
		},
		{
			name: "watermark equal to limit counts, below does not",
			stats: NetisrProtocolStats{
				QueueLimit: 256,
				Workstreams: []NetisrWorkstreamStats{
					{Watermark: 256, Handled: 1},
					{Watermark: 255, Handled: 1},
					{Watermark: 300, Handled: 1},
				},
			},
			active: 3, atLimit: 2,
			imbalance:   3.0 * 300 / (256 + 255 + 300),
			dropConcRat: 0,
		},
		{
			name: "all rows idle",
			stats: NetisrProtocolStats{
				QueueLimit: 256,
				Workstreams: []NetisrWorkstreamStats{
					{Workstream: 0, CPU: 0},
					{Workstream: 1, CPU: 1},
				},
			},
			active: 0, atLimit: 0, imbalance: 0, dropConcRat: 0,
		},
		{
			name: "single workstream protocol",
			stats: NetisrProtocolStats{
				QueueLimit: 256,
				Workstreams: []NetisrWorkstreamStats{
					{Watermark: 99, Handled: 5, QueueDrops: 3},
				},
			},
			active: 1, atLimit: 0, imbalance: 0, dropConcRat: 1.0,
		},
		{
			name: "drops spread evenly across four rows",
			stats: NetisrProtocolStats{
				QueueLimit: 256,
				Workstreams: []NetisrWorkstreamStats{
					{Watermark: 10, Handled: 1, QueueDrops: 5},
					{Watermark: 10, Handled: 1, QueueDrops: 5},
					{Watermark: 10, Handled: 1, QueueDrops: 5},
					{Watermark: 10, Handled: 1, QueueDrops: 5},
				},
			},
			active: 4, atLimit: 0, imbalance: 1.0, dropConcRat: 0.25,
		},
		{
			name: "a row is active on queued alone",
			stats: NetisrProtocolStats{
				Workstreams: []NetisrWorkstreamStats{
					{Queued: 1},
					{HybridDispatched: 1},
					{Dispatched: 1},
					{},
				},
			},
			active: 3, atLimit: 0, imbalance: 0, dropConcRat: 0,
		},
		{
			name:   "no workstream rows at all",
			stats:  NetisrProtocolStats{QueueLimit: 256},
			active: 0, atLimit: 0, imbalance: 0, dropConcRat: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.stats.ActiveWorkstreams(); got != tt.active {
				t.Errorf("ActiveWorkstreams() = %d; want %d", got, tt.active)
			}
			if got := tt.stats.WorkstreamsAtLimit(); got != tt.atLimit {
				t.Errorf("WorkstreamsAtLimit() = %d; want %d", got, tt.atLimit)
			}
			if got := tt.stats.QueueImbalanceRatio(); math.Abs(got-tt.imbalance) > 1e-9 {
				t.Errorf("QueueImbalanceRatio() = %v; want %v", got, tt.imbalance)
			}
			if got := tt.stats.DropConcentrationRatio(); math.Abs(got-tt.dropConcRat) > 1e-9 {
				t.Errorf("DropConcentrationRatio() = %v; want %v", got, tt.dropConcRat)
			}
		})
	}
}
