package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

const trafficShaperCollectorFixture = `{
  "status": "ok",
  "items": [
    {
      "type": "pipe",
      "id": "00001",
      "pipe": "00001",
      "description": "WAN down",
      "flows": [],
      "rules": []
    },
    {
      "type": "queue",
      "template": true,
      "pipe": "00001",
      "id": "00001.65",
      "description": "",
      "flows": [
        {"pkt": 1234, "bytes": 567890, "drop_pkt": 3, "drop_bytes": 1500}
      ],
      "rules": [
        {"rule": "60001", "pkts": 999, "bytes": 88888,
         "attached_to": "00001", "description": "Shape WAN"}
      ]
    },
    {
      "type": "queue",
      "id": "00001.66",
      "pipe": null,
      "description": "VoIP",
      "flows": [],
      "rules": []
    }
  ]
}`

func trafficShaperCollectorMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trafficshaper/service/statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trafficShaperCollectorFixture))
	})
	return mux
}

func TestTrafficShaperCollector_Update_Normal(t *testing.T) {
	server := httptest.NewServer(trafficShaperCollectorMux(t))
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// pipes_total (1) + queues_total (1) = 2
	// pipe×1: flows + packets + bytes + drop_packets + drop_bytes = 5
	// queue×1: flows + packets + bytes + drop_packets + drop_bytes = 5
	// rule×1: packets_total + bytes_total = 2
	// Total = 2 + 5 + 5 + 2 = 14
	expected := 14
	if len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	var foundPipesTotal, foundQueuesTotal bool
	var pipePacketsVal float64
	var queuePacketsVal float64
	var rulePacketsVal float64
	var ruleTargetType string
	var ruleAttachedTo string

	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)

		switch {
		case strings.Contains(desc, "trafficshaper_pipes_total"):
			foundPipesTotal = true
			if val != 1 {
				t.Errorf("pipes_total expected 1, got %v", val)
			}
		case strings.Contains(desc, "trafficshaper_queues_total"):
			foundQueuesTotal = true
			if val != 1 {
				t.Errorf("queues_total expected 1, got %v", val)
			}
		case strings.Contains(desc, "trafficshaper_pipe_packets"):
			if labels["pipe"] == "00001" {
				pipePacketsVal = val
			}
		case strings.Contains(desc, "trafficshaper_queue_packets"):
			queuePacketsVal = val
		case strings.Contains(desc, "trafficshaper_rule_packets_total"):
			rulePacketsVal = val
			ruleTargetType = labels["target_type"]
			ruleAttachedTo = labels["attached_to"]
		}
	}

	if !foundPipesTotal {
		t.Error("missing pipes_total metric")
	}
	if !foundQueuesTotal {
		t.Error("missing queues_total metric")
	}

	// Template-queue attribution: pipe_packets must reflect the template-queue flow.
	if pipePacketsVal != 1234 {
		t.Errorf("pipe_packets{pipe=00001} expected 1234 (from template-queue flow), got %v", pipePacketsVal)
	}

	// Non-template queue has no flows → packets should be 0.
	if queuePacketsVal != 0 {
		t.Errorf("queue_packets expected 0 (no flows), got %v", queuePacketsVal)
	}

	// Rule from template-queue: target_type must be "pipe".
	if rulePacketsVal != 999 {
		t.Errorf("rule_packets_total expected 999, got %v", rulePacketsVal)
	}
	if ruleTargetType != "pipe" {
		t.Errorf("rule target_type expected %q (template-queue rule), got %q", "pipe", ruleTargetType)
	}
	if ruleAttachedTo != "00001" {
		t.Errorf("rule attached_to expected %q, got %q", "00001", ruleAttachedTo)
	}
}

func TestTrafficShaperCollector_Update_Unconfigured(t *testing.T) {
	// status=ok but empty items: fully silent (shaper present but unconfigured).
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trafficshaper/service/statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok", "items": []}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when shaper unconfigured (empty items), got %d", len(metrics))
	}
}

func TestTrafficShaperCollector_Update_FeatureAbsent(t *testing.T) {
	// 404 → Present=false → fully silent.
	mux := http.NewServeMux() // no handlers → all 404
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when feature absent, got %d", len(metrics))
	}
}

// TestTrafficShaperCollector_RuleLastMatch covers the accessed_epoch rider
// (#224): a rule that has matched traffic emits rule_last_match_timestamp_seconds,
// one that never has (accessed_epoch=0, the sentinel) must not.
func TestTrafficShaperCollector_RuleLastMatch(t *testing.T) {
	fixture := `{
	  "status": "ok",
	  "items": [
	    {
	      "type": "pipe", "id": "00001", "pipe": "00001", "description": "WAN down",
	      "flows": [],
	      "rules": [
	        {"rule": "60001", "pkts": 999, "bytes": 88888,
	         "accessed_epoch": 1780000000,
	         "attached_to": "00001", "description": "Shape WAN"},
	        {"rule": "60002", "pkts": 0, "bytes": 0,
	         "accessed_epoch": 0,
	         "attached_to": "00001", "description": "Never matched"}
	      ]
	    }
	  ]
	}`

	mux := http.NewServeMux()
	mux.HandleFunc("/api/trafficshaper/service/statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var lastMatchSeries []map[string]string
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "trafficshaper_rule_last_match_timestamp_seconds") {
			lastMatchSeries = append(lastMatchSeries, getMetricLabels(m))
		}
	}

	if len(lastMatchSeries) != 1 {
		t.Fatalf("expected exactly 1 rule_last_match_timestamp_seconds series (the matched rule only), got %d", len(lastMatchSeries))
	}
	if lastMatchSeries[0]["rule"] != "60001" {
		t.Errorf("expected the emitted series to be for rule 60001, got rule=%q", lastMatchSeries[0]["rule"])
	}
}

// TestTrafficShaperCollector_ConfiguredCapacity guards #584: the five
// configured-capacity fields must surface as gauges alongside the existing
// live counters, presence-gated (an unconfigured/unparseable value emits NO
// series, never a fabricated 0), and the pipe-vs-queue naming split must hold
// (bandwidth/burst/delay only ever apply to a pipe; queue_size/weight apply
// to both, via template-queue folding for the pipe's own values).
func TestTrafficShaperCollector_ConfiguredCapacity(t *testing.T) {
	fixture := `{
	  "status": "ok",
	  "items": [
	    {
	      "type": "pipe", "id": "00001", "pipe": "00001", "description": "WAN down",
	      "bw": "10.000 Mbit/s", "delay": "5", "burst": "0",
	      "flows": [], "rules": []
	    },
	    {
	      "type": "queue", "template": true, "pipe": "00001", "id": "00001.65",
	      "description": "", "queue_size": "50 sl.", "weight": "1",
	      "flows": [], "rules": []
	    },
	    {
	      "type": "queue", "id": "00001.66", "pipe": null, "description": "VoIP",
	      "queue_size": "16 KB", "weight": "10",
	      "flows": [], "rules": []
	    },
	    {
	      "type": "pipe", "id": "00002", "pipe": "00002", "description": "Uncapped",
	      "bw": "unlimited", "delay": "0", "burst": "0",
	      "flows": [], "rules": []
	    }
	  ]
	}`

	mux := http.NewServeMux()
	mux.HandleFunc("/api/trafficshaper/service/statistics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	bw := metricsByDesc(metrics, "opnsense_trafficshaper_pipe_configured_bandwidth_bps")
	if len(bw) != 1 {
		t.Fatalf("expected 1 pipe_configured_bandwidth_bps series (the unlimited pipe excluded), got %d", len(bw))
	}
	if labels := getMetricLabels(bw[0]); labels["pipe"] != "00001" {
		t.Errorf("expected the bandwidth series to be for pipe 00001, got %q", labels["pipe"])
	}
	if v := getMetricValue(bw[0]); v != 10_000_000 {
		t.Errorf("expected pipe_configured_bandwidth_bps=1e7, got %v", v)
	}

	delay := metricsByDesc(metrics, "opnsense_trafficshaper_pipe_configured_delay_milliseconds")
	if len(delay) != 2 {
		t.Fatalf("expected 2 pipe_configured_delay_milliseconds series (delay has no \"unlimited\" concept, both pipes report it), got %d", len(delay))
	}

	burst := metricsByDesc(metrics, "opnsense_trafficshaper_pipe_configured_burst_bytes")
	if len(burst) != 2 {
		t.Fatalf("expected 2 pipe_configured_burst_bytes series, got %d", len(burst))
	}

	pipeQueueSize := metricsByDesc(metrics, "opnsense_trafficshaper_pipe_configured_queue_size")
	if len(pipeQueueSize) != 1 {
		t.Fatalf("expected 1 pipe_configured_queue_size series (folded from pipe 00001's template queue only), got %d", len(pipeQueueSize))
	}
	if labels := getMetricLabels(pipeQueueSize[0]); labels["unit"] != "packets" {
		t.Errorf("expected pipe_configured_queue_size unit=packets, got %q", labels["unit"])
	}

	pipeWeight := metricsByDesc(metrics, "opnsense_trafficshaper_pipe_configured_weight")
	if len(pipeWeight) != 1 {
		t.Fatalf("expected 1 pipe_configured_weight series, got %d", len(pipeWeight))
	}

	queueQueueSize := metricsByDesc(metrics, "opnsense_trafficshaper_queue_configured_queue_size")
	if len(queueQueueSize) != 1 {
		t.Fatalf("expected 1 queue_configured_queue_size series (the non-template VoIP queue), got %d", len(queueQueueSize))
	}
	if labels := getMetricLabels(queueQueueSize[0]); labels["unit"] != "bytes" {
		t.Errorf("expected queue_configured_queue_size unit=bytes, got %q", labels["unit"])
	}
	if v := getMetricValue(queueQueueSize[0]); v != 16*1024 {
		t.Errorf("expected queue_configured_queue_size=16384, got %v", v)
	}

	queueWeight := metricsByDesc(metrics, "opnsense_trafficshaper_queue_configured_weight")
	if len(queueWeight) != 1 {
		t.Fatalf("expected 1 queue_configured_weight series, got %d", len(queueWeight))
	}
	if v := getMetricValue(queueWeight[0]); v != 10 {
		t.Errorf("expected queue_configured_weight=10, got %v", v)
	}
}

func TestTrafficShaperCollector_Name(t *testing.T) {
	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	if c.Name() != TrafficShaperSubsystem {
		t.Errorf("expected %s, got %s", TrafficShaperSubsystem, c.Name())
	}
}
