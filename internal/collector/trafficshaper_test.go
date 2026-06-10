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

func TestTrafficShaperCollector_Name(t *testing.T) {
	c := &trafficShaperCollector{subsystem: TrafficShaperSubsystem}
	if c.Name() != TrafficShaperSubsystem {
		t.Errorf("expected %s, got %s", TrafficShaperSubsystem, c.Name())
	}
}
