package collector

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// TestEffectiveIntervalFollowsConsumingLane pins #550 §1: a collector must not poll
// the firewall faster than the export lane that reads its snapshot. The rule only
// ever makes polling SLOWER (max, not replace), so it can never increase load on
// anyone's box, and it applies only when OTLP is a delivery path — a Prometheus-only
// deployment keeps today's tier intervals exactly (Q1).
func TestEffectiveIntervalFollowsConsumingLane(t *testing.T) {
	for _, tc := range []struct {
		name      string
		collector string
		laneBase  time.Duration
		laneFast  time.Duration
		override  time.Duration
		want      time.Duration
	}{
		{
			name:      "otlp off leaves the fast tier at 15s",
			collector: GatewaysSubsystem,
			want:      IntervalFast,
		},
		{
			name:      "otlp off leaves a cold collector at 15m",
			collector: FirmwareSubsystem,
			want:      IntervalCold,
		},
		{
			name:      "no fast lane clamps the fast tier to the base lane",
			collector: GatewaysSubsystem,
			laneBase:  IntervalMedium,
			want:      IntervalMedium,
		},
		{
			name:      "a fast lane keeps the fast tier at the lane interval",
			collector: GatewaysSubsystem,
			laneBase:  IntervalMedium,
			laneFast:  IntervalFast,
			want:      IntervalFast,
		},
		{
			name:      "an intermediate fast lane clamps the fast tier up to it",
			collector: GatewaysSubsystem,
			laneBase:  IntervalMedium,
			laneFast:  30 * time.Second,
			want:      30 * time.Second,
		},
		{
			name:      "a cold collector is never sped up to the base lane",
			collector: FirmwareSubsystem,
			laneBase:  IntervalMedium,
			laneFast:  IntervalFast,
			want:      IntervalCold,
		},
		{
			name:      "an operator override wins outright and is never clamped",
			collector: GatewaysSubsystem,
			laneBase:  IntervalMedium,
			override:  IntervalFast,
			want:      IntervalFast,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newCollectorTestClient(t, healthOKServer(t))
			coll := &fakeCollectorInstance{name: tc.collector}
			c := newScrapeTestCollector(t, client, coll)
			c.laneBase, c.laneFast = tc.laneBase, tc.laneFast
			if tc.override > 0 {
				c.pollOverrides = map[string]time.Duration{tc.collector: tc.override}
			}

			if got := c.effectiveInterval(coll); got != tc.want {
				t.Errorf("effectiveInterval(%s) = %v, want %v", tc.collector, got, tc.want)
			}
		})
	}
}

// TestFastLaneMembershipSurvivesIntermediateFastExportInterval is the guard test for
// the trap recorded in #550's body: fast-lane membership reads the DECLARED interval
// (collector.go, `resolveInterval(coll) <= IntervalFast`). If the lane clamp were
// applied inside resolveInterval, membership would depend on the clamp that depends
// on membership, and any intermediate --otlp.fast-export-interval would silently
// produce a configured-but-EMPTY fast lane. 15s and unset both happen to survive
// that bug; 30s does not, which is why 30s is the value pinned here.
func TestFastLaneMembershipSurvivesIntermediateFastExportInterval(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	gw := &fakeCollectorInstance{name: GatewaysSubsystem}
	fw := &fakeCollectorInstance{name: FirmwareSubsystem}
	c := newScrapeTestCollector(t, client, gw, fw)
	c.laneBase, c.laneFast = IntervalMedium, 30*time.Second

	fast := c.FastCollectorNames()
	if len(fast) != 1 || fast[0] != GatewaysSubsystem {
		t.Fatalf("fast lane membership = %v, want [%s]: the lane clamp must not feed "+
			"membership, or the configured fast lane is built over an empty gatherer set",
			fast, GatewaysSubsystem)
	}
}

// TestPollLaneWarnings pins #550 §2: the two misconfigurations that are silent today.
func TestPollLaneWarnings(t *testing.T) {
	t.Run("override polls faster than the lane that consumes it", func(t *testing.T) {
		client := newCollectorTestClient(t, healthOKServer(t))
		gw := &fakeCollectorInstance{name: GatewaysSubsystem}
		c := newScrapeTestCollector(t, client, gw)
		c.laneBase = IntervalMedium
		c.pollOverrides = map[string]time.Duration{GatewaysSubsystem: IntervalFast}

		got := c.PollLaneWarnings()
		if len(got) != 1 {
			t.Fatalf("want exactly 1 warning, got %d: %+v", len(got), got)
		}
		w := got[0]
		if w.Kind != WarnPollFasterThanLane || w.Collector != GatewaysSubsystem ||
			w.Poll != IntervalFast || w.Lane != IntervalMedium {
			t.Errorf("unexpected warning %+v", w)
		}
	})

	t.Run("fast lane configured with no fast-tier collectors", func(t *testing.T) {
		client := newCollectorTestClient(t, healthOKServer(t))
		fw := &fakeCollectorInstance{name: FirmwareSubsystem}
		c := newScrapeTestCollector(t, client, fw)
		c.laneBase, c.laneFast = IntervalMedium, IntervalFast

		got := c.PollLaneWarnings()
		if len(got) != 1 || got[0].Kind != WarnFastLaneEmpty {
			t.Fatalf("want one %s warning, got %+v", WarnFastLaneEmpty, got)
		}
	})

	t.Run("silent when the clamp has done its job", func(t *testing.T) {
		client := newCollectorTestClient(t, healthOKServer(t))
		gw := &fakeCollectorInstance{name: GatewaysSubsystem}
		fw := &fakeCollectorInstance{name: FirmwareSubsystem}
		c := newScrapeTestCollector(t, client, gw, fw)
		c.laneBase, c.laneFast = IntervalMedium, IntervalFast

		if got := c.PollLaneWarnings(); len(got) != 0 {
			t.Errorf("want no warnings, got %+v", got)
		}
	})
}

// TestReportedPollIntervalIsTheEffectiveOne pins that the exported
// collector_poll_interval_seconds reports the interval the scheduler actually ticks
// on, not the declared tier — otherwise the console and the metric would both claim
// a 15s cadence for a collector the clamp has moved to 60s.
func TestReportedPollIntervalIsTheEffectiveOne(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	gw := &fakeCollectorInstance{name: GatewaysSubsystem}
	c := newScrapeTestCollector(t, client, gw)
	c.laneBase = IntervalMedium

	ch := make(chan prometheus.Metric, 128)
	c.collectLane(ch, nil, false)
	close(ch)

	var got float64
	found := false
	for m := range ch {
		if !strings.Contains(m.Desc().String(), "collector_poll_interval_seconds") {
			continue
		}
		d := &dto.Metric{}
		if err := m.Write(d); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, found = d.GetGauge().GetValue(), true
	}
	if !found {
		t.Fatal("collector_poll_interval_seconds not emitted")
	}
	if got != IntervalMedium.Seconds() {
		t.Errorf("reported poll interval = %v, want the effective %v", got, IntervalMedium.Seconds())
	}
}
