package collector

import (
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

func TestLogEventStore_ObserveZenarmor(t *testing.T) {
	s := newLogEventStore()
	flow := logship.ZenarmorObservation{Family: "flow", Action: "block", Category: "File Transfer", Interface: "LAN"}
	s.ObserveZenarmor(flow)
	s.ObserveZenarmor(flow)
	s.ObserveZenarmor(logship.ZenarmorObservation{Family: "dns", Action: "pass", Category: "Technology and Computer", RCode: "0"})

	if got := s.zen[zenKey{family: "flow", action: "block", category: "File Transfer", iface: "LAN"}]; got != 2 {
		t.Errorf("flow/block = %v, want 2", got)
	}
	if got := s.zen[zenKey{family: "dns", action: "pass", category: "Technology and Computer", rcode: "0"}]; got != 1 {
		t.Errorf("dns/pass = %v, want 1", got)
	}
	// Distinct dimensions must not collapse into one series.
	if len(s.zen) != 2 {
		t.Errorf("distinct keys = %d, want 2", len(s.zen))
	}
}

// Every family gets a counter, including ones that are empty on any given network
// (voip/sip). A family silently missing a counter looks identical to a family with
// no traffic.
func TestLogEventStore_ObserveZenarmorEveryFamily(t *testing.T) {
	s := newLogEventStore()
	for _, f := range []string{"flow", "dns", "tls", "web", "ids", "voip"} {
		s.ObserveZenarmor(logship.ZenarmorObservation{Family: f, Action: "pass"})
	}
	if len(s.zen) != 6 {
		t.Errorf("distinct families counted = %d, want 6", len(s.zen))
	}
}

// The store must satisfy the sink contract in full. This is exactly what breaks
// when a method is added to MetricSink and an implementation is missed — main.go's
// `var _ logship.MetricSink = collector.LogEvents` catches it at build time, and
// this catches it here, where the failure is legible.
func TestLogEventStore_SatisfiesMetricSink(t *testing.T) {
	var _ logship.MetricSink = newLogEventStore()
}
