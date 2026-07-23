package collector

import (
	"strconv"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

func TestLogEventStore_ObserveZenarmor(t *testing.T) {
	s := newLogEventStore()
	flow := logship.ZenarmorObservation{Family: "flow", Action: "block", Category: "File Transfer", Interface: "LAN"}
	s.ObserveZenarmor(flow)
	s.ObserveZenarmor(flow)
	s.ObserveZenarmor(logship.ZenarmorObservation{Family: "dns", Action: "pass", Category: "Technology and Computer", RCode: "0"})

	if got := s.zen.m[zenKey{family: "flow", action: "block", category: "File Transfer", iface: "LAN"}]; got != 2 {
		t.Errorf("flow/block = %v, want 2", got)
	}
	if got := s.zen.m[zenKey{family: "dns", action: "pass", category: "Technology and Computer", rcode: "0"}]; got != 1 {
		t.Errorf("dns/pass = %v, want 1", got)
	}
	// Distinct dimensions must not collapse into one series.
	if got := s.zen.len(); got != 2 {
		t.Errorf("distinct keys = %d, want 2", got)
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
	if got := s.zen.len(); got != 6 {
		t.Errorf("distinct families counted = %d, want 6", got)
	}
}

// The store must satisfy the sink contract in full. This is exactly what breaks
// when a method is added to MetricSink and an implementation is missed — main.go's
// `var _ logship.MetricSink = collector.LogEvents` catches it at build time, and
// this catches it here, where the failure is legible.
func TestLogEventStore_SatisfiesMetricSink(t *testing.T) {
	var _ logship.MetricSink = newLogEventStore()
}

// The whole point of the budget: a sender that mints novel tuples stops growing the
// map at the ceiling, and NOTHING is lost — every observation is still accounted
// for, either in a live series or in the family's overflow total.
func TestLogEventStore_CapsNovelKeysWithoutLosingObservations(t *testing.T) {
	const (
		budget       = 3
		distinct     = 10
		observations = 2
	)
	s := newLogEventStore()
	s.SetMaxKeys(budget)

	for i := 0; i < distinct; i++ {
		for j := 0; j < observations; j++ {
			// ruleID is one of the genuinely free-form dimensions: it is whatever the
			// sender's filterlog line carried.
			s.ObserveFirewall("block", "igb0", "rule-"+strconv.Itoa(i), "desc", "wan")
		}
	}

	if got := s.fw.len(); got != budget {
		t.Errorf("live keys = %d, want the budget %d", got, budget)
	}
	live, overflow := s.fw.snapshot()
	var sum float64
	for _, v := range live {
		sum += v
	}
	if want := float64(budget * observations); sum != want {
		t.Errorf("summed live series = %v, want %v", sum, want)
	}
	if want := float64((distinct - budget) * observations); overflow != want {
		t.Errorf("overflow = %v, want exactly the excess %v", overflow, want)
	}
	// The invariant that makes the cap safe to reason about: series + overflow is
	// the true observed count, at every scrape.
	if want := float64(distinct * observations); sum+overflow != want {
		t.Errorf("series + overflow = %v, want the observation count %v", sum+overflow, want)
	}
}

// An already-tracked tuple keeps counting after the ceiling is hit. Steady-state
// traffic must be unaffected once the working set is established — only NOVELTY is
// bounded.
func TestLogEventStore_KnownKeysKeepCountingAtTheCeiling(t *testing.T) {
	s := newLogEventStore()
	s.SetMaxKeys(1)
	s.ObserveFirewall("block", "igb0", "rule-1", "desc", "wan")
	s.ObserveFirewall("block", "igb0", "rule-2", "desc", "wan") // novel, refused, folded
	s.ObserveFirewall("block", "igb0", "rule-1", "desc", "wan")

	live, overflow := s.fw.snapshot()
	if got := live[fwKey{action: "block", iface: "igb0", ruleID: "rule-1", ruleName: "desc", scope: "wan"}]; got != 2 {
		t.Errorf("known key = %v, want 2", got)
	}
	if overflow != 1 {
		t.Errorf("overflow = %v, want 1", overflow)
	}
}

// 0 is the documented "disabled" value of --logs.max-metric-keys, not a budget of
// zero keys. Getting this backwards would silently fold EVERY tuple.
func TestLogEventStore_ZeroMaxKeysDisablesTheCap(t *testing.T) {
	s := newLogEventStore()
	s.SetMaxKeys(0)
	for i := 0; i < 200; i++ {
		s.ObserveFirewall("block", "igb0", "rule-"+strconv.Itoa(i), "desc", "wan")
	}
	if got := s.fw.len(); got != 200 {
		t.Errorf("live keys = %d, want all 200 (cap disabled)", got)
	}
	if _, overflow := s.fw.snapshot(); overflow != 0 {
		t.Errorf("overflow = %v, want 0 with the cap disabled", overflow)
	}
}

// SetMaxKeys must reach EVERY family. A family missed here is an unbounded map that
// no other test would notice, because each family is fed by a different program.
func TestLogEventStore_SetMaxKeysAppliesToEveryFamily(t *testing.T) {
	s := newLogEventStore()
	s.SetMaxKeys(1)

	for i := 0; i < 3; i++ {
		n := strconv.Itoa(i)
		s.ObserveFirewall("block", "igb"+n, "", "", "")
		s.ObserveHAProxy("http_request", "bk-"+n, "", "", "")
		s.ObserveSSHD("failed", "publickey-"+n, "")
		s.ObserveDHCP("ack", "igb"+n, "")
		s.ObserveAudit("config_change-"+n, "")
		s.ObserveIDS("alert", "block", "cat-"+n, "")
		s.ObserveZenarmor(logship.ZenarmorObservation{Family: "flow", Category: "cat-" + n})
	}

	type sat struct {
		keys     int
		overflow float64
	}
	families := map[string]sat{
		logFamilyFirewall: {s.fw.len(), overflowOf(s.fw.snapshot())},
		logFamilyHAProxy:  {s.ha.len(), overflowOf(s.ha.snapshot())},
		logFamilySSHD:     {s.ssh.len(), overflowOf(s.ssh.snapshot())},
		logFamilyDHCP:     {s.dhcp.len(), overflowOf(s.dhcp.snapshot())},
		logFamilyAudit:    {s.audit.len(), overflowOf(s.audit.snapshot())},
		logFamilyIDS:      {s.ids.len(), overflowOf(s.ids.snapshot())},
		logFamilyZenarmor: {s.zen.len(), overflowOf(s.zen.snapshot())},
	}
	if len(families) != 7 {
		t.Fatalf("families asserted = %d, want all 7 (duplicate family constant?)", len(families))
	}
	for name, got := range families {
		if got.keys != 1 {
			t.Errorf("%s live keys = %d, want 1", name, got.keys)
		}
		if got.overflow != 2 {
			t.Errorf("%s overflow = %v, want 2", name, got.overflow)
		}
	}
}

// overflowOf drops a snapshot's map so a call fits in a struct literal.
func overflowOf[K comparable](_ map[K]float64, overflow float64) float64 { return overflow }

// The saturation series must actually be emitted — one per family, every scrape,
// including the families sitting at zero. A counter that materialises only once it
// is non-zero cannot be alerted on before it matters.
func TestLogEventsCollector_EmitsSaturationSeries(t *testing.T) {
	c := &logEventsCollector{store: newLogEventStore(), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.SetMaxKeys(1)
	c.store.ObserveFirewall("block", "igb0", "rule-1", "", "")
	c.store.ObserveFirewall("block", "igb0", "rule-2", "", "") // folded

	metrics := collectMetrics(t, c, nil)
	assertNoDuplicateSeries(t, metrics)

	capped := map[string]float64{}
	keys := map[string]float64{}
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_log_events_cardinality_capped_total"):
			capped[getMetricLabels(m)["family"]] = getMetricValue(m)
		case hasFqName(m, "opnsense_log_events_cardinality_keys"):
			keys[getMetricLabels(m)["family"]] = getMetricValue(m)
		}
	}

	if len(capped) != 7 {
		t.Errorf("capped families emitted = %d, want 7: %v", len(capped), capped)
	}
	if len(keys) != 7 {
		t.Errorf("keys families emitted = %d, want 7: %v", len(keys), keys)
	}
	if capped[logFamilyFirewall] != 1 {
		t.Errorf("firewall capped = %v, want 1", capped[logFamilyFirewall])
	}
	if keys[logFamilyFirewall] != 1 {
		t.Errorf("firewall keys = %v, want 1", keys[logFamilyFirewall])
	}
	if capped[logFamilyZenarmor] != 0 {
		t.Errorf("zenarmor capped = %v, want 0 published from zero", capped[logFamilyZenarmor])
	}
	assertMetricsAreCounters(t, metrics, "opnsense_log_events_cardinality_capped_total")
}
