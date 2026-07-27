package main

import (
	"go/parser"
	"go/token"
	"testing"
)

// TestMetricTypesFromEmission asserts docgen documents each metric's Prometheus type from the
// prometheus.{Counter,Gauge}Value argument at its emission call site, not the _total-suffix
// heuristic (#100). The expected values are the ACTUAL emission types in current source.
func TestMetricTypesFromEmission(t *testing.T) {
	repoRoot := findRepoRoot()
	subsystems := parseSubsystemConstants(repoRoot + "/internal/collector/collector.go")
	collectors := parseAllCollectors(repoRoot+"/internal/collector", subsystems)

	got := map[string]string{}
	for _, c := range collectors {
		for _, m := range c.Metrics {
			got[m.FullName] = m.Type
		}
	}

	// _total-suffixed metrics that are actually emitted as GaugeValue (instantaneous counts).
	// Previously misdocumented as Counter by the suffix heuristic.
	gauges := []string{
		"opnsense_dhcpv4_leases_total",
		"opnsense_dnsmasq_leases_total",
		"opnsense_services_running_total",
	}
	for _, name := range gauges {
		if got[name] != "Gauge" {
			t.Errorf("%s: documented type = %q, want Gauge (emitted with GaugeValue)", name, got[name])
		}
	}

	// Genuine counters (emitted with CounterValue). The ipsec phase2 descriptors
	// lacked a _total suffix until #464 (they were the "misdocumented as Gauge by
	// the old heuristic" example here); kept as a regression guard that the type
	// still resolves from the emission site now that the suffix and the fallback
	// heuristic happen to agree too.
	counters := []string{
		"opnsense_ipsec_phase2_bytes_in_total",
		"opnsense_ipsec_phase2_bytes_out_total",
		"opnsense_ipsec_phase2_packets_in_total",
		"opnsense_ipsec_phase2_packets_out_total",
		// Reclassified to CounterValue in the Phase-2 fix #106 — docgen now follows the emission.
		"opnsense_protocol_icmp_dropped_by_reason_total",
		"opnsense_protocol_udp_dropped_by_reason_total",
	}
	for _, name := range counters {
		if got[name] != "Counter" {
			t.Errorf("%s: documented type = %q, want Counter (emitted with CounterValue)", name, got[name])
		}
	}
}

// TestMetricTypeSuffixFallback covers the retained fallback (#100 acceptance #5): a desc whose
// emission site can't be resolved statically (emitted through a local/loop desc variable) falls
// back to the _total-suffix heuristic, while a desc emitted directly is resolved from its
// ValueType even when the suffix would say otherwise.
func TestMetricTypeSuffixFallback(t *testing.T) {
	src := `package collector

import "github.com/prometheus/client_golang/prometheus"

func (c *x) Register() {
	c.foo = buildPrometheusDesc(c.subsystem, "foo_total", "help", nil)
	c.bar = buildPrometheusDesc(c.subsystem, "bar", "help", nil)
}

func (c *x) Update(ch chan<- prometheus.Metric) {
	// foo emitted through an unresolvable local desc variable -> suffix fallback.
	desc := c.foo
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1)
	// bar emitted directly with CounterValue -> resolved from emission despite no _total suffix.
	ch <- prometheus.MustNewConstMetric(c.bar, prometheus.CounterValue, 1)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	metrics := findBuildPrometheusDescCalls(f, "test", fset)

	byName := map[string]string{}
	for _, m := range metrics {
		byName[m.Name] = m.Type
	}
	if byName["foo_total"] != "Counter" {
		t.Errorf("foo_total: got %q, want Counter (unresolved emission -> _total suffix fallback)", byName["foo_total"])
	}
	if byName["bar"] != "Counter" {
		t.Errorf("bar: got %q, want Counter (resolved from CounterValue emission, not suffix)", byName["bar"])
	}
}
