package collector

import (
	"fmt"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestLogEventsCollector_EmitsTopFilterlogDomainsAndOther(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())

	// Sixty distinct names exercise the output cap. The first two have enough
	// volume to be unambiguous top entries; the remaining one-observation names
	// are selected by their deterministic lexical tie-break.
	for i := 0; i < 60; i++ {
		domain := fmt.Sprintf("domain-%02d.example", i)
		if !c.store.ObserveFilterlogDomain(domain) {
			t.Fatalf("observation for %s was refused", domain)
		}
	}
	for i := 0; i < 4; i++ {
		c.store.ObserveFilterlogDomain("domain-00.example")
	}
	for i := 0; i < 3; i++ {
		c.store.ObserveFilterlogDomain("domain-01.example")
	}

	counts := map[string]float64{}
	series := 0
	for _, metric := range collectMetrics(t, c, nil) {
		if !hasFqName(metric, "opnsense_log_events_filterlog_domain_total") {
			continue
		}
		series++
		labels := getMetricLabels(metric)
		if len(labels) != 2 {
			t.Fatalf("filterlog domain labels = %v, want domain and opnsense_instance", labels)
		}
		if labels["opnsense_instance"] != "opnsense.example.com" {
			t.Fatalf("filterlog domain instance = %q, want opnsense.example.com", labels["opnsense_instance"])
		}
		counts[labels["domain"]] = getMetricValue(metric)
	}

	if series != maxFilterlogDomainMetricSeries+1 {
		t.Fatalf("filterlog domain series = %d, want the top-50 plus other bound (%d)", series, maxFilterlogDomainMetricSeries+1)
	}
	if counts["domain-00.example"] != 5 {
		t.Errorf("domain-00 count = %v, want 5", counts["domain-00.example"])
	}
	if counts["domain-01.example"] != 4 {
		t.Errorf("domain-01 count = %v, want 4", counts["domain-01.example"])
	}
	if counts[filterlogDomainOther] != 10 {
		t.Errorf("other count = %v, want 10", counts[filterlogDomainOther])
	}
	for i := 2; i < 50; i++ {
		if _, ok := counts[fmt.Sprintf("domain-%02d.example", i)]; !ok {
			t.Errorf("domain-%02d.example was not in the deterministic top-50 view", i)
		}
	}
	for i := 50; i < 60; i++ {
		if _, ok := counts[fmt.Sprintf("domain-%02d.example", i)]; ok {
			t.Errorf("domain-%02d.example escaped the other bucket", i)
		}
	}
}

func TestLogEventsCollector_FoldsReservedOtherDomain(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	c.store.ObserveFilterlogDomain(filterlogDomainOther)

	counts := map[string]float64{}
	for _, metric := range collectMetrics(t, c, nil) {
		if hasFqName(metric, "opnsense_log_events_filterlog_domain_total") {
			counts[getMetricLabels(metric)["domain"]] = getMetricValue(metric)
		}
	}
	if len(counts) != 1 || counts[filterlogDomainOther] != 1 {
		t.Fatalf("reserved other domain output = %v, want one other series at 1", counts)
	}
}

func TestLogEventsCollector_AdmitsLateHeavyFilterlogDomain(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())

	// Fill the candidate budget with one-observation names, then make a domain
	// first seen after that point the clear heavy hitter. A first-seen-only cap
	// would strand late.example in `other` forever.
	for i := 0; i < maxFilterlogDomainCandidates; i++ {
		if !c.store.ObserveFilterlogDomain(fmt.Sprintf("cold-%04d.example", i)) {
			t.Fatalf("candidate observation %d was refused", i)
		}
	}
	for i := 0; i < 100; i++ {
		if !c.store.ObserveFilterlogDomain("late.example") {
			t.Fatal("late heavy-hitter observation was refused")
		}
	}

	counts := map[string]float64{}
	for _, metric := range collectMetrics(t, c, nil) {
		if hasFqName(metric, "opnsense_log_events_filterlog_domain_total") {
			counts[getMetricLabels(metric)["domain"]] = getMetricValue(metric)
		}
	}
	if got := counts["late.example"]; got != 100 {
		t.Fatalf("late heavy-hitter count = %v, want 100", got)
	}
	if got := counts[filterlogDomainOther]; got != 4047 {
		t.Fatalf("late heavy-hitter other count = %v, want 4047", got)
	}
	if got := len(counts); got != maxFilterlogDomainMetricSeries+1 {
		t.Fatalf("domain series = %d, want top-50 plus other (%d)", got, maxFilterlogDomainMetricSeries+1)
	}
	if got := len(c.store.filterlogDomains.m); got != maxFilterlogDomainCandidates {
		t.Fatalf("domain candidate map size = %d, want bounded %d", got, maxFilterlogDomainCandidates)
	}
}

func TestLogEventsCollector_FilterlogDomainCountersStayMonotonicAcrossRankChange(t *testing.T) {
	c := &logEventsCollector{store: newTestLogEventStore(t), subsystem: LogEventsSubsystem}
	c.Register(namespace, "opnsense.example.com", promslog.NewNopLogger())
	for i := 0; i < 60; i++ {
		c.store.ObserveFilterlogDomain(fmt.Sprintf("domain-%02d.example", i))
	}
	before := collectFilterlogDomainCounts(t, c)

	// This domain begins in `other`, then becomes the clear top-ranked series.
	for i := 0; i < 100; i++ {
		c.store.ObserveFilterlogDomain("domain-59.example")
	}
	after := collectFilterlogDomainCounts(t, c)
	if after["domain-59.example"] != 101 {
		t.Fatalf("promoted domain count = %v, want 101", after["domain-59.example"])
	}
	if after[filterlogDomainOther] < before[filterlogDomainOther] {
		t.Fatalf("other counter decreased across rank change: before=%v after=%v",
			before[filterlogDomainOther], after[filterlogDomainOther])
	}
	for domain, old := range before {
		if current, ok := after[domain]; ok && current < old {
			t.Errorf("counter %q decreased across scrapes: before=%v after=%v", domain, old, current)
		}
	}
}

func collectFilterlogDomainCounts(t *testing.T, c *logEventsCollector) map[string]float64 {
	t.Helper()
	counts := map[string]float64{}
	for _, metric := range collectMetrics(t, c, nil) {
		if hasFqName(metric, "opnsense_log_events_filterlog_domain_total") {
			counts[getMetricLabels(metric)["domain"]] = getMetricValue(metric)
		}
	}
	return counts
}
