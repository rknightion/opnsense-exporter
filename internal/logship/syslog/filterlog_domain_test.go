package syslog

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/flow"
	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

type filterlogDomainMetricSink struct {
	logship.NopMetricSink
	domains       []string
	firewallAttrs []map[string]string
}

func (s *filterlogDomainMetricSink) ObserveFilterlogDomain(domain string) bool {
	s.domains = append(s.domains, domain)
	return true
}

func (s *filterlogDomainMetricSink) ObserveFirewall(action, iface, ruleID, ruleName, scope string) bool {
	s.firewallAttrs = append(s.firewallAttrs, map[string]string{
		"action": action, "interface": iface, "rule_id": ruleID,
		"rule_name": ruleName, "scope": scope,
	})
	return true
}

func filterlogDomainTestSource(t *testing.T, cache *flow.DNSCache, sink logship.MetricSink) *source {
	t.Helper()
	return newSource(&options.SyslogConfig{}, logship.Deps{
		Registerer:   prometheus.NewRegistry(),
		FlowDNSCache: cache,
		MetricSink:   sink,
	})
}

func filterlogWireLine() []byte {
	return syslogTestLine("filterlog", realIPv4UDPLine)
}

func TestFilterlogDomainCacheHitAddsStructuredAttributeAndObservation(t *testing.T) {
	cache := flow.NewDNSCache(10, time.Hour)
	client := netip.MustParseAddr("10.0.0.5")
	answer := netip.MustParseAddr("10.0.0.6")
	cache.Put(client, answer, "laptop.example", time.Now())
	sink := &filterlogDomainMetricSink{}
	s := filterlogDomainTestSource(t, cache, sink)
	var emitted []logship.Record
	s.emit = func(rec logship.Record) { emitted = append(emitted, rec) }

	s.handle(filterlogWireLine(), netip.MustParseAddr("192.0.2.1"))

	if len(emitted) != 1 {
		t.Fatalf("emitted records = %d, want 1", len(emitted))
	}
	if got := emitted[0].Attributes["dst.domain"]; got != "laptop.example" {
		t.Fatalf("dst.domain = %q, want laptop.example", got)
	}
	if got := emitted[0].Attributes[logship.AttrSubsystem]; got != "firewall" {
		t.Fatalf("subsystem = %q, want firewall", got)
	}
	if len(sink.domains) != 1 || sink.domains[0] != "laptop.example" {
		t.Fatalf("domain observations = %v, want [laptop.example]", sink.domains)
	}
	if len(sink.firewallAttrs) != 1 {
		t.Fatalf("firewall observations = %d, want 1", len(sink.firewallAttrs))
	}
}

func TestFilterlogDomainCacheMissLeavesRecordAndMetricsUnenriched(t *testing.T) {
	cache := flow.NewDNSCache(10, time.Hour)
	sink := &filterlogDomainMetricSink{}
	s := filterlogDomainTestSource(t, cache, sink)
	var emitted []logship.Record
	s.emit = func(rec logship.Record) { emitted = append(emitted, rec) }

	s.handle(filterlogWireLine(), netip.MustParseAddr("192.0.2.1"))

	if len(emitted) != 1 {
		t.Fatalf("emitted records = %d, want 1", len(emitted))
	}
	if _, ok := emitted[0].Attributes["dst.domain"]; ok {
		t.Fatal("dst.domain present on a cache miss")
	}
	if len(sink.domains) != 0 {
		t.Fatalf("domain observations = %v, want none on cache miss", sink.domains)
	}
	if got := cache.Stats().Misses; got != 1 {
		t.Fatalf("DNS cache misses = %d, want exactly 1 cache read", got)
	}
}

// The domain is a record attribute only. It is not added to the closed
// opnsense.subsystem/action stream-shaping attributes or to the firewall metric's
// label tuple; the latter is the source-side guard against accidentally promoting
// it while the OTLP sink remains responsible for resource-label construction.
func TestFilterlogDomainDoesNotChangeStreamShapingAttributes(t *testing.T) {
	cache := flow.NewDNSCache(10, time.Hour)
	cache.Put(
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("10.0.0.6"),
		"laptop.example", time.Now(),
	)
	sink := &filterlogDomainMetricSink{}
	s := filterlogDomainTestSource(t, cache, sink)
	var emitted []logship.Record
	s.emit = func(rec logship.Record) { emitted = append(emitted, rec) }

	s.handle(filterlogWireLine(), netip.MustParseAddr("192.0.2.1"))

	if len(emitted) != 1 {
		t.Fatalf("emitted records = %d, want 1", len(emitted))
	}
	attrs := emitted[0].Attributes
	if attrs[logship.AttrSubsystem] != "firewall" {
		t.Fatalf("stream subsystem = %q, want firewall", attrs[logship.AttrSubsystem])
	}
	if _, ok := attrs["opnsense.source"]; ok {
		t.Fatal("domain enrichment introduced a source shaping attribute")
	}
	if got := len(sink.firewallAttrs); got != 1 {
		t.Fatalf("firewall metric observations = %d, want 1", got)
	}
	for key, value := range sink.firewallAttrs[0] {
		if value == "laptop.example" {
			t.Fatalf("domain reached firewall metric label %q", key)
		}
	}
}
