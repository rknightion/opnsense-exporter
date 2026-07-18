package zenarmor

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// excludeTestSource builds a source wired for handleDoc without binding a socket:
// newSource listens eagerly, which these tests neither need nor want.
func excludeTestSource(t *testing.T, reg prometheus.Registerer, sink logship.MetricSink, rules []ExcludeRule) (*zenarmorSource, *[]logship.Record) {
	t.Helper()
	var emitted []logship.Record
	s := &zenarmorSource{
		proc: docProcessor{
			cfg:   Config{Excludes: rules, Enrich: false},
			sink:  sink,
			m:     newMetrics(reg, rules),
			cache: nil,
		},
		emit: func(r logship.Record) { emitted = append(emitted, r) },
	}
	return s, &emitted
}

func mustRules(t *testing.T, raw ...string) []ExcludeRule {
	t.Helper()
	rules, err := parseExcludeRules(raw)
	if err != nil {
		t.Fatalf("parseExcludeRules: %v", err)
	}
	return rules
}

// seriesValue reads one series from reg by name+label, reporting whether it exists.
// Gather, not WithLabelValues: reading a vec child creates it (#280).
func seriesValue(t *testing.T, reg *prometheus.Registry, name, label, value string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == label && lp.GetValue() == value {
					return counterOf(m), true
				}
			}
		}
	}
	return 0, false
}

func counterOf(m *dto.Metric) float64 { return m.GetCounter().GetValue() }

// The headline contract of #279: an excluded record is dropped, but its DERIVED
// counter is observed first. The counters outlive both the exclusion and Loki's
// retention, so they are all that remains of the excluded traffic — losing them too
// would make the exclusion invisible rather than merely lossy.
func TestExcludedRecordIsDroppedButStillCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	rules := mustRules(t, `server_name=~.*\.tinionet\.net`)
	s, emitted := excludeTestSource(t, reg, sink, rules)

	s.handleDoc("zenarmor_0000000000_x_tls_write", []byte(tlsDoc), netip.MustParseAddr("10.0.0.254"))

	if len(*emitted) != 0 {
		t.Errorf("record matching an exclude rule must not be shipped, got %d records", len(*emitted))
	}
	if len(sink.got) != 1 {
		t.Fatalf("got %d derived observations, want 1 — the metric must be observed BEFORE the drop", len(sink.got))
	}

	if v, ok := seriesValue(t, reg, "opnsense_exporter_logs_zenarmor_excluded_total", "rule", rules[0].Raw); !ok {
		t.Error("logs_zenarmor_excluded_total{rule} is absent; the blind spot is invisible")
	} else if v != 1 {
		t.Errorf("excluded_total{rule} = %v, want 1", v)
	}

	if v, ok := seriesValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "excluded"); !ok {
		t.Error(`logs_rejected_total{reason="excluded"} is absent; the drop is missing from the standard rejected view`)
	} else if v != 1 {
		t.Errorf(`rejected_total{reason="excluded"} = %v, want 1`, v)
	}
}

// A record no rule matches must be untouched.
func TestNonMatchingRecordShipsNormally(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	rules := mustRules(t, `server_name=~.*\.grafana\.net`)
	s, emitted := excludeTestSource(t, reg, sink, rules)

	s.handleDoc("zenarmor_0000000000_x_tls_write", []byte(tlsDoc), netip.MustParseAddr("10.0.0.254"))

	if len(*emitted) != 1 {
		t.Errorf("record matching no rule must ship, got %d records", len(*emitted))
	}
	if len(sink.got) != 1 {
		t.Errorf("got %d derived observations, want 1", len(sink.got))
	}
	if v, _ := seriesValue(t, reg, "opnsense_exporter_logs_zenarmor_excluded_total", "rule", rules[0].Raw); v != 0 {
		t.Errorf("excluded_total{rule} = %v, want 0 — nothing matched", v)
	}
}

// Default off: with no rules configured, nothing is excluded and no rule series
// exists to imply otherwise.
func TestNoRulesExcludesNothing(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	s, emitted := excludeTestSource(t, reg, sink, nil)

	s.handleDoc("zenarmor_0000000000_x_tls_write", []byte(tlsDoc), netip.MustParseAddr("10.0.0.254"))

	if len(*emitted) != 1 {
		t.Errorf("default off must ship everything, got %d records", len(*emitted))
	}
}

// #280 applies to the new counter too: a configured rule that has never matched must
// read 0, not vanish. Otherwise "no series" means both "this rule drops nothing" and
// "this rule is eating the stream but we just restarted".
func TestExcludedTotalIsPreInitialisedPerRule(t *testing.T) {
	reg := prometheus.NewRegistry()
	rules := mustRules(t, `server_name=~.*\.grafana\.net`, `query=~.*\.grafana\.net`)
	newMetrics(reg, rules)

	for _, r := range rules {
		v, ok := seriesValue(t, reg, "opnsense_exporter_logs_zenarmor_excluded_total", "rule", r.Raw)
		if !ok {
			t.Errorf("logs_zenarmor_excluded_total{rule=%q} is ABSENT before the rule first matches", r.Raw)
			continue
		}
		if v != 0 {
			t.Errorf("excluded_total{rule=%q} = %v, want 0", r.Raw, v)
		}
	}
}
