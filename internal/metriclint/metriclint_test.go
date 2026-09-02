package metriclint

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckMetricsRejectsGaugeTotal(t *testing.T) {
	violations := CheckMetrics([]Metric{{
		Name:      "opnsense_fixture_items_total",
		LocalName: "items_total",
		Kind:      KindGauge,
		File:      "fixture.go",
		Line:      12,
	}})
	if len(violations) != 1 || violations[0].Rule != ruleGaugeTotal {
		t.Fatalf("CheckMetrics(gauge _total) = %#v, want one %s violation", violations, ruleGaugeTotal)
	}
}

func TestCheckMetricsAllowsCounterTotal(t *testing.T) {
	violations := CheckMetrics([]Metric{{
		Name:      "opnsense_fixture_events_total",
		LocalName: "events_total",
		Kind:      KindCounter,
		File:      "fixture.go",
		Line:      18,
	}})
	if len(violations) != 0 {
		t.Fatalf("CheckMetrics(counter _total) = %#v, want no violations", violations)
	}
}

func TestCheckMetricsRejectsUnknownTotal(t *testing.T) {
	violations := CheckMetrics([]Metric{{
		Name:      "opnsense_fixture_items_total",
		LocalName: "items_total",
		Kind:      KindUnknown,
		File:      "fixture.go",
		Line:      21,
	}})
	if len(violations) != 1 || violations[0].Rule != ruleGaugeTotal {
		t.Fatalf("CheckMetrics(unknown _total) = %#v, want one %s violation", violations, ruleGaugeTotal)
	}
}

func TestCheckMetricsRejectsUnsuffixedUnixTimestamp(t *testing.T) {
	violations := CheckMetrics([]Metric{{
		Name:          "opnsense_fixture_last_seen_seconds",
		LocalName:     "last_seen_seconds",
		Kind:          KindGauge,
		File:          "fixture.go",
		Line:          24,
		UnixTimestamp: true,
	}})
	if len(violations) != 1 || violations[0].Rule != ruleTimestamp {
		t.Fatalf("CheckMetrics(unsuffixed timestamp) = %#v, want one %s violation", violations, ruleTimestamp)
	}
}

func TestCheckMetricsAllowsTimestampSuffix(t *testing.T) {
	violations := CheckMetrics([]Metric{{
		Name:          "opnsense_fixture_last_seen_timestamp_seconds",
		LocalName:     "last_seen_timestamp_seconds",
		Kind:          KindGauge,
		File:          "fixture.go",
		Line:          30,
		UnixTimestamp: true,
	}})
	if len(violations) != 0 {
		t.Fatalf("CheckMetrics(timestamp suffix) = %#v, want no violations", violations)
	}
}

func TestScanFixtureRejectsBothSourceViolations(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const source = `package fixture

import "github.com/prometheus/client_golang/prometheus"

var gauge = prometheus.NewGauge(prometheus.GaugeOpts{Name: "items_total", Help: "current item count"})
var counter = prometheus.NewCounter(prometheus.CounterOpts{Name: "events_total", Help: "monotonic event count"})
var timestamp = prometheus.NewGauge(prometheus.GaugeOpts{Name: "last_seen_seconds", Help: "Unix timestamp of the last observation"})
`
	if err := os.WriteFile(filepath.Join(root, "metrics.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	metrics, err := ScanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := CheckMetrics(metrics)
	if len(violations) != 2 {
		t.Fatalf("fixture violations = %#v, want gauge_total and timestamp_suffix", violations)
	}
	seen := map[string]bool{}
	for _, violation := range violations {
		seen[violation.Rule] = true
	}
	if !seen[ruleGaugeTotal] || !seen[ruleTimestamp] {
		t.Fatalf("fixture violations = %#v, want both rules", violations)
	}
}

func TestLegacyAllowlistEntriesNameOPN0033AsRemovalTrigger(t *testing.T) {
	if len(legacyAllowlist) == 0 {
		t.Fatal("legacy allowlist is empty")
	}
	for key, note := range legacyAllowlist {
		if note == "" || !containsOPN0033(note) {
			t.Errorf("legacy allowlist entry %q has no OPN-0033 removal trigger: %q", key, note)
		}
	}
}

func TestLegacyAllowlistDoesNotCrossRuleBoundaries(t *testing.T) {
	gaugeKey := "internal/collector/acme.go:certificates_total"
	if !allowlisted(gaugeKey, ruleGaugeTotal) {
		t.Fatalf("allowlisted(%q, %q) = false, want true", gaugeKey, ruleGaugeTotal)
	}
	if allowlisted(gaugeKey, ruleTimestamp) {
		t.Fatalf("allowlisted(%q, %q) = true, want false", gaugeKey, ruleTimestamp)
	}

	timestampKey := "internal/collector/system.go:config_last_change"
	if !allowlisted(timestampKey, ruleTimestamp) {
		t.Fatalf("allowlisted(%q, %q) = false, want true", timestampKey, ruleTimestamp)
	}
	if allowlisted(timestampKey, ruleGaugeTotal) {
		t.Fatalf("allowlisted(%q, %q) = true, want false", timestampKey, ruleGaugeTotal)
	}
}

func TestScanTypeEvidenceIgnoresUnixEvidenceWithoutDescriptorKey(t *testing.T) {
	const source = `package fixture

func helper(desc any, value float64) {
	prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value)
}

func emit() {
	prometheus.MustNewConstMetric(newDescriptor(), prometheus.GaugeValue, time.Now().Unix())
	helper(newDescriptor(), time.Now().Unix())
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}

	evidence := scanTypeEvidence([]sourceFile{{rel: "fixture.go", file: file, fset: fset}})
	if len(evidence.timestamp) != 0 {
		t.Fatalf("timestamp evidence = %#v, want no entry for an unresolved descriptor", evidence.timestamp)
	}
}

func containsOPN0033(note string) bool {
	return len(note) >= len(legacyRuleMarker) &&
		containsString(note, legacyRuleMarker)
}

func containsString(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		if value[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
