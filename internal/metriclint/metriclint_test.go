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

// A renamed metric must not return under another file or Prometheus type.
func TestCheckMetricsRejectsRenamedMetricInAnotherFile(t *testing.T) {
	violations := CheckMetrics([]Metric{{
		Name: "opnsense_acme_certificates_total", LocalName: "certificates_total",
		Kind: KindCounter, File: "internal/collector/moved.go", Line: 1,
	}})
	if len(violations) == 0 {
		t.Fatal("retired metric name was accepted after moving files and changing type")
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

const namespace = "opnsense"
const fixtureSubsystem = "fixture"
func init() { collectorInstances = append(collectorInstances, &fixtureCollector{subsystem: fixtureSubsystem}) }
func register() {
    c.total = buildPrometheusDesc(c.subsystem, "total", "Current number of items", nil)
    prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, 1)
}
`
	if err := os.WriteFile(filepath.Join(root, "metrics.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	metrics, err := ScanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	violations := CheckMetrics(metrics)
	if len(violations) != 3 {
		t.Fatalf("fixture violations = %#v, want two gauge_total and one timestamp_suffix", violations)
	}
	seen := map[string]bool{}
	sawLocalTotal := false
	for _, violation := range violations {
		seen[violation.Rule] = true
		if violation.Metric.LocalName == "total" && violation.Metric.Name == "opnsense_fixture_total" {
			sawLocalTotal = true
		}
	}
	if !seen[ruleGaugeTotal] || !seen[ruleTimestamp] || !sawLocalTotal {
		t.Fatalf("fixture violations = %#v, want both rules including the qualified local-total gauge", violations)
	}
}

func TestRenamedMetricsLedgerEnforcesEveryRetiredName(t *testing.T) {
	renamed := RenamedMetrics()
	if len(renamed) != 68 {
		t.Fatalf("RenamedMetrics() returned %d entries, want 68", len(renamed))
	}

	seen := make(map[string]bool, len(renamed))
	for _, rename := range renamed {
		if rename.File == "" || rename.OldName == "" || rename.NewName == "" ||
			rename.OldFullName == "" || rename.NewFullName == "" || rename.Release == "" {
			t.Errorf("incomplete rename ledger entry: %#v", rename)
			continue
		}
		key := rename.File + ":" + rename.OldName
		if seen[key] {
			t.Errorf("duplicate rename ledger key %q", key)
		}
		seen[key] = true

		cases := []Metric{
			{
				Name: rename.OldFullName, LocalName: "moved_metric",
				Kind: KindCounter, File: "internal/collector/moved.go", Line: 1,
			},
			{
				LocalName: rename.OldName, Kind: KindGauge,
				File: rename.File, Line: 1,
			},
		}
		for _, metric := range cases {
			violations := CheckMetrics([]Metric{metric})
			if len(violations) != 1 || violations[0].Rule != ruleRenamedMetric {
				t.Errorf("retired metric %#v produced violations %#v, want one %s violation",
					metric, violations, ruleRenamedMetric)
			}
		}
	}
}

func TestRenamedMetricsReturnsIndependentCopy(t *testing.T) {
	first := RenamedMetrics()
	if len(first) == 0 {
		t.Fatal("RenamedMetrics() returned no entries")
	}
	want := first[0]
	first[0].OldName = "mutated"

	second := RenamedMetrics()
	if second[0] != want {
		t.Fatalf("RenamedMetrics() exposed mutable ledger state: got %#v, want %#v", second[0], want)
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
