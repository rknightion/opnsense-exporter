package metriclint

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestRepositoryMetricNames is intentionally a normal Go test rather than
// only a just recipe. CI's required build-test job invokes just test, and the
// repository therefore must fail when a new production metric bypasses the
// naming contract even if somebody forgets to run the dedicated recipe.
func TestRepositoryMetricNames(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed while locating repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	if err := CheckRepository(root); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryScanUsesSourceMetricTypes(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed while locating repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	metrics, err := ScanRepository(root)
	if err != nil {
		t.Fatal(err)
	}

	var sawGauge, sawCounter bool
	for _, metric := range metrics {
		switch {
		case metric.File == "internal/collector/crowdsec.go" && metric.LocalName == "alerts":
			if metric.Kind != KindGauge {
				t.Errorf("crowdsec alerts kind = %q, want Gauge", metric.Kind)
			}
			sawGauge = true
		case metric.File == "internal/collector/collector.go" && metric.LocalName == "exporter_scrapes_total":
			if metric.Kind != KindCounter {
				t.Errorf("exporter_scrapes_total kind = %q, want Counter", metric.Kind)
			}
			sawCounter = true
		}
	}
	if !sawGauge || !sawCounter {
		t.Fatalf("source scan did not find both type fixtures (gauge=%v counter=%v)", sawGauge, sawCounter)
	}
}
