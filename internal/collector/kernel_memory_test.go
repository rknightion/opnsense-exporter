package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

// kernelMemoryFixture is a trimmed verbatim capture of api/diagnostics/system/memory
// from the live prod firewall (OPNsense 26.1, 2026-07-30). It keeps a zone with
// limit == 0 while in use, a zone with a large non-zero fail, a duplicate zone name
// (UMA reports one row per NUMA domain) and a duplicate malloc type.
//
// One value is synthetic and flagged as such: "256 Bucket" has sleep raised from the
// captured 0 to 5. No zone on any of the three live boxes had a non-zero sleep at
// capture time, and the sleeps series still needs a non-degenerate assertion. sleep
// is a plain UMA counter present on every row, so this is a synthetic VALUE, never a
// shape upstream cannot produce.
const kernelMemoryFixture = `{
  "__version": "2",
  "vmstat": {
    "malloc-statistics": {
      "memory": [
        {"type": "pf_temp", "in-use": 0, "memory-use": 0, "requests": 11, "size": [16]},
        {"type": "dummynet", "in-use": 4, "memory-use": 1280, "requests": 124554, "size": [128, 256]},
        {"type": "dummynet", "in-use": 3, "memory-use": 2560, "requests": 3, "size": [512, 1024]}
      ]
    },
    "memory-zone-statistics": {
      "zone": [
        {"name": "pf states", "size": 328, "limit": 3258600, "used": 12780, "free": 10590, "requests": 41293921, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "pf state keys", "size": 88, "limit": 0, "used": 16275, "free": 10727, "requests": 41314018, "fail": 0, "sleep": 0, "xdomain": 0},
        {"name": "256 Bucket", "size": 2072, "limit": 0, "used": 1281, "free": 141, "requests": 89163726, "fail": 144270, "sleep": 5, "xdomain": 0},
        {"name": "vm pgcache", "size": 4096, "limit": 0, "used": 819065, "free": 2020, "requests": 1981217291, "fail": 8858, "sleep": 0, "xdomain": 3},
        {"name": "vm pgcache", "size": 4096, "limit": 0, "used": 2170293, "free": 3620, "requests": 398186153, "fail": 268, "sleep": 0, "xdomain": 4}
      ]
    }
  }
}`

func TestKernelMemoryCollector_Name(t *testing.T) {
	c := &kernelMemoryCollector{subsystem: KernelMemorySubsystem}
	if c.Name() != KernelMemorySubsystem {
		t.Errorf("Name() = %q, want %q", c.Name(), KernelMemorySubsystem)
	}
	if KernelMemorySubsystem == SystemSubsystem {
		t.Fatal("kernel_memory must not collide with the system subsystem")
	}
}

func TestKernelMemoryCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(kernelMemoryFixture))
	}))
	defer server.Close()

	c := &kernelMemoryCollector{subsystem: KernelMemorySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))

	// 5 zone rows collapse to 4 zones x 8 series; 3 malloc rows collapse to 2 types
	// x 3 series; plus the catch-all.
	if got, want := len(metrics), 4*8+2*3+1; got != want {
		t.Errorf("metric count = %d, want %d", got, want)
	}

	// The whole reason duplicates are merged: two "vm pgcache" rows under one
	// {zone="vm pgcache"} label would make Gather() error and 500 the scrape.
	assertNoDuplicateSeries(t, metrics)

	assertMetricsAreCounters(t, metrics,
		"opnsense_kernel_memory_zone_requests_total",
		"opnsense_kernel_memory_zone_failures_total",
		"opnsense_kernel_memory_zone_sleeps_total",
		"opnsense_kernel_memory_zone_xdomain_total",
		"opnsense_kernel_memory_zone_failures_all_total",
		"opnsense_kernel_memory_malloc_requests_total",
	)

	find := func(name, labelKey, labelValue string) float64 {
		t.Helper()
		for _, m := range metrics {
			if !hasFqName(m, name) {
				continue
			}
			if labelKey == "" {
				return getMetricValue(m)
			}
			if getMetricLabels(m)[labelKey] == labelValue {
				return getMetricValue(m)
			}
		}
		t.Fatalf("metric %s{%s=%q} not emitted", name, labelKey, labelValue)
		return 0
	}

	tests := []struct {
		name       string
		metric     string
		labelKey   string
		labelValue string
		want       float64
	}{
		{"zone used", "opnsense_kernel_memory_zone_used", "zone", "pf states", 12780},
		{"zone free", "opnsense_kernel_memory_zone_free", "zone", "pf states", 10590},
		{"zone limit", "opnsense_kernel_memory_zone_limit", "zone", "pf states", 3258600},
		{"zone item size", "opnsense_kernel_memory_zone_item_size_bytes", "zone", "pf states", 328},
		{"zone requests", "opnsense_kernel_memory_zone_requests_total", "zone", "pf states", 41293921},
		{"limit 0 is exported as 0, not omitted", "opnsense_kernel_memory_zone_limit", "zone", "pf state keys", 0},
		{"used survives a zero limit", "opnsense_kernel_memory_zone_used", "zone", "pf state keys", 16275},
		{"non-zero failures", "opnsense_kernel_memory_zone_failures_total", "zone", "256 Bucket", 144270},
		{"non-zero sleeps", "opnsense_kernel_memory_zone_sleeps_total", "zone", "256 Bucket", 5},
		{"duplicate zone rows summed", "opnsense_kernel_memory_zone_used", "zone", "vm pgcache", 819065 + 2170293},
		{"duplicate zone xdomain summed", "opnsense_kernel_memory_zone_xdomain_total", "zone", "vm pgcache", 7},
		{"catch-all sums every zone", "opnsense_kernel_memory_zone_failures_all_total", "", "", 144270 + 8858 + 268},
		{"malloc in use", "opnsense_kernel_memory_malloc_in_use", "type", "pf_temp", 0},
		{"malloc requests", "opnsense_kernel_memory_malloc_requests_total", "type", "pf_temp", 11},
		{"duplicate malloc rows summed", "opnsense_kernel_memory_malloc_bytes", "type", "dummynet", 1280 + 2560},
		{"duplicate malloc in use summed", "opnsense_kernel_memory_malloc_in_use", "type", "dummynet", 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := find(tc.metric, tc.labelKey, tc.labelValue); got != tc.want {
				t.Errorf("%s{%s=%q} = %v, want %v", tc.metric, tc.labelKey, tc.labelValue, got, tc.want)
			}
		})
	}
}

// TestKernelMemoryCollector_EmptyStillEmitsCatchAll pins the one series that must
// never disappear: an alert on the catch-all cannot fire on an absent series, so a
// box reporting nothing must still publish a zero.
func TestKernelMemoryCollector_EmptyStillEmitsCatchAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	c := &kernelMemoryCollector{subsystem: KernelMemorySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))
	if len(metrics) != 1 {
		t.Fatalf("metric count = %d, want 1 (the catch-all only)", len(metrics))
	}
	if !hasFqName(metrics[0], "opnsense_kernel_memory_zone_failures_all_total") {
		t.Errorf("the single emitted metric is %s, want the catch-all", metrics[0].Desc())
	}
	if got := getMetricValue(metrics[0]); got != 0 {
		t.Errorf("catch-all = %v, want 0", got)
	}
}

// TestKernelMemoryCollector_Registered guards the init() self-registration and the
// poll tier: absent from collectorInstances the collector silently never runs.
func TestKernelMemoryCollector_Registered(t *testing.T) {
	var found bool
	for _, ci := range collectorInstances {
		if ci.Name() == KernelMemorySubsystem {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("kernel_memory is not in collectorInstances; its init() did not run")
	}
	if got, want := collectorTiers[KernelMemorySubsystem], IntervalSlow; got != want {
		t.Errorf("kernel_memory poll tier = %v, want %v", got, want)
	}
	if _, ok := SubsystemDisplayNames[KernelMemorySubsystem]; !ok {
		t.Error("kernel_memory has no SubsystemDisplayNames entry")
	}
}
