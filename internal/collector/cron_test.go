package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestCronCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "uuid-1",
					"enabled": "1",
					"minutes": "0",
					"hours": "1",
					"days": "*",
					"months": "*",
					"weekdays": "*",
					"description": "Automatic firmware update",
					"command": "firmware auto-update",
					"origin": "cron"
				},
				{
					"uuid": "uuid-2",
					"enabled": "0",
					"minutes": "*/5",
					"hours": "*",
					"days": "*",
					"months": "*",
					"weekdays": "*",
					"description": "Update DynDNS",
					"command": "dyndns update",
					"origin": "dyndns"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &cronCollector{subsystem: CronTableSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 cron jobs = 2 metrics
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify one enabled and one disabled
	foundEnabled := false
	foundDisabled := false
	for _, m := range metrics {
		v := getMetricValue(m)
		if v == 1 {
			foundEnabled = true
		}
		if v == 0 {
			foundDisabled = true
		}
	}
	if !foundEnabled {
		t.Error("expected to find an enabled cron job metric (value=1)")
	}
	if !foundDisabled {
		t.Error("expected to find a disabled cron job metric (value=0)")
	}
}

// TestCronCollector_DuplicateFieldsStayDistinct reproduces the #81 collision: a
// cron job cloned (then the original disabled) yields two rows identical in
// (schedule, description, command, origin). Before the fix these collapsed to one
// label tuple and 500'd the whole scrape; the uuid label keeps them distinct.
func TestCronCollector_DuplicateFieldsStayDistinct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"uuid":"uuid-a","enabled":"1","minutes":"0","hours":"1","days":"*","months":"*","weekdays":"*","description":"nightly job","command":"do-thing","origin":"cron"},
				{"uuid":"uuid-b","enabled":"0","minutes":"0","hours":"1","days":"*","months":"*","weekdays":"*","description":"nightly job","command":"do-thing","origin":"cron"}
			],
			"rowCount": 2, "total": 2, "current": 1
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &cronCollector{subsystem: CronTableSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}
	assertNoDuplicateSeries(t, metrics)

	uuids := map[string]bool{}
	for _, m := range metrics {
		l := getMetricLabels(m)
		if l["uuid"] == "" {
			t.Errorf("expected a non-empty uuid label, got %v", l)
		}
		uuids[l["uuid"]] = true
	}
	if len(uuids) != 2 {
		t.Errorf("expected 2 distinct uuid labels, got %d: %v", len(uuids), uuids)
	}
}

func TestCronCollector_Name(t *testing.T) {
	c := &cronCollector{subsystem: CronTableSubsystem}
	if c.Name() != CronTableSubsystem {
		t.Errorf("expected %s, got %s", CronTableSubsystem, c.Name())
	}
}
