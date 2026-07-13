package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestBackupCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"items": [
				{"time": "1783886416.55", "filesize": 417639},
				{"time": "1783886406.03", "filesize": 417637}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &backupCollector{subsystem: BackupSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics (last_timestamp, count, last_size), got %d", len(metrics))
	}

	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_backup_last_timestamp_seconds"):
			if v := getMetricValue(m); v != 1783886416.55 {
				t.Errorf("expected last_timestamp=1783886416.55, got %v", v)
			}
		case hasFqName(m, "opnsense_backup_count"):
			if v := getMetricValue(m); v != 2 {
				t.Errorf("expected count=2, got %v", v)
			}
		case hasFqName(m, "opnsense_backup_last_size_bytes"):
			if v := getMetricValue(m); v != 417639 {
				t.Errorf("expected last_size_bytes=417639, got %v", v)
			}
		default:
			t.Errorf("unexpected metric: %s", m.Desc().String())
		}
	}
}

func TestBackupCollector_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items": []}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &backupCollector{subsystem: BackupSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics even with no backups, got %d", len(metrics))
	}
	for _, m := range metrics {
		if hasFqName(m, "opnsense_backup_count") && getMetricValue(m) != 0 {
			t.Errorf("expected count=0 with no backups")
		}
	}
}

func TestBackupCollector_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &backupCollector{subsystem: BackupSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 8)
	err := c.Update(context.Background(), client, ch)
	close(ch)
	if err == nil {
		t.Fatal("expected error propagated from failed fetch")
	}
}
