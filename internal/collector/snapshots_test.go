package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestSnapshotsCollector_ZFS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/snapshots/is_supported", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"supported": true}`))
	})
	mux.HandleFunc("/api/core/snapshots/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"total": 2,
			"rowCount": 2,
			"current": 1,
			"rows": [
				{"uuid": "a", "name": "default", "active": "NR", "mountpoint": "/", "size": "28.8G", "created_str": "x", "created": 1724915760},
				{"uuid": "b", "name": "old", "active": "-", "mountpoint": "-", "size": "13.3G", "created_str": "y", "created": 1770384480}
			]
		}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &snapshotsCollector{subsystem: SnapshotsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	if len(metrics) != 3 {
		t.Fatalf("expected 3 metrics (supported, total, active_created_timestamp), got %d", len(metrics))
	}

	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_snapshots_supported"):
			if v := getMetricValue(m); v != 1 {
				t.Errorf("expected supported=1, got %v", v)
			}
		case hasFqName(m, "opnsense_snapshots_total"):
			if v := getMetricValue(m); v != 2 {
				t.Errorf("expected total=2, got %v", v)
			}
		case hasFqName(m, "opnsense_snapshots_active_created_timestamp_seconds"):
			if v := getMetricValue(m); v != 1724915760 {
				t.Errorf("expected active_created_timestamp_seconds=1724915760, got %v", v)
			}
		default:
			t.Errorf("unexpected metric: %s", m.Desc().String())
		}
	}
}

// TestSnapshotsCollector_UFS covers the live-captured UFS shape (2026-07-13):
// supported:false and an empty rowset. The active_created_timestamp_seconds
// series must be entirely absent, not emitted as 0.
func TestSnapshotsCollector_UFS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/snapshots/is_supported", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"supported": false}`))
	})
	mux.HandleFunc("/api/core/snapshots/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &snapshotsCollector{subsystem: SnapshotsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics (supported, total) with no active_created_timestamp_seconds series, got %d", len(metrics))
	}
	for _, m := range metrics {
		switch {
		case hasFqName(m, "opnsense_snapshots_supported"):
			if v := getMetricValue(m); v != 0 {
				t.Errorf("expected supported=0 on UFS, got %v", v)
			}
		case hasFqName(m, "opnsense_snapshots_total"):
			if v := getMetricValue(m); v != 0 {
				t.Errorf("expected total=0 on UFS, got %v", v)
			}
		case hasFqName(m, "opnsense_snapshots_active_created_timestamp_seconds"):
			t.Errorf("active_created_timestamp_seconds must be absent on UFS, got a series")
		default:
			t.Errorf("unexpected metric: %s", m.Desc().String())
		}
	}
}

// TestSnapshotsCollector_ConcurrentFetch mirrors netflow's #129 pattern: the
// two independent endpoints must be fetched concurrently.
func TestSnapshotsCollector_ConcurrentFetch(t *testing.T) {
	mux := http.NewServeMux()
	const delay = 60 * time.Millisecond
	for _, p := range []string{
		"/api/core/snapshots/is_supported",
		"/api/core/snapshots/search",
	} {
		mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(delay)
			_, _ = w.Write([]byte(`{}`))
		})
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &snapshotsCollector{subsystem: SnapshotsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	start := time.Now()
	ch := make(chan prometheus.Metric, 128)
	if err := c.Update(context.Background(), client, ch); err != nil {
		t.Fatalf("update: %v", err)
	}
	close(ch)
	elapsed := time.Since(start)
	if elapsed > 140*time.Millisecond {
		t.Errorf("snapshots Update took %v; the two fetches did not run concurrently", elapsed)
	}
}

func TestSnapshotsCollector_SupportedServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/core/snapshots/is_supported", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/core/snapshots/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total": 0, "rowCount": 0, "current": 1, "rows": []}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &snapshotsCollector{subsystem: SnapshotsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	ch := make(chan prometheus.Metric, 8)
	err := c.Update(context.Background(), client, ch)
	close(ch)
	if err == nil {
		t.Fatal("expected error propagated from failed is_supported fetch")
	}
}
