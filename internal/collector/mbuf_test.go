package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestMbufCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"mbuf-statistics": {
				"mbuf-current": 512,
				"mbuf-cache": 256,
				"mbuf-total": 65536,
				"mbuf-max": 131072,
				"cluster-current": 1024,
				"cluster-cache": 512,
				"cluster-total": 32768,
				"cluster-max": 65536,
				"mbuf-failures": 0,
				"cluster-failures": 1,
				"packet-failures": 0,
				"mbuf-sleeps": 0,
				"cluster-sleeps": 2,
				"packet-sleeps": 0,
				"jumbop-current": 0,
				"jumbop-cache": 0,
				"jumbop-total": 0,
				"jumbop-max": 0,
				"jumbop-failures": 0,
				"jumbop-sleeps": 0,
				"bytes-in-use": 2097152,
				"bytes-total": 67108864,
				"percentage": 3,
				"mbuf-and-cluster": 0
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &mbufCollector{subsystem: MbufSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 8 gauge metrics (mbufCurrent, mbufCache, mbufTotal, mbufMax, clusterCurrent, clusterCache, clusterTotal, clusterMax)
	// 6 failures by type (mbuf, cluster, packet, jumbop, jumbo9, jumbo16)
	// 6 sleeps by type (mbuf, cluster, packet, jumbop, jumbo9, jumbo16)
	// 2 bytes metrics (bytesInUse, bytesTotal)
	// 3 sendfile metrics (syscalls, ioCount, pagesSent)
	// Total: 8 + 6 + 6 + 2 + 3 = 25
	expectedCount := 25
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	foundMbufMax := false
	for _, m := range metrics {
		if hasFqName(m, "opnsense_mbuf_max") {
			foundMbufMax = true
			if getMetricValue(m) != 131072 {
				t.Errorf("expected opnsense_mbuf_max=131072, got %v", getMetricValue(m))
			}
		}
	}
	if !foundMbufMax {
		t.Error("expected an opnsense_mbuf_max series")
	}
}

func TestMbufCollector_Name(t *testing.T) {
	c := &mbufCollector{subsystem: MbufSubsystem}
	if c.Name() != MbufSubsystem {
		t.Errorf("expected %s, got %s", MbufSubsystem, c.Name())
	}
}
