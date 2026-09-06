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
	// 3 bytes metrics (bytesInUse, bytesTotal, bytesInCache -- #579, unconditional like the other two)
	// 3 sendfile metrics (syscalls, ioCount, pagesSent)
	// 0 pool_{current,cache,total,max} series: this fixture predates jumbo9/jumbo16/packet-count/
	// packet-free (#579), so PoolCurrent/Cache/Total/Max come back empty and emit no series --
	// proves the "absent means no series" contract at the collector layer, not just the client.
	// Total: 8 + 6 + 6 + 3 + 3 = 26
	expectedCount := 26
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		if hasFqName(m, "opnsense_mbuf_pool_current") || hasFqName(m, "opnsense_mbuf_pool_cache") ||
			hasFqName(m, "opnsense_mbuf_pool") || hasFqName(m, "opnsense_mbuf_pool_max") {
			t.Errorf("expected no pool series on a fixture predating jumbo9/jumbo16/packet pool keys, got %s", m.Desc().String())
		}
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

// TestMbufCollector_JumboPoolMetrics covers #579: the jumbo9/jumbo16/packet pool
// utilization series (opnsense_mbuf_pool_{current,cache,total,max}{pool=...}) and
// opnsense_mbuf_bytes_in_cache, fed with a modern (26.1+) systemMbuf fixture. Confirms
// jumbo16's ceiling -- read from the upstream "jumbo16-limit" key -- surfaces on the
// SAME opnsense_mbuf_pool_max series as jumbo9's "jumbo9-max", and that the packet pool
// gets current/cache series but no total/max series (it has no ceiling upstream).
func TestMbufCollector_JumboPoolMetrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"mbuf-statistics": {
				"mbuf-current": 512, "mbuf-cache": 256, "mbuf-total": 65536, "mbuf-max": 131072,
				"cluster-current": 1024, "cluster-cache": 512, "cluster-total": 32768, "cluster-max": 65536,
				"mbuf-failures": 0, "cluster-failures": 1, "packet-failures": 0,
				"mbuf-sleeps": 0, "cluster-sleeps": 2, "packet-sleeps": 0,
				"jumbo-count": 0, "jumbo-cache": 0, "jumbo-total": 0, "jumbo-max": 0,
				"jumbop-failures": 0, "jumbop-sleeps": 0,
				"jumbo9-count": 3, "jumbo9-cache": 1, "jumbo9-total": 20, "jumbo9-max": 9,
				"jumbo9-failures": 0, "jumbo9-sleeps": 0,
				"jumbo16-count": 4, "jumbo16-cache": 2, "jumbo16-total": 30, "jumbo16-limit": 6,
				"jumbo16-failures": 0, "jumbo16-sleeps": 0,
				"packet-count": 12, "packet-free": 13,
				"bytes-in-use": 2097152, "bytes-total": 67108864, "bytes-in-cache": 3000,
				"sendfile-syscalls": 1, "sendfile-io-count": 1, "sendfile-pages-sent": 1
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &mbufCollector{subsystem: MbufSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	wantSeries := map[string]map[string]float64{
		"opnsense_mbuf_pool_current": {"jumbo9": 3, "jumbo16": 4, "packet": 12},
		"opnsense_mbuf_pool_cache":   {"jumbo9": 1, "jumbo16": 2, "packet": 13},
		"opnsense_mbuf_pool":         {"jumbo9": 20, "jumbo16": 30},
		"opnsense_mbuf_pool_max":     {"jumbo9": 9, "jumbo16": 6},
	}
	found := map[string]map[string]bool{
		"opnsense_mbuf_pool_current": {},
		"opnsense_mbuf_pool_cache":   {},
		"opnsense_mbuf_pool":         {},
		"opnsense_mbuf_pool_max":     {},
	}
	for _, m := range metrics {
		for fq, byPool := range wantSeries {
			if !hasFqName(m, fq) {
				continue
			}
			pool := getMetricLabels(m)["pool"]
			want, ok := byPool[pool]
			if !ok {
				t.Errorf("%s: unexpected pool label %q", fq, pool)
				continue
			}
			if got := getMetricValue(m); got != want {
				t.Errorf("%s{pool=%q} = %v, want %v", fq, pool, got, want)
			}
			found[fq][pool] = true
		}
	}
	for fq, byPool := range wantSeries {
		for pool := range byPool {
			if !found[fq][pool] {
				t.Errorf("expected a %s{pool=%q} series, found none", fq, pool)
			}
		}
	}

	// The packet pool has no ceiling upstream (it borrows memory from mbuf/cluster) --
	// pool/pool_max must never carry a packet series.
	for _, m := range metrics {
		if (hasFqName(m, "opnsense_mbuf_pool") || hasFqName(m, "opnsense_mbuf_pool_max")) &&
			getMetricLabels(m)["pool"] == "packet" {
			t.Errorf("expected no packet-labelled %s series (packet pool has no ceiling upstream)", m.Desc().String())
		}
	}

	foundBytesInCache := false
	for _, m := range metrics {
		if hasFqName(m, "opnsense_mbuf_bytes_in_cache") {
			foundBytesInCache = true
			if got := getMetricValue(m); got != 3000*1024 {
				t.Errorf("opnsense_mbuf_bytes_in_cache = %v, want %v", got, 3000*1024)
			}
		}
	}
	if !foundBytesInCache {
		t.Error("expected an opnsense_mbuf_bytes_in_cache series")
	}
}

func TestMbufCollector_Name(t *testing.T) {
	c := &mbufCollector{subsystem: MbufSubsystem}
	if c.Name() != MbufSubsystem {
		t.Errorf("expected %s, got %s", MbufSubsystem, c.Name())
	}
}
