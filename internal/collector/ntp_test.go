package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestNTPCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"status": "*",
					"server": "0.opnsense.pool.ntp.org",
					"refid": ".GPS.",
					"stratum": "1",
					"type": "u",
					"when": "32",
					"poll": "64",
					"reach": "377",
					"delay": "12.345",
					"offset": "-0.567",
					"jitter": "1.234"
				},
				{
					"status": "+",
					"server": "1.opnsense.pool.ntp.org",
					"refid": ".PPS.",
					"stratum": "2",
					"type": "u",
					"when": "-",
					"poll": "128",
					"reach": "177",
					"delay": "25.678",
					"offset": "1.234",
					"jitter": "2.345"
				}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ntpCollector{subsystem: NTPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// peer 1 (all valid): 8 metrics. peer 2 has when="-" so peer_when_seconds is
	// skipped (#89): 7 metrics. + 1 peersTotal = 16.
	expectedCount := 16
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestNTPCollector_DuplicateServer guards #85: two NTP associations pointing at
// the same server collide on the server-keyed per-peer metrics and would fail the
// whole scrape; the collector must guarantee unique label tuples.
func TestNTPCollector_DuplicateServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{"status":"*","server":"pool.ntp.org","refid":".GPS.","stratum":"1","type":"u","when":"32","poll":"64","reach":"377","delay":"12.3","offset":"-0.5","jitter":"1.2"},
				{"status":"+","server":"pool.ntp.org","refid":".PPS.","stratum":"2","type":"u","when":"16","poll":"128","reach":"177","delay":"25.6","offset":"1.2","jitter":"2.3"}
			]
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ntpCollector{subsystem: NTPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)
}

func TestNTPCollector_Update_NoPeers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": []}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ntpCollector{subsystem: NTPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 peersTotal with value 0
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	if getMetricValue(metrics[0]) != 0 {
		t.Errorf("expected peersTotal=0, got %f", getMetricValue(metrics[0]))
	}
}

func TestNTPCollector_Name(t *testing.T) {
	c := &ntpCollector{subsystem: NTPSubsystem}
	if c.Name() != NTPSubsystem {
		t.Errorf("expected %s, got %s", NTPSubsystem, c.Name())
	}
}
