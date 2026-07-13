package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// ntpGPSMux serves api/ntpd/service/status (empty peers, uninteresting here)
// and api/ntpd/service/gps (the fixture under test) on distinct paths, since
// both are now fetched by the same collector Update call (#224).
func ntpGPSMux(t *testing.T, gpsBody string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ntpd/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": []}`))
	})
	mux.HandleFunc("/api/ntpd/service/gps", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(gpsBody))
	})
	return mux
}

// TestNTPCollector_GPS_NoRefclock guards the no-GPS-hardware default: the gps
// key is served as an empty array, and no gps_ok/gps_satellites series must
// ever appear (absent hardware => absent series, never a fake 0, #224).
func TestNTPCollector_GPS_NoRefclock(t *testing.T) {
	server := httptest.NewServer(ntpGPSMux(t, `{"ntpq_servers":[],"gps":[]}`))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ntpCollector{subsystem: NTPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "ntp_gps_") {
			t.Errorf("expected no gps_* series when no GPS refclock, got %s", desc)
		}
	}
}

// TestNTPCollector_GPS_Fix covers a populated GPS fix: both gps_ok and
// gps_satellites must be emitted with the right values.
func TestNTPCollector_GPS_Fix(t *testing.T) {
	server := httptest.NewServer(ntpGPSMux(t, `{"ntpq_servers":[],"gps":{"sentence":"$GPGGA","ok":"1","sat":"07"}}`))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ntpCollector{subsystem: NTPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var foundOK, foundSat bool
	for _, m := range metrics {
		desc := m.Desc().String()
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "ntp_gps_ok"):
			foundOK = true
			if val != 1 {
				t.Errorf("expected gps_ok=1, got %v", val)
			}
		case strings.Contains(desc, "ntp_gps_satellites"):
			foundSat = true
			if val != 7 {
				t.Errorf("expected gps_satellites=7, got %v", val)
			}
		}
	}
	if !foundOK {
		t.Error("missing ntp_gps_ok metric")
	}
	if !foundSat {
		t.Error("missing ntp_gps_satellites metric")
	}
}

// TestNTPCollector_GPS_NoSatelliteCount covers a fix whose sentence never
// carries a satellite count ($GPRMC/$GPGLL): gps_ok must still be emitted,
// but gps_satellites must be omitted rather than reported as a fake 0.
func TestNTPCollector_GPS_NoSatelliteCount(t *testing.T) {
	server := httptest.NewServer(ntpGPSMux(t, `{"ntpq_servers":[],"gps":{"sentence":"$GPRMC","ok":true}}`))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &ntpCollector{subsystem: NTPSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	var foundOK, foundSat bool
	for _, m := range metrics {
		desc := m.Desc().String()
		switch {
		case strings.Contains(desc, "ntp_gps_ok"):
			foundOK = true
		case strings.Contains(desc, "ntp_gps_satellites"):
			foundSat = true
		}
	}
	if !foundOK {
		t.Error("missing ntp_gps_ok metric")
	}
	if foundSat {
		t.Error("expected no gps_satellites metric when the sentence never carries 'sat'")
	}
}
