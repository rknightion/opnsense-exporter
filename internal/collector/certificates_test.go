package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestCertificatesCollector_Update(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trust/cert/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 2,
			"rows": [
				{
					"uuid": "cert-uuid-1",
					"descr": "Web GUI Certificate",
					"commonname": "OPNsense",
					"valid_from": "1700000000",
					"valid_to": "1731536000",
					"in_use": "Web GUI",
					"%cert_type": "Server"
				},
				{
					"uuid": "cert-uuid-2",
					"descr": "VPN CA Certificate",
					"commonname": "VPN-CA",
					"valid_from": "1690000000",
					"valid_to": "1753000000",
					"in_use": "",
					"%cert_type": "CA"
				}
			]
		}`))
	})
	mux.HandleFunc("/api/trust/ca/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 certificateTotal + 2 certs * 3 metrics each (validFrom, validTo, info) + 1 caTotal = 8
	expectedCount := 8
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestCertificatesCollector_Update_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trust/cert/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rows": []
		}`))
	})
	mux.HandleFunc("/api/trust/ca/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 certificateTotal (value 0) + 1 caTotal (value 0) = 2
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Use name-matched lookup instead of positional — channel order not guaranteed.
	var certTotal, caTotal *float64
	for _, m := range metrics {
		v := getMetricValue(m)
		switch {
		case hasFqName(m, "opnsense_certificate_ca"):
			caTotal = &v
		case hasFqName(m, "opnsense_certificate_certificates"):
			certTotal = &v
		}
	}
	if certTotal == nil {
		t.Error("expected certificate_total metric to be emitted")
	} else if *certTotal != 0 {
		t.Errorf("expected certificate_total=0, got %f", *certTotal)
	}
	if caTotal == nil {
		t.Error("expected certificate_ca metric to be emitted")
	} else if *caTotal != 0 {
		t.Errorf("expected certificate_ca=0, got %f", *caTotal)
	}
}

// TestCertificatesCollector_Update_PendingCSR guards #167: a pending-CSR row
// (empty valid_from/valid_to) must not emit valid_from_timestamp_seconds/valid_to_timestamp_seconds
// (which would read as epoch 0 = expired 1970), while info is still emitted.
func TestCertificatesCollector_Update_PendingCSR(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trust/cert/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":1,"rows":[
			{"uuid":"csr-1","descr":"Pending CSR","commonname":"new.example.com","valid_from":"","valid_to":"","in_use":"","%cert_type":"server"}
		]}`))
	})
	mux.HandleFunc("/api/trust/ca/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	sawInfo := false
	for _, m := range metrics {
		desc := m.Desc().String()
		if hasFqName(m, "opnsense_certificate_valid_from_timestamp_seconds") || hasFqName(m, "opnsense_certificate_valid_to_timestamp_seconds") {
			t.Errorf("pending-CSR row must not emit an expiry metric: %s", desc)
		}
		if strings.Contains(desc, "certificate_info") {
			sawInfo = true
		}
	}
	if !sawInfo {
		t.Error("expected the info metric to still be emitted for a pending-CSR row")
	}
}

func TestCertificatesCollector_Name(t *testing.T) {
	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	if c.Name() != CertificatesSubsystem {
		t.Errorf("expected %s, got %s", CertificatesSubsystem, c.Name())
	}
}

func TestCertificatesCollector_CAMetrics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trust/cert/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rows":[]}`))
	})
	mux.HandleFunc("/api/trust/ca/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"uuid":"u1","descr":"OPNsense-CA","commonname":"OPNsense-CA","valid_from":"1643140565","valid_to":"1958500565","prv":"x"}],"rowCount":1,"total":1,"current":1}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	var sawCATotal, sawCAValidTo bool
	for _, m := range metrics {
		if hasFqName(m, "opnsense_certificate_ca") {
			sawCATotal = true
			if getMetricValue(m) != 1 {
				t.Errorf("expected ca=1, got %v", getMetricValue(m))
			}
		}
		if hasFqName(m, "opnsense_certificate_ca_valid_to_timestamp_seconds") {
			sawCAValidTo = true
			labels := getMetricLabels(m)
			if labels["commonname"] != "OPNsense-CA" || getMetricValue(m) != 1958500565 {
				t.Errorf("bad ca_valid_to: value=%v labels=%v", getMetricValue(m), labels)
			}
		}
	}
	if !sawCATotal || !sawCAValidTo {
		t.Errorf("missing CA metrics: total=%v valid_to=%v", sawCATotal, sawCAValidTo)
	}
}

// TestCertificatesCollector_CAReferences covers #583: refcount separates a CA
// about to expire that 50 things depend on (an outage) from one nothing uses
// (dead config). The validity gauges alone cannot tell those apart.
func TestCertificatesCollector_CAReferences(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/trust/cert/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"rows":[]}`))
	})
	mux.HandleFunc("/api/trust/ca/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[
			{"descr":"busy","commonname":"busy-cn","refcount":"50","valid_from":"1","valid_to":"2"},
			{"descr":"dead","commonname":"dead-cn","refcount":"0","valid_from":"1","valid_to":"2"},
			{"descr":"legacy","commonname":"legacy-cn","valid_from":"1","valid_to":"2"}
		]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, newCollectorTestClient(t, server))
	assertNoDuplicateSeries(t, metrics)

	got := map[string]float64{}
	for _, m := range metrics {
		if hasFqName(m, "opnsense_certificate_ca_references") {
			got[getMetricLabels(m)["description"]] = getMetricValue(m)
		}
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 ca_references series, got %d: %v", len(got), got)
	}
	if got["busy"] != 50 {
		t.Errorf("busy: got %v, want 50", got["busy"])
	}
	// A real refcount of 0 IS emitted — "nothing references this CA" is the
	// dead-config signal the metric exists for.
	if v, ok := got["dead"]; !ok || v != 0 {
		t.Errorf("dead: got %v (present=%v), want 0/true", v, ok)
	}
	// A row with no refcount key at all emits nothing, so an old generation
	// that never sent the field cannot masquerade as dead config.
	if _, ok := got["legacy"]; ok {
		t.Error("a CA row without a refcount key must emit no ca_references series")
	}
}
