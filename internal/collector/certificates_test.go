package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestCertificatesCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 certificateTotal + 2 certs * 3 metrics each (validFrom, validTo, info) = 1 + 6 = 7
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestCertificatesCollector_Update_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"total": 0,
			"rows": []
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only 1 certificateTotal with value 0
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	if getMetricValue(metrics[0]) != 0 {
		t.Errorf("expected certificateTotal=0, got %f", getMetricValue(metrics[0]))
	}
}

func TestCertificatesCollector_Name(t *testing.T) {
	c := &certificatesCollector{subsystem: CertificatesSubsystem}
	if c.Name() != CertificatesSubsystem {
		t.Errorf("expected %s, got %s", CertificatesSubsystem, c.Name())
	}
}
