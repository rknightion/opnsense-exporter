package telemetry

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

func TestMetricsTLSConfigUsesSignalEnvironment(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", "")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE", "/definitely/missing/metrics-ca.pem")
	_, err := buildTLSConfig(&options.OTLPConfig{})
	if err == nil || !strings.Contains(err.Error(), "metrics-ca.pem") {
		t.Fatalf("buildTLSConfig error = %v, want signal certificate path", err)
	}
}

func TestMetricsTLSConfigRejectsHalfClientPairFromEnvironment(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", "")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", "")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE", "/tmp/client.pem")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_CLIENT_KEY", "")
	_, err := buildTLSConfig(&options.OTLPConfig{})
	if err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("buildTLSConfig error = %v, want pair validation", err)
	}
}

func TestMetricsExporterRejectsInsecureWithTLS(t *testing.T) {
	cfg := &options.OTLPConfig{Insecure: true}
	if err := validateMetricsTransport(cfg, &tls.Config{}); err == nil {
		t.Fatal("transport validation accepted insecure mode with TLS material")
	}
}

func TestMetricsExporterRejectsHTTPEndpointWithTLS(t *testing.T) {
	cfg := &options.OTLPConfig{Endpoint: "http://collector.invalid"}
	if err := validateMetricsTransport(cfg, &tls.Config{}); err == nil {
		t.Fatal("transport validation accepted an HTTP endpoint with TLS material")
	}
}

func TestMetricsHTTPClientDoesNotFollowRedirects(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", "1234")
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := newMetricsHTTPClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.Timeout != 1234*time.Millisecond {
		t.Fatalf("timeout = %v, want configured 1234ms", client.Timeout)
	}
	resp, err := client.Post(source.URL, "application/x-protobuf", strings.NewReader("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || targetHits.Load() != 0 {
		t.Fatalf("status=%d target hits=%d", resp.StatusCode, targetHits.Load())
	}
}
