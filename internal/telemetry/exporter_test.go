package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// TestMetricsEndpointURL pins the path-join semantics that keep OTLP HTTP
// exports pointed at the /v1/metrics signal path (#80).
func TestMetricsEndpointURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"grafana cloud base url gets signal path appended",
			"https://otlp-gateway-prod-eu-west-2.grafana.net/otlp",
			"https://otlp-gateway-prod-eu-west-2.grafana.net/otlp/v1/metrics"},
		{"base url with trailing slash",
			"https://otlp-gateway-prod-eu-west-2.grafana.net/otlp/",
			"https://otlp-gateway-prod-eu-west-2.grafana.net/otlp/v1/metrics"},
		{"already a full signal url is left untouched (no double suffix)",
			"https://collector.example.com/otlp/v1/metrics",
			"https://collector.example.com/otlp/v1/metrics"},
		{"already a signal url with trailing slash",
			"https://collector.example.com/otlp/v1/metrics/",
			"https://collector.example.com/otlp/v1/metrics/"},
		{"no path is left for the SDK default",
			"https://collector.example.com",
			"https://collector.example.com"},
		{"root path is left for the SDK default",
			"https://collector.example.com/",
			"https://collector.example.com/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := metricsEndpointURL(tc.in)
			if err != nil {
				t.Fatalf("metricsEndpointURL(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("metricsEndpointURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHTTPExporterPostsToSignalPath is the end-to-end guard: a base-URL endpoint
// (the documented Grafana Cloud shortcut) must actually POST to /otlp/v1/metrics,
// not /otlp.
func TestHTTPExporterPostsToSignalPath(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		// A 200 with an empty body unmarshals to an empty
		// ExportMetricsServiceResponse, so Export succeeds.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cases := []struct {
		name     string
		endpoint string
		wantPath string
	}{
		{"base url", srv.URL + "/otlp", "/otlp/v1/metrics"},
		{"full signal url not doubled", srv.URL + "/otlp/v1/metrics", "/otlp/v1/metrics"},
		{"no path defaults to signal path", srv.URL, "/v1/metrics"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			paths = nil
			mu.Unlock()

			cfg := &options.OTLPConfig{Protocol: "http/protobuf", Endpoint: tc.endpoint, Insecure: true}
			exp, err := newExporter(context.Background(), cfg)
			if err != nil {
				t.Fatalf("newExporter: %v", err)
			}
			t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

			rm := &metricdata.ResourceMetrics{
				Resource: resource.Empty(),
				ScopeMetrics: []metricdata.ScopeMetrics{{
					Metrics: []metricdata.Metrics{{
						Name: "opnsense_test_gauge",
						Data: metricdata.Gauge[int64]{
							DataPoints: []metricdata.DataPoint[int64]{{Value: 1}},
						},
					}},
				}},
			}
			if err := exp.Export(context.Background(), rm); err != nil {
				t.Fatalf("Export: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(paths) == 0 {
				t.Fatal("exporter made no request to the test server")
			}
			for _, p := range paths {
				if p != tc.wantPath {
					t.Fatalf("export POSTed to %q, want %q", p, tc.wantPath)
				}
			}
		})
	}
}
