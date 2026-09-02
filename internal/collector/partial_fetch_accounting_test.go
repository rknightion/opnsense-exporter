package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// TestPartialFetchFailuresCountsSwallowedSubFetch proves the observability gap
// tracked by OPN-0009. FetchChronyStatus deliberately keeps valid tracking data
// when its independent sources request fails, so Update returns nil and the
// scheduler must retain scrape success. The failure still needs a collector-level
// counter for alerting without enumerating the endpoint path.
func TestPartialFetchFailuresCountsSwallowedSubFetch(t *testing.T) {
	cases := []struct {
		name         string
		writeSources func(http.ResponseWriter)
	}{
		{name: "HTTP failure", writeSources: func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }},
		{name: "decode failure behind HTTP 200", writeSources: func(w http.ResponseWriter) { _, _ = w.Write([]byte(`not JSON`)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/chrony/service/chronytracking":
					_, _ = w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestTrackingFixture) + `"}`))
				case "/api/chrony/service/chronysources":
					tc.writeSources(w)
				case "/api/chrony/service/chronysourcestats":
					_, _ = w.Write([]byte(`{"response":"` + escapeCollectorJSON(chronyTestSourceStatsFixture) + `"}`))
				case "/api/chrony/service/status":
					_, _ = w.Write([]byte(`{"status":"running"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			client := newCollectorTestClient(t, server)
			c, chrony := newPartialFetchTestCollector(t, client)
			c.pollOnce(context.Background(), chrony)

			if got := counterValue(t, c.endpointErrors.WithLabelValues("api/chrony/service/chronysources", "test")); got != 0 {
				t.Fatalf("endpoint_errors_total = %v, want 0: the nested fetch is deliberately tolerated", got)
			}
			if got := collectMetricValue(t, c, "opnsense_exporter_scrape_collector_success", "chrony"); got != 1 {
				t.Fatalf("scrape_collector_success{collector=chrony} = %v, want 1", got)
			}
			if got := collectMetricValue(t, c, "opnsense_exporter_partial_fetch_failures_total", "chrony"); got != 1 {
				t.Fatalf("partial_fetch_failures_total{collector=chrony} = %v, want 1", got)
			}
		})
	}
}

func TestPartialFetchFailuresExcludesCachedPluginAbsence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chrony/service/chronytracking" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	client.SetEndpointAbsentTTL("chronyTracking", time.Hour)
	c, chrony := newPartialFetchTestCollector(t, client)
	c.pollOnce(context.Background(), chrony)
	c.pollOnce(context.Background(), chrony)

	if got := collectMetricValue(t, c, "opnsense_exporter_partial_fetch_failures_total", "chrony"); got != 0 {
		t.Fatalf("partial_fetch_failures_total{collector=chrony} = %v, want 0 for plugin absence", got)
	}
}

func TestEndpointErrorsHelpNamesOnlyTopLevelAndPanicSites(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	c, _ := newPartialFetchTestCollector(t, client)

	const want = "Total number of top-level sub-collector Update errors and recovered sub-collector panics. The endpoint label is normally an api/* path for a returned Update error, or 'panic:<collector>' for a recovered panic; tolerated secondary fetch failures are excluded and counted by opnsense_exporter_partial_fetch_failures_total."
	if got := c.endpointErrors.WithLabelValues("api/example", "test").Desc().String(); !strings.Contains(got, want) {
		t.Fatalf("endpoint_errors_total help = %s, want it to contain %q", got, want)
	}
}

func newPartialFetchTestCollector(t *testing.T, client *opnsense.Client) (*Collector, *chronyCollector) {
	t.Helper()
	c, err := New(client, promslog.NewNopLogger(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, instance := range c.collectors {
		if chrony, ok := instance.(*chronyCollector); ok {
			return c, chrony
		}
	}
	t.Fatal("chrony collector was not registered")
	return nil, nil
}

func collectMetricValue(t *testing.T, c *Collector, fqName, collector string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 4096)
	done := make(chan struct{})
	var matches []prometheus.Metric
	go func() {
		defer close(done)
		for metric := range ch {
			if hasFqName(metric, fqName) && getMetricLabels(metric)["collector"] == collector {
				matches = append(matches, metric)
			}
		}
	}()
	c.collect(context.Background(), ch, nil)
	close(ch)
	<-done

	if len(matches) != 1 {
		t.Fatalf("%s{collector=%q}: got %d series, want 1", fqName, collector, len(matches))
	}
	return getMetricValue(matches[0])
}
