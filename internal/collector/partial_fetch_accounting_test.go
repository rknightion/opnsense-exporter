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
	"github.com/rknightion/opnsense2otel/v5/opnsense"
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

func TestPartialFetchFailuresCountsToleratedZeroTierInfo404(t *testing.T) {
	server, mux, client := newZeroTierCollectorTestClient(t)
	defer server.Close()
	client.Endpoints()["zerotierNetworks"] = "api/zerotier/network/search"
	client.Endpoints()["zerotierNetworkInfo"] = "api/zerotier/network/info"

	// This is the first row from the source-derived ZeroTier search fixture in
	// opnsense/zerotier_test.go. The info route deliberately returns the stale
	// UUID failure that the client tolerates while retaining the search result.
	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"total":1,
			"rowCount":1,
			"current":1,
			"rows":[{"uuid":"network-uuid-1","enabled":"1","networkId":"8056c2e21c000001","description":"primary mesh"}]
		}`))
	})
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("info method = %s, want GET", r.Method)
		}
		http.NotFound(w, r)
	})

	c, err := New(client, promslog.NewNopLogger(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var zeroTier *zeroTierCollector
	for _, instance := range c.collectors {
		if candidate, ok := instance.(*zeroTierCollector); ok {
			zeroTier = candidate
			break
		}
	}
	if zeroTier == nil {
		t.Fatal("zeroTier collector was not registered")
	}

	c.pollOnce(context.Background(), zeroTier)

	if got := collectMetricValue(t, c, "opnsense_exporter_scrape_collector_success", "zerotier"); got != 1 {
		t.Fatalf("scrape_collector_success{collector=zerotier} = %v, want 1", got)
	}
	if got := collectMetricValue(t, c, "opnsense_exporter_partial_fetch_failures_total", "zerotier"); got != 1 {
		t.Fatalf("partial_fetch_failures_total{collector=zerotier} = %v, want 1", got)
	}

	// The dynamic UUID route is used for the request but must be collapsed to
	// the registered endpoint in request metrics, keeping endpoint labels bounded.
	observed := make(map[string]string)
	requests := make(chan prometheus.Metric, 8)
	c.apiRequests.Collect(requests)
	close(requests)
	for metric := range requests {
		labels := getMetricLabels(metric)
		observed[labels["endpoint"]] = labels["code"]
	}
	if got := observed["api/zerotier/network/search"]; got != "200" {
		t.Errorf("search request endpoint/code = %q, want 200", got)
	}
	if got := observed["api/zerotier/network/info"]; got != "404" {
		t.Errorf("info request endpoint/code = %q, want static endpoint with 404", got)
	}
	if _, ok := observed["api/zerotier/network/info/network-uuid-1"]; ok {
		t.Errorf("dynamic ZeroTier info endpoint leaked into request metrics: %v", observed)
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
