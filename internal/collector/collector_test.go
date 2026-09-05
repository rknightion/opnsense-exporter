package collector

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

func TestCollector(t *testing.T) {
	conf := options.OPNSenseConfig{
		Protocol: "http",
		APIKey:   "test",
	}

	client, err := opnsense.NewClient(
		conf,
		"test",
		promslog.NewNopLogger(),
	)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	collectOpts := []Option{
		WithoutArpTableCollector(),
		WithoutCronCollector(),
		WithoutUnboundCollector(),
		WithoutWireguardCollector(),
		WithoutFirewallCollector(),
		WithoutFirewallRulesCollector(),
		WithoutDnsmasqCollector(),
		WithoutSystemCollector(),
		WithoutIPsecCollector(),
		WithoutOpenVPNCollector(),
		WithoutFirmwareCollector(),
		WithoutTemperatureCollector(),
		WithoutMbufCollector(),
		WithoutNTPCollector(),
		WithoutCertificatesCollector(),
		WithoutNetworkDiagnosticsCollector(),
	}

	collector, err := New(&client, promslog.NewNopLogger(), "test", collectOpts...)
	if err != nil {
		t.Errorf("expected no error when creating collector, got %v", err)
	}

	for _, c := range collector.collectors {
		switch c.Name() {
		case "arp_table":
			t.Errorf("expected arp_table collector to be removed")
		case "cron":
			t.Errorf("expected cron collector to be removed")
		case "unbound_dns":
			t.Errorf("expected unbound_dns collector to be removed")
		case "wireguard":
			t.Errorf("expected wireguard collector to be removed")
		case "firewall":
			t.Errorf("expected firewall collector to be removed")
		case "firewall_rule":
			t.Errorf("expected firewall_rule collector to be removed")
		case "dnsmasq":
			t.Errorf("expected dnsmasq collector to be removed")
		case "system":
			t.Errorf("expected system collector to be removed")
		case "ipsec":
			t.Errorf("expected ipsec collector to be removed")
		case "openvpn":
			t.Errorf("expected openvpn collector to be removed")
		case "firmware":
			t.Errorf("expected firmware collector to be removed")
		case "temperature":
			t.Errorf("expected temperature collector to be removed")
		case "mbuf":
			t.Errorf("expected mbuf collector to be removed")
		case "ntp":
			t.Errorf("expected ntp collector to be removed")
		case "certificate":
			t.Errorf("expected certificate collector to be removed")
		case "network_diag":
			t.Errorf("expected network_diag collector to be removed")
		}
	}
}

func TestWithFirewallRulesDetails(t *testing.T) {
	// Test the option function directly without calling New() to avoid
	// duplicate metrics registration on the global prometheus registry.
	frc := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	c := &Collector{
		collectors: []CollectorInstance{frc},
	}

	if frc.detailsEnabled {
		t.Fatal("expected detailsEnabled to start as false")
	}

	opt := WithFirewallRulesDetails()
	if err := opt(c); err != nil {
		t.Fatalf("expected no error applying option, got %v", err)
	}

	if !frc.detailsEnabled {
		t.Errorf("expected firewallRulesCollector.detailsEnabled to be true after applying option")
	}
}

func TestFirewallIsHealthy(t *testing.T) {
	mk := func(meta any) opnsense.HealthCheckResponse {
		var r opnsense.HealthCheckResponse
		r.Metadata.Firewall.Status = meta
		return r
	}

	cases := []struct {
		name string
		resp opnsense.HealthCheckResponse
		want bool
	}{
		// OPNsense 25.1+ healthy box: no Firewall entry at all (the original bug).
		{"new format healthy (absent)", mk(nil), true},
		// Metadata status arrives as a JSON number via encoding/json -> float64.
		{"metadata numeric OK", mk(float64(opnsense.HealthCheckStatusOK_v25_1)), true},
		{"metadata numeric not OK", mk(float64(1)), false},
		{"metadata string OK", mk("OK"), true},
		{"metadata string empty", mk(""), true},
		{"metadata string error", mk("Error"), false},
		{"metadata string ERROR", mk("ERROR"), false},
		// OPNsense 25.1+ can also report the numeric status as a string ("2").
		{"metadata numeric string OK", mk("2"), true},
		{"metadata numeric string not OK", mk("1"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firewallIsHealthy(tc.resp); got != tc.want {
				t.Errorf("firewallIsHealthy(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestWithBuildInfo(t *testing.T) {
	c := &Collector{}
	if err := WithBuildInfo("1.2.3")(c); err != nil {
		t.Fatalf("expected no error applying option, got %v", err)
	}
	if c.version != "1.2.3" {
		t.Errorf("expected version 1.2.3, got %q", c.version)
	}
}

func TestDeriveCollectorStates(t *testing.T) {
	// Use real collector structs so Name() resolves from their subsystem field,
	// without calling New() (which registers metrics on the global registry).
	frc := &firewallRulesCollector{subsystem: FirewallRulesSubsystem}
	dc := &dnsmasqCollector{subsystem: DnsmasqSubsystem}

	all := []CollectorInstance{frc, dc}
	enabled := []CollectorInstance{frc} // dnsmasq removed (disabled)

	states := deriveCollectorStates(all, enabled)

	if len(states) != 2 {
		t.Fatalf("expected 2 states, got %d", len(states))
	}
	if !states[FirewallRulesSubsystem] {
		t.Errorf("expected %s to be enabled", FirewallRulesSubsystem)
	}
	if states[DnsmasqSubsystem] {
		t.Errorf("expected %s to be disabled", DnsmasqSubsystem)
	}
}

func TestCollectExporterInfo(t *testing.T) {
	c := &Collector{
		instanceLabel:   "test-instance",
		version:         "9.9.9",
		collectorStates: map[string]bool{"firewall": true, "netflow": false},
		buildInfo: prometheus.NewDesc(
			"opnsense_exporter_build_info", "help",
			[]string{"version", "goversion", instanceLabelName}, nil,
		),
		collectorEnabled: prometheus.NewDesc(
			"opnsense_exporter_collector_enabled", "help",
			[]string{"collector", instanceLabelName}, nil,
		),
	}

	ch := make(chan prometheus.Metric, 16)
	c.collectExporterInfo(ch)
	close(ch)

	var buildInfoSeen bool
	states := map[string]float64{}
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("failed to write metric: %v", err)
		}
		desc := m.Desc().String()
		switch {
		case strings.Contains(desc, "opnsense_exporter_build_info"):
			buildInfoSeen = true
			if got := d.GetGauge().GetValue(); got != 1 {
				t.Errorf("build_info value = %v, want 1", got)
			}
			labels := map[string]string{}
			for _, l := range d.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["version"] != "9.9.9" {
				t.Errorf("build_info version = %q, want 9.9.9", labels["version"])
			}
			if labels["goversion"] == "" {
				t.Error("build_info goversion label is empty")
			}
			if labels[instanceLabelName] != "test-instance" {
				t.Errorf("build_info %s = %q, want test-instance", instanceLabelName, labels[instanceLabelName])
			}
		case strings.Contains(desc, "opnsense_exporter_collector_enabled"):
			var collector string
			for _, l := range d.GetLabel() {
				if l.GetName() == "collector" {
					collector = l.GetValue()
				}
			}
			states[collector] = d.GetGauge().GetValue()
		}
	}

	if !buildInfoSeen {
		t.Error("expected build_info metric to be emitted")
	}
	if states["firewall"] != 1 {
		t.Errorf("collector_enabled{collector=firewall} = %v, want 1", states["firewall"])
	}
	if states["netflow"] != 0 {
		t.Errorf("collector_enabled{collector=netflow} = %v, want 0", states["netflow"])
	}
}

func TestWithoutGatewaysCollector(t *testing.T) {
	// Test the option function directly without calling New() to avoid
	// duplicate metrics registration on the global prometheus registry.
	gc := &gatewaysCollector{subsystem: GatewaysSubsystem}
	c := &Collector{
		collectors: []CollectorInstance{gc},
	}

	opt := WithoutGatewaysCollector()
	if err := opt(c); err != nil {
		t.Fatalf("expected no error applying option, got %v", err)
	}

	for _, instance := range c.collectors {
		if instance.Name() == GatewaysSubsystem {
			t.Errorf("expected gateways collector to be removed")
		}
	}
}

func TestWithOpenVPNDetails(t *testing.T) {
	// Test the option function directly without calling New() to avoid
	// duplicate metrics registration on the global prometheus registry.
	oc := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c := &Collector{
		collectors: []CollectorInstance{oc},
	}

	if oc.detailsEnabled {
		t.Fatal("expected detailsEnabled to start as false")
	}

	opt := WithOpenVPNDetails()
	if err := opt(c); err != nil {
		t.Fatalf("expected no error applying option, got %v", err)
	}

	if !oc.detailsEnabled {
		t.Errorf("expected openVPNCollector.detailsEnabled to be true after applying option")
	}
}

func TestWithDnsmasqDetails(t *testing.T) {
	// Test the option function directly without calling New() to avoid
	// duplicate metrics registration on the global prometheus registry.
	dc := &dnsmasqCollector{subsystem: DnsmasqSubsystem}
	c := &Collector{
		collectors: []CollectorInstance{dc},
	}

	if dc.detailsEnabled {
		t.Fatal("expected detailsEnabled to start as false")
	}

	opt := WithDnsmasqDetails()
	if err := opt(c); err != nil {
		t.Fatalf("expected no error applying option, got %v", err)
	}

	if !dc.detailsEnabled {
		t.Errorf("expected dnsmasqCollector.detailsEnabled to be true after applying option")
	}
}

func TestSubsystemDisplayNamesComplete(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range AllCollectors() {
		registered[c.Name()] = true
		if _, ok := SubsystemDisplayNames[c.Name()]; !ok {
			t.Errorf("collector %q has no SubsystemDisplayNames entry", c.Name())
		}
	}
	if len(registered) == 0 {
		t.Fatal("no collectors registered")
	}
	for subsystem := range SubsystemDisplayNames {
		if !registered[subsystem] {
			t.Errorf("SubsystemDisplayNames entry %q matches no registered collector", subsystem)
		}
	}
}

// fakeCollectorInstance is a controllable CollectorInstance for fan-out tests.
type fakeCollectorInstance struct {
	name       string
	err        *opnsense.APICallError
	panics     bool
	blockOnCtx bool                // if set, Update blocks until the context is done (models a stalled API call)
	delay      time.Duration       // if set, Update sleeps this long (models a slow but completing API call)
	emit       []prometheus.Metric // metrics Update sends, so a poll can capture them into the snapshot
	mu         sync.Mutex          // guards calls/gotCtx (Update runs in a poll goroutine under StartPolling)
	calls      int
	gotCtx     context.Context
}

func (f *fakeCollectorInstance) Register(_, _ string, _ *slog.Logger) {}
func (f *fakeCollectorInstance) Name() string                         { return f.name }
func (f *fakeCollectorInstance) Describe(_ chan<- *prometheus.Desc)   {}
func (f *fakeCollectorInstance) Update(ctx context.Context, _ *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	f.mu.Lock()
	f.calls++
	f.gotCtx = ctx
	f.mu.Unlock()
	if f.panics {
		panic("boom")
	}
	if f.blockOnCtx {
		<-ctx.Done()
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
		}
	}
	for _, m := range f.emit {
		ch <- m
	}
	return f.err
}

// callCount returns the number of Update calls, safe under concurrent polling.
func (f *fakeCollectorInstance) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// contextValue returns the value the last Update saw for key, safe under polling.
func (f *fakeCollectorInstance) contextValue(key any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gotCtx == nil {
		return nil
	}
	return f.gotCtx.Value(key)
}

// newScrapeTestCollector builds a Collector via struct literal (NOT New(), which
// registers on the global prometheus registry) with every field the collect
// path touches initialized. The gauges/countervecs use _test-suffixed names and
// are never registered, so there are no registry collisions.
func newScrapeTestCollector(t *testing.T, client *opnsense.Client, instances ...CollectorInstance) *Collector {
	t.Helper()
	c := &Collector{
		Client:          client,
		log:             promslog.NewNopLogger(),
		instanceLabel:   "test",
		collectors:      instances,
		collectorStates: map[string]bool{},
		store:           newSnapshotStore(),
	}
	c.buildInfo = prometheus.NewDesc(
		"opnsense_exporter_build_info", "help",
		[]string{"version", "goversion", instanceLabelName}, nil,
	)
	c.collectorEnabled = prometheus.NewDesc(
		"opnsense_exporter_collector_enabled", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.scrapeDuration = prometheus.NewDesc(
		"opnsense_exporter_scrape_collector_duration_seconds", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.scrapeSuccess = prometheus.NewDesc(
		"opnsense_exporter_scrape_collector_success", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.pollInterval = prometheus.NewDesc(
		"opnsense_exporter_collector_poll_interval_seconds", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.lastPollTs = prometheus.NewDesc(
		"opnsense_exporter_collector_last_poll_timestamp_seconds", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.nextPollTs = prometheus.NewDesc(
		"opnsense_exporter_collector_next_poll_timestamp_seconds", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.snapshotTs = prometheus.NewDesc(
		"opnsense_exporter_collector_snapshot_timestamp_seconds", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.lastSuccessTs = prometheus.NewDesc(
		"opnsense_exporter_collector_last_success_timestamp_seconds", "help",
		[]string{"collector", instanceLabelName}, nil,
	)
	c.apiCacheFetchedTs = prometheus.NewDesc(
		"opnsense_exporter_api_cache_fetched_timestamp_seconds", "help",
		[]string{"endpoint", instanceLabelName}, nil,
	)
	c.isUp = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_up_test", Help: "h"})
	c.firewallHealthStatus = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_firewall_status_test", Help: "h"})
	c.crashReporterStatus = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_crash_reporter_status_test", Help: "h"})
	c.systemStatusCode = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_system_status_code_test", Help: "h"})
	c.subsystemStatusCode = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "opnsense_system_subsystem_status_code_test", Help: "h"}, []string{"subsystem"})
	c.scrapes = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_scrapes_total_test", Help: "h"},
		[]string{"opnsense_instance"},
	)
	c.endpointErrors = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_endpoint_errors_total_test", Help: "h"},
		[]string{"endpoint", "opnsense_instance"},
	)
	c.apiRequests = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_api_requests_total_test", Help: "h"},
		[]string{"endpoint", "code", "opnsense_instance"},
	)
	c.apiRequestDuration = *prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "opnsense_exporter_api_request_duration_seconds_test", Help: "h"},
		[]string{"endpoint", "opnsense_instance"},
	)
	c.apiCacheHits = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_api_cache_hits_total_test", Help: "h"},
		[]string{"endpoint", "kind", "opnsense_instance"},
	)
	c.apiCacheMisses = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_api_cache_misses_total_test", Help: "h"},
		[]string{"endpoint", "opnsense_instance"},
	)
	return c
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	d := &dto.Metric{}
	if err := counter.Write(d); err != nil {
		t.Fatalf("failed to read counter: %v", err)
	}
	return d.GetCounter().GetValue()
}

// healthOKServer serves a minimal OK health-check payload for any path, so
// pollHealth succeeds fast and deterministically.
func healthOKServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"system":{"status":"OK"}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestEnabledCollectorNames(t *testing.T) {
	c := &Collector{collectors: []CollectorInstance{
		&fakeCollectorInstance{name: "zeta"},
		&fakeCollectorInstance{name: "alpha"},
	}}
	got := c.EnabledCollectorNames()
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Errorf("EnabledCollectorNames() = %v, want [alpha zeta] (sorted)", got)
	}
}

// TestCollectReplaysSnapshot verifies collect() emits the metrics captured by the
// last poll plus the per-collector scrape meta and the health gauges — and makes no
// API call itself (the poll did).
func TestCollectReplaysSnapshot(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_fake_series", 42)}}
	c := newScrapeTestCollector(t, client, fake)
	c.pollHealth(context.Background()) // seed health so up=1 and the gauges are present
	c.pollOnce(context.Background(), fake)
	// Since #385 the next-poll deadline is scheduler state, not arithmetic on the
	// last poll, so a direct pollOnce leaves it unset. Seed it as StartPolling would.
	c.store.setDeadline("fake", time.Now().Add(IntervalMedium))

	ch := make(chan prometheus.Metric, 64)
	c.collect(context.Background(), ch, nil)
	close(ch)

	var sawSeries, sawDuration, sawSuccess, sawUp, sawInterval, sawLast, sawNext bool
	for m := range ch {
		desc := m.Desc().String()
		switch {
		case strings.Contains(desc, "opnsense_fake_series"):
			sawSeries = true
		case strings.Contains(desc, "collector_poll_interval_seconds"):
			sawInterval = true
		case strings.Contains(desc, "collector_last_poll_timestamp_seconds"):
			sawLast = true
		case strings.Contains(desc, "collector_next_poll_timestamp_seconds"):
			sawNext = true
		case strings.Contains(desc, "scrape_collector_duration_seconds"):
			sawDuration = true
		case strings.Contains(desc, "scrape_collector_success"):
			sawSuccess = true
		case strings.Contains(desc, "opnsense_up_test"):
			sawUp = true
		}
	}
	if !sawSeries {
		t.Error("collect must replay the polled metric")
	}
	if !sawDuration || !sawSuccess {
		t.Error("collect must emit per-collector scrape meta for a polled collector")
	}
	if !sawInterval || !sawLast || !sawNext {
		t.Errorf("collect must emit poll observability metrics (interval=%v last=%v next=%v)", sawInterval, sawLast, sawNext)
	}
	if !sawUp {
		t.Error("collect must emit the health gauges")
	}
	if fake.callCount() != 1 {
		t.Errorf("collect must NOT call Update (the poll did); calls=%d, want 1", fake.callCount())
	}
	if got := counterValue(t, c.scrapes.WithLabelValues("test")); got != 1 {
		t.Errorf("scrapes_total = %v, want 1", got)
	}
}

// TestCollectNeverPolledEmitsNoCollectorMeta verifies a collector that has never
// polled yields no per-collector scrape meta (cold start), while the always-on
// exporter metrics are still emitted.
func TestCollectNeverPolledEmitsNoCollectorMeta(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake"}
	c := newScrapeTestCollector(t, client, fake)

	ch := make(chan prometheus.Metric, 64)
	c.collect(context.Background(), ch, nil)
	close(ch)

	var sawScrapeMeta, sawScrapes bool
	for m := range ch {
		desc := m.Desc().String()
		if strings.Contains(desc, "scrape_collector_") {
			sawScrapeMeta = true
		}
		if strings.Contains(desc, "opnsense_exporter_scrapes_total") {
			sawScrapes = true
		}
	}
	if sawScrapeMeta {
		t.Error("a never-polled collector must not emit per-collector scrape meta")
	}
	if !sawScrapes {
		t.Error("scrapes_total must always be emitted")
	}
	if fake.callCount() != 0 {
		t.Errorf("collect must not poll; calls=%d, want 0", fake.callCount())
	}
}

// TestCollectIncludeFilterReplaysSelected verifies a non-nil include restricts the
// replay to the named collectors while the always-on metrics survive.
func TestCollectIncludeFilterReplaysSelected(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	a := &fakeCollectorInstance{name: "fake_a", emit: []prometheus.Metric{testMetric("opnsense_a", 1)}}
	b := &fakeCollectorInstance{name: "fake_b", emit: []prometheus.Metric{testMetric("opnsense_b", 1)}}
	c := newScrapeTestCollector(t, client, a, b)
	c.pollOnce(context.Background(), a)
	c.pollOnce(context.Background(), b)

	ch := make(chan prometheus.Metric, 64)
	c.collect(context.Background(), ch, map[string]bool{"fake_a": true})
	close(ch)

	var sawA, sawB, sawBuildInfo bool
	for m := range ch {
		d := m.Desc().String()
		if strings.Contains(d, "opnsense_a") {
			sawA = true
		}
		if strings.Contains(d, "opnsense_b") {
			sawB = true
		}
		if strings.Contains(d, "opnsense_exporter_build_info") {
			sawBuildInfo = true
		}
	}
	if !sawA {
		t.Error("include filter should replay fake_a")
	}
	if sawB {
		t.Error("include filter should exclude fake_b")
	}
	if !sawBuildInfo {
		t.Error("always-on build_info must survive filtering")
	}
}

// TestWithoutInterfacesProtocolServices covers #143: the three previously-ungated
// collectors can now be removed from the registered set via their Without* options.
func TestWithoutInterfacesProtocolServices(t *testing.T) {
	client, err := opnsense.NewClient(
		options.OPNSenseConfig{Protocol: "https", Host: "h", APIKey: "k", APISecret: "s"},
		"test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	c, err := New(&client, promslog.NewNopLogger(), "test",
		WithoutInterfacesCollector(), WithoutProtocolCollector(), WithoutServicesCollector())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, coll := range c.collectors {
		switch coll.Name() {
		case InterfacesSubsystem, ProtocolSubsystem, ServicesSubsystem:
			t.Errorf("expected %q collector to be removed", coll.Name())
		}
	}
}

// scrapeCtxKey is a context key used by the poll-path context-propagation test.
type scrapeCtxKey struct{}

// TestScrapeViewFiltersCollectors verifies the /metrics per-request view replays only
// the included collectors from the snapshot, with the always-on metrics surviving.
func TestScrapeViewFiltersCollectors(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))

	a := &fakeCollectorInstance{name: "fake_a", emit: []prometheus.Metric{testMetric("opnsense_a", 1)}}
	b := &fakeCollectorInstance{name: "fake_b", emit: []prometheus.Metric{testMetric("opnsense_b", 1)}}
	c := newScrapeTestCollector(t, client, a, b)
	c.pollHealth(context.Background())
	c.pollOnce(context.Background(), a)
	c.pollOnce(context.Background(), b)

	ch := make(chan prometheus.Metric, 100)
	c.ScrapeView(context.Background(), map[string]bool{"fake_a": true}).Collect(ch)
	close(ch)

	var sawA, sawB, sawUp, sawBuildInfo bool
	for m := range ch {
		desc := m.Desc().String()
		if strings.Contains(desc, "opnsense_a") {
			sawA = true
		}
		if strings.Contains(desc, "opnsense_b") {
			sawB = true
		}
		if strings.Contains(desc, "opnsense_up_test") {
			sawUp = true
		}
		if strings.Contains(desc, "opnsense_exporter_build_info") {
			sawBuildInfo = true
		}
	}
	if !sawA {
		t.Error("scrape view should replay the included fake_a")
	}
	if sawB {
		t.Error("scrape view should exclude fake_b")
	}
	if !sawUp {
		t.Error("expected up metric to be emitted despite filtering")
	}
	if !sawBuildInfo {
		t.Error("expected build_info metric to be emitted despite filtering")
	}
}

// newHealthTestCollector builds a Collector with just the health gauges (real
// metric names, not registered on the global registry) pointed at the given client.
func newHealthTestCollector(client *opnsense.Client) *Collector {
	g := func(name string) prometheus.Gauge {
		return prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: name})
	}
	return &Collector{
		Client:               client,
		log:                  promslog.NewNopLogger(),
		instanceLabel:        "test",
		isUp:                 g("up"),
		firewallHealthStatus: g("firewall_status"),
		crashReporterStatus:  g("crash_reporter_status"),
		systemStatusCode:     g("system_status_code"),
		subsystemStatusCode: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "system_subsystem_status_code",
		}, []string{"subsystem"}),
	}
}

// healthServer serves body with the given HTTP status for any path.
func healthServer(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// gatherHealthGauges drains the channel into a name->value map of the health gauges.
func gatherHealthGauges(ch chan prometheus.Metric) map[string]float64 {
	out := map[string]float64{}
	for m := range ch {
		desc := m.Desc().String()
		for _, name := range []string{"opnsense_up", "opnsense_firewall_status", "opnsense_crash_reporter_status", "opnsense_system_status_code"} {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				out[name] = getMetricValue(m)
			}
		}
	}
	return out
}

// gatherSubsystemGauges drains the channel into a subsystem-label->value map for the
// opnsense_system_subsystem_status_code gauge vec, ignoring every other metric on the
// channel (the plain health gauges use a different fqName).
func gatherSubsystemGauges(ch chan prometheus.Metric) map[string]float64 {
	out := map[string]float64{}
	for m := range ch {
		desc := m.Desc().String()
		if !strings.Contains(desc, `fqName: "opnsense_system_subsystem_status_code"`) {
			continue
		}
		labels := getMetricLabels(m)
		out[labels["subsystem"]] = getMetricValue(m)
	}
	return out
}

// TestCollectHealthMetrics_Reachable verifies the cross-version health parsing and
// the opnsense_up contract end-to-end through collectHealthMetrics: a reachable box
// is always up=1 (even when a subsystem is degraded), with degraded state surfaced
// via system_status_code and the per-subsystem gauges.
func TestCollectHealthMetrics_Reachable(t *testing.T) {
	cases := []struct {
		fixture      string
		wantUp       float64
		wantSysCode  float64
		wantCrash    float64
		wantFirewall float64
	}{
		{"v26_1_quiet.json", 1, 2, 1, 1},
		{"v26_1_acl_filtered.json", 1, 2, 1, 1},
		{"v26_1_empty_map.json", 1, 2, 1, 1},
		{"v26_1_crash_error.json", 1, -1, 0, 1},
		{"v26_1_firewall_error.json", 1, -1, 1, 0},
		{"v25_1_ok.json", 1, 2, 1, 1},
		{"v25_1_crash_error.json", 1, -1, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("..", "..", "opnsense", "testdata", "health", tc.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			client := newCollectorTestClient(t, healthServer(t, http.StatusOK, body))
			c := newHealthTestCollector(client)
			ch := make(chan prometheus.Metric, 16)
			c.pollHealth(context.Background())
			c.emitHealth(ch)
			close(ch)
			got := gatherHealthGauges(ch)

			if got["opnsense_up"] != tc.wantUp {
				t.Errorf("opnsense_up = %v, want %v", got["opnsense_up"], tc.wantUp)
			}
			if got["opnsense_system_status_code"] != tc.wantSysCode {
				t.Errorf("opnsense_system_status_code = %v, want %v", got["opnsense_system_status_code"], tc.wantSysCode)
			}
			if got["opnsense_crash_reporter_status"] != tc.wantCrash {
				t.Errorf("opnsense_crash_reporter_status = %v, want %v", got["opnsense_crash_reporter_status"], tc.wantCrash)
			}
			if got["opnsense_firewall_status"] != tc.wantFirewall {
				t.Errorf("opnsense_firewall_status = %v, want %v", got["opnsense_firewall_status"], tc.wantFirewall)
			}
		})
	}
}

// TestCollectHealthMetrics_Unreachable verifies opnsense_up = 0 only when the API
// call itself fails, and that the per-subsystem and status-code gauges are left
// absent rather than emitting a misleading 0.
func TestCollectHealthMetrics_Unreachable(t *testing.T) {
	client := newCollectorTestClient(t, healthServer(t, http.StatusInternalServerError, []byte("boom")))
	c := newHealthTestCollector(client)
	ch := make(chan prometheus.Metric, 16)
	c.pollHealth(context.Background())
	c.emitHealth(ch)
	close(ch)
	got := gatherHealthGauges(ch)

	if got["opnsense_up"] != 0 {
		t.Errorf("opnsense_up = %v, want 0", got["opnsense_up"])
	}
	for _, absent := range []string{"opnsense_system_status_code", "opnsense_crash_reporter_status", "opnsense_firewall_status"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s should be absent when unreachable, got %v", absent, got[absent])
		}
	}
}

// TestCollectHealthMetrics_Subsystems verifies opnsense_system_subsystem_status_code is
// emitted for every subsystem present in the response — including ones the exporter has
// no dedicated gauge for (disk space, root lock, plugin overrides) — carrying the
// resolved SystemStatusCode, across both the OPNsense 26.1 top-level "subsystems" map and
// the 26.1.11 metadata-only shape (#218).
func TestCollectHealthMetrics_Subsystems(t *testing.T) {
	cases := []struct {
		fixture string
		want    map[string]float64
	}{
		{"v26_1_quiet.json", map[string]float64{}},
		{"v26_1_acl_filtered.json", map[string]float64{}},
		{"v26_1_empty_map.json", map[string]float64{}},
		{"v26_1_crash_error.json", map[string]float64{"crashreporter": -1}},
		{"v26_1_multi_subsystem.json", map[string]float64{
			"diskspace":     -1,
			"rootlock":      -1,
			"monitoverride": 0,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("..", "..", "opnsense", "testdata", "health", tc.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			client := newCollectorTestClient(t, healthServer(t, http.StatusOK, body))
			c := newHealthTestCollector(client)
			ch := make(chan prometheus.Metric, 32)
			c.pollHealth(context.Background())
			c.emitHealth(ch)
			close(ch)
			got := gatherSubsystemGauges(ch)

			if len(got) != len(tc.want) {
				t.Fatalf("got %d subsystem series, want %d: %v", len(got), len(tc.want), got)
			}
			for name, wantVal := range tc.want {
				gotVal, ok := got[name]
				if !ok {
					t.Errorf("missing subsystem series %q", name)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("subsystem %q = %v, want %v", name, gotVal, wantVal)
				}
			}
		})
	}
}

// TestCollectHealthMetrics_SubsystemsResetAcrossScrapes verifies a subsystem that
// recovers between scrapes stops being reported: the gauge vec must be Reset() each
// scrape, not accumulate stale label sets from a previous unhealthy state (#218).
func TestCollectHealthMetrics_SubsystemsResetAcrossScrapes(t *testing.T) {
	unhealthy, err := os.ReadFile(filepath.Join("..", "..", "opnsense", "testdata", "health", "v26_1_multi_subsystem.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	healthy, err := os.ReadFile(filepath.Join("..", "..", "opnsense", "testdata", "health", "v26_1_empty_map.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	bodies := [][]byte{unhealthy, healthy}
	var call int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodies[call])
		call++
	}))
	t.Cleanup(server.Close)
	client := newCollectorTestClient(t, server)
	c := newHealthTestCollector(client)

	ch1 := make(chan prometheus.Metric, 32)
	c.pollHealth(context.Background())
	c.emitHealth(ch1)
	close(ch1)
	first := gatherSubsystemGauges(ch1)
	if len(first) != 3 {
		t.Fatalf("scrape 1: got %d subsystem series, want 3: %v", len(first), first)
	}

	ch2 := make(chan prometheus.Metric, 32)
	c.pollHealth(context.Background())
	c.emitHealth(ch2)
	close(ch2)
	second := gatherSubsystemGauges(ch2)
	if len(second) != 0 {
		t.Errorf("scrape 2: expected 0 subsystem series (all recovered), got %v", second)
	}
}

// TestNew_Idempotent verifies New does not register metrics on the global
// default prometheus registry: the exporter's own up/scrapes/endpoint-errors
// metrics reach /metrics through the Collector's Describe/Collect, so a second
// New in the same process must not panic on duplicate registration. Two
// Collectors against the default registry is a supported configuration (e.g.
// the test binary itself, or future multi-instance use).
func TestNew_Idempotent(t *testing.T) {
	conf := options.OPNSenseConfig{Protocol: "http", APIKey: "test"}
	client, err := opnsense.NewClient(conf, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := New(&client, promslog.NewNopLogger(), "test-idempotent"); err != nil {
			t.Fatalf("New call #%d returned error: %v", i+1, err)
		}
	}
}

// TestCacheSelfMetricsRecorded covers #196: a cache hit issues no API request, so it is
// invisible to api_requests_total by design. These counters are what make it visible —
// and a replayed 404 ("absent", plugin not installed) is counted separately from a
// replayed payload ("body"), because the two mean different things.
func TestCacheSelfMetricsRecorded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "haproxy") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"last_check":"2024-01-15T10:30:00Z","product_version":"24.1.1",
			"product":{"product_check":{"upgrade_needs_reboot":"0"}},"status":"ok"}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	client.SetEndpointCacheTTL("firmware", time.Hour)
	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)

	c := newScrapeTestCollector(t, client)
	client.SetCacheObserver(c)

	// Three calls each: one miss to populate, then two hits.
	for range 3 {
		if _, err := client.FetchFirmwareStatus(); err != nil {
			t.Fatalf("firmware: %v", err)
		}
		if _, _, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err != nil {
			t.Fatalf("haproxy: %v", err)
		}
	}

	body := counterValue(t, c.apiCacheHits.WithLabelValues("api/core/firmware/status", "body", "test"))
	if body != 2 {
		t.Errorf("expected 2 body cache hits, got %v", body)
	}
	absent := counterValue(t, c.apiCacheHits.WithLabelValues("api/haproxy/service/status", "absent", "test"))
	if absent != 2 {
		t.Errorf("expected 2 absent cache hits, got %v", absent)
	}
	misses := counterValue(t, c.apiCacheMisses.WithLabelValues("api/core/firmware/status", "test"))
	if misses != 1 {
		t.Errorf("expected 1 miss (the cold fetch), got %v", misses)
	}
}

// TestCollectEmitsDistinctPollClocks pins the exported side of #382/#385: collect()
// must expose the attempt clock, the retained-content clock, the last-success clock
// and the scheduler's real next deadline as four distinct series — and must OMIT the
// content/success clocks entirely for a collector that has never produced either,
// rather than emitting a misleading epoch-zero.
func TestCollectEmitsDistinctPollClocks(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_fake_series", 42)}}
	c := newScrapeTestCollector(t, client, fake)

	// A poll that has only ever failed emptily: attempt clock only. Note emit must
	// be cleared too — an error WITH data is a partial poll, which legitimately does
	// advance the content clock.
	fake.err = &opnsense.APICallError{Endpoint: "ep", Message: "boom"}
	emit := fake.emit
	fake.emit = nil
	c.pollOnce(context.Background(), fake)
	got := collectPollClocks(t, c)
	if _, ok := got["collector_last_poll_timestamp_seconds"]; !ok {
		t.Error("a failed poll must still publish the attempt clock")
	}
	if _, ok := got["collector_snapshot_timestamp_seconds"]; ok {
		t.Error("a collector with no stored data must NOT publish a content clock")
	}
	if _, ok := got["collector_last_success_timestamp_seconds"]; ok {
		t.Error("a collector that has never succeeded must NOT publish a success clock")
	}
	if _, ok := got["collector_next_poll_timestamp_seconds"]; ok {
		t.Error("with no poller running there is no scheduled poll, so no deadline may be published")
	}

	// Now a clean success plus a scheduler deadline: all four present.
	fake.err = nil
	fake.emit = emit
	c.pollOnce(context.Background(), fake)
	want := time.Now().Add(90 * time.Second).Truncate(time.Second)
	c.store.setDeadline("fake", want)

	got = collectPollClocks(t, c)
	for _, name := range []string{
		"collector_last_poll_timestamp_seconds",
		"collector_snapshot_timestamp_seconds",
		"collector_last_success_timestamp_seconds",
		"collector_next_poll_timestamp_seconds",
	} {
		if _, ok := got[name]; !ok {
			t.Errorf("after a clean success with a live poller, %s must be published", name)
		}
	}
	if got["collector_next_poll_timestamp_seconds"] != float64(want.Unix()) {
		t.Errorf("the next-poll metric must report the scheduler's real deadline %v, got %v",
			want.Unix(), got["collector_next_poll_timestamp_seconds"])
	}
	// The derived value the metric used to publish (lastPoll+interval) is ~60s out
	// from the deadline we set, so this also proves it is no longer self-derived.
	if got["collector_next_poll_timestamp_seconds"] == got["collector_last_poll_timestamp_seconds"]+IntervalMedium.Seconds() {
		t.Error("the next-poll metric must not be re-derived from lastPoll + interval")
	}
}

// collectPollClocks runs collect() and returns the value of each per-collector poll
// timestamp metric that was emitted, keyed by its metric name suffix.
func collectPollClocks(t *testing.T, c *Collector) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 128)
	c.collect(context.Background(), ch, nil)
	close(ch)
	out := map[string]float64{}
	for m := range ch {
		desc := m.Desc().String()
		for _, name := range []string{
			"collector_last_poll_timestamp_seconds",
			"collector_snapshot_timestamp_seconds",
			"collector_last_success_timestamp_seconds",
			"collector_next_poll_timestamp_seconds",
		} {
			if !strings.Contains(desc, name) {
				continue
			}
			d := &dto.Metric{}
			if err := m.Write(d); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			out[name] = d.GetGauge().GetValue()
		}
	}
	return out
}

// TestOTLPLanePartitionIsDisjointAndComplete pins the #390 partition contract. The
// whole risk of a second OTLP reader is emitting the same series identity twice, so
// this asserts the two lanes are disjoint AND together cover exactly what the single
// lane covers today.
func TestOTLPLanePartitionIsDisjointAndComplete(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	gw := &fakeCollectorInstance{name: GatewaysSubsystem, emit: []prometheus.Metric{testMetric("opnsense_gw_series", 1)}}  // fast tier
	fw := &fakeCollectorInstance{name: FirmwareSubsystem, emit: []prometheus.Metric{testMetric("opnsense_fw_series", 2)}}  // cold tier
	plain := &fakeCollectorInstance{name: "no_tier_plain", emit: []prometheus.Metric{testMetric("opnsense_pl_series", 3)}} // medium
	c := newScrapeTestCollector(t, client, gw, fw, plain)
	c.pollHealth(context.Background())
	for _, f := range []*fakeCollectorInstance{gw, fw, plain} {
		c.pollOnce(context.Background(), f)
	}

	fast := c.FastCollectorNames()
	if len(fast) != 1 || fast[0] != GatewaysSubsystem {
		t.Fatalf("fast lane membership = %v, want just [%s]", fast, GatewaysSubsystem)
	}

	// Compare SERIES IDENTITY (name + labels), not bare family name: two lanes may
	// legitimately both emit opnsense_exporter_collector_poll_interval_seconds, one
	// per collector they own. What must never collide is a full label tuple.
	single, singleNames := describeLane(t, c.ScrapeView(context.Background(), nil))
	baseL, baseNames := describeLane(t, c.OTLPBaseView())
	fastL, fastNames := describeLane(t, c.OTLPFastView())

	// Disjoint: not one shared series identity between the lanes.
	for k := range fastL {
		if baseL[k] {
			t.Errorf("series %q is emitted by BOTH lanes — duplicate identity", k)
		}
	}
	// Complete: the union is exactly what one lane emits today.
	union := map[string]bool{}
	for k := range baseL {
		union[k] = true
	}
	for k := range fastL {
		union[k] = true
	}
	for k := range single {
		if !union[k] {
			t.Errorf("series %q is emitted by the single lane but by NEITHER split lane", k)
		}
	}
	for k := range union {
		if !single[k] {
			t.Errorf("series %q is emitted by a split lane but not by the single lane", k)
		}
	}

	// The fast lane carries the fast collector's own series and none of the
	// always-on/health block — those belong to the base lane alone.
	if !fastNames["opnsense_gw_series"] {
		t.Error("fast lane must carry the fast collector's metrics")
	}
	if fastNames["opnsense_up_test"] {
		t.Error("health gauges must be base-lane only")
	}
	if !baseNames["opnsense_up_test"] {
		t.Error("base lane must carry the health gauges")
	}
	if !baseNames["opnsense_fw_series"] || !baseNames["opnsense_pl_series"] {
		t.Error("base lane must carry every non-fast collector's metrics")
	}
	if fastNames["opnsense_fw_series"] || fastNames["opnsense_pl_series"] {
		t.Error("fast lane must not carry non-fast collectors")
	}
	if !singleNames["opnsense_gw_series"] {
		t.Error("sanity: the single lane must carry everything")
	}
}

// TestOTLPLaneMembershipFollowsOverrides pins that lane membership follows the
// EFFECTIVE interval, so an operator override moves a collector between lanes — both
// directions.
func TestOTLPLaneMembershipFollowsOverrides(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	gw := &fakeCollectorInstance{name: GatewaysSubsystem}
	fw := &fakeCollectorInstance{name: FirmwareSubsystem}
	c := newScrapeTestCollector(t, client, gw, fw)

	// Slow the fast collector down and speed the cold one up: they swap lanes.
	c.pollOverrides = map[string]time.Duration{
		GatewaysSubsystem: IntervalMedium,
		FirmwareSubsystem: IntervalFast,
	}
	fast := c.FastCollectorNames()
	if len(fast) != 1 || fast[0] != FirmwareSubsystem {
		t.Errorf("lane membership must follow operator overrides, got %v", fast)
	}
}

// describeLane collects a lane view and returns two sets: full series identities
// (name plus every label pair, which is what must never be duplicated across
// lanes) and bare family names (convenient for presence assertions).
func describeLane(t *testing.T, view prometheus.Collector) (series, names map[string]bool) {
	t.Helper()
	ch := make(chan prometheus.Metric, 512)
	view.Collect(ch)
	close(ch)
	series, names = map[string]bool{}, map[string]bool{}
	for m := range ch {
		d := &dto.Metric{}
		if err := m.Write(d); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		name := metricNameOf(m)
		key := name
		for _, l := range d.GetLabel() {
			key += "|" + l.GetName() + "=" + l.GetValue()
		}
		series[key] = true
		names[name] = true
	}
	return series, names
}

// metricNameOf extracts the fqName out of a Desc's string form.
func metricNameOf(m prometheus.Metric) string {
	s := m.Desc().String()
	const marker = `fqName: "`
	i := strings.Index(s, marker)
	if i < 0 {
		return s
	}
	rest := s[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return s
	}
	return rest[:j]
}

// TestScrapeSkipsCounterIsRetired covers #439. opnsense_exporter_scrape_skips_total
// described "scrapes skipped because the scrape deadline expired before the collector
// lock could be acquired". After #336 serving is a pure replay of the in-memory poll
// snapshot: there is no collector lock to queue behind and no scrape deadline, so the
// counter had no increment site anywhere in the tree and could only ever read 0. It is
// removed rather than left at zero, and opnsense_exporter_scrapes_total must stop
// pointing operators at it.
func TestScrapeSkipsCounterIsRetired(t *testing.T) {
	client, err := opnsense.NewClient(
		options.OPNSenseConfig{Protocol: "https", Host: "h", APIKey: "k", APISecret: "s"},
		"test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	c, err := New(&client, promslog.NewNopLogger(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sawScrapes := false
	for _, d := range collectDescs(t, c) {
		s := d.String()
		if strings.Contains(s, "exporter_scrape_skips_total") {
			t.Errorf("retired metric still described: %s", s)
		}
		if strings.Contains(s, "opnsense_exporter_scrapes_total") {
			sawScrapes = true
			if strings.Contains(s, "skip") || strings.Contains(s, "deadline") ||
				strings.Contains(s, "lock") {
				t.Errorf("opnsense_exporter_scrapes_total help still describes the retired "+
					"deadline/skip model: %s", s)
			}
		}
	}
	if !sawScrapes {
		t.Fatal("opnsense_exporter_scrapes_total is not described at all")
	}

	metrics := make(chan prometheus.Metric, 8192)
	c.ScrapeView(context.Background(), map[string]bool{}).Collect(metrics)
	close(metrics)
	for m := range metrics {
		if strings.Contains(m.Desc().String(), "exporter_scrape_skips_total") {
			t.Errorf("retired metric still exported: %s", m.Desc().String())
		}
	}
}

// TestScrapeViewIgnoresContextDeadline is the other half of the #439 guard, on the
// collector side: an expired or cancelled request context must not change one byte of
// what a scrape replays. Serving reads memory the poll scheduler filled on its own
// clock, so nothing a Prometheus client can put on the wire — a scrape timeout header,
// an aborted request — can reach or curtail OPNsense polling.
func TestScrapeViewIgnoresContextDeadline(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	a := &fakeCollectorInstance{name: "fake_a", emit: []prometheus.Metric{testMetric("opnsense_a", 1)}}
	c := newScrapeTestCollector(t, client, a)
	c.pollHealth(context.Background())
	c.pollOnce(context.Background(), a)

	collectNames := func(ctx context.Context) []string {
		ch := make(chan prometheus.Metric, 256)
		c.ScrapeView(ctx, nil).Collect(ch)
		close(ch)
		var out []string
		for m := range ch {
			out = append(out, m.Desc().String())
		}
		sort.Strings(out)
		return out
	}

	live := collectNames(context.Background())
	if len(live) == 0 {
		t.Fatal("baseline scrape replayed nothing")
	}

	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	if got := collectNames(expired); !reflect.DeepEqual(got, live) {
		t.Errorf("an already-expired context changed the replay:\n got %v\nwant %v", got, live)
	}

	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if got := collectNames(cancelled); !reflect.DeepEqual(got, live) {
		t.Errorf("a cancelled context changed the replay:\n got %v\nwant %v", got, live)
	}
}

// TestCacheFetchedTimestampGaugeReportsHeldBodiesOnly pins the freshness half of
// GitHub issue 724 (OPN-0095): collector_last_success_timestamp_seconds advances on
// every clean poll, INCLUDING one served from the response cache, so on its own it
// cannot tell a live fetch from a 12h-old replay. The per-endpoint
// api_cache_fetched_timestamp_seconds gauge carries the time the held body was
// actually fetched from the firewall. It is emitted only while a success body is
// held: a negative (404) entry and an uncached endpoint publish nothing.
func TestCacheFetchedTimestampGaugeReportsHeldBodiesOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "haproxy") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"last_check":"2024-01-15T10:30:00Z","product_version":"24.1.1",
			"product":{"product_check":{"upgrade_needs_reboot":"0"}},"status":"ok"}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	client.SetEndpointCacheTTL("firmware", time.Hour)
	client.SetEndpointAbsentTTL("haproxyServiceStatus", time.Hour)
	c := newScrapeTestCollector(t, client)

	if got := collectCacheFetched(t, c); len(got) != 0 {
		t.Fatalf("nothing is cached yet, expected no fetched-timestamp series, got %v", got)
	}

	before := time.Now().Add(-time.Second)
	if _, err := client.FetchFirmwareStatus(); err != nil {
		t.Fatalf("firmware: %v", err)
	}
	if _, _, err := client.FetchServiceStatusOptional("haproxyServiceStatus"); err != nil {
		t.Fatalf("haproxy: %v", err)
	}

	got := collectCacheFetched(t, c)
	if len(got) != 1 {
		t.Fatalf("expected exactly one fetched-timestamp series (the held firmware body), got %v", got)
	}
	ts, ok := got["api/core/firmware/status"]
	if !ok {
		t.Fatalf("expected the series to be labelled with the firmware path, got %v", got)
	}
	if ts < float64(before.Unix()) || ts > float64(time.Now().Unix()) {
		t.Errorf("fetched timestamp %v is not the fetch time (expected within [%d, now])", ts, before.Unix())
	}
	if _, ok := got["api/haproxy/service/status"]; ok {
		t.Error("a cached 404 is not a fetched body and must not publish a fetched timestamp")
	}
}

func collectCacheFetched(t *testing.T, c *Collector) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 256)
	c.collect(context.Background(), ch, nil)
	close(ch)
	out := map[string]float64{}
	for m := range ch {
		if !strings.Contains(m.Desc().String(), "exporter_api_cache_fetched_timestamp_seconds") {
			continue
		}
		d := &dto.Metric{}
		if err := m.Write(d); err != nil {
			t.Fatalf("write: %v", err)
		}
		endpoint := ""
		for _, l := range d.GetLabel() {
			if l.GetName() == "endpoint" {
				endpoint = l.GetValue()
			}
		}
		out[endpoint] = d.GetGauge().GetValue()
	}
	return out
}
