package collector

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
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
	mk := func(legacy string, meta any) opnsense.HealthCheckResponse {
		var r opnsense.HealthCheckResponse
		r.Firewall.Status = legacy
		r.Metadata.Firewall.Status = meta
		return r
	}

	cases := []struct {
		name string
		resp opnsense.HealthCheckResponse
		want bool
	}{
		// OPNsense 25.1+ healthy box: no Firewall entry at all (the original bug).
		{"new format healthy (absent)", mk("", nil), true},
		{"legacy OK", mk(opnsense.HealthCheckStatusOK, nil), true},
		{"legacy error", mk("Error", nil), false},
		// Metadata status arrives as a JSON number via encoding/json -> float64.
		{"metadata numeric OK", mk("", float64(opnsense.HealthCheckStatusOK_v25_1)), true},
		{"metadata numeric not OK", mk("", float64(1)), false},
		{"metadata string OK", mk("", "OK"), true},
		{"metadata string empty", mk("", ""), true},
		{"metadata string error", mk("", "Error"), false},
		{"metadata string ERROR", mk("", "ERROR"), false},
		// OPNsense 25.1+ can also report the numeric status as a string ("2").
		{"metadata numeric string OK", mk("", "2"), true},
		{"metadata numeric string not OK", mk("", "1"), false},
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
	name   string
	err    *opnsense.APICallError
	panics bool
	calls  int
	gotCtx context.Context
}

func (f *fakeCollectorInstance) Register(_, _ string, _ *slog.Logger) {}
func (f *fakeCollectorInstance) Name() string                         { return f.name }
func (f *fakeCollectorInstance) Describe(_ chan<- *prometheus.Desc)   {}
func (f *fakeCollectorInstance) Update(ctx context.Context, _ *opnsense.Client, _ chan<- prometheus.Metric) *opnsense.APICallError {
	f.calls++
	f.gotCtx = ctx
	if f.panics {
		panic("boom")
	}
	return f.err
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
	c.isUp = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_up_test", Help: "h"})
	c.firewallHealthStatus = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_firewall_status_test", Help: "h"})
	c.crashReporterStatus = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_crash_reporter_status_test", Help: "h"})
	c.systemStatusCode = prometheus.NewGauge(prometheus.GaugeOpts{Name: "opnsense_system_status_code_test", Help: "h"})
	c.scrapes = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_scrapes_total_test", Help: "h"},
		[]string{"opnsense_instance"},
	)
	c.endpointErrors = *prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "opnsense_exporter_endpoint_errors_total_test", Help: "h"},
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

func TestExecuteRecordsScrapeMetrics(t *testing.T) {
	conf := options.OPNSenseConfig{Protocol: "http", APIKey: "test"}
	client, err := opnsense.NewClient(conf, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("failed to build client: %v", err)
	}

	cases := []struct {
		name        string
		fake        *fakeCollectorInstance
		wantSuccess float64
		wantErrInc  string // endpoint label expected to be incremented; "" = none
	}{
		{"success", &fakeCollectorInstance{name: "fake_ok"}, 1, ""},
		{"api error", &fakeCollectorInstance{name: "fake_err", err: &opnsense.APICallError{Endpoint: "fake_endpoint", Message: "boom"}}, 0, "fake_endpoint"},
		{"panic", &fakeCollectorInstance{name: "fake_panic", panics: true}, 0, "fake_panic"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newScrapeTestCollector(t, &client)
			ch := make(chan prometheus.Metric, 10)
			c.execute(context.Background(), tc.fake, &client, ch)
			close(ch)

			var gotSuccess, gotDuration *float64
			for m := range ch {
				desc := m.Desc().String()
				v := getMetricValue(m)
				labels := getMetricLabels(m)
				if labels["collector"] != tc.fake.name {
					t.Errorf("collector label = %q, want %q", labels["collector"], tc.fake.name)
				}
				if labels[instanceLabelName] != "test" {
					t.Errorf("%s label = %q, want test", instanceLabelName, labels[instanceLabelName])
				}
				switch {
				case strings.Contains(desc, "scrape_collector_success"):
					gotSuccess = &v
				case strings.Contains(desc, "scrape_collector_duration_seconds"):
					gotDuration = &v
				}
			}
			if gotSuccess == nil || gotDuration == nil {
				t.Fatal("expected both scrape_collector_duration_seconds and scrape_collector_success to be emitted")
			}
			if *gotSuccess != tc.wantSuccess {
				t.Errorf("success = %v, want %v", *gotSuccess, tc.wantSuccess)
			}
			if *gotDuration < 0 {
				t.Errorf("duration = %v, want >= 0", *gotDuration)
			}
			if tc.wantErrInc != "" {
				if got := counterValue(t, c.endpointErrors.WithLabelValues(tc.wantErrInc, "test")); got != 1 {
					t.Errorf("endpointErrors{endpoint=%q} = %v, want 1", tc.wantErrInc, got)
				}
			}
		})
	}
}

// healthOKServer serves a minimal OK health-check payload for any path, so
// collect()'s collectHealthMetrics succeeds fast and deterministically.
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

func TestScrapeViewFiltersCollectors(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))

	a := &fakeCollectorInstance{name: "fake_a"}
	b := &fakeCollectorInstance{name: "fake_b"}
	c := newScrapeTestCollector(t, client, a, b)

	ch := make(chan prometheus.Metric, 100)
	c.ScrapeView(context.Background(), map[string]bool{"fake_a": true}).Collect(ch)
	close(ch)

	if a.calls != 1 {
		t.Errorf("fake_a calls = %d, want 1", a.calls)
	}
	if b.calls != 0 {
		t.Errorf("fake_b calls = %d, want 0 (excluded by filter)", b.calls)
	}

	// Always-on metrics must survive filtering.
	var sawUp, sawBuildInfo bool
	for m := range ch {
		desc := m.Desc().String()
		if strings.Contains(desc, "opnsense_up_test") {
			sawUp = true
		}
		if strings.Contains(desc, "opnsense_exporter_build_info") {
			sawBuildInfo = true
		}
	}
	if !sawUp {
		t.Error("expected up metric to be emitted despite filtering")
	}
	if !sawBuildInfo {
		t.Error("expected build_info metric to be emitted despite filtering")
	}
}

func TestScrapeViewEmptyIncludeRunsNoSubCollectors(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	a := &fakeCollectorInstance{name: "fake_a"}
	c := newScrapeTestCollector(t, client, a)

	ch := make(chan prometheus.Metric, 100)
	c.ScrapeView(context.Background(), map[string]bool{}).Collect(ch)
	close(ch)

	if a.calls != 0 {
		t.Errorf("fake_a calls = %d, want 0 (empty non-nil include)", a.calls)
	}
}

func TestCollectSkipsFanOutWhenDeadlineExpired(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	a := &fakeCollectorInstance{name: "fake_a"}
	c := newScrapeTestCollector(t, client, a)

	// A scrape queued behind a slow one can acquire the lock after its own
	// deadline already expired; fanning out against a dead context must not
	// happen (it would error every endpoint and look like a firewall outage).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch := make(chan prometheus.Metric, 100)
	c.ScrapeView(ctx, nil).Collect(ch)
	close(ch)

	if a.calls != 0 {
		t.Errorf("fake_a calls = %d, want 0 (dead context must skip the fan-out)", a.calls)
	}
	var sawBuildInfo bool
	for m := range ch {
		if strings.Contains(m.Desc().String(), "opnsense_exporter_build_info") {
			sawBuildInfo = true
		}
	}
	if !sawBuildInfo {
		t.Error("expected always-on exporter info metrics even with a dead context")
	}
}

type scrapeCtxKey struct{}

func TestScrapeViewPropagatesContext(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	a := &fakeCollectorInstance{name: "fake_a"}
	c := newScrapeTestCollector(t, client, a)

	ctx := context.WithValue(context.Background(), scrapeCtxKey{}, "marker")
	ch := make(chan prometheus.Metric, 100)
	c.ScrapeView(ctx, nil).Collect(ch)
	close(ch)

	if a.gotCtx == nil || a.gotCtx.Value(scrapeCtxKey{}) != "marker" {
		t.Error("expected the request context to reach sub-collector Update")
	}
}
