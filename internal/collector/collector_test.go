package collector

import (
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
