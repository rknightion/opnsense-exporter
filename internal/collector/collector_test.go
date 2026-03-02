package collector

import (
	"testing"

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
