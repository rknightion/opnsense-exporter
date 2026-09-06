package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type firewallMigrationCollector struct {
	legacyRules            *prometheus.Desc
	legacyOutboundNATRules *prometheus.Desc
	subsystem              string
	instance               string
}

func init() {
	collectorInstances = append(collectorInstances, &firewallMigrationCollector{
		subsystem: FirewallMigrationSubsystem,
	})
}

func (c *firewallMigrationCollector) Name() string { return c.subsystem }

func (c *firewallMigrationCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.instance = instanceLabel
	log.Debug("Registering collector", "collector", c.Name())

	c.legacyRules = buildPrometheusDesc(c.subsystem, "legacy_rules",
		"Number of legacy firewall rules that remain to be migrated to the MVC configuration.", nil)
	c.legacyOutboundNATRules = buildPrometheusDesc(c.subsystem, "legacy_outbound_nat_rules",
		"Number of legacy outbound NAT rules that remain to be migrated to the MVC configuration.", nil)
}

func (c *firewallMigrationCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.legacyRules
	ch <- c.legacyOutboundNATRules
}

func (c *firewallMigrationCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchFirewallMigration()
	if err != nil {
		return err
	}
	if data.LegacyRulesPresent {
		ch <- prometheus.MustNewConstMetric(c.legacyRules, prometheus.GaugeValue, float64(data.LegacyRules), c.instance)
	}
	if data.LegacyOutboundNATPresent {
		ch <- prometheus.MustNewConstMetric(c.legacyOutboundNATRules, prometheus.GaugeValue, float64(data.LegacyOutboundNATRules), c.instance)
	}
	return nil
}
