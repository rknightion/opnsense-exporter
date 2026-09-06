package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type firewallRulesCollector struct {
	log              *slog.Logger
	rulesTotal       *prometheus.Desc
	evaluationsTotal *prometheus.Desc
	packetsTotal     *prometheus.Desc
	bytesTotal       *prometheus.Desc
	states           *prometheus.Desc
	pfRules          *prometheus.Desc
	configuredRules  *prometheus.Desc
	subsystem        string
	instance         string
	detailsEnabled   bool
}

func init() {
	collectorInstances = append(collectorInstances, &firewallRulesCollector{
		subsystem: FirewallRulesSubsystem,
	})
}

func (c *firewallRulesCollector) Name() string {
	return c.subsystem
}

func (c *firewallRulesCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.rulesTotal = buildPrometheusDesc(c.subsystem, "rules",
		"Current number of firewall rules with statistics",
		nil,
	)
	c.evaluationsTotal = buildPrometheusDesc(c.subsystem, "evaluations_total",
		"Total number of rule evaluations per firewall rule",
		[]string{"uuid", "description", "action", "interface", "direction", "protocol"},
	)
	c.packetsTotal = buildPrometheusDesc(c.subsystem, "packets_total",
		"Total number of packets matched per firewall rule",
		[]string{"uuid", "description", "action", "interface", "direction", "protocol"},
	)
	c.bytesTotal = buildPrometheusDesc(c.subsystem, "bytes_total",
		"Total number of bytes matched per firewall rule",
		[]string{"uuid", "description", "action", "interface", "direction", "protocol"},
	)
	c.states = buildPrometheusDesc(c.subsystem, "states",
		"Current number of active states per firewall rule",
		[]string{"uuid", "description", "action", "interface", "direction", "protocol"},
	)
	c.pfRules = buildPrometheusDesc(c.subsystem, "pf_rules",
		"Number of PF rules generated per firewall rule",
		[]string{"uuid", "description", "action", "interface", "direction", "protocol"},
	)
	c.configuredRules = buildPrometheusDesc(c.subsystem, "configured_rules",
		"Number of configured firewall filter rules by enabled state. Only emitted when --exporter.enable-firewall-rules-details is set.",
		[]string{"enabled"},
	)
}

func (c *firewallRulesCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *firewallRulesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rulesTotal
	ch <- c.evaluationsTotal
	ch <- c.packetsTotal
	ch <- c.bytesTotal
	ch <- c.states
	ch <- c.pfRules
	ch <- c.configuredRules
}

func (c *firewallRulesCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchFirewallRuleStats(c.detailsEnabled)
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.rulesTotal,
		prometheus.GaugeValue,
		float64(len(data.Rules)),
		c.instance,
	)

	if c.detailsEnabled {
		ch <- prometheus.MustNewConstMetric(
			c.configuredRules, prometheus.GaugeValue,
			float64(data.ConfiguredRulesEnabled), "true", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.configuredRules, prometheus.GaugeValue,
			float64(data.ConfiguredRulesDisabled), "false", c.instance,
		)

		for _, rule := range data.Rules {
			ch <- prometheus.MustNewConstMetric(
				c.evaluationsTotal,
				prometheus.CounterValue,
				float64(rule.Evaluations),
				rule.UUID,
				rule.Description,
				rule.Action,
				rule.Interface,
				rule.Direction,
				rule.Protocol,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.packetsTotal,
				prometheus.CounterValue,
				float64(rule.Packets),
				rule.UUID,
				rule.Description,
				rule.Action,
				rule.Interface,
				rule.Direction,
				rule.Protocol,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.bytesTotal,
				prometheus.CounterValue,
				float64(rule.Bytes),
				rule.UUID,
				rule.Description,
				rule.Action,
				rule.Interface,
				rule.Direction,
				rule.Protocol,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.states,
				prometheus.GaugeValue,
				float64(rule.States),
				rule.UUID,
				rule.Description,
				rule.Action,
				rule.Interface,
				rule.Direction,
				rule.Protocol,
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.pfRules,
				prometheus.GaugeValue,
				float64(rule.PfRules),
				rule.UUID,
				rule.Description,
				rule.Action,
				rule.Interface,
				rule.Direction,
				rule.Protocol,
				c.instance,
			)
		}
	}

	return nil
}
