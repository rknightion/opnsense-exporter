package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type relaydCollector struct {
	log *slog.Logger

	virtualServerStatus     *prometheus.Desc
	tableActive             *prometheus.Desc
	hostUp                  *prometheus.Desc
	hostAvailabilityPercent *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &relaydCollector{
		subsystem: RelaydSubsystem,
	})
}

func (c *relaydCollector) Name() string { return c.subsystem }

func (c *relaydCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	vsLabels := []string{"name", "type"}
	tableLabels := []string{"virtualserver", "table"}
	hostLabels := []string{"virtualserver", "table", "host", "address"}

	c.virtualServerStatus = buildPrometheusDesc(c.subsystem, "virtualserver_status",
		"Relayd virtual server (redirect/relay) status (1 = active, 0 = otherwise)",
		vsLabels,
	)
	c.tableActive = buildPrometheusDesc(c.subsystem, "table_active",
		"Relayd table status (1 = active with at least one host, 0 = otherwise)",
		tableLabels,
	)
	c.hostUp = buildPrometheusDesc(c.subsystem, "host_up",
		"Relayd table host health check status (1 = up, 0 = otherwise)",
		hostLabels,
	)
	c.hostAvailabilityPercent = buildPrometheusDesc(c.subsystem, "host_availability_percent",
		"Relayd table host availability percentage from health checks (omitted when no checks have run yet)",
		hostLabels,
	)
}

func (c *relaydCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.virtualServerStatus
	ch <- c.tableActive
	ch <- c.hostUp
	ch <- c.hostAvailabilityPercent
}

func (c *relaydCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchRelaydStatus()
	if err != nil {
		return err
	}

	// os-relayd absent (404) or present but with nothing to summarise yet
	// (result:"failed" — no topology configured / service not yet reporting):
	// stay completely silent rather than emitting a misleading all-zero shape.
	if !data.Present || !data.HasData {
		return nil
	}

	for _, vs := range data.VirtualServers {
		ch <- prometheus.MustNewConstMetric(c.virtualServerStatus, prometheus.GaugeValue,
			vs.Active, vs.Name, vs.Type, c.instance)

		for _, table := range vs.Tables {
			ch <- prometheus.MustNewConstMetric(c.tableActive, prometheus.GaugeValue,
				table.Active, vs.Name, table.Name, c.instance)

			for _, host := range table.Hosts {
				ch <- prometheus.MustNewConstMetric(c.hostUp, prometheus.GaugeValue,
					host.Up, vs.Name, table.Name, host.Name, host.Address, c.instance)

				if host.HasAvailability {
					ch <- prometheus.MustNewConstMetric(c.hostAvailabilityPercent, prometheus.GaugeValue,
						host.AvailabilityPercent, vs.Name, table.Name, host.Name, host.Address, c.instance)
				}
			}
		}
	}

	return nil
}
