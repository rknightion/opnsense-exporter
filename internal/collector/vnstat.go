package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type vnstatCollector struct {
	log *slog.Logger

	totalBytes        *prometheus.Desc
	currentDayBytes   *prometheus.Desc
	currentMonthBytes *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &vnstatCollector{
		subsystem: VnstatSubsystem,
	})
}

func (c *vnstatCollector) Name() string {
	return c.subsystem
}

func (c *vnstatCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	labels := []string{"interface", "direction"}

	c.totalBytes = buildPrometheusDesc(c.subsystem, "total_bytes",
		"Cumulative bytes recorded by vnstat since this interface's database was created (counter; resets only on vnstat --resetdb)",
		labels,
	)
	c.currentDayBytes = buildPrometheusDesc(c.subsystem, "current_day_bytes",
		"Bytes recorded by vnstat so far today (gauge; resets to 0 at local midnight in vnstat's own bookkeeping)",
		labels,
	)
	c.currentMonthBytes = buildPrometheusDesc(c.subsystem, "current_month_bytes",
		"Bytes recorded by vnstat so far this month (gauge; resets monthly)",
		labels,
	)
}

func (c *vnstatCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.totalBytes
	ch <- c.currentDayBytes
	ch <- c.currentMonthBytes
}

func (c *vnstatCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchVnstat()
	if err != nil {
		return err
	}

	// os-vnstat absent -> Present=false; stay silent (opt-in collector, mirrors
	// smartCollector's gate on SMARTDevices.Present).
	if !data.Present {
		return nil
	}

	for _, iface := range data.Interfaces {
		ch <- prometheus.MustNewConstMetric(c.totalBytes, prometheus.CounterValue,
			float64(iface.TotalRXBytes), iface.Name, "rx", c.instance)
		ch <- prometheus.MustNewConstMetric(c.totalBytes, prometheus.CounterValue,
			float64(iface.TotalTXBytes), iface.Name, "tx", c.instance)

		ch <- prometheus.MustNewConstMetric(c.currentDayBytes, prometheus.GaugeValue,
			float64(iface.CurrentDayRXBytes), iface.Name, "rx", c.instance)
		ch <- prometheus.MustNewConstMetric(c.currentDayBytes, prometheus.GaugeValue,
			float64(iface.CurrentDayTXBytes), iface.Name, "tx", c.instance)

		ch <- prometheus.MustNewConstMetric(c.currentMonthBytes, prometheus.GaugeValue,
			float64(iface.CurrentMonthRXBytes), iface.Name, "rx", c.instance)
		ch <- prometheus.MustNewConstMetric(c.currentMonthBytes, prometheus.GaugeValue,
			float64(iface.CurrentMonthTXBytes), iface.Name, "tx", c.instance)
	}

	return nil
}
