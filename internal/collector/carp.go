package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type carpCollector struct {
	log *slog.Logger

	demotion        *prometheus.Desc
	allow           *prometheus.Desc
	maintenanceMode *prometheus.Desc
	vipsTotal       *prometheus.Desc
	vipStatus       *prometheus.Desc
	vipAdvbase      *prometheus.Desc
	vipAdvskew      *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &carpCollector{
		subsystem: CARPSubsystem,
	})
}

func (c *carpCollector) Name() string {
	return c.subsystem
}

func (c *carpCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.demotion = buildPrometheusDesc(c.subsystem, "demotion",
		"CARP demotion level",
		nil,
	)
	c.allow = buildPrometheusDesc(c.subsystem, "allow",
		"Whether CARP is allowed (1 = allowed, 0 = not allowed)",
		nil,
	)
	c.maintenanceMode = buildPrometheusDesc(c.subsystem, "maintenance_mode",
		"Whether CARP maintenance mode is enabled (1 = enabled, 0 = disabled)",
		nil,
	)
	c.vipsTotal = buildPrometheusDesc(c.subsystem, "vips_total",
		"Total number of CARP Virtual IPs",
		nil,
	)
	c.vipStatus = buildPrometheusDesc(c.subsystem, "vip_status",
		"CARP VIP status (1 = MASTER, 0 = BACKUP, 2 = INIT, -1 = unknown)",
		[]string{"interface", "vhid", "vip"},
	)
	c.vipAdvbase = buildPrometheusDesc(c.subsystem, "vip_advbase_seconds",
		"CARP VIP advertisement base interval in seconds",
		[]string{"interface", "vhid", "vip"},
	)
	c.vipAdvskew = buildPrometheusDesc(c.subsystem, "vip_advskew",
		"CARP VIP advertisement skew",
		[]string{"interface", "vhid", "vip"},
	)
}

func (c *carpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.demotion
	ch <- c.allow
	ch <- c.maintenanceMode
	ch <- c.vipsTotal
	ch <- c.vipStatus
	ch <- c.vipAdvbase
	ch <- c.vipAdvskew
}

func (c *carpCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchCARPStatus()
	if err != nil {
		return err
	}

	allow := 0.0
	if data.Allow {
		allow = 1.0
	}

	maintenance := 0.0
	if data.MaintenanceMode {
		maintenance = 1.0
	}

	ch <- prometheus.MustNewConstMetric(
		c.demotion,
		prometheus.GaugeValue,
		float64(data.Demotion),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.allow,
		prometheus.GaugeValue,
		allow,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.maintenanceMode,
		prometheus.GaugeValue,
		maintenance,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.vipsTotal,
		prometheus.GaugeValue,
		float64(len(data.VIPs)),
		c.instance,
	)

	for _, vip := range data.VIPs {
		ch <- prometheus.MustNewConstMetric(
			c.vipStatus,
			prometheus.GaugeValue,
			float64(vip.Status),
			vip.Interface,
			vip.VHID,
			vip.VIP,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.vipAdvbase,
			prometheus.GaugeValue,
			float64(vip.Advbase),
			vip.Interface,
			vip.VHID,
			vip.VIP,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.vipAdvskew,
			prometheus.GaugeValue,
			float64(vip.Advskew),
			vip.Interface,
			vip.VHID,
			vip.VIP,
			c.instance,
		)
	}

	return nil
}
