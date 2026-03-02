package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type certificatesCollector struct {
	log *slog.Logger

	validFrom        *prometheus.Desc
	validTo          *prometheus.Desc
	info             *prometheus.Desc
	certificateTotal *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &certificatesCollector{
		subsystem: CertificatesSubsystem,
	})
}

func (c *certificatesCollector) Name() string {
	return c.subsystem
}

func (c *certificatesCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	certLabels := []string{"description", "commonname", "cert_type", "in_use"}

	c.validFrom = buildPrometheusDesc(c.subsystem, "valid_from_seconds",
		"Certificate valid from timestamp in seconds since epoch",
		certLabels,
	)
	c.validTo = buildPrometheusDesc(c.subsystem, "valid_to_seconds",
		"Certificate valid to (expiry) timestamp in seconds since epoch",
		certLabels,
	)
	c.info = buildPrometheusDesc(c.subsystem, "info",
		"Certificate information (value is always 1)",
		certLabels,
	)
	c.certificateTotal = buildPrometheusDesc(c.subsystem, "total",
		"Total number of certificates",
		nil,
	)
}

func (c *certificatesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.validFrom
	ch <- c.validTo
	ch <- c.info
	ch <- c.certificateTotal
}

func (c *certificatesCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchCertificates()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.certificateTotal,
		prometheus.GaugeValue,
		float64(data.Total),
		c.instance,
	)

	for _, cert := range data.Certificates {
		ch <- prometheus.MustNewConstMetric(
			c.validFrom,
			prometheus.GaugeValue,
			cert.ValidFrom,
			cert.Description,
			cert.CommonName,
			cert.CertType,
			cert.InUse,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.validTo,
			prometheus.GaugeValue,
			cert.ValidTo,
			cert.Description,
			cert.CommonName,
			cert.CertType,
			cert.InUse,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.info,
			prometheus.GaugeValue,
			1,
			cert.Description,
			cert.CommonName,
			cert.CertType,
			cert.InUse,
			c.instance,
		)
	}

	return nil
}
