package collector

import (
	"context"
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

	caValidFrom *prometheus.Desc
	caValidTo   *prometheus.Desc
	caTotal     *prometheus.Desc

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

	caLabels := []string{"description", "commonname"}

	c.caValidFrom = buildPrometheusDesc(c.subsystem, "ca_valid_from_seconds",
		"Certificate authority valid from timestamp in seconds since epoch",
		caLabels,
	)
	c.caValidTo = buildPrometheusDesc(c.subsystem, "ca_valid_to_seconds",
		"Certificate authority valid to (expiry) timestamp in seconds since epoch",
		caLabels,
	)
	c.caTotal = buildPrometheusDesc(c.subsystem, "ca_total",
		"Total number of certificate authorities",
		nil,
	)
}

func (c *certificatesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.validFrom
	ch <- c.validTo
	ch <- c.info
	ch <- c.certificateTotal
	ch <- c.caValidFrom
	ch <- c.caValidTo
	ch <- c.caTotal
}

func (c *certificatesCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
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

	// Leaf-cert metrics are keyed on (description, commonname, cert_type, in_use),
	// none guaranteed unique — e.g. an old cert left behind with the same
	// description after an ACME renewal. Skip duplicates so one collision doesn't
	// fail the whole scrape (defence-in-depth alongside the server handler) (#81).
	seenLeaf := make(map[[4]string]bool, len(data.Certificates))
	for _, cert := range data.Certificates {
		key := [4]string{cert.Description, cert.CommonName, cert.CertType, cert.InUse}
		if seenLeaf[key] {
			c.log.Warn("skipping certificate with duplicate label tuple",
				"description", cert.Description, "commonname", cert.CommonName,
				"cert_type", cert.CertType, "in_use", cert.InUse)
			continue
		}
		seenLeaf[key] = true

		// Skip valid_from/valid_to for rows with no real expiry data (pending CSR
		// or unparseable blob) rather than emitting epoch 0, which reads as
		// "expired since 1970" and false-fires expiry alerts. The info metric is
		// still emitted for visibility (#167).
		if cert.HasValidFrom {
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
		}
		if cert.HasValidTo {
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
		}
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

	caData, caErr := client.FetchCACertificates()
	if caErr != nil {
		// Leaf-cert metrics already emitted; report the CA failure.
		return caErr
	}

	ch <- prometheus.MustNewConstMetric(c.caTotal, prometheus.GaugeValue,
		float64(caData.Total), c.instance)
	seenCA := make(map[[2]string]bool, len(caData.CAs))
	for _, ca := range caData.CAs {
		key := [2]string{ca.Description, ca.CommonName}
		if seenCA[key] {
			c.log.Warn("skipping CA certificate with duplicate label tuple",
				"description", ca.Description, "commonname", ca.CommonName)
			continue
		}
		seenCA[key] = true
		if ca.HasValidFrom {
			ch <- prometheus.MustNewConstMetric(c.caValidFrom, prometheus.GaugeValue,
				ca.ValidFrom, ca.Description, ca.CommonName, c.instance)
		}
		if ca.HasValidTo {
			ch <- prometheus.MustNewConstMetric(c.caValidTo, prometheus.GaugeValue,
				ca.ValidTo, ca.Description, ca.CommonName, c.instance)
		}
	}

	return nil
}
