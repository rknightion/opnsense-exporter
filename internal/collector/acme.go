package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type acmeCollector struct {
	log *slog.Logger

	certificatesTotal *prometheus.Desc
	lastUpdate        *prometheus.Desc
	statusCode        *prometheus.Desc
	statusLastUpdate  *prometheus.Desc
	enabled           *prometheus.Desc
	info              *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &acmeCollector{
		subsystem: ACMESubsystem,
	})
}

func (c *acmeCollector) Name() string {
	return c.subsystem
}

func (c *acmeCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	certLabels := []string{"name", "description"}

	c.certificatesTotal = buildPrometheusDesc(c.subsystem, "certificates_total",
		"Total number of ACME-managed certificates",
		nil,
	)
	c.lastUpdate = buildPrometheusDesc(c.subsystem, "certificate_last_update_timestamp_seconds",
		"Unix timestamp of the last successful ACME certificate issue or renewal (0 = never)",
		certLabels,
	)
	c.statusCode = buildPrometheusDesc(c.subsystem, "certificate_status_code",
		"Numeric ACME operation status code from the last ACME run (100 = default/unknown)",
		certLabels,
	)
	c.statusLastUpdate = buildPrometheusDesc(c.subsystem, "certificate_status_last_update_timestamp_seconds",
		"Unix timestamp of the last ACME client run for this certificate (0 = never run)",
		certLabels,
	)
	c.enabled = buildPrometheusDesc(c.subsystem, "certificate_enabled",
		"Whether this ACME-managed certificate is enabled (1 = enabled, 0 = disabled)",
		certLabels,
	)
	c.info = buildPrometheusDesc(c.subsystem, "certificate_info",
		"ACME certificate information (value is always 1; use labels)",
		[]string{"name", "description", "alt_names"},
	)
}

func (c *acmeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.certificatesTotal
	ch <- c.lastUpdate
	ch <- c.statusCode
	ch <- c.statusLastUpdate
	ch <- c.enabled
	ch <- c.info
}

func (c *acmeCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchACMECertificates()
	if err != nil {
		return err
	}

	// os-acme-client absent → Present=false; stay silent so certificates_total=0
	// (plugin absent) is not confused with a present-but-empty ACME config (#87).
	if !data.Present {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(
		c.certificatesTotal,
		prometheus.GaugeValue,
		float64(data.Total),
		c.instance,
	)

	// ACME metrics are keyed on (name, description), neither guaranteed unique by
	// OPNsense. Emitting two rows with the same tuple fails the whole scrape, so
	// skip duplicates (defence-in-depth alongside the server-side partial-scrape
	// handling) (#81).
	seen := make(map[[2]string]bool, len(data.Certificates))
	for _, cert := range data.Certificates {
		key := [2]string{cert.Name, cert.Description}
		if seen[key] {
			c.log.Warn("skipping ACME certificate with duplicate (name, description) label tuple",
				"name", cert.Name, "description", cert.Description)
			continue
		}
		seen[key] = true

		enabledVal := 0.0
		if cert.Enabled {
			enabledVal = 1.0
		}

		ch <- prometheus.MustNewConstMetric(
			c.enabled,
			prometheus.GaugeValue,
			enabledVal,
			cert.Name,
			cert.Description,
			c.instance,
		)

		ch <- prometheus.MustNewConstMetric(
			c.statusCode,
			prometheus.GaugeValue,
			cert.StatusCode,
			cert.Name,
			cert.Description,
			c.instance,
		)

		ch <- prometheus.MustNewConstMetric(
			c.info,
			prometheus.GaugeValue,
			1,
			cert.Name,
			cert.Description,
			cert.AltNames,
			c.instance,
		)

		// Only emit timestamp metrics when the value is non-zero (i.e., the
		// operation has actually occurred).
		if cert.LastUpdate > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.lastUpdate,
				prometheus.GaugeValue,
				cert.LastUpdate,
				cert.Name,
				cert.Description,
				c.instance,
			)
		}

		if cert.StatusLastUpdate > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.statusLastUpdate,
				prometheus.GaugeValue,
				cert.StatusLastUpdate,
				cert.Name,
				cert.Description,
				c.instance,
			)
		}
	}

	return nil
}
