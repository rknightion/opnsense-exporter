package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// siproxdCollector surfaces the count of active SIP registrations tracked by
// the os-siproxd plugin. Deliberately no per-registration user/host labels —
// SIP AORs and their real IPs are PII (#224). This is a validate-first rider:
// the os-siproxd plugin was not installed on the test box used to build this,
// so the underlying line format is derived from source rather than a live
// populated capture; see opnsense/siproxd.go for the verification note.
type siproxdCollector struct {
	log *slog.Logger

	registrations *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &siproxdCollector{
		subsystem: SiproxdSubsystem,
	})
}

func (c *siproxdCollector) Name() string { return c.subsystem }

func (c *siproxdCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.registrations = buildPrometheusDesc(c.subsystem, "registrations",
		"Number of active SIP registrations tracked by siproxd. Silent when the os-siproxd plugin is absent.",
		nil)
}

func (c *siproxdCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.registrations
}

func (c *siproxdCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchSiproxdRegistrations()
	if err != nil {
		return err
	}

	// os-siproxd absent (404) -> Present=false; stay silent, mirroring the
	// other plugin-gated collectors' convention.
	if !data.Present {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.registrations, prometheus.GaugeValue,
		float64(data.Active), c.instance)

	return nil
}
