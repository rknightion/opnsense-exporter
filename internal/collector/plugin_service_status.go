package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// pluginServiceStatusCollector is the shared implementation for plugins whose
// only useful API surface is the standard /service/status endpoint. Each
// plugin still has a small wrapper file so that it remains an independently
// visible collector, with its own subsystem and disable flag.
type pluginServiceStatusCollector struct {
	log            *slog.Logger
	serviceRunning *prometheus.Desc
	subsystem      string
	endpoint       opnsense.EndpointName
	instance       string
}

func (c *pluginServiceStatusCollector) Name() string {
	return c.subsystem
}

func (c *pluginServiceStatusCollector) register(instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	if c.log != nil {
		c.log.Debug("Registering collector", "collector", c.Name())
	}
}

func (c *pluginServiceStatusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serviceRunning
}

func (c *pluginServiceStatusCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	status, present, err := client.FetchServiceStatusOptional(c.endpoint)
	if err != nil {
		return err
	}
	if !present {
		// A 404 means that the plugin is not installed. Do not emit a zero:
		// absence of the series lets dashboards distinguish an absent plugin
		// from an installed but stopped service.
		return nil
	}

	running := 0.0
	if status == "running" {
		running = 1.0
	}
	ch <- prometheus.MustNewConstMetric(
		c.serviceRunning,
		prometheus.GaugeValue,
		running,
		c.instance,
	)
	return nil
}
