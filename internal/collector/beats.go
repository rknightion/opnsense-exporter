package collector

import (
	"log/slog"
)

type beatsCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &beatsCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: BeatsSubsystem,
			endpoint:  "beatsServiceStatus",
		},
	})
}

func (c *beatsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Beats service is running (1 = running, 0 = stopped/disabled)", nil)
}
