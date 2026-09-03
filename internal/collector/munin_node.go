package collector

import (
	"log/slog"
)

type muninNodeCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &muninNodeCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: MuninNodeSubsystem,
			endpoint:  "muninNodeServiceStatus",
		},
	})
}

func (c *muninNodeCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Munin Node service is running (1 = running, 0 = stopped/disabled)", nil)
}
