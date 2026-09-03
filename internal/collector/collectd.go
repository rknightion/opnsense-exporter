package collector

import (
	"log/slog"
)

type collectdCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &collectdCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: CollectdSubsystem,
			endpoint:  "collectdServiceStatus",
		},
	})
}

func (c *collectdCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the collectd service is running (1 = running, 0 = stopped/disabled)", nil)
}
