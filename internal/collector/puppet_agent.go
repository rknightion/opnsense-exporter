package collector

import (
	"log/slog"
)

type puppetAgentCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &puppetAgentCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: PuppetAgentSubsystem,
			endpoint:  "puppetAgentServiceStatus",
		},
	})
}

func (c *puppetAgentCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Puppet Agent service is running (1 = running, 0 = stopped/disabled)", nil)
}
