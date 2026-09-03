package collector

import (
	"log/slog"
)

type telegrafCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &telegrafCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: TelegrafSubsystem,
			endpoint:  "telegrafServiceStatus",
		},
	})
}

func (c *telegrafCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the telegraf service is running (1 = running, 0 = stopped/disabled)", nil)
}
