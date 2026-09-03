package collector

import (
	"log/slog"
)

type wazuhAgentCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &wazuhAgentCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: WazuhAgentSubsystem,
			endpoint:  "wazuhAgentServiceStatus",
		},
	})
}

func (c *wazuhAgentCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Wazuh Agent service is running (1 = running, 0 = stopped/disabled)", nil)
}
