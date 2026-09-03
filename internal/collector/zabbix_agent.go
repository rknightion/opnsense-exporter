package collector

import (
	"log/slog"
)

type zabbixAgentCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &zabbixAgentCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: ZabbixAgentSubsystem,
			endpoint:  "zabbixAgentServiceStatus",
		},
	})
}

func (c *zabbixAgentCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Zabbix Agent service is running (1 = running, 0 = stopped/disabled)", nil)
}
