package collector

import (
	"log/slog"
)

type zabbixProxyCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &zabbixProxyCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: ZabbixProxySubsystem,
			endpoint:  "zabbixProxyServiceStatus",
		},
	})
}

func (c *zabbixProxyCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Zabbix Proxy service is running (1 = running, 0 = stopped/disabled)", nil)
}
