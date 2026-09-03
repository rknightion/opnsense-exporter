package collector

import (
	"log/slog"
)

type netdataCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &netdataCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: NetdataSubsystem,
			endpoint:  "netdataServiceStatus",
		},
	})
}

func (c *netdataCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the netdata service is running (1 = running, 0 = stopped/disabled)", nil)
}
