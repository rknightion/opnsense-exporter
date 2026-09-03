package collector

import (
	"log/slog"
)

type netSNMPCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &netSNMPCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: NetSNMPSubsystem,
			endpoint:  "netSnmpServiceStatus",
		},
	})
}

func (c *netSNMPCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Net-SNMP service is running (1 = running, 0 = stopped/disabled)", nil)
}
