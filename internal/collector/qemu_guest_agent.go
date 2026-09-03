package collector

import (
	"log/slog"
)

type qemuGuestAgentCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &qemuGuestAgentCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: QemuGuestAgentSubsystem,
			endpoint:  "qemuGuestAgentServiceStatus",
		},
	})
}

func (c *qemuGuestAgentCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the QEMU Guest Agent service is running (1 = running, 0 = stopped/disabled)", nil)
}
