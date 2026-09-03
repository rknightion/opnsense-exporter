package collector

import (
	"log/slog"
)

type nodeExporterCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &nodeExporterCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: NodeExporterSubsystem,
			endpoint:  "nodeExporterServiceStatus",
		},
	})
}

func (c *nodeExporterCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the node_exporter service is running (1 = running, 0 = stopped/disabled)", nil)
}
