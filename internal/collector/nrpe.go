package collector

import (
	"log/slog"
)

type nrpeCollector struct {
	pluginServiceStatusCollector
}

func init() {
	collectorInstances = append(collectorInstances, &nrpeCollector{
		pluginServiceStatusCollector: pluginServiceStatusCollector{
			subsystem: NRPESubsystem,
			endpoint:  "nrpeServiceStatus",
		},
	})
}

func (c *nrpeCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.register(instanceLabel, log)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the NRPE service is running (1 = running, 0 = stopped/disabled)", nil)
}
