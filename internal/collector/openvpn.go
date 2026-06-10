package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type openVPNCollector struct {
	log                *slog.Logger
	instances          *prometheus.Desc
	sessions           *prometheus.Desc
	sessionsTotal      *prometheus.Desc
	sessionsByInstance *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &openVPNCollector{
		subsystem: OpenVPNSubsystem,
	})
}

func (c *openVPNCollector) Name() string {
	return c.subsystem
}

func (c *openVPNCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel

	c.log.Debug("Registering collector", "collector", c.Name())

	c.instances = buildPrometheusDesc(c.subsystem, "instances",
		"OpenVPN instances (1 = enabled, 0 = disabled) by role (server, client)",
		[]string{"uuid", "role", "description", "device_type"},
	)
	c.sessions = buildPrometheusDesc(c.subsystem, "sessions",
		"OpenVPN session (1 = ok, 0 = not ok). Only emitted when --exporter.enable-openvpn-details is set.",
		[]string{"description", "real_address", "virtual_address", "username"},
	)
	c.sessionsTotal = buildPrometheusDesc(c.subsystem, "sessions_total",
		"Total number of OpenVPN sessions",
		nil,
	)
	c.sessionsByInstance = buildPrometheusDesc(c.subsystem, "sessions_by_instance",
		"Number of OpenVPN sessions per instance",
		[]string{"description"},
	)
}

func (c *openVPNCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *openVPNCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.instances
	ch <- c.sessions
	ch <- c.sessionsTotal
	ch <- c.sessionsByInstance
}

func (c *openVPNCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	instances, err := client.FetchOpenVPNInstances()
	if err != nil {
		return err
	}
	for _, instance := range instances.Rows {
		ch <- prometheus.MustNewConstMetric(
			c.instances,
			prometheus.GaugeValue,
			float64(instance.Enabled),
			instance.UUID,
			instance.Role,
			instance.Description,
			instance.DevType,
			c.instance,
		)
	}

	sessions, err := client.FetchOpenVPNSessions()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.sessionsTotal,
		prometheus.GaugeValue,
		float64(len(sessions.Rows)),
		c.instance,
	)

	sessionsByInstance := make(map[string]int)
	for _, session := range sessions.Rows {
		sessionsByInstance[session.Description]++
	}
	for description, count := range sessionsByInstance {
		ch <- prometheus.MustNewConstMetric(
			c.sessionsByInstance,
			prometheus.GaugeValue,
			float64(count),
			description,
			c.instance,
		)
	}

	if c.detailsEnabled {
		for _, session := range sessions.Rows {
			ch <- prometheus.MustNewConstMetric(
				c.sessions,
				prometheus.GaugeValue,
				float64(session.Status),
				session.Description,
				session.RealAddress,
				session.VirtualAddress,
				session.Username,
				c.instance,
			)
		}
	}

	return nil
}
