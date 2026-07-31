package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type openVPNCollector struct {
	log                      *slog.Logger
	instances                *prometheus.Desc
	instanceMaxClients       *prometheus.Desc
	sessions                 *prometheus.Desc
	sessionsTotal            *prometheus.Desc
	sessionsByInstance       *prometheus.Desc
	sessionReceivedBytes     *prometheus.Desc
	sessionTransmittedBytes  *prometheus.Desc
	sessionConnectedSince    *prometheus.Desc
	instanceReceivedBytes    *prometheus.Desc
	instanceTransmittedBytes *prometheus.Desc

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
	// instanceMaxClients is default-on (config data, same cardinality profile
	// as the "instances" gauge above -- bounded by configured instance count,
	// not by connected clients) and shares that gauge's exact label surface
	// for joinability. Only emitted for a server whose maxclients is actually
	// configured: an IntegerField with no Default (OpenVPN.xml), so an empty
	// value means "no cap", not "cap of 0" -- see opnsense.OpenVPN.
	// MaxClientsConfigured (#584). Never sent for client-role instances,
	// which have no maxclients concept at all.
	c.instanceMaxClients = buildPrometheusDesc(c.subsystem, "instance_max_clients",
		"Configured concurrent-client cap for this OpenVPN server instance. Divide "+
			"opnsense_openvpn_sessions_by_instance by this (joined on description) for "+
			"a utilization ratio. Only emitted for a server instance with a cap actually "+
			"configured; an unlimited/uncapped server emits no series here.",
		[]string{"uuid", "role", "description", "device_type"},
	)
	c.sessions = buildPrometheusDesc(c.subsystem, "sessions",
		"OpenVPN session (1 = ok, 0 = not ok). Only emitted when --exporter.enable-openvpn-details is set.",
		[]string{"description", "real_address", "virtual_address", "virtual_ipv6_address", "username"},
	)
	c.sessionsTotal = buildPrometheusDesc(c.subsystem, "sessions_total",
		"Total number of OpenVPN sessions",
		nil,
	)
	c.sessionsByInstance = buildPrometheusDesc(c.subsystem, "sessions_by_instance",
		"Number of OpenVPN sessions per instance",
		[]string{"description"},
	)
	// Per-session traffic/connected-since series reuse the exact label surface
	// of the existing "sessions" gauge (description, real_address,
	// virtual_address, virtual_ipv6_address, username), gated behind the same
	// --exporter.enable-openvpn-details flag. The "username" label value
	// prefers the TLS common_name (Sessions.Identity()) over the raw OpenVPN
	// username field, which is the literal "UNDEF" for cert-only sessions (#212).
	// virtual_ipv6_address is a separate label alongside virtual_address
	// (#483): empty for v4-only sessions, populated for dual-stack/v6-only.
	c.sessionReceivedBytes = buildPrometheusDesc(c.subsystem, "session_received_bytes_total",
		"Cumulative bytes received for this OpenVPN session (resets on reconnect). Only emitted when --exporter.enable-openvpn-details is set.",
		[]string{"description", "real_address", "virtual_address", "virtual_ipv6_address", "username"},
	)
	c.sessionTransmittedBytes = buildPrometheusDesc(c.subsystem, "session_transmitted_bytes_total",
		"Cumulative bytes transmitted for this OpenVPN session (resets on reconnect). Only emitted when --exporter.enable-openvpn-details is set.",
		[]string{"description", "real_address", "virtual_address", "virtual_ipv6_address", "username"},
	)
	c.sessionConnectedSince = buildPrometheusDesc(c.subsystem, "session_connected_since_timestamp_seconds",
		"Unix timestamp of when this OpenVPN session connected. Only emitted when --exporter.enable-openvpn-details is set.",
		[]string{"description", "real_address", "virtual_address", "virtual_ipv6_address", "username"},
	)
	// Instance-level traffic aggregates are default-on: no per-session identity
	// label, so cardinality is bounded by the number of configured OpenVPN
	// instances rather than by connected clients (#212).
	c.instanceReceivedBytes = buildPrometheusDesc(c.subsystem, "instance_received_bytes_total",
		"Cumulative bytes received across all active sessions on this OpenVPN instance",
		[]string{"description"},
	)
	c.instanceTransmittedBytes = buildPrometheusDesc(c.subsystem, "instance_transmitted_bytes_total",
		"Cumulative bytes transmitted across all active sessions on this OpenVPN instance",
		[]string{"description"},
	)
}

func (c *openVPNCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *openVPNCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.instances
	ch <- c.instanceMaxClients
	ch <- c.sessions
	ch <- c.sessionsTotal
	ch <- c.sessionsByInstance
	ch <- c.sessionReceivedBytes
	ch <- c.sessionTransmittedBytes
	ch <- c.sessionConnectedSince
	ch <- c.instanceReceivedBytes
	ch <- c.instanceTransmittedBytes
}

func (c *openVPNCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
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
		// Presence-gated (#584): MaxClientsConfigured is false for an
		// unlimited server (empty "maxclients") and for every client-role
		// instance, which must emit no series rather than a fabricated 0.
		if instance.MaxClientsConfigured {
			ch <- prometheus.MustNewConstMetric(
				c.instanceMaxClients,
				prometheus.GaugeValue,
				float64(instance.MaxClients),
				instance.UUID,
				instance.Role,
				instance.Description,
				instance.DevType,
				c.instance,
			)
		}
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
	type instanceTraffic struct {
		received    int64
		transmitted int64
	}
	trafficByInstance := make(map[string]*instanceTraffic)
	for _, session := range sessions.Rows {
		sessionsByInstance[session.Description]++

		t, ok := trafficByInstance[session.Description]
		if !ok {
			t = &instanceTraffic{}
			trafficByInstance[session.Description] = t
		}
		t.received += session.BytesReceived
		t.transmitted += session.BytesTransmitted
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
	// Instance-level traffic aggregates are default-on (#212): summed per
	// description, with no per-session identity label, so cardinality tracks
	// configured OpenVPN instances rather than connected clients.
	for description, t := range trafficByInstance {
		ch <- prometheus.MustNewConstMetric(
			c.instanceReceivedBytes,
			prometheus.CounterValue,
			float64(t.received),
			description,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.instanceTransmittedBytes,
			prometheus.CounterValue,
			float64(t.transmitted),
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
				session.VirtualIPv6Address,
				session.Username,
				c.instance,
			)
			// Per-session traffic counters and connected-since gauge (#212),
			// gated behind the same details flag as the "sessions" gauge above
			// and sharing its exact label surface. The identity label prefers
			// the TLS common_name over the raw username (which is the literal
			// "UNDEF" for cert-only sessions).
			ch <- prometheus.MustNewConstMetric(
				c.sessionReceivedBytes,
				prometheus.CounterValue,
				float64(session.BytesReceived),
				session.Description,
				session.RealAddress,
				session.VirtualAddress,
				session.VirtualIPv6Address,
				session.Identity(),
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.sessionTransmittedBytes,
				prometheus.CounterValue,
				float64(session.BytesTransmitted),
				session.Description,
				session.RealAddress,
				session.VirtualAddress,
				session.VirtualIPv6Address,
				session.Identity(),
				c.instance,
			)
			ch <- prometheus.MustNewConstMetric(
				c.sessionConnectedSince,
				prometheus.GaugeValue,
				float64(session.ConnectedSince),
				session.Description,
				session.RealAddress,
				session.VirtualAddress,
				session.VirtualIPv6Address,
				session.Identity(),
				c.instance,
			)
		}
	}

	return nil
}
