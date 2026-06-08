package collector

import (
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type WireguardCollector struct {
	log             *slog.Logger
	instances       *prometheus.Desc
	peers           *prometheus.Desc
	TransferRx      *prometheus.Desc
	TransferTx      *prometheus.Desc
	LatestHandshake *prometheus.Desc
	HandshakeAge    *prometheus.Desc
	serviceRunning  *prometheus.Desc
	now             func() time.Time

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &WireguardCollector{
		subsystem: WireguardSubsystem,
		now:       time.Now,
	})
}

func (c *WireguardCollector) Name() string {
	return c.subsystem
}

func (c *WireguardCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel

	if c.now == nil {
		c.now = time.Now
	}

	c.log.Debug("Registering collector", "collector", c.Name())

	c.instances = buildPrometheusDesc(c.subsystem, "interfaces_status",
		"Wireguard interface (1 = up, 0 = down)",
		[]string{"device", "device_type", "device_name"},
	)

	c.peers = buildPrometheusDesc(c.subsystem, "peer_status",
		"Wireguard peer status (1 = up, 0 = down, 2 = unknown, 3 = stale)",
		[]string{"device", "device_type", "device_name", "peer_name"},
	)

	c.TransferRx = buildPrometheusDesc(c.subsystem, "peer_received_bytes_total",
		"Bytes received by this wireguard peer",
		[]string{"device", "device_type", "device_name", "peer_name"},
	)

	c.TransferTx = buildPrometheusDesc(c.subsystem, "peer_transmitted_bytes_total",
		"Bytes transmitted by this wireguard peer",
		[]string{"device", "device_type", "device_name", "peer_name"},
	)

	c.LatestHandshake = buildPrometheusDesc(c.subsystem, "peer_last_handshake_seconds",
		"Last handshake by peer in seconds",
		[]string{"device", "device_type", "device_name", "peer_name"},
	)

	c.HandshakeAge = buildPrometheusDesc(c.subsystem, "peer_handshake_age_seconds",
		"Seconds since the peer's last handshake",
		[]string{"device", "device_type", "device_name", "peer_name"},
	)

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the service is running (1 = running, 0 = stopped/disabled)",
		nil,
	)
}

func (c *WireguardCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.instances
	ch <- c.peers
	ch <- c.LatestHandshake
	ch <- c.HandshakeAge
	ch <- c.TransferRx
	ch <- c.TransferTx
	ch <- c.serviceRunning
}

func (c *WireguardCollector) update(ch chan<- prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labelValues ...string) {
	ch <- prometheus.MustNewConstMetric(
		desc, valueType, value, labelValues...,
	)
}

func (c *WireguardCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchWireguardConfig()
	if err != nil {
		return err
	}

	for _, instance := range data.Interfaces {
		c.update(ch, c.instances, prometheus.GaugeValue, float64(instance.Status), instance.Device, instance.DeviceType, instance.DeviceName, c.instance)
	}

	now := c.now()
	for _, instance := range data.Peers {
		c.update(ch, c.peers, prometheus.GaugeValue, float64(instance.Status), instance.Device, instance.DeviceType, instance.DeviceName, instance.Name, c.instance)
		c.update(ch, c.LatestHandshake, prometheus.GaugeValue, float64(instance.LatestHandshake), instance.Device, instance.DeviceType, instance.DeviceName, instance.Name, c.instance)
		c.update(ch, c.TransferRx, prometheus.CounterValue, float64(instance.TransferRx), instance.Device, instance.DeviceType, instance.DeviceName, instance.Name, c.instance)
		c.update(ch, c.TransferTx, prometheus.CounterValue, float64(instance.TransferTx), instance.Device, instance.DeviceType, instance.DeviceName, instance.Name, c.instance)

		if instance.LatestHandshake > 0 {
			age := max(now.Unix()-int64(instance.LatestHandshake), 0)
			c.update(ch, c.HandshakeAge, prometheus.GaugeValue, float64(age), instance.Device, instance.DeviceType, instance.DeviceName, instance.Name, c.instance)
		}
	}

	status, sErr := client.FetchServiceStatus("wireguardServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch service status", "err", sErr)
	} else {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.serviceRunning, prometheus.GaugeValue,
			val, c.instance,
		)
	}

	return nil
}
