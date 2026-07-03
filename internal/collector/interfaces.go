package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type interfacesCollector struct {
	log *slog.Logger

	mtu                   *prometheus.Desc
	bytesReceived         *prometheus.Desc
	bytesTransmited       *prometheus.Desc
	multicastsTransmitted *prometheus.Desc
	multicastsReceived    *prometheus.Desc
	inputErrors           *prometheus.Desc
	outputErrors          *prometheus.Desc
	collisions            *prometheus.Desc
	receivedPackets       *prometheus.Desc
	transmittedPackets    *prometheus.Desc
	sendQueueLength       *prometheus.Desc
	sendQueueMaxLength    *prometheus.Desc
	sendQueueDrops        *prometheus.Desc
	inputQueueDrops       *prometheus.Desc
	linkState             *prometheus.Desc
	lineRate              *prometheus.Desc

	adminUp *prometheus.Desc
	info    *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &interfacesCollector{
		subsystem: InterfacesSubsystem,
	})
}

func (c *interfacesCollector) Name() string {
	return c.subsystem
}

func (c *interfacesCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel

	c.log.Debug("Registering collector", "collector", c.Name())

	c.mtu = buildPrometheusDesc(c.subsystem, "mtu_bytes",
		"The MTU value of the interface",
		[]string{"interface", "device", "type"},
	)
	c.bytesReceived = buildPrometheusDesc(c.subsystem, "received_bytes_total",
		"Bytes received on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.bytesTransmited = buildPrometheusDesc(c.subsystem, "transmitted_bytes_total",
		"Bytes transmitted on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.multicastsReceived = buildPrometheusDesc(c.subsystem, "received_multicasts_total",
		"Multicasts received on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.multicastsTransmitted = buildPrometheusDesc(c.subsystem, "transmitted_multicasts_total",
		"Multicasts transmitted on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.inputErrors = buildPrometheusDesc(c.subsystem, "input_errors_total",
		"Input errors on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.outputErrors = buildPrometheusDesc(c.subsystem, "output_errors_total",
		"Output errors on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.collisions = buildPrometheusDesc(c.subsystem, "collisions_total",
		"Collisions on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.receivedPackets = buildPrometheusDesc(c.subsystem, "received_packets_total",
		"Total packets received on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.transmittedPackets = buildPrometheusDesc(c.subsystem, "transmitted_packets_total",
		"Total packets transmitted on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.sendQueueLength = buildPrometheusDesc(c.subsystem, "send_queue_length",
		"Current send queue length on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.sendQueueMaxLength = buildPrometheusDesc(c.subsystem, "send_queue_max_length",
		"Maximum send queue length on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.sendQueueDrops = buildPrometheusDesc(c.subsystem, "send_queue_drops_total",
		"Send queue drops on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.inputQueueDrops = buildPrometheusDesc(c.subsystem, "input_queue_drops_total",
		"Input queue drops on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.linkState = buildPrometheusDesc(c.subsystem, "link_state",
		"Link state of this interface (1=up, 0=down, 2=unknown) by interface name and device. 2 (unknown) is reported by the kernel for carrier-less pseudo-devices such as PPPoE and tun/tailscale interfaces, which have no carrier-sense concept and are not actually down; alert on link_state==0, not link_state!=1.",
		[]string{"interface", "device", "type"},
	)
	c.lineRate = buildPrometheusDesc(c.subsystem, "line_rate_bits",
		"Line rate in bits per second on this interface by interface name and device",
		[]string{"interface", "device", "type"},
	)
	c.adminUp = buildPrometheusDesc(c.subsystem, "admin_up",
		"Administrative status of this interface (1 = configured up / ifconfig UP flag set, 0 = admin down). Compare with link_state for carrier detection. Join with other interfaces metrics on the device label; the interface label here is the overview description, which can differ from the traffic-based metrics' interface name for unassigned/pseudo devices.",
		[]string{"interface", "device"},
	)
	c.info = buildPrometheusDesc(c.subsystem, "info",
		"Interface identity from the interfaces overview API (media/duplex, link type, VLAN topology). Value is always 1. Join on the device label. The media label can change on link renegotiation, starting a new series.",
		[]string{"interface", "device", "identifier", "media", "link_type", "vlan_tag", "vlan_parent", "physical"},
	)
}

func (c *interfacesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.mtu
	ch <- c.bytesReceived
	ch <- c.bytesTransmited
	ch <- c.multicastsReceived
	ch <- c.multicastsTransmitted
	ch <- c.inputErrors
	ch <- c.outputErrors
	ch <- c.collisions
	ch <- c.receivedPackets
	ch <- c.transmittedPackets
	ch <- c.sendQueueLength
	ch <- c.sendQueueMaxLength
	ch <- c.sendQueueDrops
	ch <- c.inputQueueDrops
	ch <- c.linkState
	ch <- c.lineRate
	ch <- c.adminUp
	ch <- c.info
}

func (c *interfacesCollector) update(ch chan<- prometheus.Metric, desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labelValues ...string) {
	ch <- prometheus.MustNewConstMetric(
		desc, valueType, value, labelValues...,
	)
}

func (c *interfacesCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchInterfaces()
	if err != nil {
		return err
	}

	for _, iface := range data.Interfaces {
		c.update(ch, c.mtu, prometheus.GaugeValue, float64(iface.MTU), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.bytesReceived, prometheus.CounterValue, float64(iface.BytesReceived), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.bytesTransmited, prometheus.CounterValue, float64(iface.BytesTransmitted), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.multicastsReceived, prometheus.CounterValue, float64(iface.MulticastsReceived), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.multicastsTransmitted, prometheus.CounterValue, float64(iface.MulticastsTransmitted), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.inputErrors, prometheus.CounterValue, float64(iface.InputErrors), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.outputErrors, prometheus.CounterValue, float64(iface.OutputErrors), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.collisions, prometheus.CounterValue, float64(iface.Collisions), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.receivedPackets, prometheus.CounterValue, float64(iface.PacketsReceived), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.transmittedPackets, prometheus.CounterValue, float64(iface.PacketsTransmitted), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.sendQueueLength, prometheus.GaugeValue, float64(iface.SendQueueLength), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.sendQueueMaxLength, prometheus.GaugeValue, float64(iface.SendQueueMaxLength), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.sendQueueDrops, prometheus.CounterValue, float64(iface.SendQueueDrops), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.inputQueueDrops, prometheus.CounterValue, float64(iface.InputQueueDrops), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.linkState, prometheus.GaugeValue, float64(iface.LinkState), iface.Name, iface.Device, iface.Type, c.instance)
		c.update(ch, c.lineRate, prometheus.GaugeValue, float64(iface.LineRate), iface.Name, iface.Device, iface.Type, c.instance)
	}

	overview, oerr := client.FetchInterfacesOverview()
	if oerr != nil {
		// Non-fatal: keep the traffic metrics flowing even if the overview
		// endpoint is unavailable.
		c.log.Warn("failed to fetch interfaces overview; skipping interface info metrics", "err", oerr)
		return nil
	}

	for _, iface := range overview.Interfaces {
		adminVal := 0.0
		if iface.AdminUp {
			adminVal = 1.0
		}
		c.update(ch, c.adminUp, prometheus.GaugeValue, adminVal,
			iface.Description, iface.Device, c.instance)

		physical := "false"
		if iface.Physical {
			physical = "true"
		}
		c.update(ch, c.info, prometheus.GaugeValue, 1,
			iface.Description, iface.Device, iface.Identifier, iface.Media,
			iface.LinkType, iface.VlanTag, iface.VlanParent, physical, c.instance)
	}

	return nil
}
