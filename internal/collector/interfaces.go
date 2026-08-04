package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
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

	unknownProtocolPackets  *prometheus.Desc
	attachOrStatResetUptime *prometheus.Desc

	adminUp      *prometheus.Desc
	adminEnabled *prometheus.Desc
	info         *prometheus.Desc

	familyReceivedPackets *prometheus.Desc
	familyReceivedBytes   *prometheus.Desc
	familySentPackets     *prometheus.Desc
	familySentBytes       *prometheus.Desc
	outputQueueDrops      *prometheus.Desc

	laggActivePorts      *prometheus.Desc
	laggFlapping         *prometheus.Desc
	laggInfo             *prometheus.Desc
	laggPortActive       *prometheus.Desc
	laggPortCollecting   *prometheus.Desc
	laggPortDistributing *prometheus.Desc
	bridgeMember         *prometheus.Desc

	sfpInfo          *prometheus.Desc
	sfpTemperature   *prometheus.Desc
	sfpVoltage       *prometheus.Desc
	sfpLaneRXPowerMW *prometheus.Desc
	sfpLaneRXPower   *prometheus.Desc
	sfpLaneTXBias    *prometheus.Desc

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
	gapFillCaveat := " Covers every device netstat reports, assigned or not (#642): OPNsense's " +
		"assigned-interfaces traffic endpoint (api/diagnostics/traffic/interface) is the primary " +
		"source; a device it omits because it has no config identifier (e.g. a WAN's physical port " +
		"underneath a logical PPPoE interface) is filled in from get_interface_statistics instead, " +
		"never both — exactly one source wins per device."
	gapFillPacketCaveat := gapFillCaveat + " On a gap-filled device the packet count (not the byte " +
		"count) is additionally suppressed when it is physically impossible given the paired byte " +
		"count on the same row (fewer than 20 bytes/packet, below the minimum Ethernet frame) — the " +
		"series is absent rather than a fabricated or corrupt count."

	c.bytesReceived = buildPrometheusDesc(c.subsystem, "received_bytes_total",
		"Bytes received on this interface by interface name and device."+gapFillCaveat,
		[]string{"interface", "device", "type"},
	)
	c.bytesTransmited = buildPrometheusDesc(c.subsystem, "transmitted_bytes_total",
		"Bytes transmitted on this interface by interface name and device."+gapFillCaveat,
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
		"Input errors on this interface by interface name and device."+gapFillCaveat,
		[]string{"interface", "device", "type"},
	)
	c.outputErrors = buildPrometheusDesc(c.subsystem, "output_errors_total",
		"Output errors on this interface by interface name and device."+gapFillCaveat,
		[]string{"interface", "device", "type"},
	)
	c.collisions = buildPrometheusDesc(c.subsystem, "collisions_total",
		"Collisions on this interface by interface name and device."+gapFillCaveat,
		[]string{"interface", "device", "type"},
	)
	c.receivedPackets = buildPrometheusDesc(c.subsystem, "received_packets_total",
		"Total packets received on this interface by interface name and device."+gapFillPacketCaveat,
		[]string{"interface", "device", "type"},
	)
	c.transmittedPackets = buildPrometheusDesc(c.subsystem, "transmitted_packets_total",
		"Total packets transmitted on this interface by interface name and device."+gapFillPacketCaveat,
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
		"Send queue drops on this interface by interface name and device. Not emitted for an interface whose reported figure has wrapped through an unsigned 32-bit field (see input_queue_drops_total). Note this counter reads the legacy if_snd.ifq_drops and is structurally always 0 on modern buf_ring drivers, so it is not worth alerting on.",
		[]string{"interface", "device", "type"},
	)
	c.inputQueueDrops = buildPrometheusDesc(c.subsystem, "input_queue_drops_total",
		"Input queue drops on this interface by interface name and device. A value that reinterprets as a negative int32 has wrapped through an unsigned 32-bit field below the exporter (prod ixl1 reports 4294958080, which is -9216) and is suppressed rather than published: the series is absent for that interface, since a fabricated 0 would falsely assert it reported no drops.",
		[]string{"interface", "device", "type"},
	)
	c.linkState = buildPrometheusDesc(c.subsystem, "link_state",
		"Link state of this interface (1=up, 0=down, 2=unknown) by interface name and device. 2 (unknown) is reported by the kernel for carrier-less pseudo-devices such as PPPoE and tun/tailscale interfaces, which have no carrier-sense concept and are not actually down; alert on link_state==0, not link_state!=1.",
		[]string{"interface", "device", "type"},
	)
	c.lineRate = buildPrometheusDesc(c.subsystem, "line_rate_bits",
		"Line rate in bits per second on this interface by interface name and device. Not emitted for a carrier-less pseudo-device (the kernel's link state reads unknown — PPPoE, tun/tailscale, similar overlay interfaces): the kernel reports a placeholder there rather than a real negotiated rate (ng_pppoe reports a static 64000 regardless of the underlying WAN's actual speed), and publishing it would make rate(bytes)/line_rate_bits wrong by orders of magnitude (#644). Ethernet devices are unaffected.",
		[]string{"interface", "device", "type"},
	)
	c.unknownProtocolPackets = buildPrometheusDesc(c.subsystem, "unknown_protocol_packets_total",
		"Packets delivered to this interface that the network stack could not classify (kernel \"packets for unknown protocol\" counter) by interface name and device.",
		[]string{"interface", "device", "type"},
	)
	c.attachOrStatResetUptime = buildPrometheusDesc(c.subsystem, "attach_or_statistics_reset_uptime_seconds",
		"System-uptime reading at which this interface was attached OR its statistics were explicitly reset (the kernel does not distinguish the two cases) by interface name and device. Only emitted when the box reports this marker. Compute age since attach/reset with opnsense_system_uptime_seconds - opnsense_interfaces_attach_or_statistics_reset_uptime_seconds.",
		[]string{"interface", "device", "type"},
	)
	c.adminUp = buildPrometheusDesc(c.subsystem, "admin_up",
		"Administrative status of this interface (1 = configured up / ifconfig UP flag set, 0 = admin down). Compare with link_state for carrier detection. Join with other interfaces metrics on the device label; the interface label here is the overview description, which can differ from the traffic-based metrics' interface name for unassigned/pseudo devices.",
		[]string{"interface", "device"},
	)
	c.adminEnabled = buildPrometheusDesc(c.subsystem, "admin_enabled",
		"OPNsense config-level enabled flag for this interface (1 = enabled in Interfaces > [name], "+
			"0 = administratively disabled in config). Distinct from admin_up, which reflects the "+
			"ifconfig UP flag (kernel/runtime state) rather than configuration: use admin_enabled to "+
			"separate a deliberately-disabled interface (expected, not an incident) from one that is "+
			"enabled in config but down (a real problem). This endpoint's response is cached for "+
			"--exporter.cache-ttl (#573); that is fine here since this is config data, not a live "+
			"status the cache would stale-freeze.",
		[]string{"interface", "device"},
	)
	c.info = buildPrometheusDesc(c.subsystem, "info",
		"Interface identity from the interfaces overview API (media/duplex, link type, VLAN topology) plus the kernel driver name and HW offload capability set from the traffic API. Value is always 1. Join on the device label. The media label can change on link renegotiation, starting a new series. driver is the kernel driver name (e.g. igb, ixl, ixgbe) — ixl/ixgbe/igb override IFCOUNTER_OQDROPS in their own if_get_counter, so a per-driver caveat on output_queue_drops_total and on a wrapped input_queue_drops_total figure can be checked against it. hw_offload_capabilities is the box's checksum/TSO/LRO offload state, comma-joined and sorted for stability; both are empty when the device has no matching row in the traffic API fetch.",
		[]string{"interface", "device", "identifier", "media", "link_type", "vlan_tag", "vlan_parent", "physical", "driver", "hw_offload_capabilities"},
	)

	familyLabels := []string{"device", "family"}
	familyCaveat := " Counted per LOCAL ADDRESS, so this is traffic to and from the firewall's own " +
		"addresses only: forwarded transit traffic is not attributed to any local address and does " +
		"NOT appear here. On the reference box ixl0's device total read 419.9M received packets " +
		"while its address rows summed to 24.5M, about 6%. Read this as which address family the " +
		"box itself is talking, not as a split of what the interface forwards — for the device " +
		"total use the received_packets_total/received_bytes_total families, which have no such " +
		"split available from any endpoint. Addresses of the same family on one device are summed; " +
		"the address itself is deliberately not a label."

	c.familyReceivedPackets = buildPrometheusDesc(c.subsystem, "address_family_received_packets_total",
		"Packets received on this device's addresses of this family (ipv4/ipv6)."+familyCaveat,
		familyLabels,
	)
	c.familyReceivedBytes = buildPrometheusDesc(c.subsystem, "address_family_received_bytes_total",
		"Bytes received on this device's addresses of this family (ipv4/ipv6)."+familyCaveat,
		familyLabels,
	)
	c.familySentPackets = buildPrometheusDesc(c.subsystem, "address_family_sent_packets_total",
		"Packets sent from this device's addresses of this family (ipv4/ipv6)."+familyCaveat,
		familyLabels,
	)
	c.familySentBytes = buildPrometheusDesc(c.subsystem, "address_family_sent_bytes_total",
		"Bytes sent from this device's addresses of this family (ipv4/ipv6)."+familyCaveat,
		familyLabels,
	)
	c.outputQueueDrops = buildPrometheusDesc(c.subsystem, "output_queue_drops_total",
		"Packets the kernel dropped on this device's output queue (netstat's Drop column, "+
			"IFCOUNTER_OQDROPS). CAVEAT, and it matters: on ixl, ixgbe and igb the driver overrides "+
			"IFCOUNTER_OQDROPS in its own if_get_counter and reports its own figure, so on those "+
			"NICs a flat zero here does NOT prove nothing is dropping — netmap's drops in "+
			"particular are invisible. Treat a non-zero value as real and a zero on those drivers "+
			"as no information. Covers every device netstat reports, including unassigned ports and "+
			"pseudo-devices that send_queue_drops_total omits entirely (on the dev boxes tailscale0 "+
			"is the only device with non-zero drops and the only one missing from that metric).",
		[]string{"device"},
	)

	c.laggInfo = buildPrometheusDesc(c.subsystem, "lagg_info",
		"LAGG (link aggregation) interface protocol/hash configuration. Value is always 1. Only emitted for interfaces that are themselves a lagg device. Join on the device label.",
		[]string{"device", "protocol", "hash"},
	)
	c.laggActivePorts = buildPrometheusDesc(c.subsystem, "lagg_active_ports",
		"Number of currently active (traffic-carrying) member ports in this LAGG interface. Only emitted when the box reports a lagg statistics block for this device.",
		[]string{"device"},
	)
	c.laggFlapping = buildPrometheusDesc(c.subsystem, "lagg_flapping_total",
		"Cumulative count of LAGG active-port membership change (flap) events since the last stat reset. Only emitted when the box reports a lagg statistics block for this device.",
		[]string{"device"},
	)
	c.laggPortActive = buildPrometheusDesc(c.subsystem, "lagg_port_active",
		"Whether this LAGG member port is currently active/selected to carry traffic (1) or not (0). The device label is the owning lagg interface; member is the physical port.",
		[]string{"device", "member"},
	)
	c.laggPortCollecting = buildPrometheusDesc(c.subsystem, "lagg_port_collecting",
		"LACP collecting state (RX distribution enabled) for this LAGG member port (1=collecting, 0=not). Only emitted for LACP laggs whose laggport reported a state; failover/loadbalance laggs never carry this state and emit no series.",
		[]string{"device", "member"},
	)
	c.laggPortDistributing = buildPrometheusDesc(c.subsystem, "lagg_port_distributing",
		"LACP distributing state (TX distribution enabled) for this LAGG member port (1=distributing, 0=not). Only emitted for LACP laggs whose laggport reported a state; failover/loadbalance laggs never carry this state and emit no series.",
		[]string{"device", "member"},
	)
	c.bridgeMember = buildPrometheusDesc(c.subsystem, "bridge_member",
		"Whether this interface is a member of the given bridge(4) interface. Value is always 1. The device label is the owning bridge interface; member is the attached interface.",
		[]string{"device", "member"},
	)
	c.sfpInfo = buildPrometheusDesc(c.subsystem, "sfp_info",
		"SFP/SFP+ transceiver identity for this interface's optical cage. Value is always 1. Emitted for any plugged module, optical or copper. Join on the device label.",
		[]string{"device", "vendor", "part_number", "serial_number"},
	)
	c.sfpTemperature = buildPrometheusDesc(c.subsystem, "sfp_temperature_celsius",
		"SFP module temperature in degrees Celsius (Digital Optical Monitoring). Only emitted when the transceiver reports a DOM temperature reading; copper RJ45 SFPs never report DOM and emit no series here.",
		[]string{"device"},
	)
	c.sfpVoltage = buildPrometheusDesc(c.subsystem, "sfp_voltage_volts",
		"SFP module supply voltage in volts (Digital Optical Monitoring). Only emitted when the transceiver reports a DOM voltage reading; copper RJ45 SFPs never report DOM and emit no series here.",
		[]string{"device"},
	)
	c.sfpLaneRXPowerMW = buildPrometheusDesc(c.subsystem, "sfp_lane_rx_power_milliwatts",
		"SFP per-lane received optical power in milliwatts, linear scale (Digital Optical Monitoring). See also sfp_lane_rx_power_dbm for the logarithmic (dBm) reading of the same measurement. Only emitted for lanes with a DOM RX power reading; copper RJ45 SFPs never report DOM and emit no series here.",
		[]string{"device", "lane"},
	)
	c.sfpLaneRXPower = buildPrometheusDesc(c.subsystem, "sfp_lane_rx_power_dbm",
		"SFP per-lane received optical power in dBm, logarithmic scale (Digital Optical Monitoring). See also sfp_lane_rx_power_milliwatts for the linear (mW) reading of the same measurement. Only emitted for lanes with a DOM RX power reading; copper RJ45 SFPs never report DOM and emit no series here. NOTE (#456): before this release this series erroneously published the mW reading under the _dbm name — values will step-change to the correct (and much smaller-magnitude, often negative) dBm figure.",
		[]string{"device", "lane"},
	)
	c.sfpLaneTXBias = buildPrometheusDesc(c.subsystem, "sfp_lane_tx_bias_milliamps",
		"SFP per-lane laser bias current in milliamps (Digital Optical Monitoring). Only emitted for lanes with a DOM TX bias reading; copper RJ45 SFPs never report DOM and emit no series here.",
		[]string{"device", "lane"},
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
	ch <- c.unknownProtocolPackets
	ch <- c.attachOrStatResetUptime
	ch <- c.adminUp
	ch <- c.adminEnabled
	ch <- c.info
	ch <- c.familyReceivedPackets
	ch <- c.familyReceivedBytes
	ch <- c.familySentPackets
	ch <- c.familySentBytes
	ch <- c.outputQueueDrops
	ch <- c.laggInfo
	ch <- c.laggActivePorts
	ch <- c.laggFlapping
	ch <- c.laggPortActive
	ch <- c.laggPortCollecting
	ch <- c.laggPortDistributing
	ch <- c.bridgeMember
	ch <- c.sfpInfo
	ch <- c.sfpTemperature
	ch <- c.sfpVoltage
	ch <- c.sfpLaneRXPowerMW
	ch <- c.sfpLaneRXPower
	ch <- c.sfpLaneTXBias
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
		// Presence-gated: the box can report a queue-drop figure that has wrapped
		// through an unsigned 32-bit field (prod ixl1 sends 4294958080 = -9216),
		// which is not a count at any scale. Emitting nothing is honest; emitting
		// it verbatim reads as 4.29 billion drops on a healthy interface and makes
		// every rate() over the wrap garbage (#548).
		if iface.SendQueueDropsValid {
			c.update(ch, c.sendQueueDrops, prometheus.CounterValue, float64(iface.SendQueueDrops), iface.Name, iface.Device, iface.Type, c.instance)
		}
		if iface.InputQueueDropsValid {
			c.update(ch, c.inputQueueDrops, prometheus.CounterValue, float64(iface.InputQueueDrops), iface.Name, iface.Device, iface.Type, c.instance)
		}
		c.update(ch, c.linkState, prometheus.GaugeValue, float64(iface.LinkState), iface.Name, iface.Device, iface.Type, c.instance)
		// Presence-gated (#644): a carrier-less pseudo-device (LinkState
		// Unknown — PPPoE, tun/tailscale, similar overlays) reports a line
		// rate that is a kernel placeholder, not a real negotiated speed
		// (pppoe0=64000, tailscale0/zen0=0 on the reference box). A
		// suppressed series cannot be divided by; a published garbage one
		// silently corrupts any rate(bytes)/line_rate_bits panel. See
		// Interface.LineRateValid.
		if iface.LineRateValid {
			c.update(ch, c.lineRate, prometheus.GaugeValue, float64(iface.LineRate), iface.Name, iface.Device, iface.Type, c.instance)
		}
		c.update(ch, c.unknownProtocolPackets, prometheus.CounterValue, float64(iface.UnknownProtocolPackets), iface.Name, iface.Device, iface.Type, c.instance)
		if iface.AttachOrStatResetValid {
			// Presence-gated: the marker is a point-in-time uptime reading, not a
			// counter, so an absent/malformed wire value must emit no series at
			// all rather than a fabricated boot-time zero. A genuine wire "0" IS
			// emitted here (Valid=true, Uptime=0) — see Interface.AttachOrStatResetValid (#375).
			c.update(ch, c.attachOrStatResetUptime, prometheus.GaugeValue, float64(iface.AttachOrStatResetUptime), iface.Name, iface.Device, iface.Type, c.instance)
		}
	}

	// driverByDevice/hwOffloadByDevice join the traffic-endpoint fetch above
	// onto the overview-endpoint info metric below by device name: Driver and
	// HWOffloadCapabilities are only decoded from api/diagnostics/traffic/interface
	// (data.Interfaces), not from the overview endpoint, so the info metric's
	// per-device loop needs a lookup rather than a field already on hand. A
	// device present in the overview but absent from the traffic fetch (e.g. an
	// unassigned VLAN sub-interface) degrades to empty labels, never an error.
	//
	// trafficCoveredDevices (#642) is the explicit, testable record of which
	// devices this scrape already got counters for from the traffic
	// endpoint's own loop above. It is what the get_interface_statistics
	// gap-fill branch at the bottom of this function checks before emitting
	// anything, so that branch can add ONLY devices missing here — never a
	// second, independently-drifting series for one already covered.
	// TestInterfacesCollector_StatisticsGapFill_NoDoubleSource pins this.
	driverByDevice := make(map[string]string, len(data.Interfaces))
	hwOffloadByDevice := make(map[string]string, len(data.Interfaces))
	trafficCoveredDevices := make(map[string]bool, len(data.Interfaces))
	for _, iface := range data.Interfaces {
		driverByDevice[iface.Device] = iface.Driver
		hwOffloadByDevice[iface.Device] = iface.HWOffloadCapabilities
		trafficCoveredDevices[iface.Device] = true
	}

	overview, oerr := client.FetchInterfacesOverview()
	if oerr != nil {
		// Partial tolerance: the traffic metrics above were already emitted, so keep
		// them. But surface the overview failure through the standard collector error
		// path (endpoint_errors_total + scrape_collector_success=0) rather than
		// swallowing it with a nil return — mirroring kea.go's return-the-error pattern
		// so a persistent overview outage is observable via the exporter's own
		// instrumentation, not just a Warn log (#123).
		c.log.Warn("failed to fetch interfaces overview; skipping interface info metrics", "err", oerr)
		return oerr
	}

	// descriptionByDevice (#642) supplies the "interface" label for a
	// gap-filled device below, matching the precedent already established
	// for admin_up/admin_enabled just below: for an unassigned/pseudo device
	// the traffic endpoint never had a friendly name for it, so the overview
	// endpoint's description ("Unassigned Interface" etc.) is what stands in.
	descriptionByDevice := make(map[string]string, len(overview.Interfaces))

	for _, iface := range overview.Interfaces {
		descriptionByDevice[iface.Device] = iface.Description

		adminVal := 0.0
		if iface.AdminUp {
			adminVal = 1.0
		}
		c.update(ch, c.adminUp, prometheus.GaugeValue, adminVal,
			iface.Description, iface.Device, c.instance)

		// admin_enabled emits unconditionally, like admin_up above. Enabled
		// zero-values to false when the box's "enabled" key is absent (see
		// the CORRECTION on interfaceOverviewRow.Enabled's field comment in
		// opnsense/interfaces.go, #642) — which is semantically right for
		// an unassigned interface ("no config to enable"), so there is no
		// case where presence-gating this value would change anything
		// (#584).
		enabledVal := 0.0
		if iface.Enabled {
			enabledVal = 1.0
		}
		c.update(ch, c.adminEnabled, prometheus.GaugeValue, enabledVal,
			iface.Description, iface.Device, c.instance)

		physical := "false"
		if iface.Physical {
			physical = "true"
		}
		c.update(ch, c.info, prometheus.GaugeValue, 1,
			iface.Description, iface.Device, iface.Identifier, iface.Media,
			iface.LinkType, iface.VlanTag, iface.VlanParent, physical,
			driverByDevice[iface.Device], hwOffloadByDevice[iface.Device], c.instance)
	}

	// LAGG, bridge and SFP data are all hardware/config-dependent (absent on
	// most boxes) — each block below degrades to emitting nothing rather than
	// a zero when the box has no lagg, no bridge, or a DOM-incapable (e.g.
	// copper RJ45) transceiver (#214).
	for _, lagg := range overview.Laggs {
		c.update(ch, c.laggInfo, prometheus.GaugeValue, 1, lagg.Device, lagg.Protocol, lagg.Hash, c.instance)
		if lagg.StatsPresent {
			c.update(ch, c.laggActivePorts, prometheus.GaugeValue, float64(lagg.ActivePorts), lagg.Device, c.instance)
			c.update(ch, c.laggFlapping, prometheus.CounterValue, float64(lagg.Flapping), lagg.Device, c.instance)
		}
	}
	for _, port := range overview.LaggPorts {
		active := 0.0
		if port.Active {
			active = 1.0
		}
		c.update(ch, c.laggPortActive, prometheus.GaugeValue, active, port.Lagg, port.Port, c.instance)
		if port.StatePresent {
			collecting := 0.0
			if port.Collecting {
				collecting = 1.0
			}
			c.update(ch, c.laggPortCollecting, prometheus.GaugeValue, collecting, port.Lagg, port.Port, c.instance)
			distributing := 0.0
			if port.Distributing {
				distributing = 1.0
			}
			c.update(ch, c.laggPortDistributing, prometheus.GaugeValue, distributing, port.Lagg, port.Port, c.instance)
		}
	}
	for _, member := range overview.BridgeMembers {
		c.update(ch, c.bridgeMember, prometheus.GaugeValue, 1, member.Bridge, member.Member, c.instance)
	}
	for _, sfp := range overview.SFPModules {
		c.update(ch, c.sfpInfo, prometheus.GaugeValue, 1, sfp.Device, sfp.Vendor, sfp.PartNumber, sfp.SerialNumber, c.instance)
		if sfp.TemperaturePresent {
			c.update(ch, c.sfpTemperature, prometheus.GaugeValue, sfp.TemperatureC, sfp.Device, c.instance)
		}
		if sfp.VoltagePresent {
			c.update(ch, c.sfpVoltage, prometheus.GaugeValue, sfp.VoltageV, sfp.Device, c.instance)
		}
		for _, lane := range sfp.Lanes {
			// rx_power's mW and dBm halves are presence-gated independently
			// (#456): a malformed/absent half must never suppress or
			// zero-substitute the other.
			if lane.RXPowerMWPresent {
				c.update(ch, c.sfpLaneRXPowerMW, prometheus.GaugeValue, lane.RXPowerMW, sfp.Device, lane.Lane, c.instance)
			}
			if lane.RXPowerPresent {
				c.update(ch, c.sfpLaneRXPower, prometheus.GaugeValue, lane.RXPowerDBM, sfp.Device, lane.Lane, c.instance)
			}
			if lane.TXBiasPresent {
				c.update(ch, c.sfpLaneTXBias, prometheus.GaugeValue, lane.TXBiasMA, sfp.Device, lane.Lane, c.instance)
			}
		}
	}

	// get_interface_statistics is a SECOND API call on this collector's poll. It
	// is the only source for the per-address-family split and for oqdrops on
	// devices the traffic endpoint omits, and it is a plain netstat read, but it
	// is not free — see the collector's poll tier.
	//
	// Unlike the overview fetch above, a failure here is logged and swallowed
	// rather than returned. The overview carries core identity (admin_up, info)
	// whose absence is a real gap; this endpoint is purely additive, and failing
	// the whole collector for it would flip scrape_collector_success to 0 while
	// every metric that already exists is being collected perfectly well.
	stats, serr := client.FetchInterfaceStatistics()
	if serr != nil {
		c.log.Warn("failed to fetch interface statistics; skipping address-family and output-queue-drop metrics", "err", serr)
		return nil
	}
	for _, f := range stats.Families {
		c.update(ch, c.familyReceivedPackets, prometheus.CounterValue, f.ReceivedPackets, f.Device, f.Family, c.instance)
		c.update(ch, c.familyReceivedBytes, prometheus.CounterValue, f.ReceivedBytes, f.Device, f.Family, c.instance)
		c.update(ch, c.familySentPackets, prometheus.CounterValue, f.SentPackets, f.Device, f.Family, c.instance)
		c.update(ch, c.familySentBytes, prometheus.CounterValue, f.SentBytes, f.Device, f.Family, c.instance)
	}
	for _, l := range stats.Links {
		// Presence-gated: a device whose AF_LINK row carries no dropped-packets
		// key must emit no series rather than a fabricated zero, which would be
		// indistinguishable from a healthy device.
		if l.OutputQueueDropsPresent {
			c.update(ch, c.outputQueueDrops, prometheus.CounterValue, l.OutputQueueDrops, l.Device, c.instance)
		}

		// Gap-fill (#642): api/diagnostics/traffic/interface only covers
		// ASSIGNED interfaces — OPNsense's own restriction, not ours — so a
		// purely physical, unassigned port (e.g. ixl2, the SFP+ NIC
		// underneath a PPPoE WAN) gets no traffic/error counters there at
		// all. get_interface_statistics's AF_LINK row covers every device,
		// so it is the only source for that gap. This branch is the ONLY
		// place that source is used for these series, and only for a device
		// trafficCoveredDevices does NOT already have — never both, or two
		// independently-drifting series would exist for one counter and any
		// combined rate() would be nonsense.
		// See TestInterfacesCollector_StatisticsGapFill_NoDoubleSource.
		if trafficCoveredDevices[l.Device] {
			continue
		}
		name := descriptionByDevice[l.Device]
		if name == "" {
			name = l.Device
		}
		// "type" is empty for a gap-filled device: get_interface_statistics
		// carries no equivalent of the traffic endpoint's "type" field, and
		// interfaces_info's overview data has no directly matching concept
		// either — degrading to an empty label matches the existing
		// precedent for driverByDevice/hwOffloadByDevice above rather than
		// guessing at a value.
		c.update(ch, c.bytesReceived, prometheus.CounterValue, l.ReceivedBytes, name, l.Device, "", c.instance)
		c.update(ch, c.bytesTransmited, prometheus.CounterValue, l.SentBytes, name, l.Device, "", c.instance)
		if l.ReceivedPacketsPresent {
			c.update(ch, c.receivedPackets, prometheus.CounterValue, l.ReceivedPackets, name, l.Device, "", c.instance)
		}
		if l.SentPacketsPresent {
			c.update(ch, c.transmittedPackets, prometheus.CounterValue, l.SentPackets, name, l.Device, "", c.instance)
		}
		if l.InputErrorsPresent {
			c.update(ch, c.inputErrors, prometheus.CounterValue, l.InputErrors, name, l.Device, "", c.instance)
		}
		if l.OutputErrorsPresent {
			c.update(ch, c.outputErrors, prometheus.CounterValue, l.OutputErrors, name, l.Device, "", c.instance)
		}
		if l.CollisionsPresent {
			c.update(ch, c.collisions, prometheus.CounterValue, l.Collisions, name, l.Device, "", c.instance)
		}
	}

	return nil
}
