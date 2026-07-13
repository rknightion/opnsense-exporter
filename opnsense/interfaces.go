package opnsense

import (
	"regexp"
	"sort"
	"strings"
)

// Interface link-state values. The OPNsense/FreeBSD kernel link state is
// tri-state: "unknown" is reported for carrier-less pseudo-devices (PPPoE,
// tun/tailscale) and must be distinguished from a genuine "down", otherwise a
// healthy PPPoE WAN reads as permanently down (#86).
const (
	LinkStateDown    = 0
	LinkStateUp      = 1
	LinkStateUnknown = 2
)

type InterfaceDetails struct {
	Device                    string `json:"device"`
	Driver                    string `json:"driver"`
	Index                     string `json:"index"`
	Flags                     string `json:"flags"`
	PromiscuousListeners      string `json:"promiscuous listeners"`
	SendQueueLength           string `json:"send queue length"`
	SendQueueMaxLength        string `json:"send queue max length"`
	SendQueueDrops            string `json:"send queue drops"`
	Type                      string `json:"type"`
	AddressLength             string `json:"address length"`
	HeaderLength              string `json:"header length"`
	LinkState                 string `json:"link state"`
	Vhid                      string `json:"vhid"`
	Datalen                   string `json:"datalen"`
	MTU                       string `json:"mtu"`
	Metric                    string `json:"metric"`
	LineRate                  string `json:"line rate"`
	PacketsReceived           string `json:"packets received"`
	PacketsTransmitted        string `json:"packets transmitted"`
	BytesReceived             string `json:"bytes received"`
	BytesTransmitted          string `json:"bytes transmitted"`
	OutputErrors              string `json:"output errors"`
	InputErrors               string `json:"input errors"`
	Collisions                string `json:"collisions"`
	MulticastsReceived        string `json:"multicasts received"`
	MulticastsTransmitted     string `json:"multicasts transmitted"`
	InputQueueDrops           string `json:"input queue drops"`
	PacketsForUnknownProtocol string `json:"packets for unknown protocol"`
	HWOffloadCapabilities     string `json:"HW offload capabilities"`
	UptimeAtAttachOrStatReset string `json:"uptime at attach or stat reset"`
	Name                      string `json:"name"`
}

// Interface is the struct returned by the OPNsense API
// when requesting the interfaces. The response is weird json
// that have the interface name as key and the interfaceDetails struct as value
type interfaceResponse struct {
	Interface map[string]InterfaceDetails `json:"interfaces"`
}

type Interface struct {
	Name                  string
	Device                string
	Type                  string
	MTU                   int64
	PacketsReceived       int64
	PacketsTransmitted    int64
	BytesReceived         int64
	BytesTransmitted      int64
	MulticastsReceived    int64
	MulticastsTransmitted int64
	InputErrors           int64
	OutputErrors          int64
	Collisions            int64
	SendQueueLength       int64
	SendQueueMaxLength    int64
	SendQueueDrops        int64
	InputQueueDrops       int64
	LinkState             int   // 0=down, 1=up, 2=unknown — derived enum, cannot overflow; stays int
	LineRate              int64 // bits per second (10 Gbit > int32)
}

type Interfaces struct {
	Interfaces []Interface
}

func (c *Client) FetchInterfaces() (Interfaces, *APICallError) {
	var resp interfaceResponse
	var data Interfaces

	url, ok := c.endpoints["interfaces"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "arp",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	err := c.do("GET", url, nil, &resp)
	if err != nil {
		return data, err
	}

	for _, v := range resp.Interface {

		// Parse each counter/state field tolerantly (safeAtoi → 0 on a missing or
		// non-numeric value), matching carp.go/unbound_dns.go/ntp.go. A single
		// malformed field on one interface (e.g. a future driver omitting a
		// netstat column) must degrade only that one metric to 0, not abort the
		// whole fetch and blank every interface's metrics for the scrape (#102).
		// Genuine transport/decode failures are still returned above.

		// OPNsense >=25.x reports "link state" as a numeric string from the
		// kernel ifmedia status: "2" = up (LINK_STATE_UP), "1" = down,
		// "0" = unknown (LINK_STATE_UNKNOWN, e.g. PPPoE/tun pseudo-devices with
		// no carrier-sense concept). Older releases used the human string "link
		// state is up"/"...is down". Map unknown to its own value so a healthy
		// carrier-less WAN is not reported as down (#86).
		linkState := LinkStateDown
		switch {
		case v.LinkState == "2" || strings.Contains(v.LinkState, "is up"):
			linkState = LinkStateUp
		case v.LinkState == "0":
			linkState = LinkStateUnknown
		}

		data.Interfaces = append(data.Interfaces, Interface{
			Name:                  v.Name,
			Device:                v.Device,
			Type:                  v.Type,
			MTU:                   safeAtoi(v.MTU),
			BytesReceived:         safeAtoi(v.BytesReceived),
			BytesTransmitted:      safeAtoi(v.BytesTransmitted),
			PacketsReceived:       safeAtoi(v.PacketsReceived),
			PacketsTransmitted:    safeAtoi(v.PacketsTransmitted),
			MulticastsReceived:    safeAtoi(v.MulticastsReceived),
			MulticastsTransmitted: safeAtoi(v.MulticastsTransmitted),
			InputErrors:           safeAtoi(v.InputErrors),
			OutputErrors:          safeAtoi(v.OutputErrors),
			Collisions:            safeAtoi(v.Collisions),
			SendQueueLength:       safeAtoi(v.SendQueueLength),
			SendQueueMaxLength:    safeAtoi(v.SendQueueMaxLength),
			SendQueueDrops:        safeAtoi(v.SendQueueDrops),
			InputQueueDrops:       safeAtoi(v.InputQueueDrops),
			LinkState:             linkState,
			LineRate:              parseLineRateBits(v.LineRate),
		})
	}

	return data, nil
}

// interfacesOverviewResponse is the JSON returned by
// api/interfaces/overview/interfaces_info (validated against OPNsense 26.1).
type interfacesOverviewResponse struct {
	Rows []interfaceOverviewRow `json:"rows"`
}

type interfaceOverviewRow struct {
	Device      string   `json:"device"`
	Identifier  string   `json:"identifier"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Flags       []string `json:"flags"`
	Media       string   `json:"media"`
	LinkType    string   `json:"link_type"`
	VlanTag     string   `json:"vlan_tag"`
	Vlan        *struct {
		Tag    string `json:"tag"`
		Parent string `json:"parent"`
	} `json:"vlan"`
	IsPhysical bool `json:"is_physical"`

	// LAGG (link aggregation) fields. Populated only when Device is itself a
	// lagg(4) interface. Source: legacy_interfaces_details() in OPNsense
	// core's src/etc/inc/interfaces.lib.inc, which parses `ifconfig -Lmv`:
	//   laggproto (.*)$                                        -> LaggProto
	//   laggproto (\S+) lagghash (\S+)$                         -> LaggProto + LaggHash
	//   lagg statistics: / active ports: N / flapping: N        -> LaggStatistics
	//   laggport: <dev> flags=..<..> [state=..<..>]             -> LaggPort[<dev>]
	// (interfaces.lib.inc lines 431-464, opnsense/core master as of 2026-07-13).
	LaggProto      string                          `json:"laggproto"`
	LaggHash       string                          `json:"lagghash"`
	LaggStatistics *interfaceLaggStatisticsRaw     `json:"laggstatistics"`
	LaggPort       map[string]interfaceLaggPortRaw `json:"laggport"`

	// Bridge membership. Populated only when Device is itself a bridge(4)
	// interface: "members" maps each attached interface to its bridge flags.
	// Source: `member: <dev> flags=...<...>` (interfaces.lib.inc lines
	// 505-511).
	Members map[string]interfaceBridgeMemberRaw `json:"members"`

	// SFP/SFP+ transceiver block. A plain string map because OPNsense emits
	// dynamic per-lane keys ("lane_1_rx_power", "lane_2_tx_bias", ...) that
	// cannot be declared as fixed struct fields; fixed keys ("plugged",
	// "vendor", "part_number", "serial_number", "manufacturing_date") live in
	// the same map. Digital Optical Monitoring (DOM) keys — "temperature",
	// "voltage", and the lane_* keys — are only present for transceivers that
	// support DOM; copper RJ45 SFPs (verified live against a UBNT UF-RJ45-1G
	// on OPNsense 26.1) report only the identity keys, never DOM. Source:
	// interfaces.lib.inc lines 401-424.
	SFP map[string]string `json:"sfp"`
}

type interfaceLaggStatisticsRaw struct {
	ActivePorts string `json:"active ports"`
	Flapping    string `json:"flapping"`
}

type interfaceLaggPortRaw struct {
	Flags []string `json:"flags"`
	// State is only present for LACP laggs (laggproto lacp); other protocols
	// (failover, loadbalance, ...) never carry a laggport "state=" clause.
	State []string `json:"state"`
}

type interfaceBridgeMemberRaw struct {
	Flags []string `json:"flags"`
}

// InterfaceOverview is the per-interface identity/status data from the
// interfaces overview endpoint. It complements (and must not duplicate) the
// traffic statistics fetched by FetchInterfaces.
type InterfaceOverview struct {
	Device      string
	Identifier  string // OPNsense config identifier (e.g. "lan", "opt3"); empty when unassigned
	Description string // human name (e.g. "LAN", "Unassigned Interface")
	Status      string // operational status: "up", "down", "no carrier"
	Media       string // negotiated media incl. duplex (e.g. "10Gbase-SR <full-duplex>")
	LinkType    string // "static", "dhcp", "pppoe", "none"; empty when unassigned
	VlanTag     string // 802.1q tag; empty for non-VLAN interfaces
	VlanParent  string // parent device for VLAN interfaces
	AdminUp     bool   // ifconfig UP flag present
	Physical    bool
}

// LaggInfo is a LAGG (link aggregation) interface's protocol/hash
// configuration and aggregate active-port/flap counters (interfaces_info
// "laggproto"/"lagghash"/"laggstatistics"). Present in InterfacesOverview only
// for rows that are themselves a lagg device.
type LaggInfo struct {
	Device   string // the lagg device itself, e.g. "lagg0"
	Protocol string // laggproto, e.g. "lacp", "failover", "loadbalance"
	Hash     string // lagghash, e.g. "l2,l3,l4"; empty for hash-less protocols (e.g. failover)

	// StatsPresent is false when the box served no "lagg statistics:" block
	// for this device; ActivePorts/Flapping must not be read (and must not be
	// emitted as a metric) in that case.
	StatsPresent bool
	ActivePorts  int64
	Flapping     int64
}

// LaggPort is one physical member port of a LAGG, with its runtime
// active/LACP-negotiation state (interfaces_info "laggport" map).
type LaggPort struct {
	Lagg string // owning lagg device, e.g. "lagg0"
	Port string // member device, e.g. "ix0"
	// Active reports whether the "active" flag is present on this port
	// (the port is currently selected to carry traffic).
	Active bool
	// StatePresent is false for non-LACP laggs (failover/loadbalance/...),
	// which never carry a laggport "state=" clause; Collecting/Distributing
	// must not be read (or emitted) in that case.
	StatePresent bool
	Collecting   bool // LACP state: collecting (RX side up)
	Distributing bool // LACP state: distributing (TX side up)
}

// BridgeMember is one interface attached to a bridge(4) interface
// (interfaces_info "members" map).
type BridgeMember struct {
	Bridge string // owning bridge device, e.g. "bridge0"
	Member string // member device, e.g. "ix1"
}

// SFPLane is one Digital Optical Monitoring (DOM) lane reading. Only lanes
// actually reported by the box are included — never synthesized for lanes
// the transceiver doesn't have.
type SFPLane struct {
	Lane string // lane identifier as reported, e.g. "1"

	RXPowerPresent bool
	RXPowerDBM     float64
	TXBiasPresent  bool
	TXBiasMA       float64
}

// SFPModule is the transceiver identity/diagnostics for one interface's SFP
// cage (interfaces_info "sfp" block). Identity fields (Vendor/PartNumber/
// SerialNumber/ManufacturingDate) are populated for every plugged module,
// copper or optical. DOM fields (Temperature/Voltage/Lanes) are only
// populated for transceivers that support Digital Optical Monitoring; a
// copper RJ45 SFP (verified live: UBNT UF-RJ45-1G on OPNsense 26.1) reports
// identity only. Callers must check *Present before reading/emitting a DOM
// value — an absent reading must degrade to an absent series, never a zero.
type SFPModule struct {
	Device            string
	Plugged           string
	Vendor            string
	PartNumber        string
	SerialNumber      string
	ManufacturingDate string

	TemperaturePresent bool
	TemperatureC       float64
	VoltagePresent     bool
	VoltageV           float64
	Lanes              []SFPLane
}

// InterfacesOverview holds the parsed response from the interfaces overview endpoint.
type InterfacesOverview struct {
	Interfaces    []InterfaceOverview
	Laggs         []LaggInfo
	LaggPorts     []LaggPort
	BridgeMembers []BridgeMember
	SFPModules    []SFPModule
}

// sfpLaneKeyRegexp matches the dynamic per-lane SFP DOM keys OPNsense emits,
// e.g. "lane_1_rx_power" / "lane_1_tx_bias" (interfaces.lib.inc line 423:
// sprintf('lane_%s_rx_power', $matches[1])). The lane identifier itself
// (\S+, matched non-greedily) is whatever the kernel reports, typically a
// small integer.
var sfpLaneKeyRegexp = regexp.MustCompile(`^lane_(.+)_(rx_power|tx_bias)$`)

// leadingFloatRegexp extracts the leading signed decimal number from an
// OPNsense-formatted measurement string (e.g. "45.32 C", "-2.32 dBm (0.59 mW)",
// "6.02 mA"), which always carries a trailing unit the exporter must strip
// tolerantly rather than assume a fixed suffix.
var leadingFloatRegexp = regexp.MustCompile(`-?\d+(?:\.\d+)?`)

// leadingFloat parses the leading numeric token off a unit-suffixed
// measurement string, reporting false (not 0) when no numeric token is found
// so callers can distinguish "absent/malformed" from a genuine 0 reading.
func leadingFloat(s string) (float64, bool) {
	m := leadingFloatRegexp.FindString(s)
	if m == "" {
		return 0, false
	}
	return safeParseFloatOK(m)
}

// parseLaggInfo extracts LaggInfo from a row that is itself a lagg device.
// Returns ok=false when the row carries no laggproto (i.e. is not a lagg).
func parseLaggInfo(row interfaceOverviewRow) (LaggInfo, bool) {
	if row.LaggProto == "" {
		return LaggInfo{}, false
	}
	info := LaggInfo{
		Device:   row.Device,
		Protocol: row.LaggProto,
		Hash:     row.LaggHash,
	}
	if row.LaggStatistics != nil {
		info.StatsPresent = true
		info.ActivePorts = safeAtoi(row.LaggStatistics.ActivePorts)
		info.Flapping = safeAtoi(row.LaggStatistics.Flapping)
	}
	return info, true
}

// parseLaggPorts extracts the member ports of a lagg row, sorted by member
// device name for deterministic output.
func parseLaggPorts(row interfaceOverviewRow) []LaggPort {
	if len(row.LaggPort) == 0 {
		return nil
	}
	ports := make([]LaggPort, 0, len(row.LaggPort))
	for member, raw := range row.LaggPort {
		port := LaggPort{Lagg: row.Device, Port: member}
		for _, f := range raw.Flags {
			if f == "active" {
				port.Active = true
			}
		}
		if len(raw.State) > 0 {
			port.StatePresent = true
			for _, s := range raw.State {
				switch s {
				case "collecting":
					port.Collecting = true
				case "distributing":
					port.Distributing = true
				}
			}
		}
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports
}

// parseBridgeMembers extracts the member interfaces of a bridge row, sorted
// by member device name for deterministic output.
func parseBridgeMembers(row interfaceOverviewRow) []BridgeMember {
	if len(row.Members) == 0 {
		return nil
	}
	members := make([]BridgeMember, 0, len(row.Members))
	for member := range row.Members {
		members = append(members, BridgeMember{Bridge: row.Device, Member: member})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Member < members[j].Member })
	return members
}

// parseSFPModule extracts identity and (when present) DOM diagnostics from a
// row's sfp block. Returns ok=false when the row has no sfp cage at all.
func parseSFPModule(row interfaceOverviewRow) (SFPModule, bool) {
	if len(row.SFP) == 0 {
		return SFPModule{}, false
	}
	m := row.SFP
	mod := SFPModule{
		Device:            row.Device,
		Plugged:           m["plugged"],
		Vendor:            strings.TrimSpace(m["vendor"]),
		PartNumber:        strings.TrimSpace(m["part_number"]),
		SerialNumber:      strings.TrimSpace(m["serial_number"]),
		ManufacturingDate: strings.TrimSpace(m["manufacturing_date"]),
	}
	if v := m["temperature"]; v != "" {
		if f, ok := leadingFloat(v); ok {
			mod.TemperatureC = f
			mod.TemperaturePresent = true
		}
	}
	if v := m["voltage"]; v != "" {
		if f, ok := leadingFloat(v); ok {
			mod.VoltageV = f
			mod.VoltagePresent = true
		}
	}

	lanes := map[string]*SFPLane{}
	var laneOrder []string
	for k, v := range m {
		sub := sfpLaneKeyRegexp.FindStringSubmatch(k)
		if sub == nil {
			continue
		}
		lane, kind := sub[1], sub[2]
		l, ok := lanes[lane]
		if !ok {
			l = &SFPLane{Lane: lane}
			lanes[lane] = l
			laneOrder = append(laneOrder, lane)
		}
		f, fok := leadingFloat(v)
		switch kind {
		case "rx_power":
			l.RXPowerDBM = f
			l.RXPowerPresent = fok
		case "tx_bias":
			l.TXBiasMA = f
			l.TXBiasPresent = fok
		}
	}
	sort.Strings(laneOrder)
	for _, lane := range laneOrder {
		mod.Lanes = append(mod.Lanes, *lanes[lane])
	}

	return mod, true
}

// FetchInterfacesOverview calls api/interfaces/overview/interfaces_info and
// returns identity/status details for every interface (assigned or not).
// The device field is the reliable join key across all opnsense_interfaces_*
// series.
func (c *Client) FetchInterfacesOverview() (InterfacesOverview, *APICallError) {
	var resp interfacesOverviewResponse
	var data InterfacesOverview

	url, ok := c.endpoints["interfacesOverview"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "interfacesOverview",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, row := range resp.Rows {
		adminUp := false
		for _, f := range row.Flags {
			if f == "up" {
				adminUp = true
				break
			}
		}
		iface := InterfaceOverview{
			Device:      row.Device,
			Identifier:  row.Identifier,
			Description: row.Description,
			Status:      row.Status,
			Media:       row.Media,
			LinkType:    row.LinkType,
			VlanTag:     row.VlanTag,
			AdminUp:     adminUp,
			Physical:    row.IsPhysical,
		}
		if row.Vlan != nil {
			iface.VlanParent = row.Vlan.Parent
			if iface.VlanTag == "" {
				iface.VlanTag = row.Vlan.Tag
			}
		}
		data.Interfaces = append(data.Interfaces, iface)

		if info, ok := parseLaggInfo(row); ok {
			data.Laggs = append(data.Laggs, info)
		}
		data.LaggPorts = append(data.LaggPorts, parseLaggPorts(row)...)
		data.BridgeMembers = append(data.BridgeMembers, parseBridgeMembers(row)...)
		if mod, ok := parseSFPModule(row); ok {
			data.SFPModules = append(data.SFPModules, mod)
		}
	}

	return data, nil
}
