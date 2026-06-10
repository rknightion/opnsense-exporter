package opnsense

import (
	"strings"
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
	MTU                   int
	PacketsReceived       int
	PacketsTransmitted    int
	BytesReceived         int
	BytesTransmitted      int
	MulticastsReceived    int
	MulticastsTransmitted int
	InputErrors           int
	OutputErrors          int
	Collisions            int
	SendQueueLength       int
	SendQueueMaxLength    int
	SendQueueDrops        int
	InputQueueDrops       int
	LinkState             int // 1=up, 0=down
	LineRate              int // bits per second
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

		convertedValues, err := sliceIntToMapStringInt(
			[]string{
				v.MTU, v.BytesReceived, v.BytesTransmitted,
				v.PacketsReceived, v.PacketsTransmitted,
				v.MulticastsReceived, v.MulticastsTransmitted,
				v.InputErrors, v.OutputErrors,
				v.Collisions,
				v.SendQueueLength, v.SendQueueMaxLength,
				v.SendQueueDrops, v.InputQueueDrops,
			},
			url,
		)
		if err != nil {
			return data, err
		}

		// OPNsense >=25.x reports "link state" as a numeric string from the
		// kernel ifmedia status: "2" = up (LINK_STATE_UP), "1" = down,
		// "0" = unknown. Older releases used the human string "link state is
		// up"/"...is down". Treat both shapes as up only when explicitly up.
		linkState := 0
		if v.LinkState == "2" || strings.Contains(v.LinkState, "is up") {
			linkState = 1
		}

		data.Interfaces = append(data.Interfaces, Interface{
			Name:                  v.Name,
			Device:                v.Device,
			Type:                  v.Type,
			MTU:                   convertedValues[v.MTU],
			BytesReceived:         convertedValues[v.BytesReceived],
			BytesTransmitted:      convertedValues[v.BytesTransmitted],
			PacketsReceived:       convertedValues[v.PacketsReceived],
			PacketsTransmitted:    convertedValues[v.PacketsTransmitted],
			MulticastsReceived:    convertedValues[v.MulticastsReceived],
			MulticastsTransmitted: convertedValues[v.MulticastsTransmitted],
			InputErrors:           convertedValues[v.InputErrors],
			OutputErrors:          convertedValues[v.OutputErrors],
			Collisions:            convertedValues[v.Collisions],
			SendQueueLength:       convertedValues[v.SendQueueLength],
			SendQueueMaxLength:    convertedValues[v.SendQueueMaxLength],
			SendQueueDrops:        convertedValues[v.SendQueueDrops],
			InputQueueDrops:       convertedValues[v.InputQueueDrops],
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

// InterfacesOverview holds the parsed response from the interfaces overview endpoint.
type InterfacesOverview struct {
	Interfaces []InterfaceOverview
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
	}

	return data, nil
}
