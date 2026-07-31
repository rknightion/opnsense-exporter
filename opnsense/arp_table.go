package opnsense

import (
	"github.com/rknightion/opnsense-exporter/internal/fetchshare"
	"strings"
)

type arpSearchResponse struct {
	Rows []struct {
		Mac             string `json:"mac"`
		IP              string `json:"ip"`
		Intf            string `json:"intf"`
		Type            string `json:"type"`
		Manufacturer    string `json:"manufacturer"`
		Hostname        string `json:"hostname"`
		IntfDescription string `json:"intf_description"`
		Permanent       bool   `json:"permanent"`
		Expired         bool   `json:"expired"`
		Expires         int    `json:"expires"`
	} `json:"rows"`
	Total    int `json:"total"`
	RowCount int `json:"rowCount"`
	Current  int `json:"current"`
}

type Arp struct {
	Mac string
	IP  string
	// Device is the raw kernel device (the payload's `intf`), distinct from
	// IntfDescription: on VLAN children and bridges the two diverge, and only
	// the raw device joins against the interface metrics (#544).
	Device string
	Type   string
	// Manufacturer is the OUI lookup for Mac. Populated on 88 of 101 entries on
	// the reference box, whereas Hostname is empty on ALL of them (#534).
	Manufacturer    string
	Hostname        string
	IntfDescription string
	Expired         bool
	Permanent       bool
	Expires         int
}

type ArpTable struct {
	Arp          []Arp
	TotalEntries int
}

const fetchArpPayload = `{"current":1,"rowCount":-1,"sort":{},"searchPhrase":"","resolve":"no"}`

func (c *Client) FetchArpTable() (ArpTable, *APICallError) {
	var resp arpSearchResponse
	var arpTable ArpTable

	path, ok := c.endpoints["arp"]
	if !ok {
		return arpTable, &APICallError{
			Endpoint:   "arp",
			Message:    "endpoint not found",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", path, strings.NewReader(fetchArpPayload), &resp); err != nil {
		return arpTable, err
	}

	for _, arp := range resp.Rows {
		a := Arp{
			Mac:             arp.Mac,
			IP:              arp.IP,
			Expired:         arp.Expired,
			Expires:         arp.Expires,
			Permanent:       arp.Permanent,
			Type:            arp.Type,
			Device:          arp.Intf,
			Manufacturer:    arp.Manufacturer,
			Hostname:        arp.Hostname,
			IntfDescription: arp.IntfDescription,
		}
		arpTable.Arp = append(arpTable.Arp, a)
	}

	arpTable.TotalEntries = resp.Total

	c.publishResult(fetchshare.KeyArpTable, arpTable)
	return arpTable, nil
}
