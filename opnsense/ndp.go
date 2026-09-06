package opnsense

import (
	"github.com/rknightion/opnsense2otel/v5/internal/fetchshare"
)

type ndpEntry struct {
	Mac             string `json:"mac"`
	IP              string `json:"ip"`
	Intf            string `json:"intf"`
	IntfDescription string `json:"intf_description"`
	Manufacturer    string `json:"manufacturer"`
	Expire          string `json:"expire"`
	Type            string `json:"type"`
}

type NDPEntry struct {
	Mac string
	IP  string
	// Device is the raw kernel device (the payload's `intf`), distinct from
	// IntfDescription: on VLAN children and bridges the two diverge, and only
	// the raw device joins against the interface metrics (#544).
	Device string
	// Manufacturer is the OUI lookup for Mac. Populated on 72 of 83 entries on
	// the reference box (#534).
	Manufacturer    string
	IntfDescription string
	// Type is modelled but the reference box (OPNsense 26.1) sends no `type`
	// key on this endpoint at all, so it reads empty there.
	Type string
}

type NDPTable struct {
	Entries      []NDPEntry
	TotalEntries int
}

func (c *Client) FetchNDPTable() (NDPTable, *APICallError) {
	var resp []ndpEntry
	var data NDPTable

	url, ok := c.endpoints["ndpTable"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "ndpTable",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, entry := range resp {
		data.Entries = append(data.Entries, NDPEntry{
			Mac:             entry.Mac,
			IP:              entry.IP,
			Device:          entry.Intf,
			Manufacturer:    entry.Manufacturer,
			IntfDescription: entry.IntfDescription,
			Type:            entry.Type,
		})
	}

	data.TotalEntries = len(resp)

	c.publishResult(fetchshare.KeyNDPTable, data)
	return data, nil
}
