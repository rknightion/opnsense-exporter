package opnsense

import (
	"net/http"

	"github.com/rknightion/opnsense-exporter/internal/fetchshare"
)

// dhcpv4LeaseRow mirrors the JSON fields returned by the ISC DHCPv4
// api/dhcpv4/leases/searchLease endpoint (opnsense/plugins net/isc-dhcp).
//
// Field names confirmed from:
// https://github.com/opnsense/plugins/blob/master/net/isc-dhcp/src/opnsense/mvc/app/controllers/OPNsense/DHCPv4/Api/LeasesController.php
//
// Notable difference from Kea/dnsmasq: the MAC field is "mac" (not "hwaddr").
// "type" is "dynamic" or "static" (not a boolean is_reserved flag).
// "status" is "online" or "offline" (ARP-derived).
// "state" is the binding state: "active", "expired", or the raw binding value.
// "starts" and "ends" are formatted datetime strings, not Unix timestamps.
// "if" is the logical interface identifier; "if_descr" is the human description.
type dhcpv4LeaseRow struct {
	Address  string     `json:"address"`
	MAC      flexString `json:"mac"`
	Type     flexString `json:"type"`
	State    flexString `json:"state"`
	Status   flexString `json:"status"`
	Hostname flexString `json:"hostname"`
	Descr    flexString `json:"descr"`
	Starts   flexString `json:"starts"`
	Ends     flexString `json:"ends"`
	If       flexString `json:"if"`
	IfDescr  flexString `json:"if_descr"`
	Man      flexString `json:"man"`
}

type dhcpv4LeaseResponse struct {
	Total      int              `json:"total"`
	RowCount   int              `json:"rowCount"`
	Current    int              `json:"current"`
	Rows       []dhcpv4LeaseRow `json:"rows"`
	Interfaces flexStringMap    `json:"interfaces"`
}

// DHCPv4Lease is the normalised representation of one ISC DHCPv4 lease.
type DHCPv4Lease struct {
	Address  string
	MAC      string
	Type     string // "dynamic" or "static"
	State    string // "active", "expired", …
	Status   string // "online" or "offline"
	Hostname string
	Descr    string
	IfDescr  string
	// Device is the raw logical interface id (the payload's `if`), distinct
	// from IfDescr: on VLAN children and bridges the two diverge, and only
	// the raw id joins against the interface metrics — the #544 item-5
	// pattern (#556). Falls back to the "unknown" sentinel (matching the
	// codebase-wide convention, e.g. opnsense/firewall_rules.go) when the
	// payload's `if` decodes empty, so a label is never emitted blank.
	Device string
}

// DHCPv4Leases holds the aggregated result of FetchDHCPv4Leases.
type DHCPv4Leases struct {
	Present           bool // false when the ISC DHCPv4 plugin is not installed (HTTP 404)
	Leases            []DHCPv4Lease
	TotalLeases       int
	ReservedCount     int // static leases
	DynamicCount      int // dynamic leases
	LeasesByInterface map[string]int
}

// FetchDHCPv4Leases calls the ISC DHCPv4 leases search endpoint and returns
// aggregated lease data.
//
// The legacy ISC DHCPv4 backend (os-isc-dhcp) is deprecated and absent on modern
// OPNsense; the endpoint then returns HTTP 404 (verified against a live OPNsense
// 26.1 box). That is treated as "feature absent" — empty data with no error — so
// boxes without ISC DHCP do not log errors or increment endpoint counters on
// every scrape.
func (c *Client) FetchDHCPv4Leases() (DHCPv4Leases, *APICallError) {
	var resp dhcpv4LeaseResponse
	var data DHCPv4Leases

	url, ok := c.endpoints["dhcpv4"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dhcpv4",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.TotalLeases = resp.Total
	data.LeasesByInterface = make(map[string]int)

	for _, row := range resp.Rows {
		isStatic := row.Type.String() == "static"

		device := row.If.String()
		if device == "" {
			device = "unknown"
		}

		lease := DHCPv4Lease{
			Address:  row.Address,
			MAC:      row.MAC.String(),
			Type:     row.Type.String(),
			State:    row.State.String(),
			Status:   row.Status.String(),
			Hostname: row.Hostname.String(),
			Descr:    row.Descr.String(),
			IfDescr:  row.IfDescr.String(),
			Device:   device,
		}

		data.Leases = append(data.Leases, lease)
		data.LeasesByInterface[row.IfDescr.String()]++

		if isStatic {
			data.ReservedCount++
		} else {
			data.DynamicCount++
		}
	}

	c.publishResult(fetchshare.KeyDHCPv4Leases, data)
	return data, nil
}
