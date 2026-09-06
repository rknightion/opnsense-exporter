package opnsense

import (
	"net/http"

	"github.com/rknightion/opnsense2otel/v5/internal/fetchshare"
)

// dhcpv6LeaseRow mirrors the JSON fields returned by the ISC DHCPv6
// api/dhcpv6/leases/searchLease endpoint (opnsense/plugins net/isc-dhcp).
//
// VERIFICATION: unvalidated against a live os-isc-dhcp box — our box 404s for
// this endpoint (ISC DHCPv6 is absent). Shape derived from:
// https://github.com/opnsense/plugins/blob/master/net/isc-dhcp/src/opnsense/mvc/app/controllers/OPNsense/DHCPv6/Api/LeasesController.php
//
// Notable fields vs DHCPv4: "duid" replaces "hostname" as per-client identifier;
// "mac" may be empty (IPv6 does not require ARP-derived MAC resolution);
// "lease_type" distinguishes "ia-na" (address) from "ia-pd" (prefix delegation);
// "type" is "dynamic" or "static"; "state" is "active"/"expired"/binding state.
type dhcpv6LeaseRow struct {
	Address   string     `json:"address"`
	MAC       flexString `json:"mac"`
	Type      flexString `json:"type"`
	LeaseType flexString `json:"lease_type"`
	State     flexString `json:"state"`
	Status    flexString `json:"status"`
	DUID      flexString `json:"duid"`
	Descr     flexString `json:"descr"`
	If        flexString `json:"if"`
	IfDescr   flexString `json:"if_descr"`
	IAID      flexString `json:"iaid"`
	IAIDDuid  flexString `json:"iaid_duid"`
	CLTT      flexString `json:"cltt"`
	Ends      flexString `json:"ends"`
	Man       flexString `json:"man"`
}

type dhcpv6LeaseResponse struct {
	Total      int              `json:"total"`
	RowCount   int              `json:"rowCount"`
	Current    int              `json:"current"`
	Rows       []dhcpv6LeaseRow `json:"rows"`
	Interfaces flexStringMap    `json:"interfaces"`
}

// DHCPv6Lease is the normalised representation of one ISC DHCPv6 lease.
type DHCPv6Lease struct {
	Address   string
	MAC       string
	Type      string // "dynamic" or "static"
	LeaseType string // "ia-na" or "ia-pd"
	State     string // "active", "expired", …
	Status    string // "online" or "offline"
	DUID      string
	Descr     string
	IfDescr   string
	// Device is the raw logical interface id (the payload's `if`), distinct
	// from IfDescr — the #544 item-5 pattern (#556). Falls back to the
	// "unknown" sentinel when the payload's `if` decodes empty.
	Device string
}

// DHCPv6Leases holds the aggregated result of FetchDHCPv6Leases.
type DHCPv6Leases struct {
	Leases            []DHCPv6Lease
	TotalLeases       int
	ReservedCount     int // static leases
	DynamicCount      int // dynamic leases
	LeasesByInterface map[string]int
}

// FetchDHCPv6Leases calls the ISC DHCPv6 leases search endpoint and returns
// aggregated lease data.
//
// The ISC DHCPv6 backend (os-isc-dhcp) returns HTTP 404 when the plugin is
// absent (verified consistent with the DHCPv4 sibling on a live OPNsense 26.1
// box). That is treated as "feature absent" — empty data with no error.
func (c *Client) FetchDHCPv6Leases() (DHCPv6Leases, *APICallError) {
	var resp dhcpv6LeaseResponse
	var data DHCPv6Leases

	url, ok := c.endpoints["dhcpv6Leases"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dhcpv6Leases",
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

	data.TotalLeases = resp.Total
	data.LeasesByInterface = make(map[string]int)

	for _, row := range resp.Rows {
		isStatic := row.Type.String() == "static"

		device := row.If.String()
		if device == "" {
			device = "unknown"
		}

		lease := DHCPv6Lease{
			Address:   row.Address,
			MAC:       row.MAC.String(),
			Type:      row.Type.String(),
			LeaseType: row.LeaseType.String(),
			State:     row.State.String(),
			Status:    row.Status.String(),
			DUID:      row.DUID.String(),
			Descr:     row.Descr.String(),
			IfDescr:   row.IfDescr.String(),
			Device:    device,
		}

		data.Leases = append(data.Leases, lease)
		data.LeasesByInterface[row.IfDescr.String()]++

		if isStatic {
			data.ReservedCount++
		} else {
			data.DynamicCount++
		}
	}

	c.publishResult(fetchshare.KeyDHCPv6Leases, data)
	return data, nil
}

// dhcpv6PrefixRow mirrors the JSON fields returned by the ISC DHCPv6
// api/dhcpv6/leases/searchPrefix endpoint.
//
// VERIFICATION: unvalidated against a live os-isc-dhcp box.
type dhcpv6PrefixRow struct {
	Prefix    flexString `json:"prefix"`
	State     flexString `json:"state"`
	DUID      flexString `json:"duid"`
	IAID      flexString `json:"iaid"`
	CLTT      flexString `json:"cltt"`
	Ends      flexString `json:"ends"`
	LeaseType flexString `json:"lease_type"`
}

type dhcpv6PrefixResponse struct {
	Total    int               `json:"total"`
	RowCount int               `json:"rowCount"`
	Current  int               `json:"current"`
	Rows     []dhcpv6PrefixRow `json:"rows"`
}

// DHCPv6Prefixes holds the aggregated result of FetchDHCPv6Prefixes.
type DHCPv6Prefixes struct {
	Total  int // total number of PD prefix entries
	Active int // entries with state == "active"
}

// FetchDHCPv6Prefixes calls the ISC DHCPv6 prefix search endpoint and returns
// aggregated prefix delegation data.
//
// 404 is treated as "feature absent" — empty data with no error.
func (c *Client) FetchDHCPv6Prefixes() (DHCPv6Prefixes, *APICallError) {
	var resp dhcpv6PrefixResponse
	var data DHCPv6Prefixes

	url, ok := c.endpoints["dhcpv6Prefixes"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dhcpv6Prefixes",
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

	data.Total = resp.Total

	for _, row := range resp.Rows {
		if row.State.String() == "active" {
			data.Active++
		}
	}

	return data, nil
}
