package opnsense

import (
	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
)

type dnsmasqLeaseRow struct {
	Expire     int      `json:"expire"`
	HWAddr     string   `json:"hwaddr"`
	IAID       string   `json:"iaid"`
	Address    string   `json:"address"`
	Hostname   string   `json:"hostname"`
	ClientID   string   `json:"client_id"`
	If         string   `json:"if"`
	IfDescr    string   `json:"if_descr"`
	IfName     string   `json:"if_name"`
	MacInfo    string   `json:"mac_info"`
	IsReserved flexBool `json:"is_reserved"`
}

type dnsmasqLeaseResponse struct {
	Total      int               `json:"total"`
	RowCount   int               `json:"rowCount"`
	Current    int               `json:"current"`
	Rows       []dnsmasqLeaseRow `json:"rows"`
	Interfaces flexStringMap     `json:"interfaces"`
}

type DnsmasqLease struct {
	Address    string
	HWAddr     string
	Hostname   string
	IsReserved bool
	Expire     int
	IfDescr    string
	// Device is the raw logical interface id (the payload's `if`), distinct
	// from IfDescr — the #544 item-5 pattern (#556). Falls back to the
	// "unknown" sentinel when the payload's `if` is empty.
	Device string
	// Vendor is the decoded mac_info OUI vendor-name lookup, mirroring the
	// Kea collector's identical field exactly (opnsense/kea.go): populated
	// whenever the OUI is known, empty whenever it is not — Kea's own
	// lease_info metric already emits this label empty in that case, so
	// dnsmasq matches that established, shipped behaviour rather than
	// introducing a third convention.
	Vendor string
}

type DnsmasqLeases struct {
	Leases            []DnsmasqLease
	TotalLeases       int
	ReservedCount     int
	DynamicCount      int
	LeasesByInterface map[string]int
}

// dnsmasqRangeRow mirrors api/dnsmasq/settings/searchRange bootgrid rows.
// %interface carries the display name matching lease if_descr labels.
type dnsmasqRangeRow struct {
	Interface string `json:"%interface"`
	StartAddr string `json:"start_addr"`
	EndAddr   string `json:"end_addr"`
}

type dnsmasqRangeResponse struct {
	Rows []dnsmasqRangeRow `json:"rows"`
}

// DnsmasqRange is one configured dnsmasq DHCP range with its computed size.
type DnsmasqRange struct {
	Interface string
	PoolSize  float64
}

// FetchDnsmasqRanges returns configured dnsmasq DHCP ranges. Rows without a
// parseable start/end pair (e.g. constructor/SLAAC v6 ranges) are skipped —
// their pool size is not statically known.
func (c *Client) FetchDnsmasqRanges() ([]DnsmasqRange, *APICallError) {
	var resp dnsmasqRangeResponse

	url, ok := c.endpoints["dnsmasqRanges"]
	if !ok {
		return nil, &APICallError{
			Endpoint:   "dnsmasqRanges",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	var ranges []DnsmasqRange
	for _, row := range resp.Rows {
		size, ok := ipRangeSize(row.StartAddr, row.EndAddr)
		if !ok {
			continue
		}
		ranges = append(ranges, DnsmasqRange{
			Interface: row.Interface,
			PoolSize:  size,
		})
	}
	return ranges, nil
}

func (c *Client) FetchDnsmasqLeases() (DnsmasqLeases, *APICallError) {
	var resp dnsmasqLeaseResponse
	var data DnsmasqLeases

	url, ok := c.endpoints["dnsmasqLeases"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "dnsmasqLeases",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.TotalLeases = resp.Total
	data.LeasesByInterface = make(map[string]int)

	for _, row := range resp.Rows {
		reserved := row.IsReserved.Bool()

		device := row.If
		if device == "" {
			device = "unknown"
		}

		lease := DnsmasqLease{
			Address:    row.Address,
			HWAddr:     row.HWAddr,
			Hostname:   row.Hostname,
			IsReserved: reserved,
			Expire:     row.Expire,
			IfDescr:    row.IfDescr,
			Device:     device,
			Vendor:     row.MacInfo,
		}

		data.Leases = append(data.Leases, lease)
		data.LeasesByInterface[row.IfDescr]++

		if reserved {
			data.ReservedCount++
		} else {
			data.DynamicCount++
		}
	}

	c.publishResult(fetchshare.KeyDnsmasqLeases, data)
	return data, nil
}
