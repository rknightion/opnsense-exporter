package opnsense

type dnsmasqLeaseRow struct {
	Expire     int    `json:"expire"`
	HWAddr     string `json:"hwaddr"`
	IAID       string `json:"iaid"`
	Address    string `json:"address"`
	Hostname   string `json:"hostname"`
	ClientID   string `json:"client_id"`
	If         string `json:"if"`
	IfDescr    string `json:"if_descr"`
	IfName     string `json:"if_name"`
	MacInfo    string `json:"mac_info"`
	IsReserved string `json:"is_reserved"`
}

type dnsmasqLeaseResponse struct {
	Total      int               `json:"total"`
	RowCount   int               `json:"rowCount"`
	Current    int               `json:"current"`
	Rows       []dnsmasqLeaseRow `json:"rows"`
	Interfaces map[string]string `json:"interfaces"`
}

type DnsmasqLease struct {
	Address    string
	HWAddr     string
	Hostname   string
	IsReserved bool
	Expire     int
	IfDescr    string
}

type DnsmasqLeases struct {
	Leases            []DnsmasqLease
	TotalLeases       int
	ReservedCount     int
	DynamicCount      int
	LeasesByInterface map[string]int
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
		reserved := row.IsReserved == "1"

		lease := DnsmasqLease{
			Address:    row.Address,
			HWAddr:     row.HWAddr,
			Hostname:   row.Hostname,
			IsReserved: reserved,
			Expire:     row.Expire,
			IfDescr:    row.IfDescr,
		}

		data.Leases = append(data.Leases, lease)
		data.LeasesByInterface[row.IfDescr]++

		if reserved {
			data.ReservedCount++
		} else {
			data.DynamicCount++
		}
	}

	return data, nil
}
