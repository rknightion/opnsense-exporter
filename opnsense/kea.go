package opnsense

type keaLeaseRow struct {
	Address    string `json:"address"`
	HWAddr     string `json:"hwaddr"`
	Hostname   string `json:"hostname"`
	Expire     int    `json:"expire"`
	IfDescr    string `json:"if_descr"`
	IsReserved string `json:"is_reserved"`
}

type keaLeaseResponse struct {
	Total    int           `json:"total"`
	RowCount int           `json:"rowCount"`
	Current  int           `json:"current"`
	Rows     []keaLeaseRow `json:"rows"`
}

type KeaLease struct {
	Address    string
	HWAddr     string
	Hostname   string
	IsReserved bool
	Expire     int
	IfDescr    string
}

type KeaLeases struct {
	Leases            []KeaLease
	TotalLeases       int
	ReservedCount     int
	DynamicCount      int
	LeasesByInterface map[string]int
}

func (c *Client) fetchKeaLeases(endpointName EndpointName) (KeaLeases, *APICallError) {
	var resp keaLeaseResponse
	var data KeaLeases

	url, ok := c.endpoints[endpointName]
	if !ok {
		return data, &APICallError{
			Endpoint:   string(endpointName),
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

		lease := KeaLease{
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

func (c *Client) FetchKeaLeases4() (KeaLeases, *APICallError) {
	return c.fetchKeaLeases("keaLeases4")
}

func (c *Client) FetchKeaLeases6() (KeaLeases, *APICallError) {
	return c.fetchKeaLeases("keaLeases6")
}
