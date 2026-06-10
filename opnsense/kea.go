package opnsense

type keaLeaseRow struct {
	Address    string   `json:"address"`
	HWAddr     string   `json:"hwaddr"`
	Hostname   string   `json:"hostname"`
	Expire     flexInt  `json:"expire"`
	IfDescr    string   `json:"if_descr"`
	IsReserved flexBool `json:"is_reserved"`
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
		reserved := row.IsReserved.Bool()

		lease := KeaLease{
			Address:    row.Address,
			HWAddr:     row.HWAddr,
			Hostname:   row.Hostname,
			IsReserved: reserved,
			Expire:     row.Expire.Int(),
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

// keaSubnetRow mirrors api/kea/dhcpv4|dhcpv6/searchSubnet bootgrid rows.
// %interface carries the display name (e.g. "MGMT") that matches the
// if_descr labels used by the lease metrics, enabling PromQL joins.
type keaSubnetRow struct {
	Subnet    string `json:"subnet"`
	Pools     string `json:"pools"`
	Interface string `json:"%interface"`
}

type keaSubnetResponse struct {
	Rows []keaSubnetRow `json:"rows"`
}

// KeaSubnet is one configured Kea subnet with its computed pool size.
type KeaSubnet struct {
	Subnet    string
	Interface string
	PoolSize  float64
}

func (c *Client) fetchKeaSubnets(endpointName EndpointName) ([]KeaSubnet, *APICallError) {
	var resp keaSubnetResponse

	url, ok := c.endpoints[endpointName]
	if !ok {
		return nil, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if err := c.do("GET", url, nil, &resp); err != nil {
		return nil, err
	}

	subnets := make([]KeaSubnet, 0, len(resp.Rows))
	for _, row := range resp.Rows {
		subnets = append(subnets, KeaSubnet{
			Subnet:    row.Subnet,
			Interface: row.Interface,
			PoolSize:  c.poolSpecSize(row.Pools),
		})
	}
	return subnets, nil
}

// FetchKeaSubnets4 returns the configured Kea DHCPv4 subnets.
func (c *Client) FetchKeaSubnets4() ([]KeaSubnet, *APICallError) {
	return c.fetchKeaSubnets("keaSubnets4")
}

// FetchKeaSubnets6 returns the configured Kea DHCPv6 subnets.
func (c *Client) FetchKeaSubnets6() ([]KeaSubnet, *APICallError) {
	return c.fetchKeaSubnets("keaSubnets6")
}
