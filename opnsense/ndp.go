package opnsense

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
	Mac             string
	IP              string
	IntfDescription string
	Type            string
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
			IntfDescription: entry.IntfDescription,
			Type:            entry.Type,
		})
	}

	data.TotalEntries = len(resp)

	return data, nil
}
