package opnsense

type pfStatesResponse struct {
	Current string `json:"current"`
	Limit   string `json:"limit"`
}

type PFStates struct {
	Current int
	Limit   int
}

func (c *Client) FetchPFStates() (PFStates, *APICallError) {
	var resp pfStatesResponse
	var data PFStates

	url, ok := c.endpoints["pfStates"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "pfStates",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	current, cerr := parseStringToInt(resp.Current, url)
	if cerr != nil {
		return data, cerr
	}
	limit, lerr := parseStringToInt(resp.Limit, url)
	if lerr != nil {
		return data, lerr
	}

	data.Current = current
	data.Limit = limit
	return data, nil
}
