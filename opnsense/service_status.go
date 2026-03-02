package opnsense

type serviceStatusResponse struct {
	Status string `json:"status"`
}

// FetchServiceStatus fetches the running status of a subsystem service.
// Returns the status string ("running", "stopped", "disabled") or an error.
func (c *Client) FetchServiceStatus(endpointName EndpointName) (string, *APICallError) {
	var resp serviceStatusResponse

	url, ok := c.endpoints[endpointName]
	if !ok {
		return "", &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return "", err
	}

	return resp.Status, nil
}
