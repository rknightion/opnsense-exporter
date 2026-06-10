package opnsense

import "net/http"

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

// FetchServiceStatusOptional is like FetchServiceStatus but treats HTTP 404
// (plugin absent / endpoint missing) as "feature absent": it returns
// ("", false, nil) so plugin-gated collectors stay silent on boxes without
// the plugin instead of logging an error on every scrape.
func (c *Client) FetchServiceStatusOptional(endpointName EndpointName) (string, bool, *APICallError) {
	var resp serviceStatusResponse

	url, ok := c.endpoints[endpointName]
	if !ok {
		return "", false, &APICallError{
			Endpoint:   string(endpointName),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, err
	}

	return resp.Status, true, nil
}
