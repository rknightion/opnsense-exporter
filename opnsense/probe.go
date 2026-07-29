package opnsense

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// ProbeEndpoint asks the box one question about a single endpoint: does this
// route EXIST?
//
// It is the availability primitive behind opnsense_feature_available (#517,
// widened in #525). A plugin-gated endpoint answers 404
// ({"errorMessage":"Endpoint not found"}) when its plugin is not installed, so
// "not 404" is the whole test. The response body is decoded into a
// json.RawMessage and thrown away — a probe cares that the route answered, not
// what it said.
//
// It is deliberately GENERIC, keyed on the endpoint name, rather than one
// Fetch*Available wrapper per feature. There are about thirty plugin-gated
// families and hand-writing thirty near-identical wrappers is thirty places for
// the next one to be forgotten; the probe table can then be plain data.
//
// The method comes from postEndpoints, the same list the contract manifest and
// the canary read, so a POST-only endpoint (smartList) is probed with a POST and
// nothing has to restate which is which.
//
// Three outcomes, and the third is not the second:
//
//   - (true, nil)   — the route answered.
//   - (false, nil)  — the route returned 404. The plugin is absent.
//   - (false, err)  — the question could not be answered (network error, auth
//     failure, a decode failure on a 200). NOT the same as "absent", and callers
//     must not record it as one: a firewall that is briefly unreachable would
//     otherwise read as every plugin having been uninstalled at once.
//
// Callers wanting a fresh answer must probe through a WithoutCache clone; this
// method does not detach the cache itself, so a caller that genuinely wants the
// cached verdict can have it.
func (c *Client) ProbeEndpoint(name EndpointName) (bool, *APICallError) {
	path, ok := c.endpoints[name]
	if !ok {
		return false, &APICallError{
			Endpoint:   string(name),
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var sink json.RawMessage
	var err *APICallError
	if _, isPost := postEndpoints[name]; isPost {
		err = c.doForm(path, url.Values{}, &sink)
	} else {
		err = c.do("GET", path, nil, &sink)
	}
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// EndpointPathFor resolves an endpoint NAME to the path the client actually
// requests, or false when the name is unknown.
//
// It exists because the two halves of availability tracking are keyed
// differently: the probe table names endpoints, while RequestObserver and
// CacheObserver report the PATH. Without this, correlating "what did the
// collectors already observe" with "what do I still need to probe" would mean a
// second hand-maintained copy of the mapping.
func (c *Client) EndpointPathFor(name EndpointName) (EndpointPath, bool) {
	p, ok := c.endpoints[name]
	return p, ok
}
