package opnsense

import (
	"encoding/json"
	"net/http"
)

// monitStatusEnvelope is the top-level JSON wrapper for api/monit/status/get/xml.
//
// The OPNsense Monit controller (Monit/Api/StatusController.php) proxies the
// monit httpd and returns the XML status doc parsed by simplexml_load_string and
// JSON-encoded by the Phalcon framework. There are two distinct shapes:
//
//   - When monit is running: {"result":"ok","status":{...XML object...}}
//   - When monit is stopped: {"result":"failed","status":"<error message string>"}
//
// Status is therefore decoded as json.RawMessage and inspected at runtime.
//
// VERIFICATION: The "failed" shape was live-validated against a real OPNsense
// 26.1 box that has monit installed-but-not-running (2026-06-09). The "ok"
// shape is unvalidated — derived from core Monit/Api/StatusController.php and
// the monit 5.x _status?format=xml document structure as serialised by PHP's
// simplexml_load_string + json_encode. Re-check on a box with monit running
// when available.
type monitStatusEnvelope struct {
	Result string          `json:"result"`
	Status json.RawMessage `json:"status"`
}

// monitStatusBody is the inner object when result=="ok".
// It contains the list of monitored services under the "service" key.
// A single service is serialised as an object; multiple services as an array
// (standard SimpleXML→JSON quirk for repeated child elements).
type monitStatusBody struct {
	Service json.RawMessage `json:"service"`
}

// monitServiceXML is a single service entry from the monit XML status.
// All fields are XML text nodes, so they arrive as JSON strings — decoded
// via flexString so empty/missing fields parse cleanly.
type monitServiceXML struct {
	Attributes struct {
		Type flexString `json:"type"`
	} `json:"@attributes"`
	Name          flexString `json:"name"`
	Status        flexString `json:"status"`
	Monitor       flexString `json:"monitor"`
	PendingAction flexString `json:"pendingaction"`
}

// MonitCheck is the normalised representation of a single monit service check.
type MonitCheck struct {
	// Name is the monit service name.
	Name string
	// Type is a stable string label derived from the monit numeric service type.
	Type string
	// StatusOK is 1 when the monit status field equals "0" (no error), 0 otherwise.
	StatusOK float64
	// Monitored is 1 when the monitor field is non-zero (actively monitored).
	Monitored float64
}

// MonitStatus is the normalised result of FetchMonitStatus.
type MonitStatus struct {
	// StatusOK is true when result=="ok" and the status field decoded as an object.
	// It is false when monit is stopped or its httpd is unreachable.
	StatusOK bool
	// Checks holds per-service check data; empty when StatusOK is false.
	Checks []MonitCheck
}

// monitTypeName maps monit's numeric service type (from @attributes.type) to a
// stable, human-readable label value. The type integers are defined in monit's
// source (monit.h: TYPE_FILESYSTEM=0, TYPE_DIRECTORY=1, TYPE_FILE=2,
// TYPE_PROCESS=3, TYPE_HOST=4, TYPE_SYSTEM=5, TYPE_FIFO=6, TYPE_PROGRAM=7,
// TYPE_NET=8).
func monitTypeName(t string) string {
	switch t {
	case "0":
		return "filesystem"
	case "1":
		return "directory"
	case "2":
		return "file"
	case "3":
		return "process"
	case "4":
		return "host"
	case "5":
		return "system"
	case "6":
		return "fifo"
	case "7":
		return "program"
	case "8":
		return "network"
	default:
		return "unknown"
	}
}

// FetchMonitStatus calls api/monit/status/get/xml and returns the parsed monit
// service-check status.
//
// The endpoint never returns HTTP 404 on a standard OPNsense install (monit is
// a core package), but a 404 is treated as "feature absent" (empty data, nil
// error) to handle stripped builds gracefully. When monit is installed but not
// running, the API returns a JSON error envelope with result=="failed" and a
// plain-text string in the status field; FetchMonitStatus returns
// MonitStatus{StatusOK:false} in that case.
func (c *Client) FetchMonitStatus() (MonitStatus, *APICallError) {
	var data MonitStatus

	url, ok := c.endpoints["monitStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "monitStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope monitStatusEnvelope
	if err := c.do("GET", url, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // feature absent: silent
		}
		return data, err
	}

	// result != "ok" means monit is stopped or its httpd is unreachable.
	// The status field contains a plain-text error string in this case.
	if envelope.Result != "ok" {
		return data, nil // StatusOK stays false
	}

	// Decode the inner status object to reach the service list.
	var body monitStatusBody
	if err := json.Unmarshal(envelope.Status, &body); err != nil {
		// If status decodes as something other than an object (e.g. a string
		// on older controller versions) treat as no-data gracefully.
		return data, nil
	}

	if len(body.Service) == 0 {
		data.StatusOK = true
		return data, nil
	}

	// Try array first (multiple services), fall back to single object.
	var services []monitServiceXML
	if err := json.Unmarshal(body.Service, &services); err != nil {
		// Single-service case: simplexml serialises it as an object, not an array.
		var single monitServiceXML
		if err2 := json.Unmarshal(body.Service, &single); err2 != nil {
			// Unrecognised shape — return empty but mark reachable.
			data.StatusOK = true
			return data, nil
		}
		services = []monitServiceXML{single}
	}

	data.StatusOK = true
	for _, svc := range services {
		statusOK := 0.0
		if svc.Status.String() == "0" {
			statusOK = 1.0
		}
		monitored := 0.0
		if svc.Monitor.String() != "0" {
			monitored = 1.0
		}
		data.Checks = append(data.Checks, MonitCheck{
			Name:      svc.Name.String(),
			Type:      monitTypeName(svc.Attributes.Type.String()),
			StatusOK:  statusOK,
			Monitored: monitored,
		})
	}

	return data, nil
}
