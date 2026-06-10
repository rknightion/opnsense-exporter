package opnsense

import (
	"encoding/json"
	"net/url"
)

// hasyncVersionResponse is the decoded shape of api/core/hasync_status/version.
//
// Configured & reachable:
//
//	{"response": {"firmware": {"version": "<remote>", "_my_version": "<local>"}, ...}}
//
// Unconfigured / unreachable (exception path in HasyncStatusController.php):
//
//	{"status": "error", "message": "..."} — no "response" key.
//
// May also be literal JSON null.
//
// VERIFICATION: shapes derived from Core/Api/HasyncStatusController.php and
// scripts/system/ha_xmlrpc_exec.php (core master 2026-06-09). Live box is a
// single-node — only the unconfigured path can be verified there. Re-check
// the "firmware" sub-object field names against a real HA pair when available.
type hasyncVersionResponse struct {
	// Response is present only when HA is configured and the peer is reachable.
	Response json.RawMessage `json:"response"`
	// Status / Message are set on the error path.
	Status  flexString `json:"status"`
	Message flexString `json:"message"`
}

// hasyncFirmwareObj is the "firmware" sub-object inside "response".
type hasyncFirmwareObj struct {
	Version   flexString `json:"version"`
	MyVersion flexString `json:"_my_version"`
}

// hasyncVersionObj is the "response" payload.
type hasyncVersionObj struct {
	Firmware hasyncFirmwareObj `json:"firmware"`
}

// hasyncServiceRow is one row from the api/core/hasync_status/services bootgrid.
//
// The real field name is "status" (set by list_services_xmlrpc as a native JSON
// bool). "running" is kept as a defensive alias in case of future API churn; the
// effective running state is (status || running).
type hasyncServiceRow struct {
	Name        flexString `json:"name"`
	Description flexString `json:"description"`
	ID          flexString `json:"id"`
	Status      flexBool   `json:"status"`  // primary: native JSON bool
	Running     flexBool   `json:"running"` // defensive alias
}

// hasyncServicesBootgrid is the decoded api/core/hasync_status/services response.
type hasyncServicesBootgrid struct {
	Rows []hasyncServiceRow `json:"rows"`
}

// HasyncService is the normalised per-service state from the remote HA peer.
type HasyncService struct {
	// Name is the OPNsense service name (e.g. "openssh").
	Name string
	// ID is the optional instance ID (e.g. "1" for openvpn server 1). Empty
	// when absent.
	ID string
	// Running is 1 when the service is running on the remote peer, 0 otherwise.
	Running float64
}

// HasyncStatus is the normalised result of FetchHasyncStatus.
type HasyncStatus struct {
	// Reachable is true when the version endpoint returned a valid "response"
	// object. When false all other fields are zero/empty.
	Reachable bool
	// RemoteVersion is the remote peer's firmware version string
	// (firmware.version in the XML-RPC response).
	RemoteVersion string
	// LocalVersion is this node's own firmware version string
	// (firmware._my_version in the XML-RPC response).
	LocalVersion string
	// VersionMatch is true when RemoteVersion == LocalVersion.
	VersionMatch bool
	// Services is the cached remote service list. Nil when the services
	// endpoint returned an error (partial-tolerance: version data is retained).
	Services []HasyncService
}

// FetchHasyncStatus fetches HA sync status by calling two core endpoints:
//
//  1. api/core/hasync_status/version — XML-RPC firmware version comparison.
//     Returns {Reachable:false}, nil when the response is the error envelope
//     (unconfigured peer, network timeout, XML-RPC exception) so the opt-in
//     collector stays completely silent on single-node boxes.
//
//  2. api/core/hasync_status/services — bootgrid of cached remote service
//     states. Errors here are tolerated (warn-log, Services left nil) so a
//     transient service-list failure does not discard the version metrics.
func (c *Client) FetchHasyncStatus() (HasyncStatus, *APICallError) {
	versionURL, ok := c.endpoints["hasyncVersion"]
	if !ok {
		return HasyncStatus{}, &APICallError{
			Endpoint:   "hasyncVersion",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var rawVersion hasyncVersionResponse
	if err := c.do("GET", versionURL, nil, &rawVersion); err != nil {
		return HasyncStatus{}, err
	}

	// An empty/null "response" field means unconfigured or unreachable.
	// json.RawMessage is nil or "null" in these cases.
	if len(rawVersion.Response) == 0 || string(rawVersion.Response) == "null" {
		return HasyncStatus{Reachable: false}, nil
	}

	var versionObj hasyncVersionObj
	if err := json.Unmarshal(rawVersion.Response, &versionObj); err != nil {
		// Undecodable "response" — treat as unreachable.
		return HasyncStatus{Reachable: false}, nil
	}

	remote := string(versionObj.Firmware.Version)
	local := string(versionObj.Firmware.MyVersion)
	if remote == "" {
		// Response object present but no firmware.version — treat as unreachable.
		return HasyncStatus{Reachable: false}, nil
	}

	result := HasyncStatus{
		Reachable:     true,
		RemoteVersion: remote,
		LocalVersion:  local,
		VersionMatch:  remote == local,
	}

	// Fetch service list with partial-failure tolerance.
	servicesURL, ok := c.endpoints["hasyncServices"]
	if !ok {
		c.log.Warn("hasyncServices endpoint not found in client endpoints")
		return result, nil
	}

	form := url.Values{}
	form.Set("current", "1")
	form.Set("rowCount", "-1")

	var bootgrid hasyncServicesBootgrid
	if err := c.doForm(servicesURL, form, &bootgrid); err != nil {
		c.log.Warn("failed to fetch hasync services list", "err", err)
		return result, nil
	}

	services := make([]HasyncService, 0, len(bootgrid.Rows))
	for _, row := range bootgrid.Rows {
		running := 0.0
		if row.Status.Bool() || row.Running.Bool() {
			running = 1.0
		}
		services = append(services, HasyncService{
			Name:    string(row.Name),
			ID:      string(row.ID),
			Running: running,
		})
	}
	result.Services = services

	return result, nil
}
