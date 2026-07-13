package opnsense

import "strings"

// snapshotsSupportedResponse is the api/core/snapshots/is_supported payload:
// whether the underlying filesystem is ZFS (bectl-backed boot environments)
// or not (e.g. UFS, where the endpoint still answers 200 with supported:false
// rather than 404 — confirmed against a live UFS OPNsense 26.7-devel box).
type snapshotsSupportedResponse struct {
	Supported bool `json:"supported"`
}

// bootEnvironmentRow mirrors one row of the api/core/snapshots/search bootgrid
// response (SnapshotsController -> bectl.py).
//
// Field shapes confirmed against a live OPNsense 26.7 box (2026-07-13):
//   - active carries bectl's flag string: "N" (booted now), "R" (will boot on
//     next reboot), "NR" (both), or "-" (neither). Only "NR" and "-" have been
//     observed live; bare "N"/"R" are handled per the model's documented shapes.
//   - created is a plain JSON int on the wire (not a float, despite bectl
//     itself reporting one) — flexString tolerates int, float or string so a
//     future release flipping representation doesn't need a struct change.
//   - size is a human-formatted string (e.g. "28.8G") and mountpoint/created_str
//     are display-only; none of the three are modelled as metrics per the
//     issue's scope (avoid parsing human-formatted sizes into series).
type bootEnvironmentRow struct {
	UUID    string     `json:"uuid"`
	Name    string     `json:"name"`
	Active  string     `json:"active"`
	Created flexString `json:"created"`
}

// bootEnvironmentSearchResponse is the top-level api/core/snapshots/search payload.
type bootEnvironmentSearchResponse struct {
	Total    int                  `json:"total"`
	RowCount int                  `json:"rowCount"`
	Current  int                  `json:"current"`
	Rows     []bootEnvironmentRow `json:"rows"`
}

// BootEnvironments is the normalised ZFS boot-environment inventory. On a UFS
// box (or any box where bectl is unavailable) Total is 0 and HasActive is
// false — this is a normal, healthy shape, not an error.
type BootEnvironments struct {
	// Total is the number of boot environments currently present.
	Total int
	// ActiveCreatedTimestamp is the Unix-seconds creation time of the row
	// whose active flag contains "N" (the environment currently booted),
	// valid only when HasActive is true.
	ActiveCreatedTimestamp float64
	// HasActive reports whether a row with "N" in its active flag was found.
	HasActive bool
}

// FetchSnapshotsSupported retrieves whether the root filesystem supports ZFS
// boot environments. This is a core endpoint — it is never plugin-gated and
// never answers 404; unsupported filesystems (UFS) get a 200 with
// supported:false.
func (c *Client) FetchSnapshotsSupported() (bool, *APICallError) {
	var resp snapshotsSupportedResponse

	path, ok := c.endpoints["snapshotsIsSupported"]
	if !ok {
		return false, &APICallError{
			Endpoint:   "snapshotsIsSupported",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		return false, err
	}

	return resp.Supported, nil
}

// FetchBootEnvironments retrieves the ZFS boot-environment inventory. On a
// UFS box this returns an empty, zero-value result (rows: []) rather than an
// error.
func (c *Client) FetchBootEnvironments() (BootEnvironments, *APICallError) {
	var resp bootEnvironmentSearchResponse
	var data BootEnvironments

	path, ok := c.endpoints["snapshotsSearch"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "snapshotsSearch",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		return data, err
	}

	data.Total = len(resp.Rows)
	for _, row := range resp.Rows {
		if strings.Contains(row.Active, "N") {
			data.ActiveCreatedTimestamp = safeParseFloat(row.Created.String())
			data.HasActive = true
			break
		}
	}

	return data, nil
}
