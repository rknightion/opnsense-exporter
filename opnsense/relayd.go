package opnsense

import (
	"net/http"
	"strings"
)

// relaydHostProperty is the OPNsense-config-side identity of a table host, as
// embedded in a status/sum host entry's "properties" array. StatusController
// looks this up by matching the host's address against the configured
// relayd host objects, so it may legitimately be empty (a reported address
// with no matching config object — e.g. a stale/renamed host).
type relaydHostProperty struct {
	UUID    string     `json:"uuid"`
	Name    string     `json:"name"`
	Enabled flexString `json:"enabled"`
}

// relaydHostEntry mirrors one entry of a table's "hosts" object in the
// api/relayd/status/sum response.
//
// VERIFIED against `net/relayd` plugin source (StatusController::sumAction,
// which parses `relayctl show summary` output) and a live OPNsense dev box
// with a real redirect + 2-host table topology (issue #202).
//
// Field quirks (all confirmed from source, not guessed):
//   - "name" is NOT a friendly name — it is relayd's raw host identifier,
//     which is actually the configured host address. The friendly name (if a
//     matching OPNsense host object exists) is properties[0].name.
//   - "avlblty" is the empty string "" when relayd has performed zero checks
//     yet (host_check_cnt == 0, from relayctl's print_availability), a
//     "NN.NN%" string once checks have run, or JSON null for a host that is
//     configured into the table but was not reported live by relayd (the
//     controller backfills it from config so a disabled/dropped host isn't
//     silently lost). flexString folds null to "", so both "no data" shapes
//     collapse to the same empty value — exactly the "omit the metric" case.
//   - "status" is one of relayctl's print_host_status() outputs — "up",
//     "down", "unknown" — with "disabled" renamed to "stopped" by the PHP
//     controller for a live-reported host, or "disabled"/"-" for a backfilled
//     host that never reported. Only "up" is ever mapped to a healthy 1;
//     every other value (including any future/unrecognised string) maps to 0.
type relaydHostEntry struct {
	Properties []relaydHostProperty `json:"properties"`
	Name       flexString           `json:"name"`
	Avlblty    flexString           `json:"avlblty"`
	Status     flexString           `json:"status"`
}

// relaydTableEntry mirrors one entry of a virtual server's "tables" object.
//
// "name" is relayd's internal composite table name, "<configured-name>:<port>"
// (relayd generates one pf table per forwarding port), confirmed by
// StatusController::sumAction doing
// getObjectsByAttribute("table", "name", explode(":", $words[2])[0]) to
// resolve the real config object. FetchRelaydStatus strips the ":<port>"
// suffix so the table label matches the name configured in the OPNsense GUI.
//
// "status" is one of relayctl's print_table_status() outputs: "disabled",
// "empty", or "active (N hosts)". Only a value starting with "active" maps
// to a healthy 1.
type relaydTableEntry struct {
	Name   string                     `json:"name"`
	Status flexString                 `json:"status"`
	UUID   string                     `json:"uuid"`
	Hosts  map[string]relaydHostEntry `json:"hosts"`
}

// relaydVirtualServerRow mirrors one element of the top-level "rows" array —
// a relayd redirect or relay ("virtual server" in the OPNsense GUI).
//
// "status" is one of relayctl's print_rdr_status()/print_relay_status()
// outputs: "disabled", "down", "active (using backup table)", or "active".
// Only a value starting with "active" maps to a healthy 1 (map
// conservatively per the issue: unknown/future strings fall back to 0).
type relaydVirtualServerRow struct {
	ID     string                      `json:"id"`
	Type   string                      `json:"type"`
	Name   string                      `json:"name"`
	Status flexString                  `json:"status"`
	UUID   string                      `json:"uuid"`
	Tables map[string]relaydTableEntry `json:"tables"`
}

// relaydStatusSumResponse mirrors the api/relayd/status/sum response.
//
// "result" is "ok" when relayctl produced summary output, or "failed" when it
// did not — which happens both when the relayd service isn't running yet
// (no topology configured, "no actions, nothing to do" from configtest) and,
// defensively, if the control socket is otherwise unreachable. Either way it
// means "no live data right now", not an API error — StatusController itself
// initialises result to "failed" and only flips it to "ok" once it has parsed
// at least one summary line.
type relaydStatusSumResponse struct {
	Result string                   `json:"result"`
	Rows   []relaydVirtualServerRow `json:"rows"`
}

// RelaydHost is the normalised health of one table member host.
type RelaydHost struct {
	Name                string // friendly name; falls back to Address when no config object matched
	Address             string
	Up                  float64 // 1 = status "up", 0 = anything else
	AvailabilityPercent float64
	HasAvailability     bool // false when avlblty was null or "" (no checks performed yet / backfilled)
}

// RelaydTable is the normalised health of one table (a pool of hosts).
type RelaydTable struct {
	Name   string // port suffix stripped, matches the OPNsense GUI table name
	Active float64
	Hosts  []RelaydHost
}

// RelaydVirtualServer is the normalised health of one redirect/relay.
type RelaydVirtualServer struct {
	Name   string
	Type   string // "redirect" or "relay"
	Active float64
	Tables []RelaydTable
}

// RelaydStatus holds the aggregated result of FetchRelaydStatus.
type RelaydStatus struct {
	Present        bool // false when the os-relayd plugin is absent (HTTP 404)
	HasData        bool // false when result == "failed" (stopped / no topology yet — not an error)
	VirtualServers []RelaydVirtualServer
}

// relaydActive maps a relayctl status string to 1 when it represents a
// healthy/active state, conservatively: only strings starting with "active"
// count (covers plain "active", table's "active (N hosts)", and the
// redirect's "active (using backup table)"). Every other value — "disabled",
// "down", "empty", "unknown", or anything unrecognised — maps to 0.
func relaydActive(status string) float64 {
	if strings.HasPrefix(status, "active") {
		return 1
	}
	return 0
}

// relaydHostUp maps a relayctl host status string to 1 only for the exact
// value "up". Every other value (including "down", "unknown", "stopped",
// "disabled", "-", or anything unrecognised) maps to 0 — a fixed, safe
// fallback for the free-text-ish status field.
func relaydHostUp(status string) float64 {
	if status == "up" {
		return 1
	}
	return 0
}

// relaydTableDisplayName strips relayd's ":<port>" suffix from a table's
// internal composite name, matching the real config object name (see the
// relaydTableEntry doc comment).
func relaydTableDisplayName(rawName string) string {
	if idx := strings.Index(rawName, ":"); idx >= 0 {
		return rawName[:idx]
	}
	return rawName
}

// FetchRelaydStatus calls the relayd status summary endpoint and returns
// aggregated virtual server / table / host health.
//
// If the os-relayd plugin is not installed the endpoint returns HTTP 404,
// treated as "feature absent" (Present stays false, no error). When the
// plugin is present but relayd has no topology configured yet (or the
// service otherwise has nothing to summarise) the response is
// {"result":"failed"} with no rows — HasData stays false, still no error.
//
// Always called without OPNsense's optional "wait" query parameter: passing
// wait=1 makes the endpoint block server-side for up to 10 seconds while it
// retries for a "sensible" (non-unknown) status, which is not worth paying
// on every scrape.
func (c *Client) FetchRelaydStatus() (RelaydStatus, *APICallError) {
	var data RelaydStatus

	url, ok := c.endpoints["relaydStatusSum"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "relaydStatusSum",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp relaydStatusSumResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	if resp.Result != "ok" {
		return data, nil
	}
	data.HasData = true

	for _, row := range resp.Rows {
		vs := RelaydVirtualServer{
			Name:   row.Name,
			Type:   row.Type,
			Active: relaydActive(row.Status.String()),
		}

		for _, table := range row.Tables {
			t := RelaydTable{
				Name:   relaydTableDisplayName(table.Name),
				Active: relaydActive(table.Status.String()),
			}

			for _, host := range table.Hosts {
				address := host.Name.String()
				name := address
				if len(host.Properties) > 0 && host.Properties[0].Name != "" {
					name = host.Properties[0].Name
				}

				h := RelaydHost{
					Name:    name,
					Address: address,
					Up:      relaydHostUp(host.Status.String()),
				}
				avail := strings.TrimSuffix(host.Avlblty.String(), "%")
				if pct, ok := safeParseFloatOK(avail); ok {
					h.AvailabilityPercent = pct
					h.HasAvailability = true
				}

				t.Hosts = append(t.Hosts, h)
			}

			vs.Tables = append(vs.Tables, t)
		}

		data.VirtualServers = append(data.VirtualServers, vs)
	}

	return data, nil
}
