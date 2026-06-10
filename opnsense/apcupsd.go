package opnsense

import (
	"encoding/json"
	"net/http"
)

// apcupsdField is one entry in the api/apcupsd/service/getUpsStatus `status`
// map. The controller parses apcaccess output server-side:
//   - numeric-with-unit strings → norm is a JSON float64 (e.g. 100.0)
//   - plain strings (STATUS, MODEL) → norm is a JSON string
//   - unset/N/A fields → norm is JSON null
//
// VERIFICATION: unvalidated against a live sysutils/apcupsd plugin box — shape
// derived from net/apcupsd src/opnsense/mvc/app/controllers/OPNsense/Apcupsd/
// Api/ServiceController.php (getUpsStatusAction). Re-check norm field types
// against a real box when the plugin is available.
type apcupsdField struct {
	Value flexString      `json:"value"`
	Norm  json.RawMessage `json:"norm"` // float64 | string | null
}

// normFloat returns (value, true) when norm is a JSON number; (0, false)
// otherwise (null, string, or unparseable).
// Note: json.Unmarshal(null, &float64) succeeds without error in Go but leaves
// the value at zero — we must check for null explicitly before attempting to
// unmarshal to distinguish "no data" (null) from "zero value" (0).
func (f apcupsdField) normFloat() (float64, bool) {
	if len(f.Norm) == 0 || string(f.Norm) == "null" {
		return 0, false
	}
	// Reject string norms (quoted JSON values).
	if f.Norm[0] == '"' {
		return 0, false
	}
	var v float64
	if err := json.Unmarshal(f.Norm, &v); err != nil {
		return 0, false
	}
	return v, true
}

// apcupsdUpsStatusResponse is the top-level response from
// api/apcupsd/service/getUpsStatus.
//
// Controller behaviour (verified in source): $error is initialised to null and
// only set to a string on failure — success is "error": null (never false).
// When apcaccess fails the actual response is:
//
//	{"error": "Error: empty output from apcaccess", "output": null, "status": null}
//
// HasData must be gated solely on len(status) > 0 — never on error == false,
// because that value never occurs (success is null, not false).
type apcupsdUpsStatusResponse struct {
	Error  json.RawMessage         `json:"error"`  // null on success | string on failure
	Status map[string]apcupsdField `json:"status"` // null on failure → nil map
}

// ApcupsdStatus holds the normalised result of FetchApcupsdStatus.
type ApcupsdStatus struct {
	Present bool
	HasData bool
	Model   string
	Status  string             // raw STATUS value, e.g. "ONLINE"
	Metrics map[string]float64 // numeric fields keyed by apcaccess field name
}

// FetchApcupsdStatus calls api/apcupsd/service/getUpsStatus and returns the
// parsed UPS status.
//
// If the plugin is absent the endpoint returns HTTP 404, treated as "feature
// absent" → Present=false, nil error. When apcaccess fails (daemon down) the
// status map is null → Present=true, HasData=false.
//
// HasData is determined solely by len(resp.Status) > 0. The error field is
// informational only (null on success, a string on failure) and is never used
// as the data gate; gating on error==false would always fail because success
// delivers null, not false.
func (c *Client) FetchApcupsdStatus() (ApcupsdStatus, *APICallError) {
	var data ApcupsdStatus

	url, ok := c.endpoints["apcupsdUpsStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "apcupsdUpsStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp apcupsdUpsStatusResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent
		}
		return data, err
	}

	data.Present = true

	// HasData = the status map is non-empty (the sole signal; error is
	// informational — see struct comment above).
	if len(resp.Status) == 0 {
		return data, nil
	}
	data.HasData = true

	// Extract model and status strings.
	if f, ok := resp.Status["MODEL"]; ok {
		data.Model = f.Value.String()
	}
	if f, ok := resp.Status["STATUS"]; ok {
		data.Status = f.Value.String()
	}

	// Extract numeric norms for all mapped apcaccess fields.
	numericKeys := []string{
		"BCHARGE", "TIMELEFT", "LOADPCT", "LINEV", "BATTV",
		"OUTPUTV", "TONBATT", "NUMXFERS", "NOMPOWER",
	}
	data.Metrics = make(map[string]float64, len(numericKeys))
	for _, key := range numericKeys {
		if f, ok := resp.Status[key]; ok {
			if v, ok := f.normFloat(); ok {
				data.Metrics[key] = v
			}
		}
	}

	return data, nil
}
