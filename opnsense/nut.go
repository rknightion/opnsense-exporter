package opnsense

import (
	"net/http"
	"regexp"
	"strings"
)

// nutVarRe matches valid upsc variable names so error/banner lines are dropped.
var nutVarRe = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)

// parseUpscOutput parses `upsc` key-value text into a map. Lines that do not
// look like "var.name: value" (including upsc error messages) are skipped.
func parseUpscOutput(raw string) map[string]string {
	vars := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if !nutVarRe.MatchString(key) {
			continue
		}
		vars[key] = strings.TrimSpace(value)
	}
	return vars
}

type nutUpsStatusResponse struct {
	Response flexString `json:"response"`
}

// NUTStatus holds the normalised result of FetchNUTStatus.
//
// VERIFICATION: unvalidated against a live sysutils/nut box — shape derived
// from net/nut/.../Api/DiagnosticsController.php which shells out `upsc` and
// returns the raw text in a {"response":"..."} envelope. Re-check against a
// real box when the plugin is available: confirm the envelope key ("response")
// and the exact upsc variable names.
type NUTStatus struct {
	Present     bool               // false when plugin is absent (404)
	HasData     bool               // true when ≥1 upsc variable was parsed
	Model       string             // ups.model or device.model
	Status      string             // raw ups.status, e.g. "OL CHRG"
	Metrics     map[string]float64 // key = upsc var name, only numeric vars present
	StatusFlags map[string]float64 // online, on_battery, low_battery, charging, replace_battery
}

// FetchNUTStatus calls api/nut/diagnostics/upsstatus and parses the upsc
// text response into a NUTStatus. A 404 response is treated as "plugin absent"
// — empty data, nil error. When upsd is down or misconfigured the API returns
// an error message in the response field; lines without valid upsc key names
// are silently dropped so no variables are parsed (HasData=false).
func (c *Client) FetchNUTStatus() (NUTStatus, *APICallError) {
	var data NUTStatus

	url, ok := c.endpoints["nutUpsStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "nutUpsStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp nutUpsStatusResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // plugin absent: Present stays false
		}
		return data, err
	}
	data.Present = true

	vars := parseUpscOutput(resp.Response.String())
	if len(vars) == 0 {
		// upsd down or error — no usable data
		return data, nil
	}
	data.HasData = true

	// Model: prefer ups.model, fall back to device.model.
	if m, ok := vars["ups.model"]; ok && m != "" {
		data.Model = m
	} else if m, ok := vars["device.model"]; ok {
		data.Model = m
	}

	// Status string.
	data.Status = vars["ups.status"]

	// Numeric metrics — emit only keys that are present in the upsc output.
	data.Metrics = make(map[string]float64)
	numericVars := []string{
		"battery.charge",
		"battery.runtime",
		"battery.voltage",
		"input.voltage",
		"output.voltage",
		"ups.load",
		"ups.temperature",
		"input.frequency",
	}
	for _, k := range numericVars {
		if v, ok := vars[k]; ok {
			data.Metrics[k] = safeParseFloat(v)
		}
	}

	// Status flags — parsed from whitespace-separated tokens in ups.status.
	// Each flag is emitted as 1 or 0. Only populated when ups.status is present.
	if statusStr, ok := vars["ups.status"]; ok {
		tokens := strings.Fields(statusStr)
		tokenSet := make(map[string]bool, len(tokens))
		for _, t := range tokens {
			tokenSet[t] = true
		}
		data.StatusFlags = map[string]float64{
			"online":          boolToFloat(tokenSet["OL"]),
			"on_battery":      boolToFloat(tokenSet["OB"]),
			"low_battery":     boolToFloat(tokenSet["LB"]),
			"charging":        boolToFloat(tokenSet["CHRG"]),
			"replace_battery": boolToFloat(tokenSet["RB"]),
		}
	}

	return data, nil
}

// boolToFloat converts a bool to 1.0 or 0.0.
func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
