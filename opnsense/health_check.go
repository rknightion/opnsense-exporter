package opnsense

import (
	"bytes"
	"encoding/json"
	"maps"
	"strconv"
	"strings"
)

// subsystemMap is the top-level "subsystems" collection from OPNsense 26.1. OPNsense
// builds it as a PHP associative array, so json_encode renders it as a JSON object
// ({...}) when it has entries but as an empty JSON array ([]) when a healthy box has
// no subsystems to report. A plain map[...] field cannot unmarshal that "[]", which
// would fail the whole health parse and mark a HEALTHY box as down — so this type
// tolerates an array or null as "no subsystems".
type subsystemMap map[string]HealthCheckSubsystem

func (m *subsystemMap) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] == '[' || string(trimmed) == "null" {
		*m = nil
		return nil
	}
	var raw map[string]HealthCheckSubsystem
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*m = raw
	return nil
}

// HealthCheckSubsystem is one entry of the top-level "subsystems" map returned by
// OPNsense >= 26.1, keyed by the subsystem short name (e.g. "crashreporter",
// "firewall"). On 25.1 and earlier this map is absent and the per-subsystem detail
// lives under the legacy top-level / metadata fields instead.
type HealthCheckSubsystem struct {
	Message    string `json:"message"`
	Status     string `json:"status"`
	StatusCode int    `json:"statusCode"`
}

// isHealthy reports whether this subsystem entry represents an OK state. The string
// status is authoritative when present (it is the SystemStatusCode enum name, e.g.
// "OK"/"ERROR"); otherwise the numeric statusCode is used (OK == 2).
func (s HealthCheckSubsystem) isHealthy() bool {
	if s.Status != "" {
		return s.Status == HealthCheckStatusOK
	}
	return s.StatusCode == HealthCheckStatusOK_v25_1
}

type HealthCheckResponse struct {
	System struct {
		Status string `json:"status"`
	} `json:"System"`
	CrashReporter struct {
		Message    string `json:"message"`
		Status     string `json:"status"`
		StatusCode int    `json:"statusCode"`
	} `json:"CrashReporter"`
	Firewall struct {
		Message    string `json:"message"`
		Status     string `json:"status"`
		StatusCode int    `json:"statusCode"`
	} `json:"Firewall"`
	// OPNsense>25.1 has a different structure
	// See https://github.com/rknightion/opnsense2otel/issues/48#issuecomment-2692494735
	//
	// NOTE: there is deliberately NO Subsystems field here. Upstream initialises
	// metadata.subsystems to [] (SystemController::statusAction, the $response
	// ['metadata'] literal) and NEVER assigns it again — the only per-subsystem map it
	// emits is the TOP-LEVEL one below. A field here could therefore only ever decode
	// [], and modelling it as "the 26.1.11 shape" cost a fabricated pair of fixtures
	// and a permanently no-op branch in every reader (#284). Verified against upstream
	// source: the controller is byte-identical on master, stable/26.1 and stable/25.7,
	// and untouched since 2025-01-21.
	Metadata struct {
		System struct {
			Status any `json:"status"`
		} `json:"System"`
		CrashReporter struct {
			Message    string `json:"message"`
			Status     string `json:"status"`
			StatusCode int    `json:"statusCode"`
		} `json:"CrashReporter"`
		Firewall struct {
			Message    string `json:"message"`
			Status     any    `json:"status"`
			StatusCode int    `json:"statusCode"`
		} `json:"Firewall"`
	} `json:"metadata"`
	// Subsystems is the per-subsystem detail: the ONLY such map upstream emits.
	//
	// Its presence is BOX STATE, not a version. statusAction() assigns it only inside
	// `if ($statuses)` — i.e. only when configd's `system status` reported something —
	// so a box with nothing to report omits the key entirely. That is also why
	// metadata.system.status is an int on a quiet box and a string enum otherwise:
	// both are set in that same block. Absent on 25.1 and earlier, which has no such
	// map at all.
	//
	// It can arrive as an empty ARRAY: the block's ACL filter can unset every entry it
	// just built, leaving an empty PHP array that json_encode renders "[]" while the
	// status has already been stamped "OK". Hence the array-tolerant subsystemMap.
	Subsystems subsystemMap `json:"subsystems"`
}

// Canonical subsystem keys as used by OPNsense 26.1's top-level "subsystems" map.
// The key is the status class short name lowercased with "Status" stripped, e.g.
// CrashReporterStatus -> "crashreporter", FirewallStatus -> "firewall".
const (
	SubsystemCrashReporter = "crashreporter"
	SubsystemFirewall      = "firewall"
)

// systemStatusStringToCode maps OPNsense's SystemStatusCode enum name to its integer
// value (see OPNsense System/SystemStatusCode.php). 26.1 reports the overall status
// as one of these strings; legacy responses use the same names (mixed case), so the
// lookup is case-insensitive.
func systemStatusStringToCode(s string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "OK":
		return 2, true
	case "NOTICE":
		return 1, true
	case "WARNING":
		return 0, true
	case "ERROR":
		return -1, true
	}
	return 0, false
}

// GetMetadataSystemStatus resolves the rolled-up overall system status as OPNsense's
// numeric SystemStatusCode. Returns 0 when no status can be determined.
//
// metadata.system.status is an INT or a STRING depending on BOX STATE, not on version
// (#284). statusAction() seeds it with SystemStatusCode::OK->value — the int 2 — and
// only overwrites it with an enum NAME ("OK"/"NOTICE"/"WARNING"/"ERROR") inside
// `if ($statuses)`, i.e. once configd's `system status` has reported something. So a
// box with nothing to report sends 2, and a box with something to report sends a
// string. It is also a string when the ACL filter then hides every entry, which is why
// "OK" can arrive alongside an empty subsystems map.
//
// A legacy top-level string status (pre-25.1) is the final fallback.
func (h *HealthCheckResponse) GetMetadataSystemStatus() int {
	switch v := h.Metadata.System.Status.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		if code, ok := systemStatusStringToCode(v); ok {
			return code
		}
	}
	// Fall back to the legacy top-level string status (pre-25.1, and a healthy box's
	// "OK" when metadata.system.status is absent).
	if code, ok := systemStatusStringToCode(h.System.Status); ok {
		return code
	}
	return 0
}

// GetMetadataFirewallStatus converts the Status field to int, handling both string and int types
func (h *HealthCheckResponse) GetMetadataFirewallStatus() int {
	switch v := h.Metadata.Firewall.Status.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}

// subsystemHealthy resolves a single subsystem's health across every response shape:
// the top-level "subsystems" map (25.1+), the legacy <25.1 top-level string status,
// and the 25.1 metadata status (string or numeric). A subsystem is healthy unless
// some present source reports a non-OK status; an absent/empty status is treated as
// healthy because OPNsense omits healthy subsystems from the report (a perfectly
// healthy 25.1+ box carries no per-subsystem entry at all).
func (h *HealthCheckResponse) subsystemHealthy(name, legacyStatus string, metaStatus any) bool {
	if entry, ok := h.Subsystems[name]; ok && !entry.isHealthy() {
		return false
	}
	if legacyStatus != "" && legacyStatus != HealthCheckStatusOK {
		return false
	}
	switch s := metaStatus.(type) {
	case string:
		if s == "" || s == HealthCheckStatusOK {
			// healthy
		} else if i, err := strconv.Atoi(s); err == nil {
			// OPNsense 25.1+ can return the numeric status as a string (e.g. "2").
			if i != HealthCheckStatusOK_v25_1 {
				return false
			}
		} else {
			return false
		}
	case float64:
		if int(s) != HealthCheckStatusOK_v25_1 {
			return false
		}
	case int:
		if s != HealthCheckStatusOK_v25_1 {
			return false
		}
	}
	return true
}

// ResolvedStatusCode resolves this subsystem entry's numeric SystemStatusCode (2=OK,
// 1=NOTICE, 0=WARNING, -1=ERROR), preferring the string status enum (authoritative — same
// precedence as isHealthy) and falling back to the raw StatusCode field when the string is
// absent or unrecognized.
func (s HealthCheckSubsystem) ResolvedStatusCode() int {
	if code, ok := systemStatusStringToCode(s.Status); ok {
		return code
	}
	return s.StatusCode
}

// AllSubsystems returns the per-subsystem detail keyed by subsystem short name — e.g.
// "diskspace", "rootlock", "crashreporter", "firewall", or any plugin-contributed key.
// OPNsense's SystemStatus::collectStatus() omits every subsystem currently reporting OK,
// so a present entry is always worth reporting; an absent key means that subsystem is
// healthy (same convention as CrashReporterIsHealthy/FirewallIsHealthy). Returns nil
// when no subsystem is reported: a box with nothing to say, or a pre-25.1 firewall that
// has no such map at all.
//
// It used to merge a second map from metadata.subsystems. That map does not exist on
// any release — see the note on the Metadata field and #284 — so the union, its
// precedence rule and the "never observed on a real box" caveat that went with it are
// gone. The one map upstream emits is the one read here.
func (h *HealthCheckResponse) AllSubsystems() map[string]HealthCheckSubsystem {
	if len(h.Subsystems) == 0 {
		return nil
	}
	all := make(map[string]HealthCheckSubsystem, len(h.Subsystems))
	maps.Copy(all, h.Subsystems)
	return all
}

// CrashReporterIsHealthy reports whether the crash reporter subsystem is healthy
// (no crash reports present), tolerating the 26.1 subsystems map and the legacy /
// 25.1 metadata shapes.
func (h *HealthCheckResponse) CrashReporterIsHealthy() bool {
	return h.subsystemHealthy(SubsystemCrashReporter, h.CrashReporter.Status, h.Metadata.CrashReporter.Status)
}

// FirewallIsHealthy reports whether the firewall subsystem is healthy, tolerating the
// 26.1 subsystems map and the legacy / 25.1 metadata shapes (the metadata firewall
// status may arrive as a JSON number, a string, or be absent on a healthy box).
func (h *HealthCheckResponse) FirewallIsHealthy() bool {
	return h.subsystemHealthy(SubsystemFirewall, h.Firewall.Status, h.Metadata.Firewall.Status)
}

const (
	HealthCheckStatusOK = "OK"
	// OPNsense>25.1 has a different value
	// See https://github.com/rknightion/opnsense2otel/issues/48#issuecomment-2692494735
	HealthCheckStatusOK_v25_1 = 2
)

// HealthCheck checks if the OPNsense is up and running.
func (c *Client) HealthCheck() (HealthCheckResponse, error) {
	var resp HealthCheckResponse

	path, ok := c.endpoints["healthCheck"]

	if !ok {
		return HealthCheckResponse{}, &APICallError{
			Endpoint:   "healthCheck",
			Message:    "endpoint not found",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		return HealthCheckResponse{}, err
	}

	return resp, nil
}
