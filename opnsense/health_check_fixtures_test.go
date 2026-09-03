package opnsense

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadHealthFixture unmarshals a captured /api/core/system/status response from
// testdata/health into a HealthCheckResponse, mirroring how the client decodes it.
func loadHealthFixture(t *testing.T, name string) HealthCheckResponse {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "health", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var resp HealthCheckResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	return resp
}

// TestHealthCheckResponse_Shapes pins the parsing of the OPNsense system status
// across every shape the endpoint can actually serve.
//
// The 26.1 cases are BOX STATES of one unchanged endpoint, not versions (#284). What
// this file used to call "26.1" and "26.1.11" were a reporting box and a quiet one:
// statusAction() stamps both the string status and the top-level subsystems map inside
// the same `if ($statuses)` block, so they co-occur, and neither appears without it.
// There is no metadata.subsystems shape — upstream never populates that key, and the
// two fixtures that claimed otherwise were fabricated.
func TestHealthCheckResponse_Shapes(t *testing.T) {
	cases := []struct {
		fixture        string
		wantSystemCode int
		wantCrashOK    bool
		wantFirewallOK bool
	}{
		// Quiet box (configd reported nothing): metadata.system.status is the raw enum
		// VALUE (int 2), and the top-level "subsystems" key is absent entirely. Real
		// capture from a live 26.1.11.
		{"v26_1_quiet.json", 2, true, true},
		// Reporting box: status is the enum NAME (string) and the top-level map carries
		// the detail.
		{"v26_1_crash_error.json", -1, false, true},
		{"v26_1_firewall_error.json", -1, true, false},
		// Reported, then the ACL filter unset every entry: the status was already stamped
		// "OK" (statusCodes empty -> the `?? 2` default -> the NAME), and $statuses is now
		// an empty PHP array, which json_encode renders as []. So "OK" alongside an empty
		// map is reachable, not a contradiction.
		{"v26_1_acl_filtered.json", 2, true, true},
		// Same, defensive: {} rather than []. PHP cannot emit this (an empty array never
		// encodes as an object), so this fixture is deliberately synthetic — it pins the
		// parser's tolerance, not a captured payload.
		{"v26_1_empty_map.json", 2, true, true},
		// OPNsense 25.1: numeric metadata.System.status, no subsystems map at all.
		{"v25_1_ok.json", 2, true, true},
		{"v25_1_crash_error.json", -1, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			resp := loadHealthFixture(t, tc.fixture)

			if got := resp.GetMetadataSystemStatus(); got != tc.wantSystemCode {
				t.Errorf("GetMetadataSystemStatus() = %d, want %d", got, tc.wantSystemCode)
			}
			if got := resp.CrashReporterIsHealthy(); got != tc.wantCrashOK {
				t.Errorf("CrashReporterIsHealthy() = %v, want %v", got, tc.wantCrashOK)
			}
			if got := resp.FirewallIsHealthy(); got != tc.wantFirewallOK {
				t.Errorf("FirewallIsHealthy() = %v, want %v", got, tc.wantFirewallOK)
			}
		})
	}
}

// TestGetMetadataSystemStatus_StringEnum verifies the 26.1 string-enum overall
// status ("OK"/"NOTICE"/"WARNING"/"ERROR") maps to OPNsense's numeric
// SystemStatusCode values (OK=2, NOTICE=1, WARNING=0, ERROR=-1).
func TestGetMetadataSystemStatus_StringEnum(t *testing.T) {
	cases := []struct {
		status string
		want   int
	}{
		{"OK", 2},
		{"NOTICE", 1},
		{"WARNING", 0},
		{"ERROR", -1},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			h := &HealthCheckResponse{}
			h.Metadata.System.Status = tc.status
			if got := h.GetMetadataSystemStatus(); got != tc.want {
				t.Errorf("GetMetadataSystemStatus(%q) = %d, want %d", tc.status, got, tc.want)
			}
		})
	}
}
