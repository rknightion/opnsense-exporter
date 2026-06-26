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

// TestHealthCheckResponse_Shapes pins the cross-version parsing of the OPNsense
// system status across the pre-25.1 (legacy top-level), 25.1 (metadata) and 26.1
// (top-level "subsystems" map + string-enum system status) response shapes.
func TestHealthCheckResponse_Shapes(t *testing.T) {
	cases := []struct {
		fixture        string
		wantSystemCode int
		wantCrashOK    bool
		wantFirewallOK bool
	}{
		// OPNsense >= 26.1: overall status is the string enum metadata.system.status,
		// and per-subsystem detail lives in the TOP-LEVEL "subsystems" map. A healthy
		// box returns an empty subsystems array ([]) — PHP renders an empty assoc array
		// as a JSON array, so the parser must tolerate both [] and {}.
		{"v26_1_ok.json", 2, true, true},
		{"v26_1_ok_empty_map.json", 2, true, true},
		{"v26_1_crash_error.json", -1, false, true},
		{"v26_1_firewall_error.json", -1, true, false},
		// OPNsense 25.1: numeric metadata.System.status; healthy subsystems omitted.
		{"v25_1_ok.json", 2, true, true},
		{"v25_1_crash_error.json", -1, false, true},
		// OPNsense < 25.1: legacy top-level string statuses.
		{"pre25_ok.json", 2, true, true},
		{"pre25_crash_error.json", -1, false, true},
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
