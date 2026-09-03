package opnsense

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestGetMetadataSystemStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   any
		expected int
	}{
		{"Int value", 2, 2},
		{"Float64 value", float64(3), 3},
		{"String value", "5", 5},
		{"Nil value", nil, 0},
		{"Invalid string", "not_a_number", 0},
		{"Bool value (unsupported)", true, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// We need to use JSON unmarshaling to set the any field properly
			// because Go switch on interface types depends on the actual runtime type.
			// For int/float64/string, we construct directly.
			h := &HealthCheckResponse{}
			h.Metadata.System.Status = tc.status
			result := h.GetMetadataSystemStatus()
			if result != tc.expected {
				t.Errorf("GetMetadataSystemStatus() = %d; want %d", result, tc.expected)
			}
		})
	}
}

func TestGetMetadataFirewallStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   any
		expected int
	}{
		{"Int value", 1, 1},
		{"Float64 value", float64(2), 2},
		{"String value", "3", 3},
		{"Nil value", nil, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &HealthCheckResponse{}
			h.Metadata.Firewall.Status = tc.status
			result := h.GetMetadataFirewallStatus()
			if result != tc.expected {
				t.Errorf("GetMetadataFirewallStatus() = %d; want %d", result, tc.expected)
			}
		})
	}
}

func TestHealthCheck_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"metadata": {
				"System": {
					"status": 2
				},
				"CrashReporter": {
					"message": "No crash reports found",
					"status": "OK",
					"statusCode": 2
				},
				"Firewall": {
					"message": "Firewall is running",
					"status": 2,
					"statusCode": 2
				}
			}
		}`))
	})
	defer server.Close()

	resp, err := client.HealthCheck()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Metadata fields (OPNsense >= 25.1)
	// System status is an int (float64 from JSON)
	if resp.GetMetadataSystemStatus() != 2 {
		t.Errorf("expected GetMetadataSystemStatus()=2, got %d", resp.GetMetadataSystemStatus())
	}
	// Firewall status is also int
	if resp.GetMetadataFirewallStatus() != 2 {
		t.Errorf("expected GetMetadataFirewallStatus()=2, got %d", resp.GetMetadataFirewallStatus())
	}
}

func TestHealthCheck_StringMetadataStatus(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"metadata": {
				"System": {"status": "2"},
				"CrashReporter": {"message": "", "status": "OK", "statusCode": 2},
				"Firewall": {"message": "", "status": "2", "statusCode": 2}
			}
		}`))
	})
	defer server.Close()

	resp, err := client.HealthCheck()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// String-typed metadata status should still parse correctly
	if resp.GetMetadataSystemStatus() != 2 {
		t.Errorf("expected GetMetadataSystemStatus()=2 (string), got %d", resp.GetMetadataSystemStatus())
	}
	if resp.GetMetadataFirewallStatus() != 2 {
		t.Errorf("expected GetMetadataFirewallStatus()=2 (string), got %d", resp.GetMetadataFirewallStatus())
	}
}

func TestHealthCheck_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.HealthCheck()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestHealthCheckSubsystem_ResolvedStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		entry    HealthCheckSubsystem
		expected int
	}{
		{"string ERROR wins over stale numeric", HealthCheckSubsystem{Status: "ERROR", StatusCode: 2}, -1},
		{"string OK", HealthCheckSubsystem{Status: "OK", StatusCode: 2}, 2},
		{"string WARNING", HealthCheckSubsystem{Status: "WARNING", StatusCode: 0}, 0},
		{"string NOTICE", HealthCheckSubsystem{Status: "NOTICE", StatusCode: 1}, 1},
		{"empty status falls back to numeric", HealthCheckSubsystem{Status: "", StatusCode: -1}, -1},
		{"unrecognized status falls back to numeric", HealthCheckSubsystem{Status: "bogus", StatusCode: 0}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.entry.ResolvedStatusCode(); got != tc.expected {
				t.Errorf("ResolvedStatusCode() = %d; want %d", got, tc.expected)
			}
		})
	}
}

// The "metadata 26.1.11 map only" and "top-level wins on key collision" cases that
// used to live here are gone with the field they exercised: metadata.subsystems is
// never populated, so there was no second map to prefer and no collision to resolve
// (#284).
func TestAllSubsystems(t *testing.T) {
	t.Run("nil when no subsystem is reported", func(t *testing.T) {
		h := &HealthCheckResponse{}
		if got := h.AllSubsystems(); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("returns the reported subsystems", func(t *testing.T) {
		h := &HealthCheckResponse{
			Subsystems: subsystemMap{
				"diskspace": {Status: "ERROR", StatusCode: -1},
				"rootlock":  {Status: "ERROR", StatusCode: -1},
			},
		}
		got := h.AllSubsystems()
		if len(got) != 2 {
			t.Fatalf("expected 2 subsystems, got %d", len(got))
		}
		if got["diskspace"].StatusCode != -1 {
			t.Errorf("diskspace StatusCode = %d, want -1", got["diskspace"].StatusCode)
		}
	})

	// The returned map must not alias the response's own, or a caller mutating it would
	// corrupt the parsed response.
	t.Run("returns a copy", func(t *testing.T) {
		h := &HealthCheckResponse{
			Subsystems: subsystemMap{"diskspace": {Status: "ERROR", StatusCode: -1}},
		}
		got := h.AllSubsystems()
		delete(got, "diskspace")
		if _, ok := h.Subsystems["diskspace"]; !ok {
			t.Error("mutating the returned map changed the response's own map")
		}
	})
}

func TestHealthCheck_MultiSubsystemFixtures(t *testing.T) {
	tests := []struct {
		fixture string
		want    map[string]int // subsystem -> resolved status code
	}{
		{
			"v26_1_multi_subsystem.json",
			map[string]int{"diskspace": -1, "rootlock": -1, "monitoverride": 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", "health", tc.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var resp HealthCheckResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("unmarshal fixture: %v", err)
			}

			got := resp.AllSubsystems()
			if len(got) != len(tc.want) {
				t.Fatalf("AllSubsystems() = %d entries, want %d (%v)", len(got), len(tc.want), got)
			}
			for name, wantCode := range tc.want {
				entry, ok := got[name]
				if !ok {
					t.Errorf("missing subsystem %q", name)
					continue
				}
				if code := entry.ResolvedStatusCode(); code != wantCode {
					t.Errorf("subsystem %q ResolvedStatusCode() = %d, want %d", name, code, wantCode)
				}
			}
		})
	}
}
