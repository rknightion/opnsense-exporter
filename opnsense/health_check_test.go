package opnsense

import (
	"net/http"
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
			"System": {
				"status": "OK"
			},
			"CrashReporter": {
				"message": "No crash reports found",
				"status": "OK",
				"statusCode": 2
			},
			"Firewall": {
				"message": "Firewall is running",
				"status": "OK",
				"statusCode": 2
			},
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

	// Legacy fields
	if resp.System.Status != "OK" {
		t.Errorf("expected System.Status='OK', got %q", resp.System.Status)
	}
	if resp.CrashReporter.Status != "OK" {
		t.Errorf("expected CrashReporter.Status='OK', got %q", resp.CrashReporter.Status)
	}
	if resp.CrashReporter.StatusCode != 2 {
		t.Errorf("expected CrashReporter.StatusCode=2, got %d", resp.CrashReporter.StatusCode)
	}
	if resp.Firewall.Status != "OK" {
		t.Errorf("expected Firewall.Status='OK', got %q", resp.Firewall.Status)
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
			"System": {"status": "OK"},
			"CrashReporter": {"message": "", "status": "OK", "statusCode": 2},
			"Firewall": {"message": "", "status": "OK", "statusCode": 2},
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
