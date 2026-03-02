package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchCronTable_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "cron-uuid-1",
					"enabled": "1",
					"minutes": "0",
					"hours": "3",
					"days": "*",
					"months": "*",
					"weekdays": "1",
					"description": "Firmware update check",
					"command": "firmware update",
					"origin": "cron"
				},
				{
					"uuid": "cron-uuid-2",
					"enabled": "0",
					"minutes": "*/5",
					"hours": "*",
					"days": "*",
					"months": "*",
					"weekdays": "*",
					"description": "Health check",
					"command": "health check",
					"origin": "cron"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchCronTable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.TotalEntries != 2 {
		t.Errorf("expected TotalEntries=2, got %d", data.TotalEntries)
	}
	if len(data.Cron) != 2 {
		t.Fatalf("expected 2 cron entries, got %d", len(data.Cron))
	}

	// First cron: enabled, check schedule formatting
	c1 := data.Cron[0]
	if c1.UUID != "cron-uuid-1" {
		t.Errorf("expected UUID 'cron-uuid-1', got %q", c1.UUID)
	}
	if c1.Status != CronStatusEnabled {
		t.Errorf("expected CronStatusEnabled, got %d", c1.Status)
	}
	expectedSchedule := "0 3 * * 1"
	if c1.Schedule != expectedSchedule {
		t.Errorf("expected schedule %q, got %q", expectedSchedule, c1.Schedule)
	}
	if c1.Description != "Firmware update check" {
		t.Errorf("expected description 'Firmware update check', got %q", c1.Description)
	}
	if c1.Command != "firmware update" {
		t.Errorf("expected command 'firmware update', got %q", c1.Command)
	}
	if c1.Origin != "cron" {
		t.Errorf("expected origin 'cron', got %q", c1.Origin)
	}

	// Second cron: disabled
	c2 := data.Cron[1]
	if c2.Status != CronStatusDisabled {
		t.Errorf("expected CronStatusDisabled, got %d", c2.Status)
	}
	expectedSchedule2 := "*/5 * * * *"
	if c2.Schedule != expectedSchedule2 {
		t.Errorf("expected schedule %q, got %q", expectedSchedule2, c2.Schedule)
	}
}

func TestFetchCronTable_InvalidStatus(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "cron-uuid-bad",
					"enabled": "not_a_number",
					"minutes": "0",
					"hours": "0",
					"days": "*",
					"months": "*",
					"weekdays": "*",
					"description": "Bad cron",
					"command": "noop",
					"origin": "cron"
				}
			],
			"rowCount": 1,
			"total": 1,
			"current": 1
		}`))
	})
	defer server.Close()

	data, err := client.FetchCronTable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// TotalEntries should be incremented, but the bad entry should be skipped
	if data.TotalEntries != 1 {
		t.Errorf("expected TotalEntries=1 (counted), got %d", data.TotalEntries)
	}
	if len(data.Cron) != 0 {
		t.Errorf("expected 0 cron entries (skipped due to invalid status), got %d", len(data.Cron))
	}
}

func TestFetchCronTable_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchCronTable()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
