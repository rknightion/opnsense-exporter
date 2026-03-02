package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchTemperatures_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`[
			{"device": "hw.acpi.thermal", "device_seq": 0, "temperature": "45.5", "type_translated": "ACPI Thermal Zone", "type": "acpi_tz"},
			{"device": "dev.cpu", "device_seq": 0, "temperature": "62.0", "type_translated": "CPU Core", "type": "coretemp"},
			{"device": "dev.cpu", "device_seq": 1, "temperature": "", "type_translated": "CPU Core", "type": "coretemp"}
		]`))
	})
	defer server.Close()

	readings, err := client.FetchTemperatures()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(readings) != 3 {
		t.Fatalf("expected 3 readings, got %d", len(readings))
	}

	// First reading: valid temperature
	if readings[0].Device != "hw.acpi.thermal" {
		t.Errorf("expected device 'hw.acpi.thermal', got %q", readings[0].Device)
	}
	if readings[0].DeviceSeq != 0 {
		t.Errorf("expected DeviceSeq=0, got %d", readings[0].DeviceSeq)
	}
	if readings[0].Type != "acpi_tz" {
		t.Errorf("expected type 'acpi_tz', got %q", readings[0].Type)
	}
	if readings[0].Celsius != 45.5 {
		t.Errorf("expected Celsius=45.5, got %f", readings[0].Celsius)
	}

	// Second reading: valid temperature
	if readings[1].Celsius != 62.0 {
		t.Errorf("expected Celsius=62.0, got %f", readings[1].Celsius)
	}

	// Third reading: empty temperature string -> safeParseFloat returns 0
	if readings[2].Celsius != 0.0 {
		t.Errorf("expected Celsius=0.0 for empty string, got %f", readings[2].Celsius)
	}
}

func TestFetchTemperatures_EmptyArray(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	defer server.Close()

	readings, err := client.FetchTemperatures()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(readings) != 0 {
		t.Errorf("expected 0 readings, got %d", len(readings))
	}
}

func TestFetchTemperatures_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchTemperatures()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
