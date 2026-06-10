package opnsense

import (
	"net/http"
	"testing"
)

// upscNormalFixture is a realistic upsc output covering all mapped variables.
const upscNormalFixture = `battery.charge: 100
battery.charge.low: 20
battery.runtime: 1320
battery.runtime.low: 120
battery.voltage: 27.1
device.mfr: APC
device.model: Smart-UPS 1500
device.type: ups
input.frequency: 50.0
input.voltage: 230.1
output.voltage: 229.8
ups.load: 14
ups.model: Smart-UPS 1500
ups.status: OL CHRG
ups.temperature: 24.5
`

// upscErrorFixture simulates upsd down / misconfigured (error line, no valid vars).
const upscErrorFixture = `Error: Connection failure: Connection refused`

func TestParseUpscOutput_NormalText(t *testing.T) {
	vars := parseUpscOutput(upscNormalFixture)
	if len(vars) == 0 {
		t.Fatal("expected non-empty var map, got 0 vars")
	}
	// Spot-check a few values.
	checks := map[string]string{
		"battery.charge":  "100",
		"battery.runtime": "1320",
		"battery.voltage": "27.1",
		"ups.status":      "OL CHRG",
		"ups.model":       "Smart-UPS 1500",
		"input.frequency": "50.0",
		"input.voltage":   "230.1",
		"output.voltage":  "229.8",
		"ups.load":        "14",
		"ups.temperature": "24.5",
	}
	for k, want := range checks {
		got, ok := vars[k]
		if !ok {
			t.Errorf("expected var %q not found in parsed output", k)
			continue
		}
		if got != want {
			t.Errorf("var %q: want %q, got %q", k, want, got)
		}
	}
}

func TestParseUpscOutput_ErrorText(t *testing.T) {
	vars := parseUpscOutput(upscErrorFixture)
	if len(vars) != 0 {
		t.Errorf("expected 0 vars from error text, got %d: %v", len(vars), vars)
	}
}

func TestParseUpscOutput_SingleStatusLine(t *testing.T) {
	vars := parseUpscOutput("ups.status: OL\n")
	if s, ok := vars["ups.status"]; !ok || s != "OL" {
		t.Errorf("expected ups.status=OL, got ok=%v val=%q", ok, s)
	}
	if len(vars) != 1 {
		t.Errorf("expected exactly 1 var, got %d", len(vars))
	}
}

func TestFetchNUTStatus_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/nut/diagnostics/upsstatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "battery.charge: 100\nbattery.runtime: 1320\nbattery.voltage: 27.1\ninput.voltage: 230.1\noutput.voltage: 229.8\nups.load: 14\nups.model: Smart-UPS 1500\nups.status: OL CHRG\nups.temperature: 24.5\ninput.frequency: 50.0\n"}`))
	})

	data, err := client.FetchNUTStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if !data.HasData {
		t.Fatal("expected HasData=true")
	}
	if data.Model != "Smart-UPS 1500" {
		t.Errorf("Model: want %q, got %q", "Smart-UPS 1500", data.Model)
	}
	if data.Status != "OL CHRG" {
		t.Errorf("Status: want %q, got %q", "OL CHRG", data.Status)
	}
	if v, ok := data.Metrics["battery.charge"]; !ok || v != 100 {
		t.Errorf("battery.charge: want 100, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.Metrics["battery.runtime"]; !ok || v != 1320 {
		t.Errorf("battery.runtime: want 1320, got ok=%v val=%v", ok, v)
	}
	// Status flags
	if v, ok := data.StatusFlags["online"]; !ok || v != 1 {
		t.Errorf("online flag: want 1, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.StatusFlags["on_battery"]; !ok || v != 0 {
		t.Errorf("on_battery flag: want 0, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.StatusFlags["charging"]; !ok || v != 1 {
		t.Errorf("charging flag: want 1, got ok=%v val=%v", ok, v)
	}
}

func TestFetchNUTStatus_UpsdDown(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/nut/diagnostics/upsstatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response": "Error: Connection failure: Connection refused"}`))
	})

	data, err := client.FetchNUTStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (plugin installed, upsd down)")
	}
	if data.HasData {
		t.Error("expected HasData=false when error text returned")
	}
}

func TestFetchNUTStatus_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchNUTStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}
