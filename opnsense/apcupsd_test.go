package opnsense

import (
	"encoding/json"
	"net/http"
	"testing"
)

const apcupsdSuccessFixture = `{
	"error": null,
	"output": "APC      : 001,036,0857\nSTATUS   : ONLINE\n",
	"status": {
		"STATUS":   {"value": "ONLINE",         "norm": "ONLINE"},
		"BCHARGE":  {"value": "100.0 Percent",  "norm": 100.0},
		"TIMELEFT": {"value": "42.0 Minutes",   "norm": 42.0},
		"LOADPCT":  {"value": "12.0 Percent",   "norm": 12.0},
		"LINEV":    {"value": "230.0 Volts",    "norm": 230.0},
		"BATTV":    {"value": "27.1 Volts",     "norm": 27.1},
		"OUTPUTV":  {"value": "229.8 Volts",    "norm": 229.8},
		"TONBATT":  {"value": "0 Seconds",      "norm": 0.0},
		"NUMXFERS": {"value": "3",              "norm": 3.0},
		"NOMPOWER": {"value": "980 Watts",      "norm": 980.0},
		"MODEL":    {"value": "Smart-UPS 1500", "norm": "Smart-UPS 1500"},
		"DATE":     {"value": "2026-06-09 08:00:00 +0000", "norm": "2026-06-09T08:00:00+00:00"},
		"NA_FIELD": {"value": "N/A",            "norm": null}
	}
}`

const apcupsdDaemonDownFixture = `{"error": "Error: empty output from apcaccess", "output": null, "status": null}`

func TestFetchApcupsdStatus_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/apcupsd/service/getUpsStatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(apcupsdSuccessFixture))
	})

	data, err := client.FetchApcupsdStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if !data.HasData {
		t.Fatal("expected HasData=true (status map non-empty)")
	}
	if data.Model != "Smart-UPS 1500" {
		t.Errorf("Model: want %q, got %q", "Smart-UPS 1500", data.Model)
	}
	if data.Status != "ONLINE" {
		t.Errorf("Status: want %q, got %q", "ONLINE", data.Status)
	}

	// TIMELEFT norm is 42.0 (minutes) — stored as-is in Metrics, collector ×60
	if v, ok := data.Metrics["TIMELEFT"]; !ok || v != 42.0 {
		t.Errorf("TIMELEFT: want 42, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.Metrics["BCHARGE"]; !ok || v != 100.0 {
		t.Errorf("BCHARGE: want 100, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.Metrics["LINEV"]; !ok || v != 230.0 {
		t.Errorf("LINEV: want 230, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.Metrics["NOMPOWER"]; !ok || v != 980.0 {
		t.Errorf("NOMPOWER: want 980, got ok=%v val=%v", ok, v)
	}
	if v, ok := data.Metrics["NUMXFERS"]; !ok || v != 3.0 {
		t.Errorf("NUMXFERS: want 3, got ok=%v val=%v", ok, v)
	}

	// NA_FIELD has norm:null — must NOT appear in Metrics
	if _, ok := data.Metrics["NA_FIELD"]; ok {
		t.Error("NA_FIELD with norm:null should not appear in Metrics")
	}
	// MODEL is a string norm — must NOT appear in numeric Metrics
	if _, ok := data.Metrics["MODEL"]; ok {
		t.Error("MODEL (string norm) should not appear in Metrics")
	}
}

func TestFetchApcupsdStatus_DaemonDown(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/apcupsd/service/getUpsStatus", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(apcupsdDaemonDownFixture))
	})

	data, err := client.FetchApcupsdStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (plugin installed, apcaccess failed)")
	}
	if data.HasData {
		t.Error("expected HasData=false when status map is null/empty")
	}
}

func TestFetchApcupsdStatus_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchApcupsdStatus()
	if err != nil {
		t.Fatalf("expected nil error on 404 (plugin absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}

func TestApcupsdNormFloat_NAIsNull(t *testing.T) {
	// norm:null must not be numeric
	f := apcupsdField{
		Value: flexString("N/A"),
		Norm:  json.RawMessage(`null`),
	}
	if _, ok := f.normFloat(); ok {
		t.Error("expected normFloat() to return ok=false for null norm")
	}
}

func TestApcupsdNormFloat_StringNorm(t *testing.T) {
	// norm is a string (e.g. STATUS value) — not numeric
	f := apcupsdField{
		Value: flexString("ONLINE"),
		Norm:  json.RawMessage(`"ONLINE"`),
	}
	if _, ok := f.normFloat(); ok {
		t.Error("expected normFloat() to return ok=false for string norm")
	}
}

func TestApcupsdNormFloat_NumericNorm(t *testing.T) {
	f := apcupsdField{
		Value: flexString("100.0 Percent"),
		Norm:  json.RawMessage(`100.0`),
	}
	v, ok := f.normFloat()
	if !ok {
		t.Fatal("expected normFloat() to return ok=true for numeric norm")
	}
	if v != 100.0 {
		t.Errorf("expected 100.0, got %v", v)
	}
}
