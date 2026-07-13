package opnsense

import (
	"net/http"
	"testing"
)

// --- FetchDMIInfo -----------------------------------------------------------

func TestFetchDMIInfo_Success(t *testing.T) {
	// Real dev-box capture (2026-07-13, QEMU DMI).
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dmidecode/service/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"status":"ok","system":{"Manufacturer":"QEMU","Product Name":"Standard PC (i440FX + PIIX, 1996)","Version":"pc-i440fx-11.0","Serial Number":"Not Specified","Family":"Not Specified"},"bios":{"Vendor":"SeaBIOS","Version":"rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org","Release Date":"04/01/2014"}}`))
	})

	data, err := client.FetchDMIInfo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if data.Manufacturer != "QEMU" {
		t.Errorf("expected Manufacturer=QEMU, got %q", data.Manufacturer)
	}
	if data.Product != "Standard PC (i440FX + PIIX, 1996)" {
		t.Errorf("expected Product Name, got %q", data.Product)
	}
	if data.Version != "pc-i440fx-11.0" {
		t.Errorf("expected Version=pc-i440fx-11.0, got %q", data.Version)
	}
	if data.Serial != "Not Specified" {
		t.Errorf("expected Serial='Not Specified', got %q", data.Serial)
	}
	if data.Family != "Not Specified" {
		t.Errorf("expected Family='Not Specified', got %q", data.Family)
	}
	if data.BIOSVendor != "SeaBIOS" {
		t.Errorf("expected BIOSVendor=SeaBIOS, got %q", data.BIOSVendor)
	}
	if data.BIOSVersion != "rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org" {
		t.Errorf("expected BIOSVersion, got %q", data.BIOSVersion)
	}
	if data.BIOSRelease != "04/01/2014" {
		t.Errorf("expected BIOSRelease=04/01/2014, got %q", data.BIOSRelease)
	}
}

func TestFetchDMIInfo_NotFound(t *testing.T) {
	// os-dmidecode not installed: endpoint 404s. Feature absent, no error.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dmidecode/service/get", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	data, err := client.FetchDMIInfo()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for 404")
	}
	if data.Manufacturer != "" {
		t.Errorf("expected empty Manufacturer for 404, got %q", data.Manufacturer)
	}
}

func TestFetchDMIInfo_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dmidecode/service/get", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchDMIInfo()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// --- FetchDechwPowerStatus ---------------------------------------------------

func TestFetchDechwPowerStatus_OK(t *testing.T) {
	// Source-derived success shape (opnsense/plugins sysutils/dec-hw
	// InfoController::powerStatusAction): {"status":"OK","pwr1":"1","pwr2":"0"}.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"status":"OK","pwr1":"1","pwr2":"0"}`))
	})

	data, err := client.FetchDechwPowerStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true for status:OK")
	}
	if data.PSU1 == nil || !*data.PSU1 {
		t.Errorf("expected PSU1=true, got %v", data.PSU1)
	}
	if data.PSU2 == nil || *data.PSU2 {
		t.Errorf("expected PSU2=false, got %v", data.PSU2)
	}
}

func TestFetchDechwPowerStatus_OK_NumericPwr(t *testing.T) {
	// Defensive: also accept unquoted numeric 0/1 (ini scanner may auto-type).
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"OK","pwr1":1,"pwr2":0}`))
	})

	data, err := client.FetchDechwPowerStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.PSU1 == nil || !*data.PSU1 {
		t.Errorf("expected PSU1=true, got %v", data.PSU1)
	}
	if data.PSU2 == nil || *data.PSU2 {
		t.Errorf("expected PSU2=false, got %v", data.PSU2)
	}
}

func TestFetchDechwPowerStatus_HardwareAbsent(t *testing.T) {
	// Real dev-box capture (2026-07-13): plugin installed, no GPIO device
	// (non-Deciso/VM hardware) -> HTTP 200 {"status":"failed"}, no pwr1/pwr2
	// keys at all. This must NOT be treated as an error, and must yield no
	// PSU data (three-state handling: plugin-absent vs hardware-absent vs OK).
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"failed"}`))
	})

	data, err := client.FetchDechwPowerStatus()
	if err != nil {
		t.Fatalf("expected nil error for status:failed, got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for status:failed (hardware absent)")
	}
	if data.PSU1 != nil || data.PSU2 != nil {
		t.Errorf("expected nil PSU1/PSU2 for status:failed, got PSU1=%v PSU2=%v", data.PSU1, data.PSU2)
	}
}

func TestFetchDechwPowerStatus_SinglePSU(t *testing.T) {
	// Defensive: a variant reporting only one PSU must not fabricate a "failed"
	// series for the missing key.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"OK","pwr1":"1"}`))
	})

	data, err := client.FetchDechwPowerStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.PSU1 == nil || !*data.PSU1 {
		t.Errorf("expected PSU1=true, got %v", data.PSU1)
	}
	if data.PSU2 != nil {
		t.Errorf("expected PSU2=nil (key absent), got %v", *data.PSU2)
	}
}

func TestFetchDechwPowerStatus_NotFound(t *testing.T) {
	// os-dec-hw not installed at all: endpoint 404s. Feature absent, no error.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	data, err := client.FetchDechwPowerStatus()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for 404")
	}
}

func TestFetchDechwPowerStatus_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchDechwPowerStatus()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
