package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchSMARTDevices_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST for list, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content-type, got %q", ct)
		}
		w.Write([]byte(`{"devices":["ada0","nvme0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST for info, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		device := r.FormValue("device")
		switch device {
		case "ada0":
			w.Write([]byte(`{
				"output": {
					"model_name": "WDC WD40EFRX",
					"serial_number": "WD-SERIAL001",
					"smart_status": {"passed": true},
					"temperature": {"current": 38},
					"power_on_time": {"hours": 12044}
				}
			}`))
		case "nvme0":
			w.Write([]byte(`{
				"output": {
					"model_name": "Samsung SSD 970",
					"serial_number": "NVME-SERIAL002",
					"smart_status": {"passed": true},
					"temperature": {"current": 45},
					"power_on_time": {"hours": 300}
				}
			}`))
		default:
			t.Errorf("unexpected device %q in info request", device)
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.DeviceCount != 2 {
		t.Errorf("expected DeviceCount=2, got %d", data.DeviceCount)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(data.Devices))
	}

	// Check ada0
	ada0 := data.Devices[0]
	if ada0.Device != "ada0" {
		t.Errorf("expected device 'ada0', got %q", ada0.Device)
	}
	if ada0.Model != "WDC WD40EFRX" {
		t.Errorf("expected model 'WDC WD40EFRX', got %q", ada0.Model)
	}
	if ada0.Serial != "WD-SERIAL001" {
		t.Errorf("expected serial 'WD-SERIAL001', got %q", ada0.Serial)
	}
	if ada0.Health == nil {
		t.Error("expected ada0 Health to be non-nil")
	} else if !*ada0.Health {
		t.Error("expected ada0 Health=true")
	}
	if ada0.Temperature == nil {
		t.Error("expected ada0 Temperature to be non-nil")
	} else if *ada0.Temperature != 38 {
		t.Errorf("expected ada0 Temperature=38, got %v", *ada0.Temperature)
	}
	if ada0.PowerOnHours == nil {
		t.Error("expected ada0 PowerOnHours to be non-nil")
	} else if *ada0.PowerOnHours != 12044 {
		t.Errorf("expected ada0 PowerOnHours=12044, got %v", *ada0.PowerOnHours)
	}

	// Check nvme0
	nvme0 := data.Devices[1]
	if nvme0.Device != "nvme0" {
		t.Errorf("expected device 'nvme0', got %q", nvme0.Device)
	}
	if nvme0.Temperature == nil {
		t.Error("expected nvme0 Temperature to be non-nil")
	} else if *nvme0.Temperature != 45 {
		t.Errorf("expected nvme0 Temperature=45, got %v", *nvme0.Temperature)
	}
	if nvme0.PowerOnHours == nil {
		t.Error("expected nvme0 PowerOnHours to be non-nil")
	} else if *nvme0.PowerOnHours != 300 {
		t.Errorf("expected nvme0 PowerOnHours=300, got %v", *nvme0.PowerOnHours)
	}
}

func TestFetchSMARTDevices_InvalidDeviceSkipped(t *testing.T) {
	// When info returns {"message": "..."} (no output), the device entry is
	// included in DeviceCount but has nil Health/Temperature/PowerOnHours.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0","bad0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		device := r.FormValue("device")
		switch device {
		case "ada0":
			w.Write([]byte(`{
				"output": {
					"model_name": "WDC WD40EFRX",
					"serial_number": "WD-SERIAL001",
					"smart_status": {"passed": true},
					"temperature": {"current": 38},
					"power_on_time": {"hours": 12044}
				}
			}`))
		case "bad0":
			// OPNsense returns message + no output on validation failure
			w.Write([]byte(`{"message":"Invalid device name"}`))
		}
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.DeviceCount != 2 {
		t.Errorf("expected DeviceCount=2 (list count), got %d", data.DeviceCount)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("expected 2 device entries, got %d", len(data.Devices))
	}

	// ada0 should be fully populated
	ada0 := data.Devices[0]
	if ada0.Health == nil {
		t.Error("expected ada0 Health to be non-nil")
	}

	// bad0 should have nil optional fields
	bad0 := data.Devices[1]
	if bad0.Device != "bad0" {
		t.Errorf("expected device 'bad0', got %q", bad0.Device)
	}
	if bad0.Health != nil {
		t.Errorf("expected bad0 Health=nil (no output), got %v", *bad0.Health)
	}
	if bad0.Temperature != nil {
		t.Errorf("expected bad0 Temperature=nil (no output), got %v", *bad0.Temperature)
	}
	if bad0.PowerOnHours != nil {
		t.Errorf("expected bad0 PowerOnHours=nil (no output), got %v", *bad0.PowerOnHours)
	}
}

func TestFetchSMARTDevices_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":[]}`))
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if data.DeviceCount != 0 {
		t.Errorf("expected DeviceCount=0, got %d", data.DeviceCount)
	}
	if len(data.Devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(data.Devices))
	}
}

func TestFetchSMARTDevices_ListNotFound(t *testing.T) {
	// When the list endpoint returns 404 (os-smart plugin not installed),
	// FetchSMARTDevices must degrade gracefully: empty data, no error. The
	// collector is enabled by default so this keeps it quiet on boxes without
	// the plugin.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if len(data.Devices) != 0 {
		t.Errorf("expected no devices for 404, got %d", len(data.Devices))
	}
}

func TestFetchSMARTDevices_ListServerError(t *testing.T) {
	// A genuine server error (500) must still propagate.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	})

	_, err := client.FetchSMARTDevices()
	if err == nil {
		t.Fatal("expected error when list endpoint returns 500")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchSMARTDevices_AttributesAndNVMe(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0","nvme0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		switch r.FormValue("device") {
		case "ada0":
			w.Write([]byte(`{
				"output": {
					"model_name": "Samsung SSD 870 QVO 1TB",
					"serial_number": "REDACTED-SERIAL-1",
					"smart_status": {"passed": true},
					"temperature": {"current": 38},
					"power_on_time": {"hours": 38343},
					"ata_smart_attributes": {
						"revision": 1,
						"table": [
							{"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100, "thresh": 10, "when_failed": "", "raw": {"value": 0, "string": "0"}},
							{"id": 241, "name": "Total_LBAs_Written", "value": 99, "worst": 99, "thresh": 0, "when_failed": "", "raw": {"value": 199317943456, "string": "199317943456"}}
						]
					}
				}
			}`))
		case "nvme0":
			w.Write([]byte(`{
				"output": {
					"model_name": "Samsung SSD 970",
					"serial_number": "REDACTED-SERIAL-2",
					"smart_status": {"passed": true},
					"temperature": {"current": 45},
					"power_on_time": {"hours": 5000},
					"nvme_smart_health_information_log": {
						"critical_warning": 0,
						"temperature": 45,
						"available_spare": 100,
						"available_spare_threshold": 10,
						"percentage_used": 2,
						"data_units_read": 12345678,
						"data_units_written": 87654321,
						"power_cycles": 15,
						"power_on_hours": 5000,
						"unsafe_shutdowns": 3,
						"media_errors": 0,
						"num_err_log_entries": 0
					}
				}
			}`))
		default:
			t.Errorf("unexpected device %q", r.FormValue("device"))
		}
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(data.Devices))
	}

	ada0 := data.Devices[0]
	if len(ada0.Attributes) != 2 {
		t.Fatalf("expected 2 SATA attributes for ada0, got %d", len(ada0.Attributes))
	}
	a0 := ada0.Attributes[0]
	if a0.ID != 5 || a0.Name != "Reallocated_Sector_Ct" || a0.Value != 100 || a0.Worst != 100 || a0.Threshold != 10 || a0.Raw != 0 {
		t.Errorf("unexpected attribute 0: %+v", a0)
	}
	a1 := ada0.Attributes[1]
	if a1.ID != 241 || a1.Raw != 199317943456 {
		t.Errorf("unexpected attribute 1: %+v", a1)
	}
	if ada0.NVMe != nil {
		t.Error("expected no NVMe health log for ada0")
	}

	nvme0 := data.Devices[1]
	if len(nvme0.Attributes) != 0 {
		t.Errorf("expected no SATA attributes for nvme0, got %d", len(nvme0.Attributes))
	}
	if nvme0.NVMe == nil {
		t.Fatal("expected NVMe health log for nvme0")
	}
	checks := []struct {
		name string
		got  *float64
		want float64
	}{
		{"AvailableSpare", nvme0.NVMe.AvailableSpare, 100},
		{"PercentageUsed", nvme0.NVMe.PercentageUsed, 2},
		{"MediaErrors", nvme0.NVMe.MediaErrors, 0},
		{"UnsafeShutdowns", nvme0.NVMe.UnsafeShutdowns, 3},
		{"DataUnitsRead", nvme0.NVMe.DataUnitsRead, 12345678},
		{"DataUnitsWritten", nvme0.NVMe.DataUnitsWritten, 87654321},
	}
	for _, c := range checks {
		if c.got == nil {
			t.Errorf("expected %s to be non-nil", c.name)
		} else if *c.got != c.want {
			t.Errorf("expected %s=%v, got %v", c.name, c.want, *c.got)
		}
	}
}

func TestFetchSMARTDevices_PartialFields(t *testing.T) {
	// Some drives may not report temperature or power-on hours (e.g. USB attached).
	// The returned SMARTDevice should have nil for missing fields.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["da0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		// Only smart_status present; no temperature or power_on_time.
		w.Write([]byte(`{
			"output": {
				"model_name": "Generic USB Disk",
				"serial_number": "USB001",
				"smart_status": {"passed": true}
			}
		}`))
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(data.Devices))
	}

	dev := data.Devices[0]
	if dev.Health == nil {
		t.Error("expected Health to be non-nil")
	} else if !*dev.Health {
		t.Error("expected Health=true")
	}
	if dev.Temperature != nil {
		t.Errorf("expected Temperature=nil, got %v", *dev.Temperature)
	}
	if dev.PowerOnHours != nil {
		t.Errorf("expected PowerOnHours=nil, got %v", *dev.PowerOnHours)
	}
}
