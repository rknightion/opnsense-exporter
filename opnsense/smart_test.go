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

func TestFetchSMARTDevices_ListError(t *testing.T) {
	// When the list endpoint returns 404 (plugin not installed), FetchSMARTDevices
	// must propagate the error.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})

	_, err := client.FetchSMARTDevices()
	if err == nil {
		t.Fatal("expected error when list endpoint returns 404")
	}
	if err.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", err.StatusCode)
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
