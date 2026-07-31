package opnsense

import (
	"net/http"
	"os"
	"path/filepath"
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

func TestFetchSMARTDevices_WearAndRotationFields(t *testing.T) {
	// #577: endurance_used, spare_available and rotation_rate were decoded
	// nowhere. The two wear fields are OBJECTS keyed by current_percent at
	// every smartmontools emission site; this fixture originally wrote them as
	// bare numbers — a shape upstream cannot produce — which is exactly why it
	// agreed with the wrong struct and let #615 reach production.
	// rotation_rate=0 is a genuine SSD reading, not an absence, so
	// this also pins that a present-but-zero wire value must NOT collapse to
	// the same nil the "field omitted entirely" case produces (mirrors the
	// AttachOrStatResetUptime presence-gating rule in interfaces.go).
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0","nvme0","usb0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		switch r.FormValue("device") {
		case "ada0":
			// Spinning HDD: rotation_rate is a real RPM figure; no wear
			// percentages (those are SSD-only smartctl derivations).
			w.Write([]byte(`{
				"output": {
					"model_name": "WDC WD40EFRX",
					"serial_number": "WD-SERIAL001",
					"smart_status": {"passed": true},
					"rotation_rate": 5400
				}
			}`))
		case "nvme0":
			// SSD: rotation_rate is explicitly 0 (not absent) and the wear
			// percentages are present.
			w.Write([]byte(`{
				"output": {
					"model_name": "Samsung SSD 970",
					"serial_number": "NVME-SERIAL002",
					"smart_status": {"passed": true},
					"rotation_rate": 0,
					"spare_available": {"current_percent": 100, "threshold_percent": 10},
					"endurance_used": {"current_percent": 7}
				}
			}`))
		case "usb0":
			// Drive reports none of the three fields at all: must decode to
			// nil, not a fabricated 0 (0 would misreport a real HDD/SSD as
			// something it isn't, or invent wear data that was never sent).
			w.Write([]byte(`{
				"output": {
					"model_name": "Generic USB Disk",
					"serial_number": "USB001",
					"smart_status": {"passed": true}
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
	if len(data.Devices) != 3 {
		t.Fatalf("expected 3 devices, got %d", len(data.Devices))
	}

	ada0 := data.Devices[0]
	if ada0.RotationRate == nil {
		t.Fatal("expected ada0 RotationRate to be non-nil")
	} else if *ada0.RotationRate != 5400 {
		t.Errorf("expected ada0 RotationRate=5400, got %v", *ada0.RotationRate)
	}
	if ada0.SpareAvailable != nil {
		t.Errorf("expected ada0 SpareAvailable=nil (HDD has no wear %%), got %v", *ada0.SpareAvailable)
	}
	if ada0.EnduranceUsed != nil {
		t.Errorf("expected ada0 EnduranceUsed=nil (HDD has no wear %%), got %v", *ada0.EnduranceUsed)
	}

	nvme0 := data.Devices[1]
	if nvme0.RotationRate == nil {
		t.Fatal("expected nvme0 RotationRate to be non-nil (explicit 0 means SSD, not absent)")
	} else if *nvme0.RotationRate != 0 {
		t.Errorf("expected nvme0 RotationRate=0, got %v", *nvme0.RotationRate)
	}
	if nvme0.SpareAvailable == nil {
		t.Fatal("expected nvme0 SpareAvailable to be non-nil")
	} else if *nvme0.SpareAvailable != 100 {
		t.Errorf("expected nvme0 SpareAvailable=100, got %v", *nvme0.SpareAvailable)
	}
	if nvme0.EnduranceUsed == nil {
		t.Fatal("expected nvme0 EnduranceUsed to be non-nil")
	} else if *nvme0.EnduranceUsed != 7 {
		t.Errorf("expected nvme0 EnduranceUsed=7, got %v", *nvme0.EnduranceUsed)
	}

	usb0 := data.Devices[2]
	if usb0.RotationRate != nil {
		t.Errorf("expected usb0 RotationRate=nil (field omitted), got %v", *usb0.RotationRate)
	}
	if usb0.SpareAvailable != nil {
		t.Errorf("expected usb0 SpareAvailable=nil (field omitted), got %v", *usb0.SpareAvailable)
	}
	if usb0.EnduranceUsed != nil {
		t.Errorf("expected usb0 EnduranceUsed=nil (field omitted), got %v", *usb0.EnduranceUsed)
	}
}

func TestFetchSMARTDevices_AttributeWhenFailed(t *testing.T) {
	// #577: when_failed on a SATA attribute row names WHICH attribute tripped
	// a failing drive, distinct from the device-wide smart_status.passed
	// gauge. Pins that the raw smartctl string ("now"/"past"/"") survives
	// decoding unchanged onto the per-attribute struct.
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"output": {
				"model_name": "Failing Drive",
				"serial_number": "FAIL001",
				"smart_status": {"passed": false},
				"ata_smart_attributes": {
					"table": [
						{"id": 5, "name": "Reallocated_Sector_Ct", "value": 1, "worst": 1, "thresh": 10, "when_failed": "now", "raw": {"value": 200}},
						{"id": 194, "name": "Temperature_Celsius", "value": 50, "worst": 40, "thresh": 0, "when_failed": "past", "raw": {"value": 38}},
						{"id": 9, "name": "Power_On_Hours", "value": 99, "worst": 99, "thresh": 0, "when_failed": "", "raw": {"value": 12044}}
					]
				}
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

	attrs := data.Devices[0].Attributes
	if len(attrs) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(attrs))
	}
	if attrs[0].WhenFailed != "now" {
		t.Errorf("expected attribute 0 WhenFailed=%q, got %q", "now", attrs[0].WhenFailed)
	}
	if attrs[1].WhenFailed != "past" {
		t.Errorf("expected attribute 1 WhenFailed=%q, got %q", "past", attrs[1].WhenFailed)
	}
	if attrs[2].WhenFailed != "" {
		t.Errorf("expected attribute 2 WhenFailed=%q (healthy), got %q", "", attrs[2].WhenFailed)
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

// TestFetchSMARTDevices_ProdCapture replays the VERBATIM smartInfo body the
// production firewall (OPNsense 26.7.1_1, smartctl 7.5, Samsung SSD 870 QVO)
// returns for ada0 — captured read-only, serial and wwn redacted, every
// modelled field untouched.
//
// #615: endurance_used and spare_available were modelled as *float64. smartctl
// serves them as OBJECTS at every single emission site, so the whole body
// failed to decode and FetchSMARTDevices fell into its per-device error path,
// which appends nothing but the device name. That cost EVERY per-device SMART
// metric on the one box with a real disk — health, temperature, power-on
// hours, the whole ATA attribute table — silently, at Debug level, with
// collector_success=1.
//
// Same bug class as #609: a struct no fixture disagreed with, because the
// fixture was hand-written from the field NAMES. This one is derived from the
// wire.
func TestFetchSMARTDevices_ProdCapture(t *testing.T) {
	body, rerr := os.ReadFile(filepath.Join("testdata", "smart", "info_ada0_prod_26_7.json"))
	if rerr != nil {
		t.Fatalf("failed to read fixture: %v", rerr)
	}

	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(data.Devices))
	}
	dev := data.Devices[0]

	// The two fields the bug was about.
	if dev.EnduranceUsed == nil {
		t.Error("expected EnduranceUsed to be non-nil (wire: {\"current_percent\":84})")
	} else if *dev.EnduranceUsed != 84 {
		t.Errorf("expected EnduranceUsed=84, got %v", *dev.EnduranceUsed)
	}
	if dev.SpareAvailable == nil {
		t.Error("expected SpareAvailable to be non-nil (wire: {\"current_percent\":100,...})")
	} else if *dev.SpareAvailable != 100 {
		t.Errorf("expected SpareAvailable=100, got %v", *dev.SpareAvailable)
	}

	// The blast radius: everything else on the device must survive too. These
	// are what actually went missing on prod, and they are the reason this is a
	// P0 rather than two absent gauges.
	if dev.Model != "Samsung SSD 870 QVO 1TB" {
		t.Errorf("expected Model to survive, got %q", dev.Model)
	}
	if dev.Health == nil || !*dev.Health {
		t.Errorf("expected Health=true to survive, got %v", dev.Health)
	}
	if dev.Temperature == nil {
		t.Error("expected Temperature to survive")
	} else if *dev.Temperature != 42 {
		t.Errorf("expected Temperature=42, got %v", *dev.Temperature)
	}
	if dev.PowerOnHours == nil {
		t.Error("expected PowerOnHours to survive")
	} else if *dev.PowerOnHours != 39585 {
		t.Errorf("expected PowerOnHours=39585, got %v", *dev.PowerOnHours)
	}
	if len(dev.Attributes) != 14 {
		t.Errorf("expected all 14 ATA attribute rows to survive, got %d", len(dev.Attributes))
	}
	// rotation_rate is an explicit 0 on this drive: it is an SSD, which is the
	// only reason the two wear fields exist on it at all.
	if dev.RotationRate == nil {
		t.Error("expected RotationRate to survive as a present 0 (SSD)")
	} else if *dev.RotationRate != 0 {
		t.Errorf("expected RotationRate=0, got %v", *dev.RotationRate)
	}
}

// TestFetchSMARTDevices_PartialDecodeKeepsDevice pins the property #615 was
// really about: ONE field whose shape disagrees with our struct must not cost
// the whole device.
//
// The payload here is DELIBERATELY SYNTHETIC — it is not a capture. It pins
// parser tolerance against the NEXT mismodelled field, whatever that turns out
// to be, by serving a shape our struct does not expect (power_on_time.hours as
// a string). encoding/json defers a type error and keeps decoding, so every
// field it understood is already written; the point is that FetchSMARTDevices
// keeps that data instead of discarding it, and counts the disagreement so it
// is not silent a third time.
func TestFetchSMARTDevices_PartialDecodeKeepsDevice(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"output": {
				"model_name": "Samsung SSD 870 QVO 1TB",
				"smart_status": {"passed": true},
				"temperature": {"current": 42},
				"power_on_time": {"hours": "39585"},
				"rotation_rate": 0,
				"endurance_used": {"current_percent": 84},
				"ata_smart_attributes": {"table": [
					{"id": 5, "name": "Reallocated_Sector_Ct", "value": 100,
					 "worst": 100, "thresh": 10, "when_failed": "",
					 "raw": {"value": 0}}
				]}
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

	if dev.Model != "Samsung SSD 870 QVO 1TB" {
		t.Errorf("expected Model to survive the bad sibling field, got %q", dev.Model)
	}
	if dev.Health == nil || !*dev.Health {
		t.Errorf("expected Health=true to survive, got %v", dev.Health)
	}
	if dev.Temperature == nil || *dev.Temperature != 42 {
		t.Errorf("expected Temperature=42 to survive, got %v", dev.Temperature)
	}
	if len(dev.Attributes) != 1 {
		t.Errorf("expected the attribute table to survive, got %d rows", len(dev.Attributes))
	}
	if dev.EnduranceUsed == nil || *dev.EnduranceUsed != 84 {
		t.Errorf("expected EnduranceUsed=84 to survive, got %v", dev.EnduranceUsed)
	}
	// The field that actually disagreed is the only one affected — but note
	// HOW: encoding/json allocates the pointer before it discovers the type
	// mismatch, so a mismatched *float64 lands as a present ZERO, not as an
	// absence. That is the accepted cost of keeping the rest of the device,
	// and it is why InfoPartialDecodes below has to be exported and graphed:
	// the wrong-but-plausible 0 is not distinguishable at the metric.
	if dev.PowerOnHours == nil {
		t.Error("expected PowerOnHours to be a present zero (json allocates before it fails)")
	} else if *dev.PowerOnHours != 0 {
		t.Errorf("expected PowerOnHours=0 for the mismatched field, got %v", *dev.PowerOnHours)
	}

	// And it is counted, not silent.
	if data.InfoPartialDecodes != 1 {
		t.Errorf("expected InfoPartialDecodes=1, got %d", data.InfoPartialDecodes)
	}
	if data.InfoFailures != 0 {
		t.Errorf("expected InfoFailures=0, got %d", data.InfoFailures)
	}
}

// TestFetchSMARTDevices_InfoFailureCounted pins that a genuinely unusable info
// response (not JSON at all — nothing decoded, so nothing to keep) still
// degrades to a name-only device, and is counted separately from a partial
// decode.
func TestFetchSMARTDevices_InfoFailureCounted(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`this is not json`))
	})

	data, err := client.FetchSMARTDevices()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Devices) != 1 || data.Devices[0].Device != "ada0" {
		t.Fatalf("expected a name-only ada0 entry, got %+v", data.Devices)
	}
	if data.InfoFailures != 1 {
		t.Errorf("expected InfoFailures=1, got %d", data.InfoFailures)
	}
	if data.InfoPartialDecodes != 0 {
		t.Errorf("expected InfoPartialDecodes=0, got %d", data.InfoPartialDecodes)
	}
}
