package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func smartTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		// 3 devices: ada0 (SATA), nvme0 (NVMe), bad0 (validation failure)
		w.Write([]byte(`{"devices":["ada0","nvme0","bad0"]}`))
	})

	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
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
		case "bad0":
			// OPNsense returns a message with no output on device validation failure
			w.Write([]byte(`{"message":"Invalid device name"}`))
		default:
			http.Error(w, "unexpected device", http.StatusBadRequest)
		}
	})

	return mux
}

func TestSMARTCollector_Update_Normal(t *testing.T) {
	mux := smartTestMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected metrics:
	//   devices_total = 1
	//   ada0:  health + temperature + power_on_hours = 3
	//   nvme0: health + temperature + power_on_hours = 3
	//   bad0:  no output → no health/temp/hours = 0
	//   Total = 1 + 3 + 3 = 7
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// Verify devices_total = 3 (list count, including bad0)
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "devices_total") {
			val := getMetricValue(m)
			if val != 3 {
				t.Errorf("expected devices_total=3, got %v", val)
			}
		}
	}

	// Verify ada0 health = 1
	foundAda0Health := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "device_health") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["device"] == "ada0" {
			foundAda0Health = true
			if getMetricValue(m) != 1 {
				t.Errorf("expected ada0 health=1, got %v", getMetricValue(m))
			}
			if labels["model"] != "WDC WD40EFRX" {
				t.Errorf("expected model 'WDC WD40EFRX', got %q", labels["model"])
			}
			if labels["serial"] != "WD-SERIAL001" {
				t.Errorf("expected serial 'WD-SERIAL001', got %q", labels["serial"])
			}
		}
	}
	if !foundAda0Health {
		t.Error("expected health metric for ada0")
	}

	// Verify nvme0 health = 1
	foundNvme0Health := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "device_health") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["device"] == "nvme0" {
			foundNvme0Health = true
			if getMetricValue(m) != 1 {
				t.Errorf("expected nvme0 health=1, got %v", getMetricValue(m))
			}
		}
	}
	if !foundNvme0Health {
		t.Error("expected health metric for nvme0")
	}

	// Verify ada0 temperature = 38
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "device_temperature_celsius") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["device"] == "ada0" {
			if getMetricValue(m) != 38 {
				t.Errorf("expected ada0 temperature=38, got %v", getMetricValue(m))
			}
		}
		if labels["device"] == "nvme0" {
			if getMetricValue(m) != 45 {
				t.Errorf("expected nvme0 temperature=45, got %v", getMetricValue(m))
			}
		}
	}

	// Verify ada0 power_on_hours = 12044
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "device_power_on_hours") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["device"] == "ada0" {
			if getMetricValue(m) != 12044 {
				t.Errorf("expected ada0 power_on_hours=12044, got %v", getMetricValue(m))
			}
		}
		if labels["device"] == "nvme0" {
			if getMetricValue(m) != 300 {
				t.Errorf("expected nvme0 power_on_hours=300, got %v", getMetricValue(m))
			}
		}
	}

	// Verify bad0 has NO health, temperature, or power_on_hours metrics
	for _, m := range metrics {
		labels := getMetricLabels(m)
		desc := m.Desc().String()
		if labels["device"] == "bad0" {
			if strings.Contains(desc, "device_health") ||
				strings.Contains(desc, "device_temperature_celsius") ||
				strings.Contains(desc, "device_power_on_hours") {
				t.Errorf("expected no metrics for bad0 (no output), but got: %s", desc)
			}
		}
	}
}

func TestSMARTCollector_Update_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":[]}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only devices_total = 0
	if len(metrics) != 1 {
		t.Errorf("expected 1 metric (devices_total), got %d", len(metrics))
	}
	if getMetricValue(metrics[0]) != 0 {
		t.Errorf("expected devices_total=0, got %v", getMetricValue(metrics[0]))
	}
}

func TestSMARTCollector_Update_PartialFields(t *testing.T) {
	// Drive with only health — no temperature or power_on_hours.
	// Only devices_total + health should be emitted.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["da0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"output": {
				"model_name": "Generic USB",
				"serial_number": "USB001",
				"smart_status": {"passed": false}
			}
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// devices_total + device_health = 2 (no temperature, no power_on_hours)
	if len(metrics) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(metrics))
	}

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "device_health") {
			labels := getMetricLabels(m)
			if labels["device"] != "da0" {
				t.Errorf("expected device 'da0', got %q", labels["device"])
			}
			if getMetricValue(m) != 0 {
				t.Errorf("expected health=0 (failed), got %v", getMetricValue(m))
			}
		}
	}

	// No temperature or power_on_hours metrics
	for _, m := range metrics {
		desc := m.Desc().String()
		if strings.Contains(desc, "temperature") || strings.Contains(desc, "power_on_hours") {
			t.Errorf("expected no temperature/power_on_hours when absent, got: %s", desc)
		}
	}
}

// TestSmartCollector_Update_PluginAbsent guards #87: with os-smart absent (list
// endpoint 404s) the collector must emit nothing rather than devices_total=0.
func TestSmartCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: all requests 404 → plugin absent
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent (404), got %d", len(metrics))
	}
}

func TestSMARTCollector_Update_WearAndRotation(t *testing.T) {
	// #577: endurance_used, spare_available and rotation_rate must surface as
	// their own device-scoped gauges, and rotation_rate=0 (SSD) must emit a
	// real series rather than being treated as "absent".
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0","nvme0","usb0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		switch r.FormValue("device") {
		case "ada0":
			w.Write([]byte(`{
				"output": {
					"model_name": "WDC WD40EFRX",
					"serial_number": "WD-SERIAL001",
					"smart_status": {"passed": true},
					"rotation_rate": 5400
				}
			}`))
		case "nvme0":
			w.Write([]byte(`{
				"output": {
					"model_name": "Samsung SSD 970",
					"serial_number": "NVME-SERIAL002",
					"smart_status": {"passed": true},
					"rotation_rate": 0,
					"spare_available": 100,
					"endurance_used": 7
				}
			}`))
		case "usb0":
			w.Write([]byte(`{
				"output": {
					"model_name": "Generic USB",
					"serial_number": "USB001",
					"smart_status": {"passed": true}
				}
			}`))
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	// ada0 emits rotation_rate only (no wear %). nvme0 emits rotation_rate=0
	// PLUS both wear gauges. usb0 emits none of the three. Verify each value
	// individually rather than just a metric count, since a miscounted
	// "absent" vs "present-zero" bug would still add up to the right total.
	checks := []struct {
		device string
		metric string
		want   float64
		absent bool
	}{
		{"ada0", "device_rotation_rate_rpm", 5400, false},
		{"ada0", "device_spare_available_percent", 0, true},
		{"ada0", "device_endurance_used_percent", 0, true},
		{"nvme0", "device_rotation_rate_rpm", 0, false},
		{"nvme0", "device_spare_available_percent", 100, false},
		{"nvme0", "device_endurance_used_percent", 7, false},
		{"usb0", "device_rotation_rate_rpm", 0, true},
		{"usb0", "device_spare_available_percent", 0, true},
		{"usb0", "device_endurance_used_percent", 0, true},
	}

	for _, chk := range checks {
		found := false
		for _, m := range metrics {
			if !strings.Contains(m.Desc().String(), chk.metric) {
				continue
			}
			labels := getMetricLabels(m)
			if labels["device"] != chk.device {
				continue
			}
			found = true
			if got := getMetricValue(m); got != chk.want {
				t.Errorf("%s/%s: expected %v, got %v", chk.device, chk.metric, chk.want, got)
			}
		}
		if chk.absent && found {
			t.Errorf("%s/%s: expected no series, but found one", chk.device, chk.metric)
		}
		if !chk.absent && !found {
			t.Errorf("%s/%s: expected a series, found none", chk.device, chk.metric)
		}
	}
}

func TestSMARTCollector_Update_AttributeFailed(t *testing.T) {
	// #577: attribute_failed must be emitted ONLY for attributes whose
	// when_failed marker is non-empty, carrying the raw marker as a label —
	// this is the decided alternative to adding a `when_failed` label onto
	// the existing attribute_value/worst/threshold/raw series, which would
	// have changed those series' identity and broken any panel/rule reading
	// them by their current label set. A healthy attribute must add NO
	// series at all (not a 0-valued one), so a clean fleet costs ~0 cardinality.
	mux := http.NewServeMux()
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
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	var failedSeries []map[string]string
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "attribute_failed") {
			failedSeries = append(failedSeries, getMetricLabels(m))
		}
	}

	if len(failedSeries) != 2 {
		t.Fatalf("expected 2 attribute_failed series (id 5 and 194), got %d: %+v", len(failedSeries), failedSeries)
	}

	byID := map[string]map[string]string{}
	for _, labels := range failedSeries {
		byID[labels["attribute_id"]] = labels
	}

	id5, ok := byID["5"]
	if !ok {
		t.Fatal("expected an attribute_failed series for id=5")
	}
	if id5["when_failed"] != "now" {
		t.Errorf("expected id=5 when_failed=now, got %q", id5["when_failed"])
	}
	if id5["attribute_name"] != "Reallocated_Sector_Ct" {
		t.Errorf("expected id=5 attribute_name=Reallocated_Sector_Ct, got %q", id5["attribute_name"])
	}

	id194, ok := byID["194"]
	if !ok {
		t.Fatal("expected an attribute_failed series for id=194")
	}
	if id194["when_failed"] != "past" {
		t.Errorf("expected id=194 when_failed=past, got %q", id194["when_failed"])
	}

	if _, ok := byID["9"]; ok {
		t.Error("expected NO attribute_failed series for id=9 (when_failed empty / healthy)")
	}

	// Value is always 1 — the series' mere existence is the signal.
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "attribute_failed") {
			if got := getMetricValue(m); got != 1 {
				t.Errorf("expected attribute_failed value=1, got %v", got)
			}
		}
	}
}

func TestSMARTCollector_Name(t *testing.T) {
	c := &smartCollector{subsystem: SMARTSubsystem}
	if c.Name() != SMARTSubsystem {
		t.Errorf("expected %s, got %s", SMARTSubsystem, c.Name())
	}
}

func TestSMARTCollector_Update_AttributesAndNVMe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices":["ada0","nvme0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
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
						"table": [
							{"id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100, "thresh": 10, "raw": {"value": 0}},
							{"id": 241, "name": "Total_LBAs_Written", "value": 99, "worst": 99, "thresh": 0, "raw": {"value": 199317943456}}
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
						"available_spare": 100,
						"percentage_used": 2,
						"data_units_read": 12345678,
						"data_units_written": 87654321,
						"unsafe_shutdowns": 3,
						"media_errors": 0
					}
				}
			}`))
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &smartCollector{subsystem: SMARTSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	// devices_total(1) + ada0 base(3) + 2 attrs × 4 series(8) + nvme0 base(3) + nvme(6) = 21
	if expected := 21; len(metrics) != expected {
		t.Errorf("expected %d metrics, got %d", expected, len(metrics))
	}

	// attribute_raw for Total_LBAs_Written carries name+id labels and the raw value.
	foundRaw := false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "attribute_raw") {
			continue
		}
		labels := getMetricLabels(m)
		if labels["device"] == "ada0" && labels["attribute_id"] == "241" {
			foundRaw = true
			if labels["attribute_name"] != "Total_LBAs_Written" {
				t.Errorf("expected attribute_name=Total_LBAs_Written, got %q", labels["attribute_name"])
			}
			if got := getMetricValue(m); got != 199317943456 {
				t.Errorf("expected raw=199317943456, got %v", got)
			}
		}
	}
	if !foundRaw {
		t.Error("expected attribute_raw metric for ada0 id=241")
	}

	// attribute_threshold for id=5 is 10.
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "attribute_threshold") {
			labels := getMetricLabels(m)
			if labels["attribute_id"] == "5" && getMetricValue(m) != 10 {
				t.Errorf("expected threshold=10 for id=5, got %v", getMetricValue(m))
			}
		}
	}

	// NVMe series carry only the device label.
	nvmeChecks := map[string]float64{
		"nvme_available_spare_percent":  100,
		"nvme_percentage_used":          2,
		"nvme_media_errors_total":       0,
		"nvme_unsafe_shutdowns_total":   3,
		"nvme_data_units_read_total":    12345678,
		"nvme_data_units_written_total": 87654321,
	}
	for needle, want := range nvmeChecks {
		found := false
		for _, m := range metrics {
			if !strings.Contains(m.Desc().String(), needle) {
				continue
			}
			found = true
			labels := getMetricLabels(m)
			if labels["device"] != "nvme0" {
				t.Errorf("%s: expected device=nvme0, got %q", needle, labels["device"])
			}
			if got := getMetricValue(m); got != want {
				t.Errorf("%s: expected %v, got %v", needle, want, got)
			}
		}
		if !found {
			t.Errorf("expected metric %s", needle)
		}
	}
}
