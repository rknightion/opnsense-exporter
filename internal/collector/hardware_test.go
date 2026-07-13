package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func hardwareTestMux(t *testing.T, dmiResponse, psuResponse string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dmidecode/service/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dmiResponse))
	})
	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(psuResponse))
	})
	return mux
}

func TestHardwareCollector_Update_BothPresent(t *testing.T) {
	dmiResp := `{"status":"ok","system":{"Manufacturer":"QEMU","Product Name":"Standard PC (i440FX + PIIX, 1996)","Version":"pc-i440fx-11.0","Serial Number":"Not Specified","Family":"Not Specified"},"bios":{"Vendor":"SeaBIOS","Version":"rel-1.17.0","Release Date":"04/01/2014"}}`
	psuResp := `{"status":"OK","pwr1":"1","pwr2":"0"}`

	mux := hardwareTestMux(t, dmiResp, psuResp)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hardwareCollector{subsystem: HardwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 1 dmi_info + 2 psu_status (pwr1, pwr2) = 3
	expectedCount := 3
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	foundInfo, foundPSU1, foundPSU2 := false, false, false
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		switch {
		case strings.Contains(desc, "dmi_info"):
			foundInfo = true
			if val != 1 {
				t.Errorf("expected dmi_info=1, got %v", val)
			}
			if labels["manufacturer"] != "QEMU" {
				t.Errorf("expected manufacturer=QEMU, got %q", labels["manufacturer"])
			}
			if labels["serial"] != "Not Specified" {
				t.Errorf("expected serial='Not Specified', got %q", labels["serial"])
			}
			if labels["bios_vendor"] != "SeaBIOS" {
				t.Errorf("expected bios_vendor=SeaBIOS, got %q", labels["bios_vendor"])
			}
		case strings.Contains(desc, "psu_status"):
			if labels["psu"] == "1" {
				foundPSU1 = true
				if val != 1 {
					t.Errorf("expected psu=1 status=1, got %v", val)
				}
			}
			if labels["psu"] == "2" {
				foundPSU2 = true
				if val != 0 {
					t.Errorf("expected psu=2 status=0, got %v", val)
				}
			}
		}
	}
	if !foundInfo {
		t.Error("expected a dmi_info metric")
	}
	if !foundPSU1 || !foundPSU2 {
		t.Errorf("expected both psu_status metrics, foundPSU1=%v foundPSU2=%v", foundPSU1, foundPSU2)
	}
}

func TestHardwareCollector_Update_HardwareAbsent(t *testing.T) {
	// os-dec-hw installed but no GPIO hardware detected: must yield no PSU
	// series (three-state handling, #217).
	dmiResp := `{"status":"ok","system":{"Manufacturer":"QEMU","Product Name":"Standard PC","Version":"1.0","Serial Number":"Not Specified","Family":"Not Specified"},"bios":{"Vendor":"SeaBIOS","Version":"1.0","Release Date":"01/01/2020"}}`
	psuResp := `{"status":"failed"}`

	mux := hardwareTestMux(t, dmiResp, psuResp)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hardwareCollector{subsystem: HardwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only dmi_info; no psu_status series at all.
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "psu_status") {
			t.Errorf("expected no psu_status metric when hardware is absent, got: %s", m.Desc().String())
		}
	}
}

func TestHardwareCollector_Update_BothPluginsAbsent(t *testing.T) {
	mux := http.NewServeMux() // no handlers: everything 404s
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hardwareCollector{subsystem: HardwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when both plugins are absent, got %d", len(metrics))
	}
}

func TestHardwareCollector_Update_OnlyDMIPresent(t *testing.T) {
	dmiResp := `{"status":"ok","system":{"Manufacturer":"Dell Inc.","Product Name":"PowerEdge R640","Version":"","Serial Number":"ABC123","Family":"PowerEdge"},"bios":{"Vendor":"Dell Inc.","Version":"2.15.0","Release Date":"03/15/2023"}}`

	mux := http.NewServeMux()
	mux.HandleFunc("/api/dmidecode/service/get", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(dmiResp))
	})
	// os-dec-hw absent: 404 (falls through to the mux's default NotFound handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hardwareCollector{subsystem: HardwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	expectedCount := 1
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
	labels := getMetricLabels(metrics[0])
	if labels["manufacturer"] != "Dell Inc." {
		t.Errorf("expected manufacturer='Dell Inc.', got %q", labels["manufacturer"])
	}
	if labels["serial"] != "ABC123" {
		t.Errorf("expected serial=ABC123, got %q", labels["serial"])
	}
}

func TestHardwareCollector_Update_OnlyPSUPresent(t *testing.T) {
	psuResp := `{"status":"OK","pwr1":"1","pwr2":"1"}`

	mux := http.NewServeMux()
	// os-dmidecode absent: 404 (falls through to the mux's default NotFound handler)
	mux.HandleFunc("/api/dechw/info/power_status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(psuResp))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hardwareCollector{subsystem: HardwareSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Fatalf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "dmi_info") {
			t.Error("expected no dmi_info metric when os-dmidecode is absent")
		}
	}
}

func TestHardwareCollector_Name(t *testing.T) {
	c := &hardwareCollector{subsystem: HardwareSubsystem}
	if c.Name() != HardwareSubsystem {
		t.Errorf("expected %s, got %s", HardwareSubsystem, c.Name())
	}
}
