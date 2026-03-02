package opnsense

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestParseHumanBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{"Terabytes", "2T", 2 * 1024 * 1024 * 1024 * 1024},
		{"Gigabytes", "16G", 16 * 1024 * 1024 * 1024},
		{"Megabytes", "512M", 512 * 1024 * 1024},
		{"Kilobytes", "1024K", 1024 * 1024},
		{"Bytes", "4096B", 4096},
		{"Lowercase terabytes", "1t", 1024 * 1024 * 1024 * 1024},
		{"Lowercase gigabytes", "8g", 8 * 1024 * 1024 * 1024},
		{"Lowercase megabytes", "256m", 256 * 1024 * 1024},
		{"Lowercase kilobytes", "100k", 100 * 1024},
		{"No suffix", "12345", 12345},
		{"Empty string", "", 0},
		{"With spaces", " 10G ", 10 * 1024 * 1024 * 1024},
		{"Fractional gigabytes", "1.5G", int64(1.5 * 1024 * 1024 * 1024)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseHumanBytes(tc.input)
			if result != tc.expected {
				t.Errorf("parseHumanBytes(%q) = %d; want %d", tc.input, result, tc.expected)
			}
		})
	}
}

func TestFetchSystemResources_AllEndpoints(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Use a fixed boottime in the past to compute uptime
	bootTime := time.Now().Add(-2 * time.Hour)
	bootTimeStr := bootTime.Format(opnsenseTimeFormat)

	configTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	configTimeStr := configTime.Format(opnsenseTimeFormat)

	// Memory endpoint
	mux.HandleFunc("/api/diagnostics/system/systemResources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"memory": {
				"total": "8589934592",
				"used": 4294967296,
				"arc": "1073741824"
			}
		}`))
	})

	// Time endpoint
	mux.HandleFunc("/api/diagnostics/system/systemTime", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{
			"uptime": "2:00:00",
			"datetime": "Mon Jan 15 12:30:00 UTC 2024",
			"boottime": %q,
			"config": %q,
			"loadavg": "0.12, 0.34, 0.56"
		}`, bootTimeStr, configTimeStr)
	})

	// Disk endpoint
	mux.HandleFunc("/api/diagnostics/system/systemDisk", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"devices": [
				{
					"device": "/dev/ada0p3",
					"type": "ufs",
					"blocks": "100G",
					"used": "30G",
					"available": "70G",
					"used_pct": 30,
					"mountpoint": "/"
				},
				{
					"device": "/dev/ada0p4",
					"type": "ufs",
					"blocks": "500M",
					"used": "200M",
					"available": "300M",
					"used_pct": 40,
					"mountpoint": "/var"
				}
			]
		}`))
	})

	// Swap endpoint
	mux.HandleFunc("/api/diagnostics/system/systemSwap", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"swap": [
				{
					"device": "/dev/ada0p2",
					"total": "4194304",
					"used": "1048576"
				}
			]
		}`))
	})

	data, err := client.FetchSystemResources()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Memory
	if data.Memory.Total != 8589934592 {
		t.Errorf("expected Memory.Total=8589934592, got %d", data.Memory.Total)
	}
	if data.Memory.Used != 4294967296 {
		t.Errorf("expected Memory.Used=4294967296, got %d", data.Memory.Used)
	}
	if data.Memory.Arc != 1073741824 {
		t.Errorf("expected Memory.Arc=1073741824, got %d", data.Memory.Arc)
	}
	if !data.Memory.HasArc {
		t.Error("expected Memory.HasArc=true")
	}

	// Time - uptime should be approximately 2 hours
	if data.Time.Uptime < 7100 || data.Time.Uptime > 7300 {
		t.Errorf("expected uptime around 7200s, got %f", data.Time.Uptime)
	}

	// Load average
	if data.Time.LoadAverage[0] != 0.12 {
		t.Errorf("expected LoadAverage[0]=0.12, got %f", data.Time.LoadAverage[0])
	}
	if data.Time.LoadAverage[1] != 0.34 {
		t.Errorf("expected LoadAverage[1]=0.34, got %f", data.Time.LoadAverage[1])
	}
	if data.Time.LoadAverage[2] != 0.56 {
		t.Errorf("expected LoadAverage[2]=0.56, got %f", data.Time.LoadAverage[2])
	}

	// Config last change
	expectedConfigTime := float64(configTime.Unix())
	if data.Time.ConfigLastChange != expectedConfigTime {
		t.Errorf("expected ConfigLastChange=%f, got %f", expectedConfigTime, data.Time.ConfigLastChange)
	}

	// Disks
	if len(data.Disks) != 2 {
		t.Fatalf("expected 2 disks, got %d", len(data.Disks))
	}
	disk1 := data.Disks[0]
	if disk1.Device != "/dev/ada0p3" {
		t.Errorf("expected device '/dev/ada0p3', got %q", disk1.Device)
	}
	if disk1.Mountpoint != "/" {
		t.Errorf("expected mountpoint '/', got %q", disk1.Mountpoint)
	}
	expectedTotal := int64(100) * 1024 * 1024 * 1024
	if disk1.Total != expectedTotal {
		t.Errorf("expected disk total=%d, got %d", expectedTotal, disk1.Total)
	}
	expectedUsed := int64(30) * 1024 * 1024 * 1024
	if disk1.Used != expectedUsed {
		t.Errorf("expected disk used=%d, got %d", expectedUsed, disk1.Used)
	}
	if disk1.UsageRatio != 0.30 {
		t.Errorf("expected UsageRatio=0.30, got %f", disk1.UsageRatio)
	}

	// Swap
	if len(data.Swaps) != 1 {
		t.Fatalf("expected 1 swap device, got %d", len(data.Swaps))
	}
	swap1 := data.Swaps[0]
	if swap1.Device != "/dev/ada0p2" {
		t.Errorf("expected swap device '/dev/ada0p2', got %q", swap1.Device)
	}
	// Total is in KB, converted to bytes
	if swap1.Total != 4194304*1024 {
		t.Errorf("expected swap total=%d, got %d", 4194304*1024, swap1.Total)
	}
	if swap1.Used != 1048576*1024 {
		t.Errorf("expected swap used=%d, got %d", 1048576*1024, swap1.Used)
	}
}

func TestFetchSystemResources_PartialFailure(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Memory endpoint succeeds
	mux.HandleFunc("/api/diagnostics/system/systemResources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"memory": {
				"total": "4294967296",
				"used": 2147483648,
				"arc": ""
			}
		}`))
	})

	// Time endpoint fails
	mux.HandleFunc("/api/diagnostics/system/systemTime", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	// Disk endpoint succeeds
	mux.HandleFunc("/api/diagnostics/system/systemDisk", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices": []}`))
	})

	// Swap endpoint succeeds
	mux.HandleFunc("/api/diagnostics/system/systemSwap", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"swap": []}`))
	})

	data, err := client.FetchSystemResources()
	if err != nil {
		t.Fatalf("expected no error for partial failure, got: %v", err)
	}

	// Memory should still be populated
	if data.Memory.Total != 4294967296 {
		t.Errorf("expected Memory.Total=4294967296, got %d", data.Memory.Total)
	}
	// ARC empty string should result in HasArc=false
	if data.Memory.HasArc {
		t.Error("expected Memory.HasArc=false for empty arc string")
	}
}

func TestFetchSystemResources_AllFail(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// All endpoints fail
	failHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}

	mux.HandleFunc("/api/diagnostics/system/systemResources", failHandler)
	mux.HandleFunc("/api/diagnostics/system/systemTime", failHandler)
	mux.HandleFunc("/api/diagnostics/system/systemDisk", failHandler)
	mux.HandleFunc("/api/diagnostics/system/systemSwap", failHandler)

	_, err := client.FetchSystemResources()
	if err == nil {
		t.Fatal("expected error when all sub-calls fail")
	}
}

func TestFetchSystemResources_ArcZeroString(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/diagnostics/system/systemResources", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"memory": {
				"total": "4294967296",
				"used": 2147483648,
				"arc": "0"
			}
		}`))
	})
	mux.HandleFunc("/api/diagnostics/system/systemTime", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"uptime": "", "datetime": "", "boottime": "", "config": "", "loadavg": ""}`))
	})
	mux.HandleFunc("/api/diagnostics/system/systemDisk", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"devices": []}`))
	})
	mux.HandleFunc("/api/diagnostics/system/systemSwap", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"swap": []}`))
	})

	data, err := client.FetchSystemResources()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Arc value "0" should be treated as no ARC
	if data.Memory.HasArc {
		t.Error("expected Memory.HasArc=false for arc='0'")
	}
	if data.Memory.Arc != 0 {
		t.Errorf("expected Memory.Arc=0, got %d", data.Memory.Arc)
	}
}
