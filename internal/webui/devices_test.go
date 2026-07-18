package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

func TestMergeDevices(t *testing.T) {
	arp := opnsense.ArpTable{Arp: []opnsense.Arp{
		{IP: "192.168.1.10", Mac: "B8:27:EB:11:22:33", Hostname: "arp-name", IntfDescription: "LAN", Expires: 1893456000},
		{IP: "192.168.1.20", Mac: "AA:BB:CC:DD:EE:FF", Hostname: "", IntfDescription: "LAN", Expires: 0},
	}}
	d4 := opnsense.DHCPv4Leases{Leases: []opnsense.DHCPv4Lease{
		// Same IP+MAC as the first ARP row: must dedupe and the DHCP hostname wins.
		{Address: "192.168.1.10", MAC: "B8:27:EB:11:22:33", Hostname: "dhcp-name", IfDescr: "LAN"},
		// DHCPv4-only device.
		{Address: "192.168.1.30", MAC: "24:0A:C4:00:11:22", Hostname: "esp32", IfDescr: "IOT"},
	}}
	d6 := opnsense.DHCPv6Leases{Leases: []opnsense.DHCPv6Lease{
		{Address: "fe80::1", MAC: "DC:A6:32:44:55:66", IfDescr: "LAN"},
	}}

	rows := mergeDevices(arp, d4, d6)

	byKey := map[string]DeviceRow{}
	for _, r := range rows {
		byKey[r.IP+"|"+strings.ToUpper(r.MAC)] = r
	}

	if len(rows) != 4 {
		t.Fatalf("want 4 deduped rows, got %d: %+v", len(rows), rows)
	}

	// Deduped ARP+DHCPv4 row: DHCP hostname preferred, ARP expiry retained.
	merged := byKey["192.168.1.10|B8:27:EB:11:22:33"]
	if merged.Hostname != "dhcp-name" {
		t.Fatalf("DHCP hostname should win over ARP, got %q", merged.Hostname)
	}
	if merged.Expiry == "" {
		t.Fatalf("ARP-sourced row must carry a formatted Expiry, got empty")
	}
	if merged.Manufacturer == "" {
		t.Fatalf("manufacturer should resolve for a known prefix (B827EB), got empty")
	}

	// DHCPv6 row: no hostname, source dhcp6.
	v6 := byKey["fe80::1|DC:A6:32:44:55:66"]
	if v6.Hostname != "" {
		t.Fatalf("DHCPv6 row must have empty hostname, got %q", v6.Hostname)
	}
	if v6.Source != "dhcp6" {
		t.Fatalf("DHCPv6 row source want dhcp6, got %q", v6.Source)
	}
	if v6.Manufacturer == "" {
		t.Fatalf("DHCPv6 manufacturer should resolve (DCA632), got empty")
	}

	// DHCPv4-only row keeps its own expiry-less, dhcp4-sourced shape.
	esp := byKey["192.168.1.30|24:0A:C4:00:11:22"]
	if esp.Source != "dhcp4" || esp.Expiry != "" {
		t.Fatalf("dhcp4-only row want source dhcp4 + empty expiry, got %q/%q", esp.Source, esp.Expiry)
	}
}

func TestHandler_DevicesDisabled(t *testing.T) {
	d := testDeps()
	d.DisableDevices = true
	d.Devices = func(ctx context.Context) (DeviceReport, error) { return DeviceReport{}, nil }
	srv := NewServer(d)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled devices page want 404, got %d", rec.Code)
	}
}

func TestHandler_DevicesPage(t *testing.T) {
	d := testDeps()
	d.Devices = func(ctx context.Context) (DeviceReport, error) {
		return DeviceReport{Devices: []DeviceRow{
			{IP: "192.168.1.10", MAC: "B8:27:EB:11:22:33", Hostname: "pi", Interface: "LAN", Manufacturer: "Raspberry Pi", Source: "arp"},
		}}, nil
	}
	srv := NewServer(d)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("devices page want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "192.168.1.10") || !strings.Contains(body, "Raspberry Pi") {
		t.Fatalf("devices page missing row data, got %q", body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("content-type want html, got %q", got)
	}
}
