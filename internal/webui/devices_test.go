package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
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

// TestHandler_DevicesDisabled asserts the devices kill switch omits the devices
// tab AND 404s the lazy JSON endpoint (which is a live firewall read).
func TestHandler_DevicesDisabled(t *testing.T) {
	d := testDeps()
	d.DisableDevices = true
	d.Devices = func(ctx context.Context) (DeviceReport, error) { return DeviceReport{}, nil }
	srv := NewServer(d)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(rec.Body.String(), `data-tab="devices"`) {
		t.Fatalf("devices tab should be omitted when disabled")
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices.json", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled devices JSON want 404, got %d", rec.Code)
	}
}

// TestHandler_DevicesLazyJSON asserts the Devices tab is present on the page and
// the device rows load from the lazy /api/devices.json endpoint (NOT on the poll
// — that endpoint is the only console call that reaches the firewall).
func TestHandler_DevicesLazyJSON(t *testing.T) {
	d := testDeps()
	d.Devices = func(ctx context.Context) (DeviceReport, error) {
		return DeviceReport{Devices: []DeviceRow{
			{IP: "192.168.1.10", MAC: "B8:27:EB:11:22:33", Hostname: "pi", Interface: "LAN", Manufacturer: "Raspberry Pi", Source: "arp"},
		}}, nil
	}
	srv := NewServer(d)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), `data-tab="devices"`) {
		t.Fatalf("page missing devices tab")
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("devices JSON want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "192.168.1.10") || !strings.Contains(body, "Raspberry Pi") {
		t.Fatalf("devices JSON missing row data, got %q", body)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("content-type want json, got %q", got)
	}
}

// countingDevices returns a Deps.Devices func that counts invocations and blocks
// on gate (when non-nil) before returning, so a test can hold a fetch open and
// observe how many upstream fetches a burst of requests produced.
func countingDevices(calls *int64, gate <-chan struct{}) func(context.Context) (DeviceReport, error) {
	return func(ctx context.Context) (DeviceReport, error) {
		atomic.AddInt64(calls, 1)
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return DeviceReport{}, ctx.Err()
			}
		}
		return DeviceReport{Devices: []DeviceRow{{IP: "192.168.1.10", MAC: "B8:27:EB:11:22:33"}}}, nil
	}
}

// TestDevicesJSON_ConcurrentRequestsCollapseToOneFetch pins the single-flight
// guarantee: /api/devices.json is unauthenticated and each miss costs THREE live
// OPNsense calls on the same shared client the poll scheduler uses, so a burst
// must collapse into exactly one upstream fetch.
func TestDevicesJSON_ConcurrentRequestsCollapseToOneFetch(t *testing.T) {
	var calls int64
	gate := make(chan struct{})
	d := testDeps()
	d.Devices = countingDevices(&calls, gate)
	srv := NewServer(d)

	const n = 25
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices.json", nil))
			codes[i] = rec.Code
		}()
	}
	// Let the burst pile up behind the in-flight fetch, then release it.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("upstream fetches = %d, want exactly 1 for %d concurrent requests", got, n)
	}
	ok, refused := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusServiceUnavailable:
			refused++
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if ok == 0 || ok+refused != n {
		t.Fatalf("admission results: ok=%d refused=%d", ok, refused)
	}
}

// TestDevicesJSON_SecondRequestWithinTTLIsServedFromCache asserts a repeat request
// inside the TTL window costs zero further upstream fetches and returns the same
// payload shape.
func TestDevicesJSON_SecondRequestWithinTTLIsServedFromCache(t *testing.T) {
	var calls int64
	d := testDeps()
	d.Devices = countingDevices(&calls, nil)
	srv := NewServer(d)

	first := httptest.NewRecorder()
	srv.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/devices.json", nil))
	second := httptest.NewRecorder()
	srv.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/devices.json", nil))

	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("upstream fetches = %d, want 1 (second request served from cache)", got)
	}
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("codes = %d/%d, want 200/200", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("cached body differs:\n%s\n%s", first.Body.String(), second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "192.168.1.10") {
		t.Fatalf("cached body missing row data: %s", second.Body.String())
	}
}

// TestDevicesCache_ExpiresAfterTTL asserts the cache is a short-TTL window, not a
// permanent freeze: once the TTL lapses the next request re-fetches.
func TestDevicesCache_ExpiresAfterTTL(t *testing.T) {
	c := &devicesCache{ttl: 20 * time.Millisecond, timeout: time.Second}
	var calls int64
	fetch := func(context.Context) devicesView {
		atomic.AddInt64(&calls, 1)
		return devicesView{Report: DeviceReport{Generated: time.Now()}}
	}

	c.get(t.Context(), fetch)
	c.get(t.Context(), fetch)
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("fetches within TTL = %d, want 1", got)
	}
	time.Sleep(40 * time.Millisecond)
	c.get(t.Context(), fetch)
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("fetches after TTL = %d, want 2", got)
	}
}

func TestDevicesCache_FailedFetchUsesShortBackoff(t *testing.T) {
	now := time.Unix(100, 0)
	c := &devicesCache{ttl: time.Minute, failureTTL: 2 * time.Second, timeout: time.Second, now: func() time.Time { return now }}
	var calls int64
	fetch := func(context.Context) devicesView {
		n := atomic.AddInt64(&calls, 1)
		if n == 1 {
			return devicesView{Error: "boom"}
		}
		return devicesView{Report: DeviceReport{Generated: time.Now()}}
	}

	if v := c.get(t.Context(), fetch); v.Error != "boom" {
		t.Fatalf("first view error = %q, want boom", v.Error)
	}
	if v := c.get(t.Context(), fetch); v.Error != "boom" {
		t.Fatalf("second view error = %q, want cached backoff error", v.Error)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("fetches = %d, want 1 during failure backoff", got)
	}
	now = now.Add(3 * time.Second)
	if v := c.get(t.Context(), fetch); v.Error != "" {
		t.Fatalf("post-backoff view error = %q, want fresh success", v.Error)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("fetches after backoff = %d, want 2", got)
	}
}

// TestDevicesCache_FetchTimeoutBoundsTheRoute asserts a request cannot wait
// indefinitely on an unresponsive firewall: the route-local deadline cancels the
// fetch context and the request returns.
func TestDevicesCache_FetchTimeoutBoundsTheRoute(t *testing.T) {
	c := &devicesCache{ttl: time.Minute, timeout: 30 * time.Millisecond}
	fetch := func(ctx context.Context) devicesView {
		<-ctx.Done()
		return devicesView{Error: ctx.Err().Error()}
	}

	done := make(chan devicesView, 1)
	go func() { done <- c.get(context.Background(), fetch) }()
	select {
	case v := <-done:
		if v.Error == "" {
			t.Fatalf("want a deadline error in the view, got %+v", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("get did not return: the route has no deadline")
	}
}

// TestDevicesCache_WaiterHonoursRequestContext asserts a request that is itself
// cancelled stops waiting on someone else's in-flight fetch.
func TestDevicesCache_WaiterHonoursRequestContext(t *testing.T) {
	c := &devicesCache{ttl: time.Minute, timeout: time.Minute}
	gate := make(chan struct{})
	defer close(gate)
	fetch := func(context.Context) devicesView {
		<-gate
		return devicesView{}
	}

	go c.get(context.Background(), fetch)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan devicesView, 1)
	go func() { done <- c.get(ctx, fetch) }()
	select {
	case v := <-done:
		if v.Error == "" {
			t.Fatalf("cancelled waiter should surface an error, got %+v", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter ignored its own request context")
	}
}
