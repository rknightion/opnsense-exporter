package enrich

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

var errBoom = errors.New("boom")

// testRefresher is a Refresher plus the registry its metrics were registered on,
// so tests can read metric values back. (prometheus/client_golang's testutil
// package is not vendored in this repo, so we gather from the registry directly.)
type testRefresher struct {
	*Refresher
	reg *prometheus.Registry
}

// metricValue returns the value of the single sample of metric `name` carrying
// label table=<table>, or 0 when no such sample exists.
func metricValue(t *testing.T, reg *prometheus.Registry, name, table string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() != "table" || l.GetValue() != table {
					continue
				}
				if c := m.GetCounter(); c != nil {
					return c.GetValue()
				}
				if g := m.GetGauge(); g != nil {
					return g.GetValue()
				}
			}
		}
	}
	return 0
}

// newTestRefresher builds a Refresher with no API client: the three doRefresh
// closures are replaced with stubs that populate their own table, so the
// scheduling/serialisation logic can be tested without HTTP.
func newTestRefresher(now func() time.Time) *testRefresher {
	reg := prometheus.NewRegistry()
	r := &Refresher{
		cache:         NewCache(),
		m:             NewMetrics(reg),
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:           now,
		missInterval:  missInterval,
		missCh:        make(chan struct{}, 1),
		rulesTTL:      time.Hour,
		ifacesTTL:     time.Hour,
		leasesTTL:     time.Hour,
		tunnelsTTL:    time.Hour,
		ifaceOrderTTL: time.Hour,
	}
	r.refreshTunnels = func() error {
		r.update("tunnels", func(s *Snapshot) {
			s.Tunnels = map[string]string{"5e891b0c-ca13-4e38-a7c0-a2aa891c30b4": "test ipsec conn"}
			s.VPNInstances = map[string]string{"6f86d5cd-44f2-47ea-a882-f8773b65c190": "test server"}
		})
		return nil
	}
	r.refreshRules = func() error {
		r.update("rules", func(s *Snapshot) {
			s.RuleLabels = map[string]string{"rid1": "allow all"}
		})
		return nil
	}
	r.refreshIfaces = func() error {
		r.update("interfaces", func(s *Snapshot) {
			s.IfaceNames = map[string]string{"vtnet0": "LAN"}
			s.LocalNets = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
			s.SelfIPs = map[netip.Addr]bool{netip.MustParseAddr("10.0.0.114"): true}
		})
		return nil
	}
	r.refreshLeases = func() error {
		r.update("leases", func(s *Snapshot) {
			s.Hostnames = map[string]string{"10.0.0.6": "robs-laptop"}
			s.MACs = map[string]string{"10.0.0.6": "aa:bb:cc:dd:ee:ff"}
		})
		return nil
	}
	return &testRefresher{Refresher: r, reg: reg}
}

// THE DoS GUARD. A flood of unknown rids must trigger at most ONE refresh per
// window — and NoteMiss must NEVER call the API inline (it runs on the receiver
// goroutine; a blocking HTTPS call there stops the UDP read loop and silently
// drops datagrams).
func TestNoteMissIsRateLimitedAndNonBlocking(t *testing.T) {
	r := newTestRefresher(func() time.Time { return time.Unix(1700000000, 0) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10_000; i++ {
			r.NoteMiss("rules") // must return immediately, every time
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("NoteMiss blocked — the receiver goroutine would stall and drop datagrams")
	}

	if got := len(r.missCh); got != 1 {
		t.Fatalf("10k misses queued %d refresh signals, want exactly 1 (buffered, coalesced)", got)
	}
	if got := metricValue(t, r.reg, "opnsense_exporter_logs_enrich_misses_total", "rules"); got != 10_000 {
		t.Errorf("Misses{rules} = %v, want 10000 (every miss is counted, even when coalesced)", got)
	}
}

func TestNoteMissRefreshesAgainAfterInterval(t *testing.T) {
	now := time.Unix(1700000000, 0)
	r := newTestRefresher(func() time.Time { return now })
	r.NoteMiss("rules")
	<-r.missCh // drain, as Run would
	now = now.Add(31 * time.Second)
	r.NoteMiss("rules")
	if len(r.missCh) != 1 {
		t.Fatal("a miss after the window must re-signal")
	}
}

// A failed refresh must leave the PREVIOUS snapshot in place. Stale enrichment
// beats none; enrichment must never drop a record.
func TestRefreshErrorKeepsPreviousSnapshot(t *testing.T) {
	r := newTestRefresher(time.Now)
	good := testSnapshot()
	r.cache.Store(good)
	r.refreshRules = func() error { return errBoom }
	r.tick("rules", r.refreshRules)

	if r.cache.Load() != good {
		t.Fatal("a failed refresh must not disturb the cached snapshot")
	}
	if got := metricValue(t, r.reg, "opnsense_exporter_logs_enrich_refresh_errors_total", "rules"); got != 1 {
		t.Errorf("RefreshErrors = %v, want 1", got)
	}
	if got := metricValue(t, r.reg, "opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds", "rules"); got != 0 {
		t.Errorf("LastRefresh{rules} = %v, want 0 (a failed refresh is not fresh)", got)
	}
}

// Two refreshers racing must not lose each other's tables (load->build->store is a
// read-modify-write; the atomic pointer makes the SWAP safe, not the RMW).
func TestConcurrentRefreshersDoNotLoseUpdates(t *testing.T) {
	r := newTestRefresher(time.Now)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.tick("rules", r.refreshRules) }()
	go func() { defer wg.Done(); r.tick("interfaces", r.refreshIfaces) }()
	wg.Wait()

	s := r.cache.Load()
	if len(s.RuleLabels) == 0 {
		t.Error("rules table lost")
	}
	if len(s.IfaceNames) == 0 {
		t.Error("interfaces table lost")
	}
}

func TestTickSetsLastRefreshPerTable(t *testing.T) {
	now := time.Unix(1700000000, 0)
	r := newTestRefresher(func() time.Time { return now })
	r.tick("rules", r.refreshRules)

	const lastRefreshName = "opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds"
	if got := metricValue(t, r.reg, lastRefreshName, "rules"); got != float64(now.Unix()) {
		t.Errorf("LastRefresh{rules} = %v, want %v", got, now.Unix())
	}
	if got := metricValue(t, r.reg, lastRefreshName, "leases"); got != 0 {
		t.Errorf("LastRefresh{leases} = %v, want 0 — freshness is per table", got)
	}
	if ts, ok := r.cache.Load().LastRefresh["rules"]; !ok || !ts.Equal(now) {
		t.Errorf("snapshot LastRefresh[rules] = %v, %v", ts, ok)
	}
}

// Run must refresh every table once immediately, and must return on ctx cancel.
func TestRunRefreshesOnceThenExitsOnCancel(t *testing.T) {
	r := newTestRefresher(time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		s := r.cache.Load()
		if len(s.RuleLabels) > 0 && len(s.IfaceNames) > 0 && len(s.Hostnames) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not refresh all three tables on start")
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on ctx cancel")
	}
}

// A miss signal drained by Run triggers a real refresh.
func TestRunRefreshesOnMissSignal(t *testing.T) {
	r := newTestRefresher(time.Now)
	var mu sync.Mutex
	rules := 0
	r.refreshRules = func() error {
		mu.Lock()
		rules++
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()

	r.NoteMiss("rules")

	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := rules
		mu.Unlock()
		if n >= 2 { // one initial refresh + one miss-triggered
			break
		}
		select {
		case <-deadline:
			t.Fatalf("miss signal did not trigger a refresh (rules refreshed %d times)", n)
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
}

// ifaceOverviewFixture is an interfaces_info response in the shape verified
// against OPNsense 26.1 (see opnsense/interfaces.go): addresses arrive as arrays
// of {"ipaddr": "<cidr>"} objects, and a VLAN child carries either the flat
// "vlan_tag" or the nested "vlan" object.
const ifaceOverviewFixture = `{"rows":[
  {"device":"ixl0","identifier":"lan","description":"LAN",
   "ipv4":[{"ipaddr":"10.0.0.114/24"}],"ipv6":[{"ipaddr":"fe80::1/64"}]},
  {"device":"igb0","identifier":"opt5","description":"WAN2",
   "ipv4":[{"ipaddr":"203.0.113.9/29"}]},
  {"device":"lo0","identifier":"","description":"","ipv4":[{"ipaddr":"127.0.0.1/8"}]},
  {"device":"ixl0_vlan50","identifier":"opt3","description":"IOT",
   "vlan":{"tag":"50","parent":"ixl0"},"ipv4":[{"ipaddr":"192.168.50.1/24"}]},
  {"device":"ixl0_vlan60","identifier":"opt7","description":"DMZ",
   "vlan":{"tag":"60","parent":"ixl0"},"ipv4":[{"ipaddr":"203.0.113.130/29"}]},
  {"device":"pppoe0","identifier":"wan","description":"WAN1",
   "ipv4":[{"ipaddr":"198.51.100.42/32"}]}
]}`

// newFixtureRefresher wires a Refresher to a real API client pointed at an
// httptest server serving body for every request, so doRefreshIfaces is exercised
// end to end rather than through a stub.
func newFixtureRefresher(t *testing.T, body string) *Refresher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	client, err := opnsense.NewClient(options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(srv.URL, "http://"),
		APIKey: "k", APISecret: "s",
	}, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &Refresher{
		client: &client,
		cache:  NewCache(),
		m:      NewMetrics(prometheus.NewRegistry()),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    time.Now,
	}
}

// The new Ifaces table must carry EVERY interface the box reports, in the order the
// API returned it — that order is what the ifIndex enumeration is derived from, so
// reordering or dropping a row silently remaps every historical series.
func TestDoRefreshIfacesPopulatesIfacesInAPIOrder(t *testing.T) {
	r := newFixtureRefresher(t, ifaceOverviewFixture)
	if err := r.doRefreshIfaces(); err != nil {
		t.Fatalf("doRefreshIfaces: %v", err)
	}
	got := r.cache.Load().Ifaces

	want := []IfaceInfo{
		{Device: "ixl0", Name: "LAN", Identifier: "lan",
			Addrs: mustAddrs("10.0.0.114", "fe80::1")},
		{Device: "igb0", Name: "WAN2", Identifier: "opt5", IsWAN: true,
			Addrs: mustAddrs("203.0.113.9")},
		{Device: "lo0", Addrs: mustAddrs("127.0.0.1")},
		{Device: "ixl0_vlan50", Name: "IOT", Identifier: "opt3",
			VlanTag: "50", VlanParent: "ixl0", Addrs: mustAddrs("192.168.50.1")},
		{Device: "ixl0_vlan60", Name: "DMZ", Identifier: "opt7",
			VlanTag: "60", VlanParent: "ixl0", Addrs: mustAddrs("203.0.113.130")},
		{Device: "pppoe0", Name: "WAN1", Identifier: "wan", IsWAN: true,
			Addrs: mustAddrs("198.51.100.42")},
	}
	if len(got) != len(want) {
		t.Fatalf("Ifaces has %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !ifaceInfoEqual(got[i], want[i]) {
			t.Errorf("Ifaces[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// IsWAN is a heuristic and its failure modes are deliberate. Pin them, so a later
// change to the signal is a decision rather than an accident.
func TestDoRefreshIfacesIsWANHeuristic(t *testing.T) {
	r := newFixtureRefresher(t, ifaceOverviewFixture)
	if err := r.doRefreshIfaces(); err != nil {
		t.Fatalf("doRefreshIfaces: %v", err)
	}
	byDevice := map[string]IfaceInfo{}
	for _, i := range r.cache.Load().Ifaces {
		byDevice[i.Device] = i
	}

	tests := []struct {
		device string
		want   bool
		why    string
	}{
		{"pppoe0", true, "identifier wan + a globally-routable address"},
		{"igb0", true, "identifier optN + a globally-routable address"},
		{"ixl0", false, "identifier lan is never a WAN"},
		{"lo0", false, "no identifier, and 127.0.0.1 is not globally routable"},
		{"ixl0_vlan50", false, "a VLAN child is never treated as a WAN"},
		{"ixl0_vlan60", false, "a routed public subnet on a VLAN DMZ is NOT a WAN — " +
			"the deliberate false-negative side of excluding VLANs"},
	}
	for _, tc := range tests {
		if got := byDevice[tc.device].IsWAN; got != tc.want {
			t.Errorf("IsWAN(%s) = %v, want %v — %s", tc.device, got, tc.want, tc.why)
		}
	}
}

// The Ifaces table is an ADDITION. Everything the interfaces refresh already
// produced must be bit-for-bit unchanged.
func TestDoRefreshIfacesPreservesExistingTables(t *testing.T) {
	r := newFixtureRefresher(t, ifaceOverviewFixture)
	if err := r.doRefreshIfaces(); err != nil {
		t.Fatalf("doRefreshIfaces: %v", err)
	}
	s := r.cache.Load()

	wantNames := map[string]string{
		"ixl0": "LAN", "igb0": "WAN2", "ixl0_vlan50": "IOT",
		"ixl0_vlan60": "DMZ", "pppoe0": "WAN1",
	}
	if len(s.IfaceNames) != len(wantNames) {
		t.Errorf("IfaceNames = %v, want %v (lo0 has no description and must be absent)",
			s.IfaceNames, wantNames)
	}
	for dev, name := range wantNames {
		if got := s.IfaceNames[dev]; got != name {
			t.Errorf("IfaceNames[%s] = %q, want %q", dev, got, name)
		}
	}

	for _, ip := range []string{"10.0.0.114", "fe80::1", "203.0.113.9", "127.0.0.1",
		"192.168.50.1", "203.0.113.130", "198.51.100.42"} {
		if !s.SelfIPs[netip.MustParseAddr(ip)] {
			t.Errorf("SelfIPs missing %s", ip)
		}
	}
	if got := len(s.SelfIPs); got != 7 {
		t.Errorf("len(SelfIPs) = %d, want 7", got)
	}

	wantNets := []string{"10.0.0.0/24", "fe80::/64", "203.0.113.8/29", "127.0.0.0/8",
		"192.168.50.0/24", "203.0.113.128/29", "198.51.100.42/32"}
	if len(s.LocalNets) != len(wantNets) {
		t.Fatalf("LocalNets = %v, want %d entries", s.LocalNets, len(wantNets))
	}
	for i, want := range wantNets {
		if s.LocalNets[i] != netip.MustParsePrefix(want) {
			t.Errorf("LocalNets[%d] = %v, want %v (order follows the API)", i, s.LocalNets[i], want)
		}
	}

	// And the behaviour those tables drive is unchanged.
	if got := s.Scope("10.0.0.114"); got != "self" {
		t.Errorf("Scope(10.0.0.114) = %q, want self", got)
	}
	if got := s.Scope("10.0.0.6"); got != "local" {
		t.Errorf("Scope(10.0.0.6) = %q, want local", got)
	}
	if got := s.Scope("8.8.8.8"); got != "remote" {
		t.Errorf("Scope(8.8.8.8) = %q, want remote", got)
	}
	if got, ok := s.InterfaceName("ixl0"); !ok || got != "LAN" {
		t.Errorf("InterfaceName(ixl0) = %q,%v want LAN,true", got, ok)
	}
}

func mustAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s).Unmap())
	}
	return out
}

func ifaceInfoEqual(a, b IfaceInfo) bool {
	if a.Device != b.Device || a.Name != b.Name || a.Identifier != b.Identifier ||
		a.VlanTag != b.VlanTag || a.VlanParent != b.VlanParent || a.IsWAN != b.IsWAN {
		return false
	}
	if len(a.Addrs) != len(b.Addrs) {
		return false
	}
	for i := range a.Addrs {
		if a.Addrs[i] != b.Addrs[i] {
			return false
		}
	}
	return true
}

func TestParseAddrPrefix(t *testing.T) {
	addr, pfx, err := parseAddrPrefix("10.0.0.114/24")
	if err != nil {
		t.Fatalf("parseAddrPrefix: %v", err)
	}
	if addr != netip.MustParseAddr("10.0.0.114") {
		t.Errorf("addr = %v", addr)
	}
	if pfx != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("prefix = %v, want the masked network", pfx)
	}
	if _, _, err := parseAddrPrefix("garbage"); err == nil {
		t.Error("parseAddrPrefix(garbage) must error")
	}
	if _, _, err := parseAddrPrefix(""); err == nil {
		t.Error("parseAddrPrefix(\"\") must error")
	}
}

func TestNewMetricsRegisters(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	m.Misses.WithLabelValues("rules").Inc()
	m.RefreshErrors.WithLabelValues("leases").Inc()
	m.LastRefresh.WithLabelValues("interfaces").Set(1)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"opnsense_exporter_logs_enrich_misses_total":                   false,
		"opnsense_exporter_logs_enrich_refresh_errors_total":           false,
		"opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds": false,
	}
	for _, f := range families {
		if _, ok := want[f.GetName()]; ok {
			want[f.GetName()] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("metric %s not registered", name)
		}
	}
}

// A rebuild of ONE table must not wipe the others. clone() has to carry every map
// forward, and it is trivially easy to add a new table to the Snapshot and forget
// it there — at which point tunnel names would silently vanish every 60s when the
// rules table refreshed. Guard the whole snapshot, not just the table under test.
func TestRefreshOneTableKeepsTheOthers(t *testing.T) {
	r := newTestRefresher(time.Now)
	r.tick("tunnels", r.refreshTunnels)
	r.tick("interfaces", r.refreshIfaces)

	if _, ok := r.cache.Load().Tunnel("5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"); !ok {
		t.Fatal("precondition: tunnels table should be populated")
	}

	// Refresh an unrelated table.
	r.tick("rules", r.refreshRules)

	s := r.cache.Load()
	if _, ok := s.Tunnel("5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"); !ok {
		t.Error("a rules refresh wiped the tunnels table (clone() is not carrying it forward)")
	}
	if _, ok := s.VPNInstance("6f86d5cd-44f2-47ea-a882-f8773b65c190"); !ok {
		t.Error("a rules refresh wiped the VPN-instances table")
	}
	if len(s.IfaceNames) == 0 {
		t.Error("a rules refresh wiped the interfaces table")
	}
	if _, ok := s.RuleLabel("rid1"); !ok {
		t.Error("the rules table itself did not land")
	}
}

// --- the ifIndex enumeration (#361) -----------------------------------------

// The 16-device enumeration the reference box actually returns, and the 15-row
// overview that omits pfsync0. The pair is the whole of #361: counting overview
// rows put every index from 10 up one too low.
const ifaceConfigFixture = `{
 "ixl0":{"device":"ixl0"},"ixl1":{"device":"ixl1"},"ixl2":{"device":"ixl2"},
 "ixl3":{"device":"ixl3"},"igb0":{"device":"igb0"},"igb1":{"device":"igb1"},
 "lo0":{"device":"lo0"},"enc0":{"device":"enc0"},"pflog0":{"device":"pflog0"},
 "pfsync0":{"device":"pfsync0"},"ixl0_vlan100":{"device":"ixl0_vlan100"},
 "ixl0_vlan25":{"device":"ixl0_vlan25"},"ixl0_vlan50":{"device":"ixl0_vlan50"},
 "zen0":{"device":"zen0"},"pppoe0":{"device":"pppoe0"},
 "tailscale0":{"device":"tailscale0"}}`

const trafficIfaceFixture = `{"interfaces":{
 "opt7":{"device":"pppoe0","index":"15","name":"AAISP"},
 "lan":{"device":"ixl0","index":"1","name":"LAN"},
 "opt1":{"device":"tailscale0","index":"16","name":"tailscale"}}}`

// newRoutedRefresher serves a different body per URL path, which the enumeration
// refresh needs: it reads TWO endpoints and they must not answer each other.
func newRoutedRefresher(t *testing.T, byPath map[string]string) *Refresher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for suffix, body := range byPath {
			if strings.Contains(req.URL.Path, suffix) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
				return
			}
		}
		http.Error(w, "no fixture for "+req.URL.Path, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	client, err := opnsense.NewClient(options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(srv.URL, "http://"),
		APIKey: "k", APISecret: "s",
	}, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &Refresher{
		client:  &client,
		cache:   NewCache(),
		m:       NewMetrics(prometheus.NewRegistry()),
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:     time.Now,
		missCh:  make(chan struct{}, 1),
		orderCh: make(chan struct{}, 1),
	}
}

// The enumeration must arrive in the box's own order, pfsync0 included. This is
// the table internal/flow turns into ifIndex -> interface, so a dropped or
// reordered device silently relabels every historical flow series.
func TestDoRefreshIfaceOrderPublishesTheBoxEnumeration(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"get_interface_config": ifaceConfigFixture,
		"traffic/interface":    trafficIfaceFixture,
	})
	if err := r.doRefreshIfaceOrder(); err != nil {
		t.Fatalf("doRefreshIfaceOrder: %v", err)
	}
	snap := r.cache.Load()

	want := []string{
		"ixl0", "ixl1", "ixl2", "ixl3", "igb0", "igb1", "lo0", "enc0",
		"pflog0", "pfsync0", "ixl0_vlan100", "ixl0_vlan25", "ixl0_vlan50",
		"zen0", "pppoe0", "tailscale0",
	}
	if len(snap.IfaceOrder) != len(want) {
		t.Fatalf("IfaceOrder has %d devices, want %d: %v", len(snap.IfaceOrder), len(want), snap.IfaceOrder)
	}
	for i := range want {
		if snap.IfaceOrder[i] != want[i] {
			t.Errorf("IfaceOrder[%d] = %q, want %q", i, snap.IfaceOrder[i], want[i])
		}
	}
	// pppoe0 sits at position 15 and the API states 15. Agreement is what the
	// guard is checking for; the value itself is only ever a cross-check.
	if got := snap.IfaceStatedIndex["pppoe0"]; got != 15 {
		t.Errorf("IfaceStatedIndex[pppoe0] = %d, want 15", got)
	}
	if got := snap.IfaceStatedIndex["tailscale0"]; got != 16 {
		t.Errorf("IfaceStatedIndex[tailscale0] = %d, want 16", got)
	}
}

// An empty enumeration is a failed fetch wearing a success. Publishing it would
// blank the map, and a blank map labels nothing at all, so it must be an error
// and leave whatever was there in place.
func TestDoRefreshIfaceOrderRefusesAnEmptyEnumeration(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"get_interface_config": `{}`,
		"traffic/interface":    trafficIfaceFixture,
	})
	if err := r.doRefreshIfaceOrder(); err == nil {
		t.Fatal("doRefreshIfaceOrder accepted an empty enumeration; want an error")
	}
	if got := r.cache.Load().IfaceOrder; len(got) != 0 {
		t.Errorf("IfaceOrder = %v, want it left untouched", got)
	}
}

// The stated index is a guard, not the map. Losing it must never cost us the
// ordering — but it must also not silently blank the guard, which would read as
// "nothing disagrees" when the truth is "nothing was checked".
func TestDoRefreshIfaceOrderKeepsTheLastStatedIndexesOnFailure(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"get_interface_config": ifaceConfigFixture,
		"traffic/interface":    trafficIfaceFixture,
	})
	if err := r.doRefreshIfaceOrder(); err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	broken := newRoutedRefresher(t, map[string]string{"get_interface_config": ifaceConfigFixture})
	broken.cache = r.cache // carry the good snapshot forward
	if err := broken.doRefreshIfaceOrder(); err != nil {
		t.Fatalf("doRefreshIfaceOrder failed on a stated-index error; the ordering was fine: %v", err)
	}
	if got := broken.cache.Load().IfaceStatedIndex["pppoe0"]; got != 15 {
		t.Errorf("IfaceStatedIndex[pppoe0] = %d after a failed stated fetch, want the previous 15", got)
	}
}

// A device the overview knows that the ordering does not is direct evidence the
// enumeration moved. It must trigger a re-fetch rather than wait out the hour.
func TestDoRefreshIfacesSignalsWhenTheInterfaceSetOutgrowsTheOrdering(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"get_interface_config":     ifaceConfigFixture,
		"traffic/interface":        trafficIfaceFixture,
		"overview/interfaces_info": ifaceOverviewFixture,
	})
	if err := r.doRefreshIfaceOrder(); err != nil {
		t.Fatalf("doRefreshIfaceOrder: %v", err)
	}

	// An ordering that already covers every device the overview names must stay
	// quiet — otherwise the trigger fires on every refresh and stops meaning
	// anything.
	r.update("ifaceorder", func(s *Snapshot) {
		s.IfaceOrder = []string{"ixl0", "igb0", "lo0", "ixl0_vlan50", "ixl0_vlan60", "pppoe0"}
	})
	drain(r.orderCh)
	if err := r.doRefreshIfaces(); err != nil {
		t.Fatalf("doRefreshIfaces: %v", err)
	}
	if signalled(r.orderCh) {
		t.Error("a device set already covered by the ordering signalled a re-fetch")
	}

	// Drop one device from the ordering: the overview now names an interface that
	// has no slot, which is the enumeration having moved under us.
	r.update("ifaceorder", func(s *Snapshot) { s.IfaceOrder = []string{"ixl0"} })
	if err := r.doRefreshIfaces(); err != nil {
		t.Fatalf("doRefreshIfaces: %v", err)
	}
	if !signalled(r.orderCh) {
		t.Error("a device absent from the ordering did not signal a re-fetch")
	}
}

// Before the first successful enumeration fetch every device looks new, so the
// trigger must stay silent rather than firing on a cold start.
func TestDoRefreshIfacesDoesNotSignalBeforeTheFirstEnumeration(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"overview/interfaces_info": ifaceOverviewFixture,
	})
	if err := r.doRefreshIfaces(); err != nil {
		t.Fatalf("doRefreshIfaces: %v", err)
	}
	if signalled(r.orderCh) {
		t.Error("signalled a re-fetch with no enumeration yet; every device looks new there")
	}
}

func drain(ch chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

func signalled(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// --- reconstructing ifinfo order (#363) -------------------------------------

// The pair that broke #361's assumption, captured live on 2026-07-24 after a
// PPPoE reconnect. get_interface_config is in ATTACH order, so the recreated
// pppoe0 is last; ifinfo sorts by kernel index, so it is back at 15. The netgraph
// hook proved ifinfo right: rc.d/netflow re-derived it as iface15.
func bouncedAttachOrder() []string {
	return []string{
		"ixl0", "ixl1", "ixl2", "ixl3", "igb0", "igb1", "lo0", "enc0",
		"pflog0", "pfsync0", "ixl0_vlan100", "ixl0_vlan25", "ixl0_vlan50",
		"zen0", "tailscale0", "pppoe0",
	}
}

// bouncedStated is what traffic/interface reports: an index for the CONFIGURED
// interfaces only. The unconfigured remainder has none, which is the whole
// difficulty — and also why it works, since only a configured interface can be
// destroyed and recreated at runtime.
func bouncedStated() map[string]uint32 {
	return map[string]uint32{
		"ixl0": 1, "ixl1": 2, "ixl0_vlan100": 11, "ixl0_vlan25": 12,
		"ixl0_vlan50": 13, "zen0": 14, "pppoe0": 15, "tailscale0": 16,
	}
}

func ifinfoTruth() []string {
	return []string{
		"ixl0", "ixl1", "ixl2", "ixl3", "igb0", "igb1", "lo0", "enc0",
		"pflog0", "pfsync0", "ixl0_vlan100", "ixl0_vlan25", "ixl0_vlan50",
		"zen0", "pppoe0", "tailscale0",
	}
}

func sameOrder(t *testing.T, got, want []string, label string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d devices, want %d: %v", label, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: position %d = %q, want %q\n got: %v\nwant: %v",
				label, i+1, got[i], want[i], got, want)
		}
	}
}

// The regression. Attach order alone puts pppoe0 at 16 and tailscale0 at 15,
// which mislabels the WAN carrying 91% of the box's volume.
func TestReconstructIfinfoOrderRecoversTheKernelIndexOrder(t *testing.T) {
	got, err := reconstructIfinfoOrder(bouncedAttachOrder(), bouncedStated())
	if err != nil {
		t.Fatalf("reconstructIfinfoOrder: %v", err)
	}
	sameOrder(t, got, ifinfoTruth(), "reconstructed")

	// Guard the guard: the raw attach order must NOT already equal the truth, or
	// this test would pass without the reconstruction doing anything.
	if attach := bouncedAttachOrder(); attach[14] == ifinfoTruth()[14] {
		t.Fatal("fixture is not exercising the bug: attach order already matches ifinfo")
	}
}

// The undisturbed case must be a no-op rather than a reshuffle.
func TestReconstructIfinfoOrderLeavesAnAgreeingListAlone(t *testing.T) {
	stated := map[string]uint32{}
	for i, d := range ifinfoTruth() {
		stated[d] = uint32(i + 1) //nolint:gosec // fixture
	}
	got, err := reconstructIfinfoOrder(ifinfoTruth(), stated)
	if err != nil {
		t.Fatalf("reconstructIfinfoOrder: %v", err)
	}
	sameOrder(t, got, ifinfoTruth(), "unchanged")
}

// With no stated indices at all there is nothing to correct with, so attach order
// is the only answer available. It must be returned as-is rather than refused:
// a box whose traffic/interface fetch failed is still better served by the
// probably-right order than by no map.
func TestReconstructIfinfoOrderWithoutAnyStatedIndexReturnsAttachOrder(t *testing.T) {
	got, err := reconstructIfinfoOrder(bouncedAttachOrder(), nil)
	if err != nil {
		t.Fatalf("reconstructIfinfoOrder: %v", err)
	}
	sameOrder(t, got, bouncedAttachOrder(), "passthrough")
}

// A stated index outside the device count means the index space has a GAP - an
// interface was removed permanently - and position no longer equals index. The
// reconstruction cannot resolve that, and must say so rather than place a device
// in a slot it invented.
func TestReconstructIfinfoOrderRefusesAnOutOfRangeIndex(t *testing.T) {
	stated := bouncedStated()
	stated["pppoe0"] = 99
	if _, err := reconstructIfinfoOrder(bouncedAttachOrder(), stated); err == nil {
		t.Fatal("accepted a stated index beyond the device count; want an error")
	}
}

// Two devices claiming one slot is the same class of unresolvable input.
func TestReconstructIfinfoOrderRefusesACollision(t *testing.T) {
	stated := bouncedStated()
	stated["tailscale0"] = 15 // pppoe0 already states 15
	if _, err := reconstructIfinfoOrder(bouncedAttachOrder(), stated); err == nil {
		t.Fatal("accepted two devices claiming index 15; want an error")
	}
}

// A stated index for a device the enumeration does not list says the two sources
// disagree about which interfaces exist, so neither can be trusted to order.
func TestReconstructIfinfoOrderRefusesAnUnknownDevice(t *testing.T) {
	stated := bouncedStated()
	stated["vtnet9"] = 3
	if _, err := reconstructIfinfoOrder(bouncedAttachOrder(), stated); err == nil {
		t.Fatal("accepted a stated index for a device absent from the enumeration; want an error")
	}
}

// An index of 0 is "the API stated nothing", not "slot zero" - ifIndex 0 is the
// synthetic locally-originated entry and is never a device.
func TestReconstructIfinfoOrderIgnoresAZeroStatedIndex(t *testing.T) {
	stated := map[string]uint32{"ixl0": 0, "pppoe0": 15, "tailscale0": 16}
	got, err := reconstructIfinfoOrder(bouncedAttachOrder(), stated)
	if err != nil {
		t.Fatalf("reconstructIfinfoOrder: %v", err)
	}
	sameOrder(t, got, ifinfoTruth(), "zero ignored")
}

// End to end through the refresh, not just the pure function: the published
// ordering must be the corrected one. This is the shape the reference box was
// actually serving after the WAN bounce — pppoe0 last in the API, 15 in ifinfo.
const bouncedConfigFixture = `{
 "ixl0":{"device":"ixl0"},"ixl1":{"device":"ixl1"},"ixl2":{"device":"ixl2"},
 "ixl3":{"device":"ixl3"},"igb0":{"device":"igb0"},"igb1":{"device":"igb1"},
 "lo0":{"device":"lo0"},"enc0":{"device":"enc0"},"pflog0":{"device":"pflog0"},
 "pfsync0":{"device":"pfsync0"},"ixl0_vlan100":{"device":"ixl0_vlan100"},
 "ixl0_vlan25":{"device":"ixl0_vlan25"},"ixl0_vlan50":{"device":"ixl0_vlan50"},
 "zen0":{"device":"zen0"},"tailscale0":{"device":"tailscale0"},
 "pppoe0":{"device":"pppoe0"}}`

const bouncedTrafficFixture = `{"interfaces":{
 "lan":{"device":"ixl0","index":"1","name":"LAN"},
 "opt6":{"device":"ixl1","index":"2","name":"VIRGIN"},
 "opt3":{"device":"ixl0_vlan100","index":"11","name":"MGMT"},
 "opt4":{"device":"ixl0_vlan25","index":"12","name":"CAM"},
 "opt2":{"device":"ixl0_vlan50","index":"13","name":"IOT"},
 "opt5":{"device":"zen0","index":"14","name":"zenoverlay"},
 "opt7":{"device":"pppoe0","index":"15","name":"AAISP"},
 "opt1":{"device":"tailscale0","index":"16","name":"tailscale"}}}`

func TestDoRefreshIfaceOrderPublishesTheCorrectedOrder(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"get_interface_config": bouncedConfigFixture,
		"traffic/interface":    bouncedTrafficFixture,
	})
	if err := r.doRefreshIfaceOrder(); err != nil {
		t.Fatalf("doRefreshIfaceOrder: %v", err)
	}
	got := r.cache.Load().IfaceOrder
	sameOrder(t, got, ifinfoTruth(), "published")

	// The two that matter: 91% of the box's volume arrives on ifIndex 15.
	if got[14] != "pppoe0" {
		t.Errorf("ifIndex 15 = %q, want pppoe0 (the API served tailscale0 there)", got[14])
	}
	if got[15] != "tailscale0" {
		t.Errorf("ifIndex 16 = %q, want tailscale0", got[15])
	}
}

// A reconstruction that cannot be trusted must leave the previous ordering alone,
// never publish a guess. Same rule as a failed fetch.
func TestDoRefreshIfaceOrderKeepsThePreviousOrderWhenReconstructionFails(t *testing.T) {
	r := newRoutedRefresher(t, map[string]string{
		"get_interface_config": bouncedConfigFixture,
		// pppoe0 claims an index past the device count: the index space has a gap,
		// so position and index are no longer equal and this cannot be resolved.
		"traffic/interface": `{"interfaces":{"opt7":{"device":"pppoe0","index":"99","name":"AAISP"}}}`,
	})
	good := []string{"previous", "order"}
	r.update("ifaceorder", func(s *Snapshot) { s.IfaceOrder = good })

	if err := r.doRefreshIfaceOrder(); err == nil {
		t.Fatal("published an unreconstructable ordering; want an error")
	}
	sameOrder(t, r.cache.Load().IfaceOrder, good, "kept previous")
}
