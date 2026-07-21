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
		cache:        NewCache(),
		m:            NewMetrics(reg),
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:          now,
		missInterval: missInterval,
		missCh:       make(chan struct{}, 1),
		rulesTTL:     time.Hour,
		ifacesTTL:    time.Hour,
		leasesTTL:    time.Hour,
		tunnelsTTL:   time.Hour,
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
