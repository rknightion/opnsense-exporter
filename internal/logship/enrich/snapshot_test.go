package enrich

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testSnapshot() *Snapshot {
	return &Snapshot{
		RuleLabels: map[string]string{
			"60533d555322b9f6a009f71c1c471480": "anti-lockout rule",
		},
		IfaceNames: map[string]string{"vtnet0": "LAN"},
		Hostnames:  map[string]string{"10.0.0.6": "robs-laptop"},
		MACs:       map[string]string{"10.0.0.6": "aa:bb:cc:dd:ee:ff"},
		LocalNets: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
		SelfIPs: map[netip.Addr]bool{
			netip.MustParseAddr("10.0.0.114"):  true,
			netip.MustParseAddr("2001:db8::1"): true,
		},
		LastRefresh: map[string]time.Time{"rules": time.Unix(1700000000, 0)},
	}
}

func TestSnapshotLookups(t *testing.T) {
	s := testSnapshot()

	if got, ok := s.RuleLabel("60533d555322b9f6a009f71c1c471480"); !ok || got != "anti-lockout rule" {
		t.Errorf("RuleLabel = %q, %v", got, ok)
	}
	if _, ok := s.RuleLabel("nope"); ok {
		t.Error("RuleLabel(nope) should miss")
	}
	if got, ok := s.InterfaceName("vtnet0"); !ok || got != "LAN" {
		t.Errorf("InterfaceName = %q, %v", got, ok)
	}
	if _, ok := s.InterfaceName("vtnet9"); ok {
		t.Error("InterfaceName(vtnet9) should miss")
	}
	if got, ok := s.Hostname("10.0.0.6"); !ok || got != "robs-laptop" {
		t.Errorf("Hostname = %q, %v", got, ok)
	}
	if _, ok := s.Hostname("10.0.0.7"); ok {
		t.Error("Hostname(10.0.0.7) should miss")
	}
	if got, ok := s.MAC("10.0.0.6"); !ok || got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q, %v", got, ok)
	}
	if _, ok := s.MAC("10.0.0.7"); ok {
		t.Error("MAC(10.0.0.7) should miss")
	}
}

func TestSnapshotEmptyValuesMiss(t *testing.T) {
	s := &Snapshot{RuleLabels: map[string]string{"a": ""}, IfaceNames: map[string]string{"b": ""}}
	if _, ok := s.RuleLabel("a"); ok {
		t.Error("an empty rule description must count as a miss, not a hit")
	}
	if _, ok := s.InterfaceName("b"); ok {
		t.Error("an empty interface name must count as a miss, not a hit")
	}
}

// clone() must carry the Ifaces table forward like every other table: a rules
// refresh 60 seconds from now would otherwise wipe the interface topology the
// NetFlow ifIndex map is derived from, and every flow would lose its interface
// label until the 5-minute interfaces TTL came round again.
func TestCloneCarriesIfaces(t *testing.T) {
	s := testSnapshot()
	s.Ifaces = []IfaceInfo{{
		Device: "ixl0_vlan50", Name: "IOT", Identifier: "opt3",
		VlanTag: "50", VlanParent: "ixl0",
		Addrs: []netip.Addr{netip.MustParseAddr("10.50.0.1")},
	}}

	next := s.clone()
	if len(next.Ifaces) != 1 {
		t.Fatalf("clone() dropped the Ifaces table: %+v", next.Ifaces)
	}
	if next.Ifaces[0].Device != "ixl0_vlan50" || next.Ifaces[0].Name != "IOT" ||
		next.Ifaces[0].VlanParent != "ixl0" || len(next.Ifaces[0].Addrs) != 1 {
		t.Errorf("clone() mangled Ifaces[0] = %+v", next.Ifaces[0])
	}
}

func TestScope(t *testing.T) {
	s := testSnapshot()

	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.114", "self"},
		{"2001:db8::1", "self"},
		// IPv6 canonicalisation: the same address in three textual forms.
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "self"},
		{"2001:db8::0001", "self"},
		{"10.0.0.6", "local"},
		{"2001:db8:1::99", "local"},
		{"8.8.8.8", "remote"},
		{"2606:4700::1", "remote"},
		{"", ""},
		{"not-an-ip", ""},
		{"10.0.0.256", ""},
	}
	for _, tc := range tests {
		if got := s.Scope(tc.ip); got != tc.want {
			t.Errorf("Scope(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestScopeIPv6TextualFormsAreOneKey(t *testing.T) {
	// A string-keyed SelfIPs map would silently miss here. Prove the netip.Addr key
	// canonicalises: build the map from the long form, look up the short form.
	s := &Snapshot{SelfIPs: map[netip.Addr]bool{
		netip.MustParseAddr("2001:0db8:0000:0000:0000:0000:0000:0001"): true,
	}}
	if got := s.Scope("2001:db8::1"); got != "self" {
		t.Fatalf("Scope(short form) = %q, want self", got)
	}
}

func TestColdCacheMissesEverythingAndNeverNil(t *testing.T) {
	c := NewCache()
	s := c.Load()
	if s == nil {
		t.Fatal("Load() on a cold cache returned nil — the hot path would panic")
	}
	if _, ok := s.RuleLabel("x"); ok {
		t.Error("cold cache should miss")
	}
	if _, ok := s.InterfaceName("x"); ok {
		t.Error("cold cache should miss")
	}
	if _, ok := s.Hostname("x"); ok {
		t.Error("cold cache should miss")
	}
	if _, ok := s.MAC("x"); ok {
		t.Error("cold cache should miss")
	}
	// A cold cache knows no topology, so it must say NOTHING about scope. Calling a
	// LAN address "remote" because we have not loaded the subnets yet is a confident
	// lie; an absent attribute is merely an absence.
	if got := s.Scope("10.0.0.6"); got != "" {
		t.Errorf("cold Scope = %q, want \"\" (unknown, not a guess)", got)
	}
}

func TestCacheStoreLoad(t *testing.T) {
	c := NewCache()
	s := testSnapshot()
	c.Store(s)
	if c.Load() != s {
		t.Fatal("Load must return the stored snapshot")
	}
}

func TestCacheConcurrentReadsUnderSwap(t *testing.T) {
	c := NewCache()
	c.Store(testSnapshot())

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := c.Load()
				_, _ = s.RuleLabel("60533d555322b9f6a009f71c1c471480")
				_ = s.Scope("10.0.0.6")
			}
		}()
	}
	for i := 0; i < 100; i++ {
		c.Store(testSnapshot())
	}
	close(stop)
	wg.Wait()
}

func TestServiceName(t *testing.T) {
	tests := []struct {
		port, proto, want string
		ok                bool
	}{
		{"22", "tcp", "ssh", true},
		{"53", "udp", "domain", true},
		{"443", "tcp", "https", true},
		{"123", "udp", "ntp", true},
		{"51820", "udp", "wireguard", true},
		{"22", "udp", "", false},    // right port, wrong proto
		{"49152", "tcp", "", false}, // ephemeral: no service
		{"", "", "", false},
	}
	for _, tc := range tests {
		got, ok := ServiceName(tc.port, tc.proto)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ServiceName(%q,%q) = %q,%v want %q,%v", tc.port, tc.proto, got, ok, tc.want, tc.ok)
		}
	}
}

func TestServiceNameProtoIsCaseInsensitive(t *testing.T) {
	if got, ok := ServiceName("443", "TCP"); !ok || got != "https" {
		t.Errorf("ServiceName(443,TCP) = %q,%v want https,true", got, ok)
	}
}

// A cold or failed snapshot knows no topology. It must say NOTHING about scope
// rather than confidently labelling every LAN address "remote" — an absence is
// recoverable, a lie is not. (Caught by the #250 universal-enrichment tests: the
// same bug would have mislabelled filterlog records on a cold cache.)
func TestScopeSaysNothingWithoutTopology(t *testing.T) {
	cold := &Snapshot{}
	for _, ip := range []string{"10.0.0.6", "8.8.8.8", "fe80::1"} {
		if got := cold.Scope(ip); got != "" {
			t.Errorf("cold snapshot Scope(%q) = %q, want \"\" (unknown, not a guess)", ip, got)
		}
	}
	// With topology, it answers normally.
	if got := testSnapshot().Scope("8.8.8.8"); got != "remote" {
		t.Errorf("warm snapshot Scope(8.8.8.8) = %q, want remote", got)
	}
}
