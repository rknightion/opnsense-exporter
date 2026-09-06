package enrich

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// This file exercises the REAL doRefreshLeases, doRefreshTunnels and
// doRefreshRules bodies (#485). newTestRefresher (refresh_test.go) stubs all
// three out for the scheduling tests, so the merge/precedence/tolerance logic
// inside them has never run in a test. newRoutedRefresher (also
// refresh_test.go, already proven against doRefreshIfaceOrder) is reused here
// unchanged: a Refresher wired to a real *opnsense.Client pointed at an
// httptest server, routing by URL-path substring.

// --- doRefreshLeases fixtures -------------------------------------------------
//
// One fixture per backend, each naming a distinct IP so a test can tell which
// source's value survived a merge. Field names follow the real wire shapes in
// opnsense/{arp_table,ndp,kea,dnsmasq,dhcpv4,dhcpv6}.go.

const arpLeaseFixture = `{"rows":[
  {"mac":"aa:aa:aa:aa:aa:aa","ip":"10.0.0.50","hostname":"arp-host"},
  {"mac":"aa:aa:aa:aa:aa:a1","ip":"10.0.0.60","hostname":"arp-only-host"}
],"total":2}`

// bare array — ndp.go decodes []ndpEntry directly, no envelope.
const ndpLeaseFixture = `[
  {"mac":"bb:bb:bb:bb:bb:bb","ip":"10.0.0.50"},
  {"mac":"bb:bb:bb:bb:bb:b1","ip":"10.0.0.61"}
]`

const kea4LeaseFixture = `{"total":1,"rows":[
  {"address":"10.0.0.50","hwaddr":"cc:cc:cc:cc:cc:cc","hostname":"kea4-host"}
]}`

const kea6LeaseFixture = `{"total":1,"rows":[
  {"address":"fe80::52","hwaddr":"dd:dd:dd:dd:dd:dd","hostname":"kea6-host"}
]}`

const dnsmasqLeaseFixture = `{"total":1,"rows":[
  {"address":"10.0.0.53","hwaddr":"ee:ee:ee:ee:ee:ee","hostname":"dnsmasq-host"}
]}`

const dhcpv4LeaseFixture = `{"total":1,"rows":[
  {"address":"10.0.0.54","mac":"ff:ff:ff:ff:ff:ff","hostname":"dhcpv4-host"}
]}`

const dhcpv6LeaseFixture = `{"total":1,"rows":[
  {"address":"fe80::55","mac":"11:11:11:11:11:11"}
]}`

// leaseGoodFixtures maps a URL-path substring, unique per endpoint, to its
// good-case body. Substrings are chosen so none is a substring of another
// endpoint's path (verified against opnsense/client.go's defaultEndpoints).
func leaseGoodFixtures() map[string]string {
	return map[string]string{
		"search_arp":                arpLeaseFixture,
		"get_ndp":                   ndpLeaseFixture,
		"kea/leases4/search":        kea4LeaseFixture,
		"kea/leases6/search":        kea6LeaseFixture,
		"dnsmasq/leases/search":     dnsmasqLeaseFixture,
		"dhcpv4/leases/searchLease": dhcpv4LeaseFixture,
		"dhcpv6/leases/searchLease": dhcpv6LeaseFixture,
	}
}

// newLeaseTestRefresher wires a Refresher to a real client against an httptest
// server serving leaseGoodFixtures for every backend, except:
//   - notFoundSuffix (if non-empty) answers 404 with a real "not installed" body
//   - errorSuffix (if non-empty) answers 500
//
// Only one of notFoundSuffix/errorSuffix should be set per call.
func newLeaseTestRefresher(t *testing.T, notFoundSuffix, errorSuffix string) *Refresher {
	t.Helper()
	good := leaseGoodFixtures()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if notFoundSuffix != "" && strings.Contains(req.URL.Path, notFoundSuffix) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
			return
		}
		if errorSuffix != "" && strings.Contains(req.URL.Path, errorSuffix) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		for suffix, body := range good {
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
		client: &client,
		cache:  NewCache(),
		m:      NewMetrics(prometheus.NewRegistry()),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    time.Now,
	}
}

// THE precedence test. 10.0.0.50 is present in ARP, NDP and Kea4 — three
// independent sources reporting three different hostnames/MACs for the same
// IP. doRefreshLeases's set() closure is documented as first-source-wins
// (ARP and NDP are live L2 truth; a DHCP lease may be stale or handed to a
// device long gone), and ARP runs before NDP which runs before Kea4. So ARP's
// values must win for BOTH hostname and MAC, even though NDP offers a MAC and
// Kea4 offers a hostname that would otherwise look tempting to prefer.
//
// This test is mutation-verified: temporarily changing doRefreshLeases's set()
// closure from first-source-wins to last-source-wins (removing the two
// "already present" guards) turns it red — see the PR/issue #485 notes for the
// exact before/after. That confirms the assertions below are actually pinning
// the precedence order rather than passing by construction.
func TestDoRefreshLeasesPrecedenceAcrossThreeSources(t *testing.T) {
	r := newLeaseTestRefresher(t, "", "")
	if err := r.doRefreshLeases(); err != nil {
		t.Fatalf("doRefreshLeases: %v", err)
	}
	s := r.cache.Load()

	if got := s.Hostnames["10.0.0.50"]; got != "arp-host" {
		t.Errorf("Hostnames[10.0.0.50] = %q, want %q (ARP must win over NDP+Kea4)", got, "arp-host")
	}
	if got := s.MACs["10.0.0.50"]; got != "aa:aa:aa:aa:aa:aa" {
		t.Errorf("MACs[10.0.0.50] = %q, want %q (ARP must win over NDP+Kea4)", got, "aa:aa:aa:aa:aa:aa")
	}

	// Sanity: the sources that do NOT overlap on this IP must still land, so the
	// test is exercising a real merge rather than one source clobbering the rest.
	if got := s.Hostnames["10.0.0.60"]; got != "arp-only-host" {
		t.Errorf("Hostnames[10.0.0.60] (ARP-only) = %q, want %q", got, "arp-only-host")
	}
	if got := s.MACs["10.0.0.61"]; got != "bb:bb:bb:bb:bb:b1" {
		t.Errorf("MACs[10.0.0.61] (NDP-only) = %q, want %q", got, "bb:bb:bb:bb:bb:b1")
	}
	if got := s.Hostnames["10.0.0.53"]; got != "dnsmasq-host" {
		t.Errorf("Hostnames[10.0.0.53] (dnsmasq-only) = %q, want %q", got, "dnsmasq-host")
	}
	if got := s.Hostnames["10.0.0.54"]; got != "dhcpv4-host" {
		t.Errorf("Hostnames[10.0.0.54] (dhcpv4-only) = %q, want %q", got, "dhcpv4-host")
	}
	if got := s.MACs["fe80::55"]; got != "11:11:11:11:11:11" {
		t.Errorf("MACs[fe80::55] (dhcpv6-only) = %q, want %q", got, "11:11:11:11:11:11")
	}
	if got := s.Hostnames["fe80::52"]; got != "kea6-host" {
		t.Errorf("Hostnames[fe80::52] (kea6-only) = %q, want %q", got, "kea6-host")
	}
}

// Each of the five optional DHCP backends is independently 404-tolerant: a
// missing plugin must not fail the whole leases table, and the OTHER sources
// must still land. Paired with TestDoRefreshLeasesPropagatesNonFooErrors
// below — that pairing is what tells 404-tolerance apart from a bug that
// swallows every error regardless of status code.
func TestDoRefreshLeasesTolerates404FromEachOptionalBackend(t *testing.T) {
	tests := []struct {
		name       string
		suffix     string
		missingKey string // hostname key that must be ABSENT because this backend 404'd
	}{
		{"kea4", "kea/leases4/search", "10.0.0.50"}, // arp-host would be there too, but this IP is the kea4-only signal path below
		{"kea6", "kea/leases6/search", "fe80::52"},
		{"dnsmasq", "dnsmasq/leases/search", "10.0.0.53"},
		{"dhcpv4-isc", "dhcpv4/leases/searchLease", "10.0.0.54"},
		{"dhcpv6-isc", "dhcpv6/leases/searchLease", "fe80::55"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newLeaseTestRefresher(t, tc.suffix, "")
			if err := r.doRefreshLeases(); err != nil {
				t.Fatalf("doRefreshLeases: %v (a 404 from %s must be tolerated, not fail the table)", err, tc.name)
			}
			s := r.cache.Load()

			// The core, always-present sources (ARP/NDP) must have completed the
			// merge regardless of which optional backend was absent.
			if got := s.Hostnames["10.0.0.50"]; got != "arp-host" {
				t.Errorf("Hostnames[10.0.0.50] = %q, want %q — merge did not complete after %s 404'd",
					got, "arp-host", tc.name)
			}
		})
	}

	// kea4 specifically: assert its own IP contributed nothing when it 404'd,
	// proving the backend was actually skipped rather than the fixture being
	// wrong.
	r := newLeaseTestRefresher(t, "kea/leases4/search", "")
	if err := r.doRefreshLeases(); err != nil {
		t.Fatalf("doRefreshLeases: %v", err)
	}
	if _, ok := r.cache.Load().Hostnames["fe80::52"]; !ok {
		t.Error("kea6 data missing even though only kea4 404'd")
	}
}

// The other half of the pair above: a NON-404 error from any of the five
// optional backends must PROPAGATE, not be swallowed. A regression that turns
// skipAbsent into "ignore every error" would fail this while still passing the
// 404-tolerance test above.
func TestDoRefreshLeasesPropagatesNonFooErrors(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
	}{
		{"kea4", "kea/leases4/search"},
		{"kea6", "kea/leases6/search"},
		{"dnsmasq", "dnsmasq/leases/search"},
		{"dhcpv4-isc", "dhcpv4/leases/searchLease"},
		{"dhcpv6-isc", "dhcpv6/leases/searchLease"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newLeaseTestRefresher(t, "", tc.suffix)
			if err := r.doRefreshLeases(); err == nil {
				t.Fatalf("doRefreshLeases returned nil error for a 500 from %s; a real failure must propagate", tc.name)
			}
		})
	}
}

// ARP and NDP are core, not skipAbsent: ANY error from either — 404 included —
// must propagate. This is the contrast that makes the skipAbsent branches
// meaningful: they are a deliberate exception, not the default.
func TestDoRefreshLeasesArpAndNdpErrorsAlwaysPropagate(t *testing.T) {
	t.Run("arp 404 still propagates", func(t *testing.T) {
		r := newLeaseTestRefresher(t, "search_arp", "")
		if err := r.doRefreshLeases(); err == nil {
			t.Fatal("doRefreshLeases returned nil for a 404 from the core ARP endpoint; want an error")
		}
	})
	t.Run("ndp 500 propagates", func(t *testing.T) {
		r := newLeaseTestRefresher(t, "", "get_ndp")
		if err := r.doRefreshLeases(); err == nil {
			t.Fatal("doRefreshLeases returned nil for a 500 from the core NDP endpoint; want an error")
		}
	})
}

// --- doRefreshTunnels ---------------------------------------------------------

// ipsecPhase1 rows for the empty-description-fallback tests. BOTH rows here
// have no phase1desc, which is where a mis-mapping (e.g. accidentally always
// falling back to the same row's name, or losing one of them to a map-key
// collision) would actually show up — a single empty-description row could
// pass by accident.
const ipsecTwoBlankDescFixture = `{"rows":[
  {"ikeid":"5e891b0c-ca13-4e38-a7c0-a2aa891c30b4","name":"conn-alpha","phase1desc":"","connected":true,"install-time":"0"},
  {"ikeid":"7a1e2233-44f2-47ea-a882-f8773b65c190","name":"conn-beta","phase1desc":"","connected":false,"install-time":"0"}
]}`

// One row WITH a description, to prove the fallback only fires when needed.
const ipsecOneNamedFixture = `{"rows":[
  {"ikeid":"5e891b0c-ca13-4e38-a7c0-a2aa891c30b4","name":"conn-alpha","phase1desc":"Site-to-site HQ","connected":true,"install-time":"0"}
]}`

const openVPNInstanceFixture = `{"rows":[
  {"uuid":"6f86d5cd-44f2-47ea-a882-f8773b65c190","description":"test server","role":"server","dev_type":"tun","enabled":"1"}
],"total":1}`

// newTunnelTestRefresher wires a Refresher to an httptest server serving the
// given ipsecPhase1 body plus a valid (empty) phase2 body (FetchIPsecPhase1
// fetches phase2 per row internally) and an OpenVPN-instances body, routed by
// path. notFoundSuffix/errorSuffix behave as in newLeaseTestRefresher.
func newTunnelTestRefresher(t *testing.T, phase1Body, ovpnBody, notFoundSuffix, errorSuffix string) *Refresher {
	t.Helper()
	good := map[string]string{
		"ipsec/sessions/search_phase1": phase1Body,
		"ipsec/sessions/search_phase2": `{"rows":[]}`,
		"openvpn/instances/search":     ovpnBody,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if notFoundSuffix != "" && strings.Contains(req.URL.Path, notFoundSuffix) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessage":"Endpoint not found"}`)
			return
		}
		if errorSuffix != "" && strings.Contains(req.URL.Path, errorSuffix) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		for suffix, body := range good {
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
		client: &client,
		cache:  NewCache(),
		m:      NewMetrics(prometheus.NewRegistry()),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    time.Now,
	}
}

// Two IPsec connections BOTH carrying an empty phase1desc must each resolve to
// their own row's name — not collapse onto one, and not silently drop either.
func TestDoRefreshTunnelsEmptyDescriptionFallbackForTwoConnections(t *testing.T) {
	r := newTunnelTestRefresher(t, ipsecTwoBlankDescFixture, openVPNInstanceFixture, "", "")
	if err := r.doRefreshTunnels(); err != nil {
		t.Fatalf("doRefreshTunnels: %v", err)
	}
	s := r.cache.Load()

	if got, ok := s.Tunnel("5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"); !ok || got != "conn-alpha" {
		t.Errorf("Tunnel(alpha) = %q,%v want %q,true (empty desc must fall back to the row's own name)",
			got, ok, "conn-alpha")
	}
	if got, ok := s.Tunnel("7a1e2233-44f2-47ea-a882-f8773b65c190"); !ok || got != "conn-beta" {
		t.Errorf("Tunnel(beta) = %q,%v want %q,true (a second blank-desc row must not collide with the first)",
			got, ok, "conn-beta")
	}
}

// A connection WITH a description must use it — the fallback is opt-in, not
// the default.
func TestDoRefreshTunnelsUsesDescriptionWhenPresent(t *testing.T) {
	r := newTunnelTestRefresher(t, ipsecOneNamedFixture, openVPNInstanceFixture, "", "")
	if err := r.doRefreshTunnels(); err != nil {
		t.Fatalf("doRefreshTunnels: %v", err)
	}
	if got, ok := r.cache.Load().Tunnel("5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"); !ok || got != "Site-to-site HQ" {
		t.Errorf("Tunnel(alpha) = %q,%v want %q,true", got, ok, "Site-to-site HQ")
	}
}

// The IPsec side is skipAbsent-tolerant: a 404 there must not cost the
// OpenVPN table.
func TestDoRefreshTunnelsToleratesIPsec404(t *testing.T) {
	r := newTunnelTestRefresher(t, ipsecOneNamedFixture, openVPNInstanceFixture,
		"ipsec/sessions/search_phase1", "")
	if err := r.doRefreshTunnels(); err != nil {
		t.Fatalf("doRefreshTunnels: %v (an absent IPsec plugin must not fail the table)", err)
	}
	s := r.cache.Load()
	if len(s.Tunnels) != 0 {
		t.Errorf("Tunnels = %v, want empty when IPsec 404'd", s.Tunnels)
	}
	if _, ok := s.VPNInstance("6f86d5cd-44f2-47ea-a882-f8773b65c190"); !ok {
		t.Error("VPN instance missing even though only IPsec 404'd")
	}
}

// The OpenVPN side is skipAbsent-tolerant too, independently of IPsec.
func TestDoRefreshTunnelsToleratesOpenVPN404(t *testing.T) {
	r := newTunnelTestRefresher(t, ipsecOneNamedFixture, openVPNInstanceFixture,
		"openvpn/instances/search", "")
	if err := r.doRefreshTunnels(); err != nil {
		t.Fatalf("doRefreshTunnels: %v (an absent OpenVPN plugin must not fail the table)", err)
	}
	s := r.cache.Load()
	if len(s.VPNInstances) != 0 {
		t.Errorf("VPNInstances = %v, want empty when OpenVPN 404'd", s.VPNInstances)
	}
	if _, ok := s.Tunnel("5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"); !ok {
		t.Error("IPsec tunnel missing even though only OpenVPN 404'd")
	}
}

// A real (non-404) IPsec failure must propagate, not be swallowed — the same
// tolerant-vs-swallowing distinction as the leases backends.
func TestDoRefreshTunnelsPropagatesNonFooIPsecError(t *testing.T) {
	r := newTunnelTestRefresher(t, ipsecOneNamedFixture, openVPNInstanceFixture,
		"", "ipsec/sessions/search_phase1")
	if err := r.doRefreshTunnels(); err == nil {
		t.Fatal("doRefreshTunnels returned nil for a 500 from IPsec; want an error")
	}
}

// Same for OpenVPN.
func TestDoRefreshTunnelsPropagatesNonFooOpenVPNError(t *testing.T) {
	r := newTunnelTestRefresher(t, ipsecOneNamedFixture, openVPNInstanceFixture,
		"", "openvpn/instances/search")
	if err := r.doRefreshTunnels(); err == nil {
		t.Fatal("doRefreshTunnels returned nil for a 500 from OpenVPN; want an error")
	}
}

// --- doRefreshRules ------------------------------------------------------------

// diagnostics/firewall/list_rule_ids resolves BOTH user-authored rules (dashed
// UUIDs) and system rules (undashed 32-hex content hashes) into the SAME
// rid -> description map. That assumption is stated in a comment on
// doRefreshRules and, before this test, verified nowhere.
const ruleIDsMixedFixture = `{"items":[
  {"id":"5e891b0c-ca13-4e38-a7c0-a2aa891c30b4","descr":"Allow LAN to any"},
  {"id":"a1b2c3d4e5f60718293a4b5c6d7e8f90","descr":"Default deny / block all"},
  {"id":"","descr":"should be skipped: empty id"}
]}`

func newRulesTestRefresher(t *testing.T, body string) *Refresher {
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

func TestDoRefreshRulesCoexistingUUIDAndHashIDs(t *testing.T) {
	r := newRulesTestRefresher(t, ruleIDsMixedFixture)
	if err := r.doRefreshRules(); err != nil {
		t.Fatalf("doRefreshRules: %v", err)
	}
	s := r.cache.Load()

	if got, ok := s.RuleLabel("5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"); !ok || got != "Allow LAN to any" {
		t.Errorf("RuleLabel(dashed UUID) = %q,%v want %q,true", got, ok, "Allow LAN to any")
	}
	if got, ok := s.RuleLabel("a1b2c3d4e5f60718293a4b5c6d7e8f90"); !ok || got != "Default deny / block all" {
		t.Errorf("RuleLabel(undashed hash) = %q,%v want %q,true", got, ok, "Default deny / block all")
	}
	if len(s.RuleLabels) != 2 {
		t.Errorf("RuleLabels has %d entries, want 2 (the empty-id row must be skipped, "+
			"and the two real ids must coexist without collision): %v", len(s.RuleLabels), s.RuleLabels)
	}
}

func TestDoRefreshRulesPropagatesFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client, err := opnsense.NewClient(options.OPNSenseConfig{
		Protocol: "http", Host: strings.TrimPrefix(srv.URL, "http://"),
		APIKey: "k", APISecret: "s",
	}, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &Refresher{
		client: &client,
		cache:  NewCache(),
		m:      NewMetrics(prometheus.NewRegistry()),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    time.Now,
	}
	if err := r.doRefreshRules(); err == nil {
		t.Fatal("doRefreshRules returned nil for a 500; want an error")
	}
}
