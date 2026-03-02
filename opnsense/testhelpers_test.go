package opnsense

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// newTestClientWithServer creates an httptest.Server with a single handler and
// returns a Client pointed at it. The caller must call server.Close().
func newTestClientWithServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewServer(handler)

	client := &Client{
		httpClient:       server.Client(),
		baseURL:          server.URL,
		key:              "test-key",
		secret:           "test-secret",
		log:              slog.Default(),
		gatewayLossRegex: regexp.MustCompile(`\d\.\d %`),
		gatewayRTTRegex:  regexp.MustCompile(`\d+\.\d+ ms`),
		headers: map[string]string{
			"Accept":          "application/json",
			"User-Agent":      "prometheus-opnsense-exporter/test",
			"Accept-Encoding": "gzip, deflate, br",
		},
		endpoints: testEndpoints(),
	}

	return server, client
}

// newTestClientWithMux creates an httptest.Server with a ServeMux and returns
// the server, mux, and a Client. Use this for tests that need multiple endpoints.
func newTestClientWithMux(t *testing.T) (*httptest.Server, *http.ServeMux, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	client := &Client{
		httpClient:       server.Client(),
		baseURL:          server.URL,
		key:              "test-key",
		secret:           "test-secret",
		log:              slog.Default(),
		gatewayLossRegex: regexp.MustCompile(`\d\.\d %`),
		gatewayRTTRegex:  regexp.MustCompile(`\d+\.\d+ ms`),
		headers: map[string]string{
			"Accept":          "application/json",
			"User-Agent":      "prometheus-opnsense-exporter/test",
			"Accept-Encoding": "gzip, deflate, br",
		},
		endpoints: testEndpoints(),
	}

	return server, mux, client
}

// mustMarshal JSON-encodes v, failing the test on error.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return data
}

// testEndpoints returns the full endpoint map matching client.go.
func testEndpoints() map[EndpointName]EndpointPath {
	return map[EndpointName]EndpointPath{
		"services":                "api/core/service/search",
		"interfaces":              "api/diagnostics/traffic/interface",
		"protocolStatistics":      "api/diagnostics/interface/get_protocol_statistics",
		"pfStatisticsByInterface": "api/diagnostics/firewall/pf_statistics/interfaces",
		"arp":                     "api/diagnostics/interface/search_arp",
		"dhcpv4":                  "api/dhcpv4/leases/searchLease",
		"openVPNInstances":        "api/openvpn/instances/search",
		"openVPNSessions":         "api/openvpn/service/search_sessions",
		"gatewaysStatus":          "api/routing/settings/searchGateway",
		"unboundDNSStatus":        "api/unbound/diagnostics/stats",
		"cronJobs":                "api/cron/settings/searchJobs",
		"wireguardClients":        "api/wireguard/service/show",
		"ipsecPhase1":             "api/ipsec/sessions/search_phase1",
		"ipsecPhase2":             "api/ipsec/sessions/search_phase2",
		"healthCheck":             "api/core/system/status",
		"firmware":                "api/core/firmware/status",
		"dnsmasqLeases":           "api/dnsmasq/leases/search",
		"systemResources":         "api/diagnostics/system/systemResources",
		"systemTime":              "api/diagnostics/system/systemTime",
		"systemDisk":              "api/diagnostics/system/systemDisk",
		"systemSwap":              "api/diagnostics/system/systemSwap",
		"systemTemperature":       "api/diagnostics/system/systemTemperature",
		"pfStates":                "api/diagnostics/firewall/pf_states/1",
		"firewallRuleStats":       "api/firewall/filter_util/rule_stats",
		"firewallRules":           "api/firewall/filter/search_rule",
		"systemMbuf":              "api/diagnostics/system/systemMbuf",
		"ntpStatus":               "api/ntpd/service/status",
		"certificates":            "api/trust/cert/search",
		"unboundBlockList":        "api/unbound/overview/isBlockListEnabled",
		"carpStatus":              "api/diagnostics/interface/get_vip_status",
		"systemActivity":          "api/diagnostics/activity/get_activity",
		"keaLeases4":              "api/kea/leases4/search",
		"keaLeases6":              "api/kea/leases6/search",
	}
}
