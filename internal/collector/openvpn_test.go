package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func openVPNTestServer(t *testing.T, sessionsJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/openvpn/instances/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Site-to-Site VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1"
				},
				{
					"uuid": "vpn-uuid-2",
					"description": "Road Warrior",
					"role": "Client",
					"dev_type": "tun",
					"enabled": "0"
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})

	mux.HandleFunc("/api/openvpn/service/search_sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sessionsJSON))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

const openVPNTestSessions = `{
	"rows": [
		{
			"description": "Site-to-Site VPN",
			"username": "user1",
			"common_name": null,
			"real_address": "203.0.113.10:51820",
			"virtual_address": "10.0.0.2",
			"status": "ok",
			"is_client": true,
			"bytes_received": "1000",
			"bytes_sent": "2000",
			"connected_since__time_t_": "1700000000"
		},
		{
			"description": "Site-to-Site VPN",
			"username": "UNDEF",
			"common_name": "cert-user2",
			"real_address": "203.0.113.11:51820",
			"virtual_address": "10.0.0.3",
			"virtual_ipv6_address": "fd00:0:0::3",
			"status": "ok",
			"is_client": true,
			"bytes_received": "3000",
			"bytes_sent": "4000",
			"connected_since__time_t_": "1700000100"
		},
		{
			"description": "Road Warrior",
			"username": "user3",
			"common_name": null,
			"real_address": "198.51.100.7:1194",
			"virtual_address": "10.0.1.2",
			"status": "ok",
			"is_client": true,
			"bytes_received": "500",
			"bytes_sent": "600",
			"connected_since__time_t_": "1700000200"
		}
	],
	"rowCount": 3,
	"total": 3,
	"current": 1
}`

// metricsByDesc groups collected metrics by exact fqName.
func metricsByDesc(metrics []prometheus.Metric, fqName string) []prometheus.Metric {
	var out []prometheus.Metric
	needle := `fqName: "` + fqName + `"`
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), needle) {
			out = append(out, m)
		}
	}
	return out
}

func TestOpenVPNCollector_Update_DefaultNoSessionDetails(t *testing.T) {
	server := openVPNTestServer(t, openVPNTestSessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Per-session series must NOT be emitted by default.
	if got := metricsByDesc(metrics, "opnsense_openvpn_sessions"); len(got) != 0 {
		t.Errorf("expected no per-session metrics by default, got %d", len(got))
	}

	totals := metricsByDesc(metrics, "opnsense_openvpn_current_sessions")
	if len(totals) != 1 {
		t.Fatalf("expected 1 current_sessions metric, got %d", len(totals))
	}
	if v := getMetricValue(totals[0]); v != 3 {
		t.Errorf("expected current_sessions = 3, got %v", v)
	}

	byInstance := metricsByDesc(metrics, "opnsense_openvpn_sessions_by_instance")
	if len(byInstance) != 2 {
		t.Fatalf("expected 2 sessions_by_instance metrics, got %d", len(byInstance))
	}
	counts := map[string]float64{}
	for _, m := range byInstance {
		counts[getMetricLabels(m)["description"]] = getMetricValue(m)
	}
	if counts["Site-to-Site VPN"] != 2 {
		t.Errorf("expected 2 sessions for Site-to-Site VPN, got %v", counts["Site-to-Site VPN"])
	}
	if counts["Road Warrior"] != 1 {
		t.Errorf("expected 1 session for Road Warrior, got %v", counts["Road Warrior"])
	}

	// Instance-level traffic aggregates are default-on (no per-session identity
	// label), summed over that instance's sessions.
	instanceRx := metricsByDesc(metrics, "opnsense_openvpn_instance_received_bytes_total")
	if len(instanceRx) != 2 {
		t.Fatalf("expected 2 instance_received_bytes_total metrics, got %d", len(instanceRx))
	}
	rxByInstance := map[string]float64{}
	for _, m := range instanceRx {
		rxByInstance[getMetricLabels(m)["description"]] = getMetricValue(m)
	}
	if rxByInstance["Site-to-Site VPN"] != 4000 {
		t.Errorf("expected instance_received_bytes_total=4000 for Site-to-Site VPN (1000+3000), got %v", rxByInstance["Site-to-Site VPN"])
	}
	if rxByInstance["Road Warrior"] != 500 {
		t.Errorf("expected instance_received_bytes_total=500 for Road Warrior, got %v", rxByInstance["Road Warrior"])
	}

	instanceTx := metricsByDesc(metrics, "opnsense_openvpn_instance_transmitted_bytes_total")
	if len(instanceTx) != 2 {
		t.Fatalf("expected 2 instance_transmitted_bytes_total metrics, got %d", len(instanceTx))
	}
	txByInstance := map[string]float64{}
	for _, m := range instanceTx {
		txByInstance[getMetricLabels(m)["description"]] = getMetricValue(m)
	}
	if txByInstance["Site-to-Site VPN"] != 6000 {
		t.Errorf("expected instance_transmitted_bytes_total=6000 for Site-to-Site VPN (2000+4000), got %v", txByInstance["Site-to-Site VPN"])
	}
	if txByInstance["Road Warrior"] != 600 {
		t.Errorf("expected instance_transmitted_bytes_total=600 for Road Warrior, got %v", txByInstance["Road Warrior"])
	}

	// Per-session traffic/connected-since series must NOT be emitted by default.
	if got := metricsByDesc(metrics, "opnsense_openvpn_session_received_bytes_total"); len(got) != 0 {
		t.Errorf("expected no per-session received-bytes metrics by default, got %d", len(got))
	}
	if got := metricsByDesc(metrics, "opnsense_openvpn_session_transmitted_bytes_total"); len(got) != 0 {
		t.Errorf("expected no per-session transmitted-bytes metrics by default, got %d", len(got))
	}
	if got := metricsByDesc(metrics, "opnsense_openvpn_session_connected_since_timestamp_seconds"); len(got) != 0 {
		t.Errorf("expected no per-session connected-since metrics by default, got %d", len(got))
	}

	// 2 instances + 1 current_sessions + 2 sessions_by_instance
	// + 2 instance_received_bytes_total + 2 instance_transmitted_bytes_total = 9
	if expectedCount := 9; len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestOpenVPNCollector_Update_DetailsEnabled(t *testing.T) {
	server := openVPNTestServer(t, openVPNTestSessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	sessions := metricsByDesc(metrics, "opnsense_openvpn_sessions")
	if len(sessions) != 3 {
		t.Fatalf("expected 3 per-session metrics with details enabled, got %d", len(sessions))
	}
	found := false
	foundV6 := false
	for _, m := range sessions {
		labels := getMetricLabels(m)
		if labels["username"] == "user1" &&
			labels["virtual_address"] == "10.0.0.2" &&
			labels["real_address"] == "203.0.113.10:51820" {
			found = true
			// v4-only session: the new label must be present but empty, not
			// simply absent (it is a declared label on the metric).
			if v6, ok := labels["virtual_ipv6_address"]; !ok || v6 != "" {
				t.Errorf("expected virtual_ipv6_address='' for v4-only session user1, got %q (present=%v)", v6, ok)
			}
		}
		// The "sessions" gauge labels by the raw OpenVPN username field
		// (not Identity()/common_name, unlike the other three per-session
		// metrics below) — the dual-stack fixture row has username "UNDEF".
		if labels["username"] == "UNDEF" &&
			labels["virtual_address"] == "10.0.0.3" &&
			labels["virtual_ipv6_address"] == "fd00:0:0::3" {
			foundV6 = true
		}
	}
	if !found {
		t.Error("expected a per-session metric with username=user1, virtual_address=10.0.0.2 and real_address=203.0.113.10:51820")
	}
	if !foundV6 {
		t.Error("expected a per-session metric with username=UNDEF, virtual_address=10.0.0.3 and virtual_ipv6_address=fd00:0:0::3 (dual-stack session)")
	}

	// Aggregates still emitted alongside details.
	if got := metricsByDesc(metrics, "opnsense_openvpn_current_sessions"); len(got) != 1 {
		t.Errorf("expected 1 current_sessions metric, got %d", len(got))
	}

	// Per-session traffic counters + connected-since gauge, one series per
	// session, using the SAME label surface as the existing per-session
	// "sessions" gauge (description, real_address, virtual_address, username)
	// — the "username" label value prefers common_name (cert identity) when
	// present, else falls back to the OpenVPN username field (#212).
	rxSessions := metricsByDesc(metrics, "opnsense_openvpn_session_received_bytes_total")
	if len(rxSessions) != 3 {
		t.Fatalf("expected 3 per-session received-bytes metrics, got %d", len(rxSessions))
	}
	rxByUser := map[string]float64{}
	rxV6ByUser := map[string]string{}
	for _, m := range rxSessions {
		labels := getMetricLabels(m)
		rxByUser[labels["username"]] = getMetricValue(m)
		rxV6ByUser[labels["username"]] = labels["virtual_ipv6_address"]
	}
	if rxByUser["user1"] != 1000 {
		t.Errorf("expected session_received_bytes_total=1000 for user1 (no common_name), got %v", rxByUser["user1"])
	}
	if rxByUser["cert-user2"] != 3000 {
		t.Errorf("expected session_received_bytes_total=3000 labeled 'cert-user2' (common_name preferred over UNDEF username), got %v", rxByUser["cert-user2"])
	}
	if rxByUser["user3"] != 500 {
		t.Errorf("expected session_received_bytes_total=500 for user3, got %v", rxByUser["user3"])
	}
	// The raw "UNDEF" username must never leak through when a common_name exists.
	if _, ok := rxByUser["UNDEF"]; ok {
		t.Error("expected no series labeled 'UNDEF' when common_name is present")
	}
	// Label-value assertions (not just series count) prove the new label
	// landed in the right variadic position at this call site: a shifted
	// argument would put the username or byte count into
	// virtual_ipv6_address, or vice versa.
	if rxV6ByUser["user1"] != "" {
		t.Errorf("expected virtual_ipv6_address='' for v4-only session user1, got %q", rxV6ByUser["user1"])
	}
	if rxV6ByUser["cert-user2"] != "fd00:0:0::3" {
		t.Errorf("expected virtual_ipv6_address='fd00:0:0::3' for dual-stack session cert-user2, got %q", rxV6ByUser["cert-user2"])
	}

	txSessions := metricsByDesc(metrics, "opnsense_openvpn_session_transmitted_bytes_total")
	if len(txSessions) != 3 {
		t.Fatalf("expected 3 per-session transmitted-bytes metrics, got %d", len(txSessions))
	}
	txByUser := map[string]float64{}
	txV6ByUser := map[string]string{}
	for _, m := range txSessions {
		labels := getMetricLabels(m)
		txByUser[labels["username"]] = getMetricValue(m)
		txV6ByUser[labels["username"]] = labels["virtual_ipv6_address"]
	}
	if txByUser["user1"] != 2000 {
		t.Errorf("expected session_transmitted_bytes_total=2000 for user1, got %v", txByUser["user1"])
	}
	if txByUser["cert-user2"] != 4000 {
		t.Errorf("expected session_transmitted_bytes_total=4000 for cert-user2, got %v", txByUser["cert-user2"])
	}
	if txByUser["user3"] != 600 {
		t.Errorf("expected session_transmitted_bytes_total=600 for user3, got %v", txByUser["user3"])
	}
	if txV6ByUser["cert-user2"] != "fd00:0:0::3" {
		t.Errorf("expected virtual_ipv6_address='fd00:0:0::3' for dual-stack session cert-user2 on tx series, got %q", txV6ByUser["cert-user2"])
	}

	connSince := metricsByDesc(metrics, "opnsense_openvpn_session_connected_since_timestamp_seconds")
	if len(connSince) != 3 {
		t.Fatalf("expected 3 per-session connected-since metrics, got %d", len(connSince))
	}
	csByUser := map[string]float64{}
	csV6ByUser := map[string]string{}
	for _, m := range connSince {
		labels := getMetricLabels(m)
		csByUser[labels["username"]] = getMetricValue(m)
		csV6ByUser[labels["username"]] = labels["virtual_ipv6_address"]
	}
	if csByUser["user1"] != 1700000000 {
		t.Errorf("expected connected_since=1700000000 for user1, got %v", csByUser["user1"])
	}
	if csByUser["cert-user2"] != 1700000100 {
		t.Errorf("expected connected_since=1700000100 for cert-user2, got %v", csByUser["cert-user2"])
	}
	if csV6ByUser["cert-user2"] != "fd00:0:0::3" {
		t.Errorf("expected virtual_ipv6_address='fd00:0:0::3' for dual-stack session cert-user2 on connected-since series, got %q", csV6ByUser["cert-user2"])
	}

	// 2 instances + 1 current_sessions + 2 sessions_by_instance + 3 sessions
	// + 2 instance_received_bytes_total + 2 instance_transmitted_bytes_total
	// + 3 session_received_bytes_total + 3 session_transmitted_bytes_total
	// + 3 session_connected_since_timestamp_seconds = 21
	if expectedCount := 21; len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestOpenVPNCollector_Update_VirtualIPv6AddressSessionShapes guards #483's
// three real-world session shapes on the gated per-session "sessions" series:
// v4-only (new label empty), dual-stack (both populated), and v6-only
// (virtual_address empty, virtual_ipv6_address populated) — the shape most
// likely to be mis-handled since it is easy to assume virtual_address is
// always non-empty.
func TestOpenVPNCollector_Update_VirtualIPv6AddressSessionShapes(t *testing.T) {
	sessions := `{
		"rows": [
			{"description":"Road Warrior","username":"v4only","real_address":"203.0.113.10:1194","virtual_address":"10.0.0.2","status":"ok","is_client":true},
			{"description":"Road Warrior","username":"dualstack","real_address":"203.0.113.11:1194","virtual_address":"10.0.0.3","virtual_ipv6_address":"fd00:0:0::3","status":"ok","is_client":true},
			{"description":"Road Warrior","username":"v6only","real_address":"203.0.113.12:1194","virtual_ipv6_address":"fd00:0:0::4","status":"ok","is_client":true}
		],
		"rowCount": 3, "total": 3, "current": 1
	}`
	server := openVPNTestServer(t, sessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	detail := metricsByDesc(metrics, "opnsense_openvpn_sessions")
	if len(detail) != 3 {
		t.Fatalf("expected 3 per-session metrics, got %d", len(detail))
	}

	byUser := map[string]map[string]string{}
	for _, m := range detail {
		labels := getMetricLabels(m)
		byUser[labels["username"]] = labels
	}

	v4only, ok := byUser["v4only"]
	if !ok {
		t.Fatal("expected a session labeled username=v4only")
	}
	if v4only["virtual_address"] != "10.0.0.2" {
		t.Errorf("expected virtual_address='10.0.0.2' for v4only, got %q", v4only["virtual_address"])
	}
	if v4only["virtual_ipv6_address"] != "" {
		t.Errorf("expected virtual_ipv6_address='' for v4only, got %q", v4only["virtual_ipv6_address"])
	}

	dual, ok := byUser["dualstack"]
	if !ok {
		t.Fatal("expected a session labeled username=dualstack")
	}
	if dual["virtual_address"] != "10.0.0.3" {
		t.Errorf("expected virtual_address='10.0.0.3' for dualstack, got %q", dual["virtual_address"])
	}
	if dual["virtual_ipv6_address"] != "fd00:0:0::3" {
		t.Errorf("expected virtual_ipv6_address='fd00:0:0::3' for dualstack, got %q", dual["virtual_ipv6_address"])
	}

	v6only, ok := byUser["v6only"]
	if !ok {
		t.Fatal("expected a session labeled username=v6only")
	}
	if v6only["virtual_address"] != "" {
		t.Errorf("expected virtual_address='' for v6only, got %q", v6only["virtual_address"])
	}
	if v6only["virtual_ipv6_address"] != "fd00:0:0::4" {
		t.Errorf("expected virtual_ipv6_address='fd00:0:0::4' for v6only, got %q", v6only["virtual_ipv6_address"])
	}
}

// TestOpenVPNCollector_Update_VirtualIPv6AddressDuplicateSeries guards the
// duplicate-series hazard directly: adding a label changes series identity
// for a Prometheus const-metric collector, and MustNewConstMetric panics
// (failing the whole scrape) if two sessions collapse onto the same label
// set. Two sessions here differ ONLY in virtual_ipv6_address, and two more
// differ ONLY in virtual_address — both pairs must resolve to distinct
// series with no panic.
func TestOpenVPNCollector_Update_VirtualIPv6AddressDuplicateSeries(t *testing.T) {
	sessions := `{
		"rows": [
			{"description":"Road Warrior","username":"sameuser","real_address":"203.0.113.10:1194","virtual_address":"10.0.0.2","virtual_ipv6_address":"fd00:0:0::a","status":"ok","is_client":true},
			{"description":"Road Warrior","username":"sameuser","real_address":"203.0.113.10:1194","virtual_address":"10.0.0.2","virtual_ipv6_address":"fd00:0:0::b","status":"ok","is_client":true},
			{"description":"Road Warrior","username":"otheruser","real_address":"203.0.113.11:1194","virtual_address":"10.0.0.5","virtual_ipv6_address":"fd00:0:0::c","status":"ok","is_client":true},
			{"description":"Road Warrior","username":"otheruser","real_address":"203.0.113.11:1194","virtual_address":"10.0.0.6","virtual_ipv6_address":"fd00:0:0::c","status":"ok","is_client":true}
		],
		"rowCount": 4, "total": 4, "current": 1
	}`
	server := openVPNTestServer(t, sessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	// MustNewConstMetric panics on any programming error such as a duplicate
	// label set within one Collect() batch; a panic here fails the test.
	metrics := collectMetrics(t, c, client)

	detail := metricsByDesc(metrics, "opnsense_openvpn_sessions")
	if len(detail) != 4 {
		t.Fatalf("expected 4 distinct per-session metrics (differing only by v4 or v6 address), got %d", len(detail))
	}

	seen := map[string]bool{}
	for _, m := range detail {
		labels := getMetricLabels(m)
		key := labels["username"] + "|" + labels["virtual_address"] + "|" + labels["virtual_ipv6_address"]
		if seen[key] {
			t.Errorf("duplicate series for label set %q", key)
		}
		seen[key] = true
	}
	if len(seen) != 4 {
		t.Errorf("expected 4 unique label combinations, got %d", len(seen))
	}
}

func TestOpenVPNCollector_Update_NoSessions(t *testing.T) {
	server := openVPNTestServer(t, `{
		"rows": [],
		"rowCount": 0,
		"total": 0,
		"current": 1
	}`)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// current_sessions must be emitted even when there are zero sessions.
	totals := metricsByDesc(metrics, "opnsense_openvpn_current_sessions")
	if len(totals) != 1 {
		t.Fatalf("expected 1 current_sessions metric, got %d", len(totals))
	}
	if v := getMetricValue(totals[0]); v != 0 {
		t.Errorf("expected current_sessions = 0, got %v", v)
	}

	// 2 instances + 1 current_sessions = 3
	if expectedCount := 3; len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestOpenVPNCollector_Update_ExcludesNonClientRows guards #88: idle running-
// instance rows and enabled-but-stopped stub rows must not inflate current_sessions,
// sessions_by_instance, or the per-session detail metric.
func TestOpenVPNCollector_Update_ExcludesNonClientRows(t *testing.T) {
	sessions := `{
		"rows": [
			{"description":"Site-to-Site VPN","username":"user1","real_address":"203.0.113.10:1194","virtual_address":"10.0.0.2","status":"ok","is_client":true},
			{"description":"Idle Server","username":"","real_address":"","virtual_address":"","status":"connected"},
			{"description":"Stopped Server","username":"","real_address":"","virtual_address":"","status":"failed"}
		],
		"rowCount": 3, "total": 3, "current": 1
	}`
	server := openVPNTestServer(t, sessions)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetDetailsEnabled(true)

	metrics := collectMetrics(t, c, client)

	totals := metricsByDesc(metrics, "opnsense_openvpn_current_sessions")
	if len(totals) != 1 {
		t.Fatalf("expected 1 current_sessions metric, got %d", len(totals))
	}
	if v := getMetricValue(totals[0]); v != 1 {
		t.Errorf("expected current_sessions = 1 (only the client row), got %v", v)
	}

	byInstance := metricsByDesc(metrics, "opnsense_openvpn_sessions_by_instance")
	if len(byInstance) != 1 {
		t.Errorf("expected 1 sessions_by_instance series (idle/stopped excluded), got %d", len(byInstance))
	}
	for _, m := range byInstance {
		if d := getMetricLabels(m)["description"]; d != "Site-to-Site VPN" {
			t.Errorf("unexpected sessions_by_instance for %q; non-client rows should be excluded", d)
		}
	}

	detail := metricsByDesc(metrics, "opnsense_openvpn_sessions")
	if len(detail) != 1 {
		t.Errorf("expected 1 per-session detail metric (only the client row), got %d", len(detail))
	}

	// Instance aggregates and per-session traffic series must also exclude the
	// idle/stopped non-client rows (#88 applies equally to #212's new metrics).
	instanceRx := metricsByDesc(metrics, "opnsense_openvpn_instance_received_bytes_total")
	if len(instanceRx) != 1 {
		t.Errorf("expected 1 instance_received_bytes_total series (idle/stopped excluded), got %d", len(instanceRx))
	}
	sessionRx := metricsByDesc(metrics, "opnsense_openvpn_session_received_bytes_total")
	if len(sessionRx) != 1 {
		t.Errorf("expected 1 session_received_bytes_total series (idle/stopped excluded), got %d", len(sessionRx))
	}
	// The fixture omits bytes_received/bytes_sent for the surviving client row;
	// absent fields must decode to 0, not fail the scrape.
	if len(sessionRx) == 1 && getMetricValue(sessionRx[0]) != 0 {
		t.Errorf("expected session_received_bytes_total=0 when bytes_received is absent, got %v", getMetricValue(sessionRx[0]))
	}
}

func TestOpenVPNCollector_Name(t *testing.T) {
	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	if c.Name() != OpenVPNSubsystem {
		t.Errorf("expected %s, got %s", OpenVPNSubsystem, c.Name())
	}
}

// TestOpenVPNCollector_MaxClients guards #584: the configured concurrent-
// client cap must be exported as a default-on (no details flag) gauge, one
// series per instance that actually has a cap configured -- a server with no
// configured cap ("maxclients" empty/absent) must emit NO series, never a
// fabricated 0 that would read as "server accepts no clients".
func TestOpenVPNCollector_MaxClients(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/openvpn/instances/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"rows": [
				{
					"uuid": "vpn-uuid-1",
					"description": "Capped VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1",
					"maxclients": "25"
				},
				{
					"uuid": "vpn-uuid-2",
					"description": "Unlimited VPN",
					"role": "Server",
					"dev_type": "tun",
					"enabled": "1",
					"maxclients": ""
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})
	mux.HandleFunc("/api/openvpn/service/search_sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows": [], "rowCount": 0, "total": 0, "current": 1}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := newCollectorTestClient(t, server)

	c := &openVPNCollector{subsystem: OpenVPNSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	maxClients := metricsByDesc(metrics, "opnsense_openvpn_instance_max_clients")
	if len(maxClients) != 1 {
		t.Fatalf("expected exactly 1 instance_max_clients series (unlimited instance excluded), got %d", len(maxClients))
	}
	labels := getMetricLabels(maxClients[0])
	if labels["description"] != "Capped VPN" {
		t.Errorf("expected description='Capped VPN', got %q", labels["description"])
	}
	if v := getMetricValue(maxClients[0]); v != 25 {
		t.Errorf("expected instance_max_clients=25, got %v", v)
	}
}
