package syslog

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// haproxySnapshot mirrors the live box the fixtures came from: the load
// generator at 172.16.9.99 sits on a LAN we own, the firewall's own address on
// that segment is 172.16.9.1.
func haproxySnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		Hostnames: map[string]string{
			"172.16.9.99": "exporter-traffgen",
		},
		MACs: map[string]string{
			"172.16.9.99": "bc:24:11:eb:db:3d",
		},
		LocalNets: []netip.Prefix{netip.MustParsePrefix("172.16.9.0/24")},
		SelfIPs:   map[netip.Addr]bool{netip.MustParseAddr("172.16.9.1"): true},
	}
}

func haproxyEnvelope(msg string, sev int) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "haproxy",
		PID:       "4242",
		Facility:  16,
		Severity:  sev,
		Message:   msg,
	}
}

// parseHAProxyLine runs the parser the way BuildRecord does, with a miss
// recorder so a test can assert that address lookups never signal a cache miss.
func parseHAProxyLine(t *testing.T, msg string, sev int) (logship.Record, bool, *missRecorder) {
	t.Helper()
	m := &missRecorder{}
	rec, ok := parseHAProxy(haproxyEnvelope(msg, sev), haproxySnapshot(), m.miss)
	return rec, ok, m
}

func wantAttr(t *testing.T, rec logship.Record, key, want string) {
	t.Helper()
	if got := rec.Attributes[key]; got != want {
		t.Errorf("attribute %q = %q, want %q", key, got, want)
	}
}

func wantNoAttr(t *testing.T, rec logship.Record, key string) {
	t.Helper()
	if got, ok := rec.Attributes[key]; ok {
		t.Errorf("attribute %q present with %q, want absent", key, got)
	}
}

// TestParseHAProxy_ServerUpWithCode is the health transition that matters: a
// backend server coming back, with the Layer7 check code.
func TestParseHAProxy_ServerUpWithCode(t *testing.T) {
	const line = `Server bk-heavy/heavy-1 is UP, reason: Layer7 check passed, code: 200, check duration: 3ms. 2 active and 0 backup servers online. 0 sessions requeued, 0 total in queue.`

	rec, ok, m := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for a Server UP line")
	}
	wantAttr(t, rec, "haproxy.event", "server_state")
	wantAttr(t, rec, "haproxy.backend", "bk-heavy")
	wantAttr(t, rec, "haproxy.server", "heavy-1")
	wantAttr(t, rec, "haproxy.state", "up")
	wantAttr(t, rec, "haproxy.reason", "Layer7 check passed")
	wantAttr(t, rec, "haproxy.check_code", "200")
	wantAttr(t, rec, "haproxy.check_duration_ms", "3")
	wantNoAttr(t, rec, "haproxy.info")

	if rec.Severity != logship.SeverityInfo {
		t.Errorf("severity = %v, want Info for an UP transition", rec.Severity)
	}
	if rec.Body != line {
		t.Errorf("body = %q, want the raw message", rec.Body)
	}
	if len(m.calls) != 0 {
		t.Errorf("miss() called %v, want no misses", m.calls)
	}
}

// TestParseHAProxy_ServerDownLayer4NoCode covers the DOWN shape that carries NO
// code: an L4 timeout never gets far enough to have an HTTP status.
func TestParseHAProxy_ServerDownLayer4NoCode(t *testing.T) {
	const line = `Server bk-heavy/heavy-2 is DOWN, reason: Layer4 timeout, check duration: 2001ms. 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.`

	rec, ok, _ := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for a Server DOWN line")
	}
	wantAttr(t, rec, "haproxy.backend", "bk-heavy")
	wantAttr(t, rec, "haproxy.server", "heavy-2")
	wantAttr(t, rec, "haproxy.state", "down")
	wantAttr(t, rec, "haproxy.reason", "Layer4 timeout")
	wantAttr(t, rec, "haproxy.check_duration_ms", "2001")
	wantNoAttr(t, rec, "haproxy.check_code")
	wantNoAttr(t, rec, "haproxy.info")

	if rec.Severity != logship.SeverityWarn {
		t.Errorf("severity = %v, want Warn for a DOWN transition", rec.Severity)
	}
}

// TestParseHAProxy_ServerDownWithInfo covers the DOWN shape whose reason is
// followed by a quoted info string (connection refused) instead of a code.
func TestParseHAProxy_ServerDownWithInfo(t *testing.T) {
	const line = `Server bk-heavy/heavy-1 is DOWN, reason: Layer4 connection problem, info: "Connection refused", check duration: 1ms. 1 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.`

	rec, ok, _ := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for a Server DOWN line with info")
	}
	wantAttr(t, rec, "haproxy.server", "heavy-1")
	wantAttr(t, rec, "haproxy.state", "down")
	wantAttr(t, rec, "haproxy.reason", "Layer4 connection problem")
	wantAttr(t, rec, "haproxy.info", "Connection refused")
	wantAttr(t, rec, "haproxy.check_duration_ms", "1")
	wantNoAttr(t, rec, "haproxy.check_code")

	if rec.Severity != logship.SeverityWarn {
		t.Errorf("severity = %v, want Warn", rec.Severity)
	}
}

// TestParseHAProxy_ServerDownWithCodeAndInfo covers an L7 failure, where HAProxy
// emits BOTH a code and an info string.
func TestParseHAProxy_ServerDownWithCodeAndInfo(t *testing.T) {
	const line = `Server bk-heavy/heavy-1 is DOWN, reason: Layer7 wrong status, code: 503, info: "HTTP status check returned code <503>", check duration: 4ms. 0 active and 0 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.`

	rec, ok, _ := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false")
	}
	wantAttr(t, rec, "haproxy.state", "down")
	wantAttr(t, rec, "haproxy.reason", "Layer7 wrong status")
	wantAttr(t, rec, "haproxy.check_code", "503")
	wantAttr(t, rec, "haproxy.info", "HTTP status check returned code <503>")
	wantAttr(t, rec, "haproxy.check_duration_ms", "4")
}

// TestParseHAProxy_NoServerAvailable is the outage line: every server in the
// backend is gone.
func TestParseHAProxy_NoServerAvailable(t *testing.T) {
	const line = `backend bk-heavy has no server available!`

	rec, ok, _ := parseHAProxyLine(t, line, 3)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for a no-server-available line")
	}
	wantAttr(t, rec, "haproxy.event", "no_server_available")
	wantAttr(t, rec, "haproxy.backend", "bk-heavy")
	wantAttr(t, rec, "haproxy.state", "no-servers")

	if rec.Severity != logship.SeverityError {
		t.Errorf("severity = %v, want Error for a backend with no servers", rec.Severity)
	}
	if rec.Body != line {
		t.Errorf("body = %q, want the raw message", rec.Body)
	}
}

// TestParseHAProxy_Connect covers the bulk line (99.9% of the volume), and its
// address enrichment: the client is a known lease on a local net, the listener
// is the firewall itself.
func TestParseHAProxy_Connect(t *testing.T) {
	const line = `Connect from 172.16.9.99:34000 to 172.16.9.1:8090 (ft-heavy/HTTP)`

	rec, ok, m := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for a Connect line")
	}
	wantAttr(t, rec, "haproxy.event", "connect")
	wantAttr(t, rec, "src.ip", "172.16.9.99")
	wantAttr(t, rec, "src.port", "34000")
	wantAttr(t, rec, "dst.ip", "172.16.9.1")
	wantAttr(t, rec, "dst.port", "8090")
	wantAttr(t, rec, "haproxy.frontend", "ft-heavy")
	wantAttr(t, rec, "haproxy.mode", "HTTP")

	// Enrichment is the parser's own job — BuildRecord does not re-scan a
	// structured parser's body.
	wantAttr(t, rec, "src.hostname", "exporter-traffgen")
	wantAttr(t, rec, "src.mac", "bc:24:11:eb:db:3d")
	wantAttr(t, rec, "src.scope", "local")
	wantAttr(t, rec, "dst.scope", "self")

	if rec.Severity != logship.SeverityInfo {
		t.Errorf("severity = %v, want Info", rec.Severity)
	}
	// An address lookup that finds nothing is normal, never a cache miss.
	if len(m.calls) != 0 {
		t.Errorf("miss() called %v, want no misses", m.calls)
	}
}

// TestParseHAProxy_ConnectUnknownAddresses proves an unresolvable address is
// silent: no hostname, no miss, still parsed.
func TestParseHAProxy_ConnectUnknownAddresses(t *testing.T) {
	const line = `Connect from 203.0.113.7:52344 to 198.51.100.9:443 (ft-wan/TCP)`

	rec, ok, m := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false")
	}
	wantAttr(t, rec, "src.ip", "203.0.113.7")
	wantAttr(t, rec, "dst.port", "443")
	wantAttr(t, rec, "haproxy.mode", "TCP")
	wantNoAttr(t, rec, "src.hostname")
	if len(m.calls) != 0 {
		t.Errorf("miss() called %v, want no misses for unknown addresses", m.calls)
	}
}

// TestParseHAProxy_HTTPLog covers the classic httplog format. It is NOT emitted
// by OPNsense's default HAProxy config — it only appears if an operator sets
// `option httplog` — so this fixture is synthesised from HAProxy's documented
// field order, not captured from the live box.
func TestParseHAProxy_HTTPLog(t *testing.T) {
	const line = `172.16.9.99:34000 [14/Jul/2026:12:00:00.123] ft-heavy bk-heavy/heavy-1 12/0/1/9/22 503 1234 - - ---- 5/3/2/1/0 0/0 "GET /api/health HTTP/1.1"`

	rec, ok, m := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for an httplog line")
	}
	wantAttr(t, rec, "haproxy.event", "http_request")
	wantAttr(t, rec, "src.ip", "172.16.9.99")
	wantAttr(t, rec, "src.port", "34000")
	wantAttr(t, rec, "src.hostname", "exporter-traffgen")
	wantAttr(t, rec, "haproxy.frontend", "ft-heavy")
	wantAttr(t, rec, "haproxy.backend", "bk-heavy")
	wantAttr(t, rec, "haproxy.server", "heavy-1")
	wantAttr(t, rec, "haproxy.timers.tq_ms", "12")
	wantAttr(t, rec, "haproxy.timers.tw_ms", "0")
	wantAttr(t, rec, "haproxy.timers.tc_ms", "1")
	wantAttr(t, rec, "haproxy.timers.tr_ms", "9")
	wantAttr(t, rec, "haproxy.timers.tt_ms", "22")
	wantAttr(t, rec, "http.status_code", "503")
	wantAttr(t, rec, "bytes_read", "1234")
	wantAttr(t, rec, "haproxy.termination_state", "----")
	wantAttr(t, rec, "haproxy.conn.actconn", "5")
	wantAttr(t, rec, "haproxy.conn.feconn", "3")
	wantAttr(t, rec, "haproxy.conn.beconn", "2")
	wantAttr(t, rec, "haproxy.conn.srv_conn", "1")
	wantAttr(t, rec, "haproxy.conn.retries", "0")
	wantAttr(t, rec, "haproxy.queue.server", "0")
	wantAttr(t, rec, "haproxy.queue.backend", "0")
	wantAttr(t, rec, "http.method", "GET")
	wantAttr(t, rec, "http.target", "/api/health")

	if rec.Severity != logship.SeverityError {
		t.Errorf("severity = %v, want Error for a 5xx", rec.Severity)
	}
	if len(m.calls) != 0 {
		t.Errorf("miss() called %v, want no misses", m.calls)
	}
}

// TestParseHAProxy_HTTPLogSeverity checks the status -> severity mapping without
// re-asserting the whole field set.
func TestParseHAProxy_HTTPLogSeverity(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   logship.Severity
	}{
		{"2xx is info", "200", logship.SeverityInfo},
		{"3xx is info", "301", logship.SeverityInfo},
		{"4xx is warn", "404", logship.SeverityWarn},
		{"5xx is error", "502", logship.SeverityError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := `172.16.9.99:34000 [14/Jul/2026:12:00:00.123] ft-heavy bk-heavy/heavy-1 12/0/1/9/22 ` +
				tc.status + ` 1234 - - ---- 5/3/2/1/0 0/0 "GET /api/health HTTP/1.1"`
			rec, ok, _ := parseHAProxyLine(t, line, 6)
			if !ok {
				t.Fatal("parseHAProxy returned ok=false")
			}
			wantAttr(t, rec, "http.status_code", tc.status)
			if rec.Severity != tc.want {
				t.Errorf("severity = %v, want %v", rec.Severity, tc.want)
			}
		})
	}
}

// TestParseHAProxy_HTTPLogNegativeTimersAndNoRequest covers the aborted-session
// shape: HAProxy writes -1 for a timer it never measured, and the captured
// request is absent when the client never sent one.
func TestParseHAProxy_HTTPLogNegativeTimersAndNoRequest(t *testing.T) {
	const line = `172.16.9.99:34000 [14/Jul/2026:12:00:00.123] ft-heavy bk-heavy/<NOSRV> -1/-1/-1/-1/2000 400 0 - - CR-- 5/3/0/0/0 0/0 ""`

	rec, ok, _ := parseHAProxyLine(t, line, 6)
	if !ok {
		t.Fatal("parseHAProxy returned ok=false for an aborted httplog line")
	}
	wantAttr(t, rec, "haproxy.server", "<NOSRV>")
	wantAttr(t, rec, "haproxy.timers.tq_ms", "-1")
	wantAttr(t, rec, "haproxy.timers.tt_ms", "2000")
	wantAttr(t, rec, "haproxy.termination_state", "CR--")
	wantAttr(t, rec, "http.status_code", "400")
	wantNoAttr(t, rec, "http.method")
	wantNoAttr(t, rec, "http.target")
}

// TestParseHAProxy_Unrecognised: anything the parser does not know degrades to a
// generic record — ok=false, never a drop, never a panic.
func TestParseHAProxy_Unrecognised(t *testing.T) {
	lines := []string{
		"",
		"   ",
		"Proxy ft-heavy started.",
		"Server bk-heavy/heavy-1 is",
		"Connect from garbage",
		"Connect from 172.16.9.99 to 172.16.9.1 (ft-heavy/HTTP)",
		`{"json":"not haproxy"}`,
		"backend bk-heavy has servers, thanks",
		"172.16.9.99:34000 [14/Jul/2026:12:00:00.123] ft-heavy",
	}
	for _, line := range lines {
		rec, ok, _ := parseHAProxyLine(t, line, 6)
		if ok {
			t.Errorf("parseHAProxy(%q) = ok, want ok=false (degrade to generic); attrs=%v", line, rec.Attributes)
		}
	}
}

// TestParseHAProxy_RegisteredForProgram checks the whole pipeline: a haproxy
// envelope routed through BuildRecord comes out structured and subsystem-tagged,
// and an unparseable one still ships with its body intact.
func TestParseHAProxy_RegisteredForProgram(t *testing.T) {
	rec := BuildRecord(haproxyEnvelope(`backend bk-heavy has no server available!`, 3), haproxySnapshot(), func(string) {})
	wantAttr(t, rec, "subsystem", "proxy")
	wantAttr(t, rec, "haproxy.backend", "bk-heavy")
	wantAttr(t, rec, "program", "haproxy")

	generic := BuildRecord(haproxyEnvelope("Proxy ft-heavy started.", 6), haproxySnapshot(), func(string) {})
	if generic.Body != "Proxy ft-heavy started." {
		t.Errorf("generic body = %q, want the raw message", generic.Body)
	}
	wantAttr(t, generic, "subsystem", "proxy")
	wantNoAttr(t, generic, "haproxy.backend")
}
