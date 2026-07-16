package syslog

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// HAProxy on OPNsense does NOT emit the classic httplog line by default, and the
// value in this stream is inverted from what one would expect. Over a live box's
// entire log history:
//
//	860542  Connect from 172.16.9.99:34000 to 172.16.9.1:8090 (ft-heavy/HTTP)
//	     3  Server bk-heavy/heavy-1 is UP, reason: Layer7 check passed, code: 200, check duration: 3ms. …
//	     2  Server bk-heavy/heavy-2 is DOWN, reason: Layer4 timeout, check duration: 2001ms. …
//	     1  Server bk-heavy/heavy-1 is DOWN, reason: Layer4 connection problem, info: "Connection refused", …
//	     1  backend bk-heavy has no server available!
//
// The connect line is ~99.9% of the volume and says almost nothing. The server
// UP/DOWN transitions and the "no server available" outage line are the rare,
// high-signal events, so they are what this parser is built around; the connect
// line is handled because it is cheap, not because it is interesting.
//
// The classic httplog shape (status, timers, termination state) is parsed too —
// an operator CAN turn `option httplog` on — but that lane is written from
// HAProxy's documented field order and is NOT verified against a real box. It is
// anchored strictly enough that a line which is not httplog cannot be mistaken
// for one: anything it does not match degrades to a generic record.
var (
	// Server <backend>/<server> is UP|DOWN, reason: <reason>[, code: <n>][, info: "<info>"][, check duration: <n>ms]. <tail>
	//
	// Every clause after the state is optional and they are ordered as HAProxy
	// emits them (reason, code, info, duration): an L4 failure has no code, an L7
	// status failure has both a code and an info string. The trailing sentence
	// ("2 active and 0 backup servers online…") is counted state we do not model —
	// the metric collectors already carry it.
	haproxyServerStateRE = regexp.MustCompile(
		`^Server ([^/\s]+)/(\S+) is (UP|DOWN)` +
			`(?:, reason: ([^,]+))?` +
			`(?:, code: (\d+))?` +
			`(?:, info: "([^"]*)")?` +
			`(?:, check duration: (\d+)ms)?`,
	)

	// backend <name> has no server available!  ("proxy" is the wording on some
	// HAProxy versions; both mean every server in the backend is gone.)
	haproxyNoServerRE = regexp.MustCompile(`^(?:backend|proxy) (\S+) has no server available!?$`)

	// Connect from <ip>:<port> to <ip>:<port> (<frontend>/<mode>)
	//
	// The address groups are greedy so an IPv6 literal (which is itself full of
	// colons) still splits on its LAST colon, where the port is.
	haproxyConnectRE = regexp.MustCompile(`^Connect from (.+):(\d+) to (.+):(\d+) \(([^/()]+)/([^()]+)\)$`)

	// Classic httplog, per HAProxy's documented field order:
	//
	//	client_ip:client_port [accept_date] frontend backend/server \
	//	  Tq/Tw/Tc/Tr/Tt status bytes req_cookie resp_cookie termination_state \
	//	  actconn/feconn/beconn/srv_conn/retries srv_queue/backend_queue \
	//	  {req_headers} {resp_headers} "<method> <target> <version>"
	//
	// Timers are -1 when never measured and may carry a leading '+' when the log
	// was truncated; the byte count takes '+' the same way. Captured headers are
	// only present if the config captures any, and the quoted request is empty on
	// a session that never sent one.
	haproxyHTTPLogRE = regexp.MustCompile(
		`^(\S+):(\d+) \[([^\]]+)\] (\S+) (\S+)/(\S+) ` +
			`([-+]?\d+)/([-+]?\d+)/([-+]?\d+)/([-+]?\d+)/([-+]?\d+) ` +
			`(\d{3}) ([-+]?\d+) (\S+) (\S+) (\S{4}) ` +
			`(\d+)/(\d+)/(\d+)/(\d+)/(\d+) (\d+)/(\d+)` +
			`(?:\s+\{[^}]*\})*` +
			`(?:\s+"([^"]*)")?\s*$`,
	)

	// "<method> <target> <version>" inside an httplog line. A malformed or absent
	// request leaves method/target unset rather than guessing.
	haproxyRequestRE = regexp.MustCompile(`^(\S+) (\S+)(?: (\S+))?$`)
)

func init() {
	// HAProxy resolves its own positional src/dst addresses, so BuildRecord must
	// not re-scan the body for peer.* addresses.
	RegisterParser(parseHAProxy, "haproxy")
}

// parseHAProxy turns one HAProxy message into a structured Record. It returns
// ok=false for anything it does not recognise (including the many operational
// lines HAProxy emits at startup and reload) so the caller degrades to a generic
// record carrying the raw body — never a drop, never a panic.
func parseHAProxy(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	msg := strings.TrimSpace(env.Message)
	if msg == "" {
		return logship.Record{}, false
	}

	switch {
	case strings.HasPrefix(msg, "Server "):
		return parseHAProxyServerState(env, msg)
	case strings.HasPrefix(msg, "backend ") || strings.HasPrefix(msg, "proxy "):
		return parseHAProxyNoServer(env, msg)
	case strings.HasPrefix(msg, "Connect from "):
		return parseHAProxyConnect(env, msg, snap)
	default:
		return parseHAProxyHTTPLog(env, msg, snap)
	}
}

// parseHAProxyServerState handles the health transition — the line an operator
// actually wants to see. A DOWN transition is at least a Warn regardless of the
// severity HAProxy stamped on it (it logs these at notice/info), because a
// backend server dropping out is the whole reason to ship this stream.
func parseHAProxyServerState(env Envelope, msg string) (logship.Record, bool) {
	m := haproxyServerStateRE.FindStringSubmatch(msg)
	if m == nil {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("haproxy.event", "server_state")
	set("haproxy.backend", m[1])
	set("haproxy.server", m[2])
	set("haproxy.state", strings.ToLower(m[3]))
	set("haproxy.reason", strings.TrimSpace(m[4]))
	set("haproxy.check_code", m[5])
	set("haproxy.info", m[6])
	set("haproxy.check_duration_ms", m[7])

	if strings.EqualFold(m[3], "DOWN") {
		rec.Severity = logship.SeverityWarn
	} else {
		rec.Severity = logship.SeverityInfo
	}
	return rec, true
}

// parseHAProxyNoServer handles "backend X has no server available!" — every
// server in the backend has failed its check, so the service behind it is down.
// That is an outage, hence Error.
func parseHAProxyNoServer(env Envelope, msg string) (logship.Record, bool) {
	m := haproxyNoServerRE.FindStringSubmatch(msg)
	if m == nil {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("haproxy.event", "no_server_available")
	set("haproxy.backend", m[1])
	set("haproxy.state", "no-servers")
	rec.Severity = logship.SeverityError
	return rec, true
}

// parseHAProxyConnect handles the bulk line. Address enrichment is the parser's
// own job: BuildRecord does not re-scan a structured parser's body, and an
// address it cannot resolve is normal (every WAN client is unknown), so a lookup
// that finds nothing is silent and NEVER a cache miss.
func parseHAProxyConnect(env Envelope, msg string, snap *enrich.Snapshot) (logship.Record, bool) {
	m := haproxyConnectRE.FindStringSubmatch(msg)
	if m == nil {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("haproxy.event", "connect")
	set("src.ip", m[1])
	set("src.port", m[2])
	set("dst.ip", m[3])
	set("dst.port", m[4])
	set("haproxy.frontend", m[5])
	set("haproxy.mode", m[6])

	// The frontend's mode names the protocol HAProxy speaks, not the transport;
	// the transport is TCP either way, which is what the service table keys on.
	enrichEndpoint(set, snap, "src", m[1], m[2], "tcp")
	enrichEndpoint(set, snap, "dst", m[3], m[4], "tcp")

	rec.Severity = logship.SeverityInfo
	return rec, true
}

// parseHAProxyHTTPLog handles the classic httplog format, which OPNsense does
// NOT emit by default (see the block comment above): this lane exists for the
// operator who has turned `option httplog` on, and its field order comes from
// HAProxy's docs rather than a captured line. The regex is fully anchored, so a
// line that merely resembles httplog fails outright and degrades to generic
// rather than producing plausible-looking wrong attributes.
func parseHAProxyHTTPLog(env Envelope, msg string, snap *enrich.Snapshot) (logship.Record, bool) {
	m := haproxyHTTPLogRE.FindStringSubmatch(msg)
	if m == nil {
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("haproxy.event", "http_request")
	set("src.ip", m[1])
	set("src.port", m[2])
	set("haproxy.accept_date", m[3])
	set("haproxy.frontend", m[4])
	set("haproxy.backend", m[5])
	set("haproxy.server", m[6])
	set("haproxy.timers.tq_ms", m[7])
	set("haproxy.timers.tw_ms", m[8])
	set("haproxy.timers.tc_ms", m[9])
	set("haproxy.timers.tr_ms", m[10])
	set("haproxy.timers.tt_ms", m[11])
	set(attrHTTPResponseStatusCode, m[12])
	set("bytes_read", m[13])
	// m[14]/m[15] are the captured request/response cookies ("-" when none) — not
	// modelled: they are a per-site config knob and can carry session identifiers.
	set("haproxy.termination_state", m[16])
	set("haproxy.conn.actconn", m[17])
	set("haproxy.conn.feconn", m[18])
	set("haproxy.conn.beconn", m[19])
	set("haproxy.conn.srv_conn", m[20])
	set("haproxy.conn.retries", m[21])
	set("haproxy.queue.server", m[22])
	set("haproxy.queue.backend", m[23])

	if req := haproxyRequestRE.FindStringSubmatch(m[24]); req != nil {
		set("http.request.method", req[1])
		set("url.path", req[2])
		// network.protocol.version is the version number alone ("1.1"), not "HTTP/1.1".
		set("network.protocol.version", strings.TrimPrefix(req[3], "HTTP/"))
	}

	enrichEndpoint(set, snap, "src", m[1], m[2], "tcp")

	rec.Severity = haproxyStatusSeverity(m[12])
	return rec, true
}

// haproxyStatusSeverity maps a response status onto a severity: 5xx is a server
// failure (Error), 4xx is a client-side rejection (Warn), everything else is
// unremarkable. An unparseable status is Info — a status we cannot read is not
// evidence of a problem.
func haproxyStatusSeverity(status string) logship.Severity {
	code, err := strconv.Atoi(status)
	if err != nil {
		return logship.SeverityInfo
	}
	switch {
	case code >= 500:
		return logship.SeverityError
	case code >= 400:
		return logship.SeverityWarn
	default:
		return logship.SeverityInfo
	}
}
