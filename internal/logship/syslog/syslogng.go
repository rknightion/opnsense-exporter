package syslog

import (
	"regexp"
	"strconv"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// syslog-ng is the daemon carrying our own syslog feed (#665). It is the second-
// largest unparsed program in the camden debug-capture archive (294/1956 entries,
// 15.0%, captured 2026-08-04 08:46 -> 2026-08-07 16:33 UTC) and has a subsystem
// already (`logging`, registry.go) but no parser. Every shape below is verbatim
// from that capture unless a comment says otherwise.
//
// Four groups were triaged; only two are structured here.
//
// Group 1 -- connection lifecycle against our OWN listener (structured, the
// highest-value item in the issue). Every "Syslog connection ..." / "EOF
// occurred" line below names 10.0.0.5:5847, this exporter's TCP syslog listener
// (OPN2OTEL_LOGS_SYSLOG_LISTEN_TCP=:5847). These lines are the firewall's own,
// independent, timestamped account of a gap in the very pipeline that carries
// them: a `closed`/`broken` plus its `time_reopen` answers "did we lose syslog,
// or did nothing happen?" -- a question the exporter's own receiver metrics
// cannot answer, because from our side a dropped TCP connection and an idle
// firewall look identical.
//
//	Syslog connection established; fd='23', server='AF_INET(10.0.0.5:5847)', local='AF_INET(0.0.0.0:0)'
//	Syslog connection closed; fd='23', server='AF_INET(10.0.0.5:5847)', time_reopen='60'
//	Syslog connection broken; fd='27', server='AF_INET(10.0.0.5:5847)', time_reopen='60'
//	EOF occurred; fd='23'
//
// Attributes:
//
//	syslogng.event                  connection_established | connection_closed | connection_broken | eof
//	syslogng.fd                     the file descriptor number
//	dst.ip / dst.port                parsed out of the AF_INET(...) server field
//	syslogng.time_reopen_seconds     present on closed/broken only
//
// Group 2 -- the periodic "Log statistics;" dump (structured, narrowly). One
// ~4 KB line, ~80 `key='scope(name)=value'` pairs covering every syslog-ng
// source/destination on the box. Parsing all of them would mint one attribute
// per destination and turn a log line into a metrics scrape by the back door --
// wrong shape, and a cardinality problem on a box with many destinations. Only
// `dropped` is unavailable anywhere else: it is the firewall's own pipeline
// throwing our messages away before they ever reached us. The issue's acceptance
// criteria are explicit that this is `syslogng.dropped_total` and
// `syslogng.truncated_total` ONLY -- no per-scope name attribute, even though
// the issue's prose floats emitting non-zero scope names too. The checklist is
// the binding spec; a per-scope name is exactly the fan-out the verdict warns
// against, so it is left out. A test pins the fixed attribute count against the
// full captured line so a future fan-out regression is caught, not just
// described.
//
// Group 3 -- configuration reload (deliberately left generic). Three fixed
// strings with no variable content:
//
//	Configuration reload requested over control channel;
//	Loading the new configuration;
//	Configuration reload finished;
//
// No operational question they answer isn't already answered better by
// config/configd.py (the config-apply chain covered elsewhere). Structuring
// them would add a vocabulary entry per string for zero query value, so they
// fall through to a generic record like any other unmatched syslog-ng line.
//
// Group 4 -- errors (structured). `Child program exited, restarting` with a
// non-zero status is a real failure of an OPNsense event handler; `Error
// reading data` names the failing fd, which correlates directly with Group 1's
// syslogng.fd.
//
//	Child program exited, restarting; cmdline='/usr/local/sbin/configctl -e -t 0.5 system event config_changed', status='256'
//	Error reading data; fd='27', error='Operation timed out (60)'
//
// Attributes:
//
//	syslogng.event         child_exited | read_error
//	syslogng.cmdline        child_exited only
//	syslogng.exit_status    child_exited only
//	syslogng.fd             read_error only
//	syslogng.error          read_error only
var (
	// AF_INET(<addr>:<port>) -- the address portion is matched greedily so an
	// IPv6 literal (colons and all) is captured whole and only the trailing
	// ":<digits>)" is treated as the port; the capture only ever produced IPv4
	// here (10.0.0.5:5847), but nothing about the shape restricts it to IPv4.
	reSyslogngEstablished = regexp.MustCompile(
		`^Syslog connection established; fd='(\d+)', server='AF_INET\((.+):(\d+)\)', local='AF_INET\([^)]*\)'$`)
	reSyslogngClosed = regexp.MustCompile(
		`^Syslog connection closed; fd='(\d+)', server='AF_INET\((.+):(\d+)\)', time_reopen='(\d+)'$`)
	reSyslogngBroken = regexp.MustCompile(
		`^Syslog connection broken; fd='(\d+)', server='AF_INET\((.+):(\d+)\)', time_reopen='(\d+)'$`)
	reSyslogngEOF = regexp.MustCompile(`^EOF occurred; fd='(\d+)'$`)

	reSyslogngChildExited = regexp.MustCompile(
		`^Child program exited, restarting; cmdline='(.+)', status='(\d+)'$`)
	reSyslogngReadError = regexp.MustCompile(
		`^Error reading data; fd='(\d+)', error='(.+)'$`)

	reSyslogngStatsLine = regexp.MustCompile(`^Log statistics;`)
	// Each `dropped='<scope>=<digits>'` / `truncated_count='<scope>=<digits>'`
	// pair anywhere in the statistics line; the scope text itself is discarded,
	// only the trailing numeric value is summed (Group 2's narrow extraction).
	reSyslogngDropped        = regexp.MustCompile(`dropped='[^']*=(\d+)'`)
	reSyslogngTruncatedCount = regexp.MustCompile(`truncated_count='[^']*=(\d+)'`)
)

func init() {
	RegisterParser(parseSyslogNG, "syslog-ng")
}

func parseSyslogNG(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reSyslogngEstablished.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("syslogng.event", "connection_established")
		set("syslogng.fd", m[1])
		set("dst.ip", m[2])
		set("dst.port", m[3])
		return rec, true
	}
	if m := reSyslogngClosed.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("syslogng.event", "connection_closed")
		set("syslogng.fd", m[1])
		set("dst.ip", m[2])
		set("dst.port", m[3])
		set("syslogng.time_reopen_seconds", m[4])
		return rec, true
	}
	if m := reSyslogngBroken.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("syslogng.event", "connection_broken")
		set("syslogng.fd", m[1])
		set("dst.ip", m[2])
		set("dst.port", m[3])
		set("syslogng.time_reopen_seconds", m[4])
		return rec, true
	}
	if m := reSyslogngEOF.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("syslogng.event", "eof")
		set("syslogng.fd", m[1])
		return rec, true
	}

	if m := reSyslogngChildExited.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("syslogng.event", "child_exited")
		set("syslogng.cmdline", m[1])
		set("syslogng.exit_status", m[2])
		return rec, true
	}
	if m := reSyslogngReadError.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("syslogng.event", "read_error")
		set("syslogng.fd", m[1])
		set("syslogng.error", m[2])
		return rec, true
	}

	if reSyslogngStatsLine.MatchString(env.Message) {
		rec, set := newRecord(env)
		set("syslogng.event", "statistics")
		set("syslogng.dropped_total", strconv.Itoa(sumSyslogngCounters(reSyslogngDropped, env.Message)))
		set("syslogng.truncated_total", strconv.Itoa(sumSyslogngCounters(reSyslogngTruncatedCount, env.Message)))
		return rec, true
	}

	// Group 3 (configuration reload) and everything else syslog-ng logs falls
	// through here deliberately -- see the Group 3 comment above.
	return logship.Record{}, false
}

// sumSyslogngCounters sums the numeric capture group of every match of re
// against msg. Used to fold the statistics line's per-scope dropped/
// truncated_count pairs into a single total without emitting one attribute per
// scope.
func sumSyslogngCounters(re *regexp.Regexp, msg string) int {
	total := 0
	for _, m := range re.FindAllStringSubmatch(msg, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		total += n
	}
	return total
}
