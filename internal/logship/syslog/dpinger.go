package syslog

import (
	"regexp"
	"strings"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// dpinger emits alarm transitions for a configured gateway. OPN-0104's full
// Camden corpus extends the original none/down and none/delay pairs with
// none/loss, loss/none, loss/down and down/loss, under MONITOR or ALERT.
//
// gateway.alarm.previous/current preserve the exact states. Transitions between
// two alarm states emit alarm_changed, never alarm_cleared: loss -> down is a
// worsening fault, and down -> loss still has packet loss. Only observed edges
// are admitted; new states and uncaptured cross-edges remain unknown.
//
// Existing gateway.name, gateway.address, gateway.rtt_ms, gateway.rttd_ms and
// gateway.loss_percent attributes and derived gateway counters are preserved.
// A sanitized example of the newly captured format:
//
// ALERT: TEST_GATEWAY (Addr: 192.0.2.1 Alarm: loss -> down RTT: 12.5 ms RTTd: 1.2 ms Loss: 100.0 %)
//
// # Lifecycle lines (#668)
//
// The transitions above cover dpinger while it is running. Three more lines,
// captured on the camden testbed (2026-08-04 08:46 -> 2026-08-07 16:33 UTC,
// cross-checked live against /opt/opnsense2otel/capture/syslog on 2026-08-07),
// bracket a dpinger restart or an in-place SIGHUP reconfigure. The addresses
// below are RFC 5737 documentation addresses substituted for the captured
// ones; every other character is verbatim, and the structure is what the
// parser is written against:
//
//	exiting on signal 15
//	Reloaded gateway watcher configuration on SIGHUP
//	send_interval 1000ms  loss_interval 4000ms  time_period 60000ms  report_interval 0ms  data_len 1  alert_interval 1000ms  latency_alarm 0ms  loss_alarm 0%  alarm_hold 10000ms  dest_addr 192.0.2.1  bind_addr 198.51.100.31  identifier "AAISP_PPPOE "
//
// Why this matters: the alarm-transition parser above can only structure a
// transition that fires. A dpinger restart (`exiting on signal 15` followed,
// moments later, by the startup config line) is exactly the window in which
// no transition CAN fire — the watcher is not running, so an alarm that
// appears to "clear" during that gap may just be dpinger having restarted,
// not the gateway having recovered. That is indistinguishable from a real
// recovery without these lines, and it is the same blind spot the hysteresis
// added to the gateway flapping rule in b64d34b6 is working around: a
// hysteresis window that spans a dpinger restart is reasoning over a period
// where the signal was structurally absent, not stable. Emitting
// watcher_stopped/watcher_reloaded/watcher_started alongside the existing
// alarm events makes that window identifiable.
//
// The startup line is a second, independent finding: on this box it reads
// `latency_alarm 0ms  loss_alarm 0%`, meaning the firewall-side `delay` alarm
// threshold is configured OFF for this gateway. Every `delay` alarm the
// parser above is built to catch therefore cannot fire here — "we have never
// seen a delay alarm" is a configuration fact, not an absence of evidence.
// Structuring the thresholds (gateway.latency_alarm_ms,
// gateway.loss_alarm_percent, gateway.alarm_hold_ms) is what makes that
// checkable instead of merely inferred.
//
// The startup line's fields are separated by two spaces, and the identifier
// is quoted with a trailing space INSIDE the quotes (`"AAISP_PPPOE "`) —
// upstream's padding, not a capture artifact. The trailing space is trimmed
// before the value is used as gateway.name.
//
// Attributes added:
//
//	gateway.event             watcher_stopped | watcher_reloaded | watcher_started (closed vocabulary, alongside alarm_started | alarm_cleared above)
//	gateway.signal             signal number, on watcher_stopped only (e.g. "15")
//	gateway.name               dpinger identifier, trailing space trimmed, on watcher_started only
//	gateway.address             dest_addr, on watcher_started only
//	gateway.bind_address        bind_addr, on watcher_started only
//	gateway.latency_alarm_ms    configured latency_alarm threshold in ms, on watcher_started only
//	gateway.loss_alarm_percent  configured loss_alarm threshold in %, on watcher_started only
//	gateway.alarm_hold_ms       configured alarm_hold in ms, on watcher_started only
//
// send_interval, loss_interval, time_period, report_interval, data_len and
// alert_interval are present on the startup line but not structured: the
// issue's acceptance criteria call out only the alarm thresholds and
// addressing fields, and a fixed field the parser doesn't read yet is safer
// left unclaimed than guessed at.
var (
	// Full-corpus replay in OPN-0104 added ALERT and loss edges. Only the
	// observed edges below are admitted; loss -> down is degradation, not clear.
	reDPingerTransition = regexp.MustCompile(`^(?:MONITOR|ALERT): (\S+) \(Addr: (\S+) Alarm: (none|down|delay|loss) -> (none|down|delay|loss) RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)

	reDPingerExiting = regexp.MustCompile(`^exiting on signal (\d+)$`)
	reDPingerSIGHUP  = regexp.MustCompile(`^Reloaded gateway watcher configuration on SIGHUP$`)
	reDPingerStartup = regexp.MustCompile(`^send_interval \d+ms  loss_interval \d+ms  time_period \d+ms  report_interval \d+ms  data_len \d+  alert_interval \d+ms  latency_alarm (\d+)ms  loss_alarm (\d+)%  alarm_hold (\d+)ms  dest_addr (\S+)  bind_addr (\S+)  identifier "(.*)"$`)
)

func init() {
	RegisterParser(parseDPinger, "dpinger")
}

func parseDPinger(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reDPingerTransition.FindStringSubmatch(env.Message); m != nil {
		event := ""
		switch m[3] + ">" + m[4] {
		case "none>down", "none>delay", "none>loss":
			event = "alarm_started"
		case "down>none", "delay>none", "loss>none":
			event = "alarm_cleared"
		case "loss>down", "down>loss":
			event = "alarm_changed"
		default:
			return logship.Record{}, false
		}
		return dpingerRecord(env, []string{m[0], m[1], m[2], m[5], m[6], m[7]}, m[3], m[4], event), true
	}
	if m := reDPingerExiting.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("gateway.event", "watcher_stopped")
		set("gateway.signal", m[1])
		return rec, true
	}
	if reDPingerSIGHUP.MatchString(env.Message) {
		rec, set := newRecord(env)
		set("gateway.event", "watcher_reloaded")
		return rec, true
	}
	if m := reDPingerStartup.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("gateway.event", "watcher_started")
		set("gateway.name", strings.TrimSuffix(m[6], " "))
		set("gateway.address", m[4])
		set("gateway.bind_address", m[5])
		set("gateway.latency_alarm_ms", m[1])
		set("gateway.loss_alarm_percent", m[2])
		set("gateway.alarm_hold_ms", m[3])
		return rec, true
	}
	return logship.Record{}, false
}

func dpingerRecord(env Envelope, match []string, previous, current, event string) logship.Record {
	rec, set := newRecord(env)
	set("gateway.event", event)
	set("gateway.name", match[1])
	set("gateway.address", match[2])
	set("gateway.alarm.previous", previous)
	set("gateway.alarm.current", current)
	set("gateway.rtt_ms", match[3])
	set("gateway.rttd_ms", match[4])
	set("gateway.loss_percent", match[5])
	return rec
}
