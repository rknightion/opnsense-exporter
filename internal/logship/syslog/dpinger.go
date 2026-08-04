package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// dpinger emits an alarm transition when a monitored gateway changes state. The
// development testbed captured these two shapes:
//
//	MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: none -> down RTT: 1000.000 ms RTTd: 12.345 ms Loss: 100.000 %)
//	MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: down -> none RTT: 1.234 ms RTTd: 0.123 ms Loss: 0.000 %)
//
// A live box also emits a third alarm state, `delay` — the RTT/loss latency
// threshold breached without the gateway going down, a different operational
// signal from a dead gateway (#641). Sanitized from a prod-box capture,
// 2026-08-04 (the real monitored address is replaced with a documentation
// one; the gateway name and RTT/loss figures are unchanged):
//
//	MONITOR: WAN_DHCP (Addr: 203.0.113.53 Alarm: none -> delay RTT: 201.2 ms RTTd: 29.6 ms Loss: 0.0 %)
//	MONITOR: WAN_DHCP (Addr: 203.0.113.53 Alarm: delay -> none RTT: 199.9 ms RTTd: 63.2 ms Loss: 0.0 %)
//
// Attributes emitted:
//
//	gateway.event           alarm_started | alarm_cleared
//	gateway.name            dpinger monitor name
//	gateway.address         monitored address
//	gateway.alarm.previous  state before the captured transition (none | down | delay)
//	gateway.alarm.current   state after the captured transition (none | down | delay)
//	gateway.rtt_ms          RTT value as it appeared on the wire
//	gateway.rttd_ms         RTT deviation value as it appeared on the wire
//	gateway.loss_percent    loss value as it appeared on the wire
//
// `delay` is kept as its own dedicated pattern pair, mirroring the down pair,
// rather than a single Alarm: (none|down|delay) -> (none|down|delay) regex: only
// none<->down and none<->delay have been observed on a real box, and a general
// N-way pattern would also match a down<->delay transition nothing has ever
// captured.
//
// CARP state, other dpinger transitions, causes and stable-release variants
// deliberately remain generic until real capture evidence exists.
var (
	reDPingerAlarmStarted = regexp.MustCompile(`^MONITOR: (\S+) \(Addr: (\S+) Alarm: none -> down RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)
	reDPingerAlarmCleared = regexp.MustCompile(`^MONITOR: (\S+) \(Addr: (\S+) Alarm: down -> none RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)

	reDPingerDelayStarted = regexp.MustCompile(`^MONITOR: (\S+) \(Addr: (\S+) Alarm: none -> delay RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)
	reDPingerDelayCleared = regexp.MustCompile(`^MONITOR: (\S+) \(Addr: (\S+) Alarm: delay -> none RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)
)

func init() {
	RegisterParser(parseDPinger, "dpinger")
}

func parseDPinger(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reDPingerAlarmStarted.FindStringSubmatch(env.Message); m != nil {
		return dpingerRecord(env, m, "none", "down", "alarm_started"), true
	}
	if m := reDPingerAlarmCleared.FindStringSubmatch(env.Message); m != nil {
		return dpingerRecord(env, m, "down", "none", "alarm_cleared"), true
	}
	if m := reDPingerDelayStarted.FindStringSubmatch(env.Message); m != nil {
		return dpingerRecord(env, m, "none", "delay", "alarm_started"), true
	}
	if m := reDPingerDelayCleared.FindStringSubmatch(env.Message); m != nil {
		return dpingerRecord(env, m, "delay", "none", "alarm_cleared"), true
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
