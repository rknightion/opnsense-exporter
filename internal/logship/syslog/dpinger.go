package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// dpinger emits an alarm transition when a monitored gateway changes state. The
// development testbed captured exactly these two shapes:
//
//	MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: none -> down RTT: 1000.000 ms RTTd: 12.345 ms Loss: 100.000 %)
//	MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: down -> none RTT: 1.234 ms RTTd: 0.123 ms Loss: 0.000 %)
//
// Attributes emitted:
//
//	gateway.event           alarm_started | alarm_cleared
//	gateway.name            dpinger monitor name
//	gateway.address         monitored address
//	gateway.alarm.previous  state before the captured transition
//	gateway.alarm.current   state after the captured transition
//	gateway.rtt_ms          RTT value as it appeared on the wire
//	gateway.rttd_ms         RTT deviation value as it appeared on the wire
//	gateway.loss_percent    loss value as it appeared on the wire
//
// CARP state, other dpinger transitions, causes and stable-release variants
// deliberately remain generic until real capture evidence exists.
var (
	reDPingerAlarmStarted = regexp.MustCompile(`^MONITOR: (\S+) \(Addr: (\S+) Alarm: none -> down RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)
	reDPingerAlarmCleared = regexp.MustCompile(`^MONITOR: (\S+) \(Addr: (\S+) Alarm: down -> none RTT: ([0-9]+(?:\.[0-9]+)?) ms RTTd: ([0-9]+(?:\.[0-9]+)?) ms Loss: ([0-9]+(?:\.[0-9]+)?) %\)$`)
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
