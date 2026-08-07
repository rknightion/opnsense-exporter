package syslog

import (
	"strings"
	"testing"
	"time"
)

func dpingerEnv(t *testing.T, message string) Envelope {
	t.Helper()

	// Sanitized from OPNsense 27.1.a_40 TESTLAN captures for #405.
	env, err := ParseEnvelope([]byte("<134>1 2026-07-26T16:14:24Z test-firewall dpinger 314 - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestDPingerRegistered(t *testing.T) {
	if _, ok := parserFor("dpinger"); !ok {
		t.Fatal("no parser registered for program dpinger")
	}
}

func TestDPingerCapturedTransitions(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "alarm started",
			msg:  "MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: none -> down RTT: 1000.000 ms RTTd: 12.345 ms Loss: 100.000 %)",
			want: map[string]string{
				"gateway.event":          "alarm_started",
				"gateway.name":           "TEST_GATEWAY",
				"gateway.address":        "192.0.2.100",
				"gateway.alarm.previous": "none",
				"gateway.alarm.current":  "down",
				"gateway.rtt_ms":         "1000.000",
				"gateway.rttd_ms":        "12.345",
				"gateway.loss_percent":   "100.000",
			},
		},
		{
			name: "alarm cleared",
			msg:  "MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: down -> none RTT: 1.234 ms RTTd: 0.123 ms Loss: 0.000 %)",
			want: map[string]string{
				"gateway.event":          "alarm_cleared",
				"gateway.name":           "TEST_GATEWAY",
				"gateway.address":        "192.0.2.100",
				"gateway.alarm.previous": "down",
				"gateway.alarm.current":  "none",
				"gateway.rtt_ms":         "1.234",
				"gateway.rttd_ms":        "0.123",
				"gateway.loss_percent":   "0.000",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseDPinger(dpingerEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseDPinger(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestDPingerDelayAlarmTransitions: dpinger's third alarm state (#641) — the
// latency threshold breached without the gateway going down. Distinguishable
// from a down alarm via gateway.alarm.current, not folded into it.
//
// Sanitized from a live-box capture for #641, 2026-08-04 (the real monitored
// address, a public DNS resolver, is replaced below with a documentation
// address; the gateway name and RTT/loss figures are unchanged):
//
//	MONITOR: WAN_DHCP (Addr: 203.0.113.53 Alarm: none -> delay RTT: 201.2 ms RTTd: 29.6 ms Loss: 0.0 %)
//	MONITOR: WAN_DHCP (Addr: 203.0.113.53 Alarm: delay -> none RTT: 199.9 ms RTTd: 63.2 ms Loss: 0.0 %)
func TestDPingerDelayAlarmTransitions(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "delay alarm started",
			msg:  "MONITOR: WAN_DHCP (Addr: 203.0.113.53 Alarm: none -> delay RTT: 201.2 ms RTTd: 29.6 ms Loss: 0.0 %)",
			want: map[string]string{
				"gateway.event":          "alarm_started",
				"gateway.name":           "WAN_DHCP",
				"gateway.address":        "203.0.113.53",
				"gateway.alarm.previous": "none",
				"gateway.alarm.current":  "delay",
				"gateway.rtt_ms":         "201.2",
				"gateway.rttd_ms":        "29.6",
				"gateway.loss_percent":   "0.0",
			},
		},
		{
			name: "delay alarm cleared",
			msg:  "MONITOR: WAN_DHCP (Addr: 203.0.113.53 Alarm: delay -> none RTT: 199.9 ms RTTd: 63.2 ms Loss: 0.0 %)",
			want: map[string]string{
				"gateway.event":          "alarm_cleared",
				"gateway.name":           "WAN_DHCP",
				"gateway.address":        "203.0.113.53",
				"gateway.alarm.previous": "delay",
				"gateway.alarm.current":  "none",
				"gateway.rtt_ms":         "199.9",
				"gateway.rttd_ms":        "63.2",
				"gateway.loss_percent":   "0.0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseDPinger(dpingerEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseDPinger(%q) returned ok=false", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestDPingerLifecycleLines: the three lifecycle shapes bracketing a dpinger
// restart or SIGHUP reconfigure (#668). All three captured verbatim on the
// camden testbed and cross-checked live against
// /opt/opnsense2otel/capture/syslog/*.ndjson on 2026-08-07 (program dpinger,
// subsystem gateways) — not sanitized, since none of these lines carry a WAN
// address; "8.8.4.4" / "81.187.237.31" are the box's own configured
// dest_addr/bind_addr for its AAISP_PPPOE gateway monitor, and the identifier
// is a gateway name, not a secret.
func TestDPingerLifecycleLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "exiting on signal",
			msg:  "exiting on signal 15",
			want: map[string]string{
				"gateway.event":  "watcher_stopped",
				"gateway.signal": "15",
			},
		},
		{
			name: "SIGHUP reload",
			msg:  "Reloaded gateway watcher configuration on SIGHUP",
			want: map[string]string{
				"gateway.event": "watcher_reloaded",
			},
		},
		{
			// The two-space field separator and the quoted identifier's
			// trailing space inside the quotes (`"AAISP_PPPOE "`) are both
			// load-bearing here: upstream's padding, not a capture artifact.
			name: "startup config line",
			msg:  `send_interval 1000ms  loss_interval 4000ms  time_period 60000ms  report_interval 0ms  data_len 1  alert_interval 1000ms  latency_alarm 0ms  loss_alarm 0%  alarm_hold 10000ms  dest_addr 8.8.4.4  bind_addr 81.187.237.31  identifier "AAISP_PPPOE "`,
			want: map[string]string{
				"gateway.event":              "watcher_started",
				"gateway.name":               "AAISP_PPPOE",
				"gateway.address":            "8.8.4.4",
				"gateway.bind_address":       "81.187.237.31",
				"gateway.latency_alarm_ms":   "0",
				"gateway.loss_alarm_percent": "0",
				"gateway.alarm_hold_ms":      "10000",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseDPinger(dpingerEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseDPinger(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

func TestDPingerEventVocabularyIsClosed(t *testing.T) {
	const gateway = "branch-gateway-42"
	const address = "198.51.100.42"
	const msg = "MONITOR: " + gateway + " (Addr: " + address + " Alarm: none -> down RTT: 7.500 ms RTTd: 0.125 ms Loss: 25.000 %)"

	rec, ok := parseDPinger(dpingerEnv(t, msg), nil, func(string) {})
	if !ok {
		t.Fatal("parseDPinger() returned ok=false")
	}
	if got := rec.Attributes["gateway.event"]; got != "alarm_started" {
		t.Errorf("gateway.event = %q, want closed value %q", got, "alarm_started")
	}
	for _, dynamic := range []string{gateway, address, "none", "down", "7.500", "0.125", "25.000"} {
		if got := rec.Attributes["gateway.event"]; got == dynamic {
			t.Errorf("gateway.event = dynamic value %q", got)
		}
	}
}

func TestDPingerUnknownOrMalformedTransitionsDegradeToGeneric(t *testing.T) {
	tests := []string{
		"MONITOR: TEST_GATEWAY (Address: 192.0.2.100 Alarm: none -> down RTT: 1000.000 ms RTTd: 12.345 ms Loss: 100.000 %)",
		"MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: none -> down RTT: 1000.000 ms RTTd: 12.345 ms",
		"MONITOR: TEST_GATEWAY (Addr: 192.0.2.100 Alarm: none -> degraded RTT: 1000.000 ms RTTd: 12.345 ms Loss: 100.000 %)",
		"exiting on signal",
		"Reloaded gateway watcher configuration",
		// single-space separator instead of the real two-space one, and an
		// unquoted identifier: both must fail to match, not partially match.
		`send_interval 1000ms loss_interval 4000ms time_period 60000ms report_interval 0ms data_len 1 alert_interval 1000ms latency_alarm 0ms loss_alarm 0% alarm_hold 10000ms dest_addr 8.8.4.4 bind_addr 81.187.237.31 identifier AAISP_PPPOE`,
	}

	for _, msg := range tests {
		t.Run(strings.ReplaceAll(msg, " ", "_"), func(t *testing.T) {
			env := dpingerEnv(t, msg)
			rec, parsed := buildRecord(env, nil, func(string) {})
			if parsed {
				t.Fatalf("buildRecord(%q) parsed an unsupported dpinger shape", msg)
			}
			if rec.Body != msg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
			}
			assertAttrs(t, rec, map[string]string{"program": "dpinger"})
			assertNoAttrs(t, rec, "gateway.event", "gateway.name", "gateway.address")
		})
	}
}
