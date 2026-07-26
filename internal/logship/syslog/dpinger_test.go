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
