package syslog

import (
	"fmt"
	"testing"
)

func TestCapturedDPingerTransitions(t *testing.T) {
	for _, tc := range []struct{ tag, previous, current, event string }{
		{"MONITOR", "none", "loss", "alarm_started"},
		{"ALERT", "loss", "down", "alarm_changed"},
		{"ALERT", "down", "loss", "alarm_changed"},
		{"ALERT", "down", "none", "alarm_cleared"},
		{"MONITOR", "loss", "none", "alarm_cleared"},
	} {
		t.Run(tc.previous+"_"+tc.current, func(t *testing.T) {
			msg := fmt.Sprintf("%s: TEST_GATEWAY (Addr: 192.0.2.1 Alarm: %s -> %s RTT: 12.5 ms RTTd: 1.2 ms Loss: 25.0 %%)", tc.tag, tc.previous, tc.current)
			rec, ok := parseDPinger(Envelope{Program: "dpinger", Message: msg}, nil, nil)
			if !ok {
				t.Fatal("captured alarm transition was not parsed")
			}
			assertAttrs(t, rec, map[string]string{"gateway.alarm.previous": tc.previous, "gateway.alarm.current": tc.current, "gateway.event": tc.event, "gateway.loss_percent": "25.0"})
		})
	}
	for _, edge := range []string{"loss -> unexpected", "loss -> loss", "delay -> down"} {
		msg := fmt.Sprintf("MONITOR: TEST_GATEWAY (Addr: 192.0.2.1 Alarm: %s RTT: 12.5 ms RTTd: 1.2 ms Loss: 25.0 %%)", edge)
		if _, ok := parseDPinger(Envelope{Program: "dpinger", Message: msg}, nil, nil); ok {
			t.Fatalf("unobserved edge claimed: %s", edge)
		}
	}
}
