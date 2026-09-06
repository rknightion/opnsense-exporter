package syslog

import (
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

func radvdEnv(msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "radvd",
		Facility:  3,
		Severity:  6, // info
		Message:   msg,
	}
}

// radvdSnapshot: ixl0_vlan100 is a known VLAN interface; ixl0 is not (an unknown
// device is normal and must not signal a miss).
func radvdSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		IfaceNames: map[string]string{
			"ixl0_vlan100": "IOT",
		},
	}
}

func TestRadvdRegistered(t *testing.T) {
	if _, ok := parserFor("radvd"); !ok {
		t.Fatal("no parser registered for program radvd")
	}
}

// TestRadvdVerbatimLines covers the four shapes captured verbatim from the live
// box: polling and timer_handler, each on a VLAN sub-interface and a bare
// interface.
func TestRadvdVerbatimLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "polling, VLAN sub-interface",
			msg:  "polling for 27.344 second(s), next iface is ixl0_vlan100",
			want: map[string]string{
				"radvd.event":            "polling",
				"interface":              "ixl0_vlan100",
				"interface.name":         "IOT",
				"radvd.interval_seconds": "27.344",
			},
		},
		{
			name: "polling, bare interface",
			msg:  "polling for 51.757 second(s), next iface is ixl0",
			want: map[string]string{
				"radvd.event":            "polling",
				"interface":              "ixl0",
				"radvd.interval_seconds": "51.757",
			},
		},
		{
			name: "timer_handler, VLAN sub-interface",
			msg:  "timer_handler called for ixl0_vlan100",
			want: map[string]string{
				"radvd.event":    "timer",
				"interface":      "ixl0_vlan100",
				"interface.name": "IOT",
			},
		},
		{
			name: "timer_handler, bare interface",
			msg:  "timer_handler called for ixl0",
			want: map[string]string{
				"radvd.event": "timer",
				"interface":   "ixl0",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseRadvd(radvdEnv(tc.msg), radvdSnapshot(), func(string) {})
			if !ok {
				t.Fatalf("parseRadvd returned ok=false for %q", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message", rec.Body)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestRadvdIntervalOnlyOnPolling: radvd.interval_seconds is present on polling
// lines and absent on timer lines.
func TestRadvdIntervalOnlyOnPolling(t *testing.T) {
	rec, ok := parseRadvd(radvdEnv("timer_handler called for ixl0"), radvdSnapshot(), func(string) {})
	if !ok {
		t.Fatal("ok=false")
	}
	assertNoAttrs(t, rec, "radvd.interval_seconds")
}

// TestRadvdInterfaceNameEnrichment: a known device resolves interface.name; an
// unknown one leaves it absent.
func TestRadvdInterfaceNameEnrichment(t *testing.T) {
	rec, ok := parseRadvd(radvdEnv("polling for 27.344 second(s), next iface is ixl0_vlan100"), radvdSnapshot(), func(string) {})
	if !ok {
		t.Fatal("ok=false")
	}
	assertAttrs(t, rec, map[string]string{"interface.name": "IOT"})

	rec, ok = parseRadvd(radvdEnv("polling for 51.757 second(s), next iface is ixl0"), radvdSnapshot(), func(string) {})
	if !ok {
		t.Fatal("ok=false")
	}
	assertNoAttrs(t, rec, "interface.name")
}

// TestRadvdNonMatchingLineDegrades: a radvd line not matching either shape
// returns ok=false so BuildRecord ships it as a generic record.
func TestRadvdNonMatchingLineDegrades(t *testing.T) {
	if _, ok := parseRadvd(radvdEnv("version 2.19 started"), nil, func(string) {}); ok {
		t.Error("parseRadvd returned ok=true for a non-matching line, want a generic-record fallthrough")
	}
}
