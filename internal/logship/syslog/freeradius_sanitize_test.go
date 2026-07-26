package syslog

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"
)

var freeRADIUSCanaries = []string{
	"radius-host-canary",
	"radius-user-canary",
	"radius-password-canary",
	"radius-client-canary",
	"radius-nas-canary",
	"02:ca:na:ry:00:01",
	"198.51.100.47",
	"radius-reply-canary",
	"radius-structured-canary",
}

func freeRADIUSEnvelope(message string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		Hostname:  "radius-host-canary",
		Program:   "radiusd",
		PID:       "7001",
		Facility:  10,
		Severity:  6,
		Message:   message,
	}
}

func freeRADIUSRaw(message string) []byte {
	return []byte(`<86>1 2026-07-26T12:00:00Z radius-host-canary radiusd 7001 - [radius@32473 marker="radius-structured-canary" username="radius-user-canary" password="radius-password-canary" client="radius-client-canary" nas="radius-nas-canary" mac="02:ca:na:ry:00:01" ip="198.51.100.47" reply="radius-reply-canary"] ` + message)
}

func assertFreeRADIUSCanariesAbsent(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		for _, canary := range freeRADIUSCanaries {
			if strings.Contains(value, canary) {
				t.Errorf("unsafe output contains canary %q: %q", canary, value)
			}
		}
	}
}

// TestSanitizeFreeRADIUS_RedactsTheEntireRecognizedEnvelope pins the privacy
// boundary before any parser, generic enrichment, or debug-capture consumer can
// inspect a radiusd frame. The two Login shapes are the normal-service shapes
// captured for #407; the surrounding distinct values are deliberate leak canaries.
func TestSanitizeFreeRADIUS_RedactsTheEntireRecognizedEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{name: "access accept", message: `Login OK: [radius-user-canary] (from client radius-client-canary port 0 cli 02:ca:na:ry:00:01)`},
		{name: "access reject", message: `Login incorrect (No Auth-Type found: rejecting the user via Post-Auth-Type = Reject): [radius-user-canary/radius-password-canary] (from client radius-client-canary port 0 cli 02:ca:na:ry:00:01)`},
		{name: "unrecognised radiusd support message", message: `Ignoring request from NAS radius-nas-canary at 198.51.100.47: radius-reply-canary`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := freeRADIUSEnvelope(tt.message)
			raw := freeRADIUSRaw(tt.message)
			originalEnv := env
			originalRaw := append([]byte(nil), raw...)

			safeEnv, safeRaw, recognized := sanitizeFreeRADIUS(env, raw)
			if !recognized {
				t.Fatal("sanitizeFreeRADIUS() recognized = false, want true for radiusd")
			}
			if !reflect.DeepEqual(env, originalEnv) || !bytes.Equal(raw, originalRaw) {
				t.Fatal("sanitizeFreeRADIUS() mutated its input envelope or raw frame")
			}
			if safeEnv.Program != "radiusd" {
				t.Errorf("safe program = %q, want radiusd so parser dispatch remains possible", safeEnv.Program)
			}
			if safeEnv.Hostname != "" || safeEnv.PID != "" {
				t.Errorf("safe envelope retains wire identity: host=%q pid=%q", safeEnv.Hostname, safeEnv.PID)
			}
			if bytes.Equal(safeRaw, raw) {
				t.Error("safe raw frame is byte-identical to unsafe input")
			}
			if strings.Contains(string(safeRaw), "[") {
				t.Errorf("safe raw frame retains RFC5424 structured data: %q", safeRaw)
			}
			assertFreeRADIUSCanariesAbsent(t, safeEnv.Hostname, safeEnv.PID, safeEnv.Message, string(safeRaw))

			againEnv, againRaw, againRecognized := sanitizeFreeRADIUS(safeEnv, safeRaw)
			if !againRecognized {
				t.Fatal("sanitizeFreeRADIUS(safe value) recognized = false, want true")
			}
			if !reflect.DeepEqual(againEnv, safeEnv) || !bytes.Equal(againRaw, safeRaw) {
				t.Errorf("sanitizeFreeRADIUS is not idempotent: second env=%+v raw=%q, first env=%+v raw=%q", againEnv, againRaw, safeEnv, safeRaw)
			}
		})
	}
}

func TestSanitizeFreeRADIUS_LeavesOtherProgramsUntouched(t *testing.T) {
	env := freeRADIUSEnvelope("Login OK: radius-user-canary")
	env.Program = "sshd"
	raw := freeRADIUSRaw(env.Message)
	wantEnv := env
	wantRaw := append([]byte(nil), raw...)

	gotEnv, gotRaw, recognized := sanitizeFreeRADIUS(env, raw)
	if recognized {
		t.Fatal("sanitizeFreeRADIUS() recognized = true for sshd, want false")
	}
	if !reflect.DeepEqual(gotEnv, wantEnv) || !bytes.Equal(gotRaw, wantRaw) {
		t.Errorf("unrecognized program changed: env=%+v raw=%q, want env=%+v raw=%q", gotEnv, gotRaw, wantEnv, wantRaw)
	}
}

func TestSanitizeMalformedFreeRADIUS_EmptyInputIsNotRecognized(t *testing.T) {
	env, raw, recognized := sanitizeMalformedFreeRADIUS(nil, time.Now())
	if recognized {
		t.Fatal("empty input recognized as FreeRADIUS")
	}
	if !reflect.DeepEqual(env, Envelope{}) || raw != nil {
		t.Fatalf("empty input changed: env=%+v raw=%q", env, raw)
	}
}
