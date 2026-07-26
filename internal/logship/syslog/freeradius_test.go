package syslog

import (
	"strings"
	"testing"
)

func TestFreeRADIUS_SanitizedAccessEventsAreStructuredWithoutWireIdentity(t *testing.T) {
	tests := []struct {
		name    string
		message string
		result  string
	}{
		{name: "Login OK", message: `Login OK: [radius-user-canary] (from client radius-client-canary port 0 cli 02:ca:na:ry:00:01)`, result: "accepted"},
		{name: "Login incorrect", message: `Login incorrect (No Auth-Type found: rejecting the user via Post-Auth-Type = Reject): [radius-user-canary/radius-password-canary] (from client radius-client-canary port 0 cli 02:ca:na:ry:00:01)`, result: "rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safeEnv, safeRaw, recognized := sanitizeFreeRADIUS(freeRADIUSEnvelope(tt.message), freeRADIUSRaw(tt.message))
			if !recognized {
				t.Fatal("sanitizer did not recognize radiusd envelope")
			}
			rec := BuildRecord(safeEnv, nil, nil)

			assertAttr(t, rec, "radius.event", "access")
			assertAttr(t, rec, "radius.result", tt.result)
			assertAttr(t, rec, "radius.client_scope", "configured")
			assertAttr(t, rec, "program", "radiusd")
			assertNoAttr(t, rec, "host")
			assertNoAttr(t, rec, "pid")
			for key, value := range rec.Attributes {
				if key != "radius.client_scope" && (strings.Contains(key, "user") || strings.Contains(key, "client") || strings.Contains(key, "nas") || strings.Contains(key, "mac") || strings.Contains(key, ".ip") || strings.Contains(key, "reply")) {
					t.Errorf("record contains wire identity attribute %q=%q", key, value)
				}
				assertFreeRADIUSCanariesAbsent(t, value)
			}
			assertFreeRADIUSCanariesAbsent(t, rec.Body, string(safeRaw))
		})
	}
}

func TestFreeRADIUS_SanitizedUnsupportedMessageStaysGenericAndUncounted(t *testing.T) {
	message := `Accounting Start from radius-client-canary NAS radius-nas-canary 198.51.100.47 radius-reply-canary`
	safeEnv, safeRaw, recognized := sanitizeFreeRADIUS(freeRADIUSEnvelope(message), freeRADIUSRaw(message))
	if !recognized {
		t.Fatal("sanitizer did not recognize radiusd accounting envelope")
	}

	rec := BuildRecord(safeEnv, nil, nil)
	assertNoAttr(t, rec, "radius.event")
	assertNoAttr(t, rec, "radius.result")
	assertFreeRADIUSCanariesAbsent(t, rec.Body, string(safeRaw))
	for key, value := range rec.Attributes {
		if strings.Contains(key, "user") || strings.Contains(key, "client") || strings.Contains(key, "nas") || strings.Contains(key, "mac") || strings.Contains(key, ".ip") || strings.Contains(key, "reply") {
			t.Errorf("generic record contains wire identity attribute %q=%q", key, value)
		}
		assertFreeRADIUSCanariesAbsent(t, value)
	}
}
