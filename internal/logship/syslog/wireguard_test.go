package syslog

import (
	"strings"
	"testing"
	"time"
)

// wireguardCanaries are the identity-bearing values that appear in the confirmed
// `wireguard` lines and must never reach a record attribute this parser writes, nor
// a metric label. The instance NAME is admin-chosen deployment identity and the
// device is resolved by the existing generic interface enrichment, not by this
// parser. The raw body still ships verbatim, as it does for every program.
var wireguardCanaries = []string{"fixture-site-to-site"}

func wireguardEnvelope(message string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		Hostname:  "fixture-firewall",
		Program:   "wireguard",
		PID:       "41522",
		// OPNsense's wg-service-control.php opens syslog with LOG_AUTH and logs at
		// LOG_NOTICE: openlog("wireguard", LOG_ODELAY, LOG_AUTH) plus syslog(LOG_NOTICE,…).
		Facility: 4,
		Severity: 5,
		Message:  message,
	}
}

func TestWireGuardRegisteredForItsProgram(t *testing.T) {
	if _, ok := parserFor("wireguard"); !ok {
		t.Fatal("no parser registered for wireguard")
	}
}

// The three service-lifecycle grammars confirmed in OPNsense core's
// wg-service-control.php (#596), byte-identical on master and on stable/26.7,
// stable/26.1 and stable/25.7.
func TestParseWireGuardServiceLifecycleShapes(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantEvent string
	}{
		{
			name:      "instance started",
			message:   `wireguard instance fixture-site-to-site (wg1) started`,
			wantEvent: "established",
		},
		{
			name:      "instance stopped",
			message:   `wireguard instance fixture-site-to-site (wg1) stopped`,
			wantEvent: "terminated",
		},
		{
			name:      "CARP promotion brings the instance up",
			message:   `wireguard instance fixture-site-to-site (wg1) switching to UP`,
			wantEvent: "established",
		},
		{
			name:      "CARP demotion takes the instance down",
			message:   `wireguard instance fixture-site-to-site (wg1) switching to DOWN`,
			wantEvent: "terminated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseWireGuard(wireguardEnvelope(tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseWireGuard returned ok=false for a confirmed shape: %q", tt.message)
			}
			assertAttr(t, rec, "vpn.backend", "wireguard")
			assertAttr(t, rec, "vpn.event", tt.wantEvent)
			// Every confirmed grammar is an intended administrative or CARP transition,
			// never a failure: the script logs failures through a different path (see the
			// Shell.php case in TestParseWireGuardLeavesUncapturedLinesGeneric).
			assertAttr(t, rec, "vpn.result", "success")
			if rec.Body != tt.message {
				t.Errorf("body = %q, want the message verbatim", rec.Body)
			}
			assertWireGuardAttributesCarryNoIdentity(t, rec.Attributes)
		})
	}
}

// The instance name is free text an administrator typed, and the device number is
// whatever OPNsense assigned. Neither may be anchored on.
func TestParseWireGuardToleratesAnyInstanceNameAndDevice(t *testing.T) {
	messages := []string{
		`wireguard instance wg0 (wg0) started`,
		`wireguard instance Road Warriors (wg12) started`,
		`wireguard instance site_2-site.eu (wg3) started`,
	}
	for _, message := range messages {
		rec, ok := parseWireGuard(wireguardEnvelope(message), nil, nil)
		if !ok {
			t.Fatalf("parseWireGuard returned ok=false for %q", message)
		}
		assertAttr(t, rec, "vpn.event", "established")
	}
}

// Everything else that reaches app-name `wireguard` stays generic. Each of these is
// a real line the confirmed producers emit, and each is excluded for a stated
// reason rather than overlooked — see wireguard.go.
func TestParseWireGuardLeavesUncapturedLinesGeneric(t *testing.T) {
	messages := []string{
		// The CARP traceability line: reports the CURRENT status on every configure
		// event, whether or not anything changed, so it is not a transition.
		`Wireguard configure event instance fixture-site-to-site (wg1) vhid: 1 carp: MASTER interface: up`,
		// Announces that the reconfigure needs a restart; the script then calls wg_start,
		// which logs the `started` line this parser already counts.
		`wireguard instance fixture-site-to-site (wg1) can not reconfigure without stopping it first.`,
		// A failing shell command, logged under this app-name because Shell.php inherits
		// the ident wg-service-control.php opened. Not a tunnel transition.
		`/usr/local/opnsense/scripts/wireguard/wg-service-control.php: The command </sbin/ifconfig wg create name wg1> returned exit code 1 and the output was ""`,
		// The kernel driver's per-peer handshake lines. They arrive under app-name
		// `kernel`, never `wireguard`, and are IFF_DEBUG-gated — but a parser that
		// matched them would turn the annotation layer into a solid wall of markers,
		// because a healthy peer rekeys every ~120s. See wireguard.go.
		`wg1: Sending handshake initiation to peer 3`,
		`wg1: Receiving handshake response from peer 3`,
		`wg1: Handshake for peer 3 did not complete after 5 seconds, retrying (try 2)`,
		`wg1: Peer 3 created`,
		`wg1: Peer 3 destroyed`,
		// Shape-adjacent lines that must not be forced into the vocabulary.
		`wireguard instance fixture-site-to-site (wg1) switching to up`,
		`wireguard instance fixture-site-to-site (wg1) restarted`,
		`wireguard instance (wg1) started`,
		`instance fixture-site-to-site (wg1) started`,
		`wireguard instance fixture-site-to-site (wg1) started now`,
	}
	for _, message := range messages {
		if _, ok := parseWireGuard(wireguardEnvelope(message), nil, nil); ok {
			t.Errorf("parseWireGuard claimed a line outside the confirmed grammar: %q", message)
		}
	}
}

// The confirmed lines carry the admin-chosen instance name and the tunnel device.
// Neither becomes an attribute this parser writes: the metric contract needs only
// the code-defined backend/event/result, the device is resolved by the generic
// interface enrichment this parser opts into, and the body ships verbatim.
func TestParseWireGuardNeverExtractsInstanceIdentity(t *testing.T) {
	rec, ok := parseWireGuard(wireguardEnvelope(`wireguard instance fixture-site-to-site (wg1) started`), nil, nil)
	if !ok {
		t.Fatal("parseWireGuard returned ok=false for the confirmed started shape")
	}
	assertWireGuardAttributesCarryNoIdentity(t, rec.Attributes)
	assertNoAttrs(t, rec,
		"wireguard.instance", "wireguard.instance_id", "wireguard.interface",
		"wireguard.peer", "vpn.connection", "ipsec.connection", "openvpn.instance",
	)
}

// The parser keeps the generic body scan (it extracts no address of its own), so a
// `wireguard` line must still gain the interface resolution it carried while it was
// generic. deviceRe already matches `wg\d+`.
func TestWireGuardKeepsBodyEnrichment(t *testing.T) {
	if !parserEnrichesBody("wireguard") {
		t.Error("wireguard opted out of body enrichment; its lines would lose interface.name")
	}
}

func assertWireGuardAttributesCarryNoIdentity(t *testing.T, attrs map[string]string) {
	t.Helper()
	for key, value := range attrs {
		for _, canary := range wireguardCanaries {
			if strings.Contains(value, canary) {
				t.Errorf("attribute %q=%q carries identity canary %q", key, value, canary)
			}
		}
	}
}
