package syslog

import (
	"strings"
	"testing"
	"time"
)

// tailscaledDaemonEnvelope is the daemon(8)-forwarded route: the rc script passes
// `-t tailscaled -T tailscaled -s info -l daemon`, so app-name tailscaled, facility
// daemon(3), severity info(6).
func tailscaledDaemonEnvelope(message string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		Hostname:  "fixture-firewall",
		Program:   "tailscaled",
		PID:       "47318",
		Facility:  3,
		Severity:  6,
		Message:   message,
	}
}

// TestTailscaleWithoutTheDIsStillTheVPNSubsystem covers the SECOND app-name the
// Tailscale plugin puts on the wire. Its rc script also logs under `tailscale` —
// no trailing `d` — via `logger -s -t tailscale` ("Enabling Exit node mode",
// "Opting out of client logging telemetry."), and `subsystems` had an entry for
// `tailscaled` only, so those lines shipped with an EMPTY opnsense_subsystem.
//
// Neither line is a tunnel transition, so this is attribution, not lifecycle: no
// parser is registered for the program and none should be. It gets a subsystem so
// the records land in the same bucket a reader filtering `subsystem=vpn` expects,
// instead of in the unattributed pile.
//
// Not caught by TestEveryParserProgramHasAFamilyDecision, which reasons over
// REGISTERED PARSER programs — `tailscale` has no parser, so nothing was looking.
func TestTailscaleWithoutTheDIsStillTheVPNSubsystem(t *testing.T) {
	for _, program := range []string{"tailscale", "tailscaled"} {
		if got := subsystemFor(program); got != "vpn" {
			t.Errorf("subsystemFor(%q) = %q, want \"vpn\"", program, got)
		}
	}
}

// tailscaledLoggerEnvelope is the rc-script route: `logger -s -t tailscaled`, whose
// default priority is user.notice — a different facility from the daemon's own
// lines, on the same app-name.
func tailscaledLoggerEnvelope(message string) Envelope {
	env := tailscaledDaemonEnvelope(message)
	env.Facility, env.Severity = 1, 5
	return env
}

func TestTailscaledRegisteredForItsProgram(t *testing.T) {
	if _, ok := parserFor("tailscaled"); !ok {
		t.Fatal("no parser registered for tailscaled")
	}
}

// The ipn state transition is the node-local lifecycle edge (#596). ipnlocal
// returns early when oldState == newState, so the line only ever describes a real
// transition.
func TestParseTailscaledIPNStateTransitions(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantEvent string // "" means the line must stay generic
	}{
		{
			name:      "the node comes up",
			message:   `Switching ipn state Starting -> Running (WantRunning=true, nm=true)`,
			wantEvent: "established",
		},
		{
			name:      "tailscale down",
			message:   `Switching ipn state Running -> Stopped (WantRunning=false, nm=true)`,
			wantEvent: "terminated",
		},
		{
			name:      "the node key expired or was logged out",
			message:   `Switching ipn state Running -> NeedsLogin (WantRunning=true, nm=true)`,
			wantEvent: "terminated",
		},
		{
			name:    "first boot, never logged in",
			message: `Switching ipn state NoState -> NeedsLogin (WantRunning=false, nm=false)`,
		},
		{
			name:    "login accepted, not yet up",
			message: `Switching ipn state NeedsLogin -> Starting (WantRunning=true, nm=false)`,
		},
		{
			name:    "coming back from stopped, not yet up",
			message: `Switching ipn state Stopped -> Starting (WantRunning=true, nm=true)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseTailscaled(tailscaledDaemonEnvelope(tt.message), nil, nil)
			if tt.wantEvent == "" {
				if ok {
					t.Fatalf("parseTailscaled claimed a transition that is neither an "+
						"establishment nor a termination: %q", tt.message)
				}
				return
			}
			if !ok {
				t.Fatalf("parseTailscaled returned ok=false for a confirmed shape: %q", tt.message)
			}
			assertAttr(t, rec, "vpn.backend", "tailscale")
			assertAttr(t, rec, "vpn.event", tt.wantEvent)
			assertAttr(t, rec, "vpn.result", "success")
			if rec.Body != tt.message {
				t.Errorf("body = %q, want the message verbatim", rec.Body)
			}
		})
	}
}

// tailscaled prepends its OWN Go-log timestamp when stderr is not a terminal, which
// is exactly the daemon(8) case, so the syslog body carries a second timestamp
// before the message. TS_DEBUG_LOG_TIME adds microseconds. The native --syslog flag
// (not in the version FreeBSD packages) sets log flags to 0 and carries none.
func TestParseTailscaledToleratesItsOwnTimestampPrefix(t *testing.T) {
	for _, prefix := range []string{"", "2026/07/31 12:34:56 ", "2026/07/31 12:34:56.123456 "} {
		message := prefix + `Switching ipn state Starting -> Running (WantRunning=true, nm=true)`
		rec, ok := parseTailscaled(tailscaledDaemonEnvelope(message), nil, nil)
		if !ok {
			t.Fatalf("parseTailscaled returned ok=false for prefix %q", prefix)
		}
		assertAttr(t, rec, "vpn.event", "established")
	}
}

// The service-stop teardown line, emitted by the rc script's poststop. It is the
// ONLY lifecycle line present on a stock OPNsense box, because tailscaled's own
// output is opt-in. It does not double-count with the ipn line: LocalBackend's
// Shutdown never enters a new ipn state, so a `service tailscaled stop` produces no
// `Switching ipn state` line at all.
func TestParseTailscaledServiceStopTeardown(t *testing.T) {
	rec, ok := parseTailscaled(tailscaledLoggerEnvelope(`Destroying tailscale0 adapter`), nil, nil)
	if !ok {
		t.Fatal("parseTailscaled returned ok=false for the rc-script teardown line")
	}
	assertAttr(t, rec, "vpn.backend", "tailscale")
	assertAttr(t, rec, "vpn.event", "terminated")
	assertAttr(t, rec, "vpn.result", "success")

	// The device name is configurable (tailscaled_tun_dev), so it must not be anchored.
	if _, ok := parseTailscaled(tailscaledLoggerEnvelope(`Destroying ts0 adapter`), nil, nil); !ok {
		t.Error("parseTailscaled anchored on the default tun device name")
	}
}

// Everything else tailscaled says stays generic, and each exclusion has a reason —
// see tailscaled.go.
func TestParseTailscaledLeavesUncapturedLinesGeneric(t *testing.T) {
	messages := []string{
		// The rate limiter's synthetic summary. It QUOTES the format string of the very
		// line this parser matches, so a loose regex would read a suppression notice as a
		// state transition.
		`[RATELIMIT] format("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)") (3 dropped)`,
		`2026/07/31 12:34:56 [RATELIMIT] format("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)")`,
		// A state name outside ipn.State's closed seven. Neither side may be trusted from
		// the wire: an unrecognised name must not become an event, in either direction.
		`Switching ipn state Bananas -> Running (WantRunning=true, nm=true)`,
		`Switching ipn state Running -> Bananas (WantRunning=true, nm=true)`,
		// The underlay, not the tunnel: the ipn state stays Running through a WAN flap.
		`magicsock: SetNetworkUp(false)`,
		`magicsock: home is now derp-10 (lhr)`,
		`magicsock: closing connection to derp-10 (network-down), age 4m12s`,
		`magicsock: derp-10 connected; connGen=3`,
		// Process start/stop and control-plane chatter.
		`Program starting: v1.98.10, Go 1.26.0: []string{"/usr/local/bin/tailscaled"}`,
		`control: setPaused(true)`,
		`health(warnable=not-in-map-poll): error: Some peers are advertising routes but are not connected.`,
		// The destroy FAILED, so the tunnel device's state is unknown. Counting it as a
		// termination would assert something the line denies.
		`Failed to destroy tailscale0 adapter`,
		// Shape-adjacent lines.
		`Switching ipn state Running -> Stopped`,
		`Switching ipn state Running (WantRunning=false, nm=true)`,
		`Destroying tailscale0`,
		`Destroying tailscale0 adapter now`,
	}
	for _, message := range messages {
		if _, ok := parseTailscaled(tailscaledDaemonEnvelope(message), nil, nil); ok {
			t.Errorf("parseTailscaled claimed a line outside the confirmed grammar: %q", message)
		}
	}
}

// The parser writes the vpn triple and nothing else. The transition's endpoints and
// the WantRunning/nm flags stay in the body: a second, unconsumed tailscale.state.*
// vocabulary would be a dimension nothing reads, and the peer telemetry this box
// could name belongs to the poll lane, not here.
func TestParseTailscaledNeverExtractsNodeOrPeerState(t *testing.T) {
	rec, ok := parseTailscaled(tailscaledDaemonEnvelope(
		`Switching ipn state Running -> Stopped (WantRunning=false, nm=true)`), nil, nil)
	if !ok {
		t.Fatal("parseTailscaled returned ok=false for the confirmed terminated shape")
	}
	assertNoAttrs(t, rec,
		"tailscale.state", "tailscale.state.previous", "tailscale.state.current",
		"tailscale.want_running", "tailscale.node", "tailscale.peer", "vpn.connection",
	)
	for key, value := range rec.Attributes {
		if strings.Contains(value, "WantRunning") {
			t.Errorf("attribute %q=%q copied the flag list out of the body", key, value)
		}
	}
}

func TestTailscaledKeepsBodyEnrichment(t *testing.T) {
	if !parserEnrichesBody("tailscaled") {
		t.Error("tailscaled opted out of body enrichment; its lines would lose peer.* and interface.name")
	}
}
