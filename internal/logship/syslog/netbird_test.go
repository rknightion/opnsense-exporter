package syslog

import (
	"strings"
	"testing"
	"time"
)

// netbirdDaemonEnvelope is the daemon's OWN route, and the app-name is the whole
// point: `/usr/local/bin/netbird`, not `netbird`. Captured from the enrolled devel
// testbed on 2026-07-31 (#601) — 4,817 of the 4,888 retained lines carry it.
//
// Facility/severity are what the capture shows: `<6>` on every daemon line, i.e.
// kern(0)/info(6). That is not a mistake in this fixture — logrus's syslog hook is
// created with `syslog.LOG_INFO` and no facility bits (util/syslog_nonwindows.go:17),
// and 0 | LOG_INFO is facility 0. Nothing in this parser reads either field.
func netbirdDaemonEnvelope(message string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC),
		Hostname:  "fixture-firewall",
		Program:   netbirdDaemonProgram,
		PID:       "95047",
		Facility:  0,
		Severity:  6,
		Message:   message,
	}
}

// netbirdRCEnvelope is the rc script's `logger -s -t netbird` route: app-name
// `netbird`, logger(1)'s default user.notice priority.
func netbirdRCEnvelope(message string) Envelope {
	env := netbirdDaemonEnvelope(message)
	env.Program = "netbird"
	env.Facility, env.Severity = 1, 5
	return env
}

// TestNetbirdDaemonAppNameIsTheVPNSubsystem is the attribution half, and it is a bug
// fix rather than a new feature: `subsystems` held `netbird` only, so
// subsystemFor("/usr/local/bin/netbird") returned EMPTY and every one of the daemon's
// lines shipped unattributed. The `netbird` entry reached exactly one line in 18 days
// of capture (`Starting netbird.`).
//
// That is the same class of miss as `tailscale` without the trailing `d` (#596), with
// a worse blast radius: it also means the Tunnel lifecycle annotation's
// `opnsense_subsystem=~"vpn|ipsec"` filter could not select netbird records even as a
// denominator, so the "wide regex keeps the gap observable" argument did not hold for
// netbird until this entry existed.
func TestNetbirdDaemonAppNameIsTheVPNSubsystem(t *testing.T) {
	for _, program := range []string{netbirdDaemonProgram, "netbird"} {
		if got := subsystemFor(program); got != "vpn" {
			t.Errorf("subsystemFor(%q) = %q, want \"vpn\"", program, got)
		}
	}
}

// The parser is registered for the DAEMON app-name only. The rc script's app-name
// carries no transition — `Starting netbird.` is the only line of it observed in 18
// days — so it gets attribution and deliberately no parser, exactly as `tailscale`
// (no `d`) does.
func TestNetbirdRegisteredForItsWireAppNameOnly(t *testing.T) {
	if _, ok := parserFor(netbirdDaemonProgram); !ok {
		t.Fatalf("no parser registered for %q", netbirdDaemonProgram)
	}
	if _, ok := parserFor("netbird"); ok {
		t.Error("a parser is registered for `netbird`; that app-name carries only the " +
			"rc script's service-start notice, which is not a tunnel transition")
	}
}

// The engine lifecycle pair. Both ends come from ONE function — the backoff-retried
// closure in client/internal/connect.go — and `stopped NetBird client` sits strictly
// downstream of `Netbird engine started`, so a termination can never be minted
// without a preceding establishment.
func TestParseNetbirdEngineLifecycle(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantEvent string
	}{
		{
			name:      "the overlay comes up and the interface holds an address",
			message:   `Netbird engine started, the IP is: 100.64.0.5/16`,
			wantEvent: "established",
		},
		{
			name:      "the connect loop finished tearing the engine down",
			message:   `stopped NetBird client`,
			wantEvent: "terminated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseNetbird(netbirdDaemonEnvelope(tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseNetbird returned ok=false for a captured shape: %q", tt.message)
			}
			assertAttr(t, rec, "vpn.backend", "netbird")
			assertAttr(t, rec, "vpn.event", tt.wantEvent)
			assertAttr(t, rec, "vpn.result", "success")
			if rec.Body != tt.message {
				t.Errorf("body = %q, want the message verbatim", rec.Body)
			}
		})
	}
}

// The establishment line is anchored on its literal prefix, never on the address
// shape: the overlay address is IPv4/CIDR today but it is `peerConfig.GetAddress()`,
// a management-supplied string this parser must not constrain.
func TestParseNetbirdEstablishedDoesNotAnchorOnTheAddress(t *testing.T) {
	for _, address := range []string{"100.64.0.5/16", "100.64.0.5", "fixture-unset", ""} {
		message := `Netbird engine started, the IP is: ` + address
		if _, ok := parseNetbird(netbirdDaemonEnvelope(message), nil, nil); !ok {
			t.Errorf("parseNetbird returned ok=false for address %q", address)
		}
	}
}

// Every exclusion here is a line the live capture actually contains, and each has a
// reason written down in netbird.go. This is the churn question #601 posed, answered
// against the capture rather than against upstream source alone.
func TestParseNetbirdLeavesUncapturedLinesGeneric(t *testing.T) {
	messages := []string{
		// DOUBLE-LOGGED, twice per teardown, from two call sites (connect.go's post-cancel
		// Stop and the daemon server's down path, which upstream itself flags with a TODO).
		// Observed 2/2 on all four teardowns in the capture, same PID, same second.
		`stopped Netbird Engine`,
		// The DAEMON process lifecycle, not the overlay. Six of these pairs in the capture
		// happened while the box was unenrolled and no tunnel ever came up.
		`starting NetBird service`,
		`stopped NetBird service`,
		`starting NetBird client`,
		// Peer-level, and the lazy-connection idle timer drives them: the capture shows
		// `lazy connection manager is enabled by management feature flag` and
		// `inactivity threshold configured: 15m0s`, so the close/open pair recurs on an
		// idle-but-healthy peer.
		`[peer: fixture-peer-key=] set ICE to active connection`,
		`[peer: fixture-peer-key=] close peer connection`,
		`[peer: fixture-peer-key=] peer connection closed`,
		`[peer: fixture-peer-key=] peer added to lazy conn manager`,
		`[peer: fixture-peer-key=] adding peer to inactivity manager`,
		`[peer: fixture-peer-key=] closing activity listener (LazyConn)`,
		`[peer: fixture-peer-key=] first wg handshake detected within: 1.2sec, (2026-07-31 12:00:00 +0100 BST)`,
		`[peer: fixture-peer-key=] connection succeeded with offer session: fixture-session`,
		// Control-plane reachability, which is not the tunnel — and the daemon says in the
		// line itself that it is retrying, so neither is a teardown.
		`connected to the Management Service stream`,
		`disconnected from the Management service but will retry silently. Reason: rpc error: code = Unavailable desc = keepalive ping failed to receive ACK within timeout`,
		`reconnected to Signal or Relay server`,
		`[relay: rels://fixture-relay.example.net:443] relay connection established`,
		`[relay: rels://fixture-relay.example.net:443] relay connection closed`,
		// Login refusal on an unenrolled box: 248 of these in the capture, and not one of
		// them is a tunnel event in either direction.
		`failed to login to Management Service: rpc error: code = PermissionDenied desc = no peer auth method provided, please use a setup key or interactive SSO login`,
		// Interface plumbing. It reports a step of the teardown, not its completion, and
		// `stopped NetBird client` already covers the event it belongs to.
		`ensuring wg interface is removed, Netbird engine context cancelled`,
		`interface wt0 has been removed`,
		`create tun interface`,
		// Shape-adjacent lines that must not be read as the real ones.
		`Netbird engine started`,
		`Netbird engine starting, the IP is: 100.64.0.5/16`,
		`stopped NetBird clients`,
		`not stopped NetBird client`,
	}
	for _, message := range messages {
		if _, ok := parseNetbird(netbirdDaemonEnvelope(message), nil, nil); ok {
			t.Errorf("parseNetbird claimed a line outside the confirmed grammar: %q", message)
		}
	}
}

// The rc script's own app-name has no parser, so its lines must stay generic through
// the real dispatch path too — not merely be unclaimed by parseNetbird.
func TestNetbirdRCScriptLineStaysGeneric(t *testing.T) {
	rec, parsed := buildRecord(netbirdRCEnvelope(`Starting netbird.`), nil, nil)
	if parsed {
		t.Error("the rc script's service-start notice was parsed as a structured record")
	}
	assertAttr(t, rec, "opnsense.subsystem", "vpn")
	assertNoAttrs(t, rec, "vpn.event", "vpn.backend", "vpn.result")
}

// The contract is the code-defined backend/event/result triple and nothing else. The
// overlay address stays in the body, which ships verbatim; a netbird.* vocabulary
// would be a dimension nothing reads, and peer identity is out of scope by the
// standing boundary against this exporter owning peer-level VPN data.
func TestParseNetbirdNeverExtractsPeerOrOverlayIdentity(t *testing.T) {
	rec, ok := parseNetbird(netbirdDaemonEnvelope(
		`Netbird engine started, the IP is: 100.64.0.5/16`), nil, nil)
	if !ok {
		t.Fatal("parseNetbird returned ok=false for the confirmed established shape")
	}
	assertNoAttrs(t, rec,
		"netbird.address", "netbird.peer", "netbird.engine", "netbird.state",
		"vpn.connection", "vpn.peer",
	)
	for key, value := range rec.Attributes {
		if strings.Contains(value, "100.64.0.5") {
			t.Errorf("attribute %q=%q copied the overlay address out of the body", key, value)
		}
	}
}

func TestNetbirdKeepsBodyEnrichment(t *testing.T) {
	if !parserEnrichesBody(netbirdDaemonProgram) {
		t.Errorf("%s opted out of body enrichment; its lines would lose the peer.* and "+
			"interface.name attributes they carried while they were generic",
			netbirdDaemonProgram)
	}
}
