package syslog

import (
	"strings"
	"testing"
	"time"
)

// openvpnCanaries are the identity-bearing values present in the captured OpenVPN
// server lines. None may reach a record attribute this parser writes, nor a metric
// label. The raw body still ships verbatim, as it does for every program.
var openvpnCanaries = []string{
	"fixture-user",
	"fixture-untrusted",
	"192.0.2.2",
	"11940",
	"1111111111111111",
}

func openvpnEnvelope(program, message string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		Hostname:  "fixture-firewall",
		Program:   program,
		PID:       "1",
		Facility:  3,
		Severity:  5,
		Message:   message,
	}
}

// OPNsense names one syslog program PER CONFIGURED INSTANCE, so no exact-match
// registration can reach them; the parser is registered on the `openvpn` prefix.
func TestOpenVPNRegisteredForEveryInstanceProgramName(t *testing.T) {
	for _, program := range []string{"openvpn_server40", "openvpn_client2", "openvpn", "openvpn_server1"} {
		if _, ok := parserFor(program); !ok {
			t.Errorf("no parser registered for program %q", program)
		}
	}
}

// The four canonical shapes captured on OPNsense 27.1.a_40 with the OPNsense
// OpenVPN SERVER package 2.7.5 (#406). The retained bundle mislabelled these
// "OpenVPN 2.6.14" — that was the Debian test CLIENT; `pkg info openvpn` on the
// box reported 2.7.5, and every template below is a server-side line.
func TestParseOpenVPNCapturedLifecycleShapes(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantEvent string
		wantResp  string
	}{
		{
			name:      "peer connection initiated",
			message:   `udp4:192.0.2.2:11940 [fixture-user] Peer Connection Initiated with [AF_INET]192.0.2.2:11940`,
			wantEvent: "established",
			wantResp:  "success",
		},
		{
			name:      "AUTH_FAILED sent to the client",
			message:   `udp4:192.0.2.2:11940 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)`,
			wantEvent: "authentication_failed",
			wantResp:  "failure",
		},
		{
			name:      "client certificate verification failed",
			message:   `udp4:192.0.2.2:11940 VERIFY ERROR: depth=0, error=self-signed certificate: CN=fixture-untrusted, serial=1111111111111111`,
			wantEvent: "certificate_failed",
			wantResp:  "failure",
		},
		{
			name:      "peer ping-restart disconnect",
			message:   `fixture-user/udp4:192.0.2.2:11940 SIGUSR1[soft,ping-restart] received, client-instance restarting`,
			wantEvent: "terminated",
			wantResp:  "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseOpenVPN returned ok=false for a captured shape: %q", tt.message)
			}
			assertAttr(t, rec, "vpn.backend", "openvpn")
			assertAttr(t, rec, "vpn.event", tt.wantEvent)
			assertAttr(t, rec, "vpn.result", tt.wantResp)
			if rec.Body != tt.message {
				t.Errorf("body = %q, want the message verbatim", rec.Body)
			}
			assertOpenVPNAttributesCarryNoIdentity(t, rec.Attributes)
		})
	}
}

// DERIVED FROM SOURCE, NOT CAPTURED. Only [AF_INET] was observed on the testbed —
// the client was IPv4. [AF_INET6] is OpenVPN's own address-family tag for the same
// `Peer Connection Initiated with` message, so this pins parser tolerance for an
// IPv6 peer rather than a captured payload. Without it an IPv6 roadwarrior's
// `established` would silently never be counted. Do not read this case as evidence
// that the IPv6 form was seen on a box.
func TestParseOpenVPNAcceptsTheIPv6AddressFamilyTag(t *testing.T) {
	message := `udp6:[2001:db8::2]:11940 [fixture-user] Peer Connection Initiated with [AF_INET6]2001:db8::2:11940`
	rec, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", message), nil, nil)
	if !ok {
		t.Fatalf("parseOpenVPN returned ok=false for the IPv6 family tag: %q", message)
	}
	assertAttr(t, rec, "vpn.backend", "openvpn")
	assertAttr(t, rec, "vpn.event", "established")
	assertAttr(t, rec, "vpn.result", "success")
}

// VERIFY ERROR is matched on OpenVPN's actual format string — `depth=<n>, error=`
// — not on the bare prefix. Expired, revoked and depth-N rejections are all the
// same event class and all match; a line that merely mentions the words does not.
// Neither the depth nor the error text is captured.
func TestParseOpenVPNCertificateFailureMatchesTheFormatStringOnly(t *testing.T) {
	matching := []string{
		`udp4:192.0.2.2:11940 VERIFY ERROR: depth=0, error=self-signed certificate: CN=fixture-untrusted, serial=1111111111111111`,
		`udp4:192.0.2.2:11940 VERIFY ERROR: depth=1, error=certificate has expired: CN=fixture-untrusted`,
		`udp4:192.0.2.2:11940 VERIFY ERROR: depth=0, error=certificate revoked: CN=fixture-untrusted`,
	}
	for _, message := range matching {
		rec, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", message), nil, nil)
		if !ok {
			t.Fatalf("parseOpenVPN returned ok=false for %q", message)
		}
		assertAttr(t, rec, "vpn.event", "certificate_failed")
		assertOpenVPNAttributesCarryNoIdentity(t, rec.Attributes)
		assertNoAttrs(t, rec, "openvpn.verify_depth", "openvpn.verify_error")
	}
	notMatching := []string{
		`udp4:192.0.2.2:11940 VERIFY ERROR: could not extract Common Name`,
		`udp4:192.0.2.2:11940 mentioning VERIFY ERROR: depth=0, error=x in prose`,
	}
	for _, message := range notMatching {
		if _, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", message), nil, nil); ok {
			t.Errorf("parseOpenVPN claimed a line outside the VERIFY ERROR format string: %q", message)
		}
	}
}

// These were all captured as REAL supporting lines beside the four canonical
// shapes, and every one is deliberately left generic. The tls-error signal matters
// most: only the ping-restart variant was captured as a genuine peer disconnect,
// so mapping SIGUSR1[soft,tls-error] to `terminated` would count a control-channel
// failure as a session that ended.
func TestParseOpenVPNLeavesCapturedSupportingLinesGeneric(t *testing.T) {
	messages := []string{
		`fixture-user/udp4:192.0.2.2:11940 SIGUSR1[soft,tls-error] received, client-instance restarting`,
		`udp4:192.0.2.2:11940 SIGTERM[soft,delayed-exit] received, client-instance exiting`,
		`udp4:192.0.2.2:11940 TLS Error: TLS handshake failed`,
		`udp4:192.0.2.2:11940 TLS Error: TLS object -> incoming plaintext read error`,
		`fixture-user/udp4:192.0.2.2:11940 Inactivity timeout (--ping-restart), restarting`,
	}
	for _, message := range messages {
		if _, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", message), nil, nil); ok {
			t.Errorf("parseOpenVPN claimed a supporting line that must stay generic: %q", message)
		}
	}
}

// Nothing outside the captured four is inferred. `SENT CONTROL` with any other
// control string, a successful verify, MULTI/MANAGEMENT bookkeeping and the daemon
// lifecycle all stay generic.
func TestParseOpenVPNLeavesUncapturedLinesGeneric(t *testing.T) {
	messages := []string{
		`udp4:192.0.2.2:11940 SENT CONTROL [fixture-user]: 'PUSH_REPLY,route 10.0.0.0 255.255.255.0' (status=1)`,
		`udp4:192.0.2.2:11940 SENT CONTROL [UNDEF]: 'RESTART' (status=1)`,
		`udp4:192.0.2.2:11940 VERIFY OK: depth=0, CN=fixture-user`,
		`fixture-user/udp4:192.0.2.2:11940 MULTI_sva: pool returned IPv4=10.8.0.2, IPv6=(Not enabled)`,
		`MANAGEMENT: Client connected from /var/etc/openvpn/instance-6f86d5cd-0000-4000-8000-000000000000.sock`,
		`Initialization Sequence Completed`,
		`Peer Connection Initiated with [AF_INET]192.0.2.2:11940`,
		`event_wait : Interrupted system call (fd=-1,code=4)`,
	}
	for _, message := range messages {
		if _, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", message), nil, nil); ok {
			t.Errorf("parseOpenVPN claimed an uncaptured line: %q", message)
		}
	}
}

// The captured lines carry a username, a certificate CN and serial, and the peer's
// address and port. The parser extracts NONE of them.
func TestParseOpenVPNNeverExtractsUsernameCertificateOrAddress(t *testing.T) {
	for _, message := range []string{
		`udp4:192.0.2.2:11940 [fixture-user] Peer Connection Initiated with [AF_INET]192.0.2.2:11940`,
		`udp4:192.0.2.2:11940 VERIFY ERROR: depth=0, error=self-signed certificate: CN=fixture-untrusted, serial=1111111111111111`,
		`fixture-user/udp4:192.0.2.2:11940 SIGUSR1[soft,ping-restart] received, client-instance restarting`,
	} {
		rec, ok := parseOpenVPN(openvpnEnvelope("openvpn_server40", message), nil, nil)
		if !ok {
			t.Fatalf("parseOpenVPN returned ok=false for a captured shape: %q", message)
		}
		assertOpenVPNAttributesCarryNoIdentity(t, rec.Attributes)
		assertNoAttrs(t, rec,
			"user.name", "openvpn.username", "openvpn.common_name", "openvpn.cert_serial",
			"openvpn.peer_address", "openvpn.peer_port", "openvpn.error", "openvpn.instance_id",
			"peer.ip", "peer.2.ip",
		)
	}
}

func assertOpenVPNAttributesCarryNoIdentity(t *testing.T, attrs map[string]string) {
	t.Helper()
	for key, value := range attrs {
		for _, canary := range openvpnCanaries {
			if strings.Contains(value, canary) {
				t.Errorf("attribute %q=%q carries identity canary %q", key, value, canary)
			}
		}
	}
}
