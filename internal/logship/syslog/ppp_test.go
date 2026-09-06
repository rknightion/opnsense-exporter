package syslog

import (
	"strings"
	"testing"
	"time"
)

func pppEnv(t *testing.T, message string) Envelope {
	t.Helper()

	// Framing lifted from the same #631 capture window, program tag "ppp".
	env, err := ParseEnvelope([]byte("<134>1 2026-07-27T09:12:03Z test-firewall ppp 39598 - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestPPPRegistered(t *testing.T) {
	if _, ok := parserFor("ppp"); !ok {
		t.Fatal("no parser registered for program ppp")
	}
}

func TestPPPCapturedShapes(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "link up event",
			msg:  "[opt7_link0] Link: UP event",
			want: map[string]string{
				"ppp.event": "link_up",
				"ppp.link":  "opt7_link0",
			},
		},
		{
			name: "link down event",
			msg:  "[opt7_link0] Link: DOWN event",
			want: map[string]string{
				"ppp.event": "link_down",
				"ppp.link":  "opt7_link0",
			},
		},
		{
			name: "iface up event",
			msg:  "[opt7] IFACE: Up event",
			want: map[string]string{
				"ppp.event":  "iface_up",
				"ppp.bundle": "opt7",
			},
		},
		{
			name: "iface down event",
			msg:  "[opt7] IFACE: Down event",
			want: map[string]string{
				"ppp.event":  "iface_down",
				"ppp.bundle": "opt7",
			},
		},
		{
			name: "ppp-linkup script executing inet",
			msg:  "ppp-linkup: executing on pppoe0 for inet",
			want: map[string]string{
				"ppp.event":          "iface_up",
				"ppp.interface":      "pppoe0",
				"ppp.address_family": "inet",
			},
		},
		{
			name: "ppp-linkdown script executing inet6",
			msg:  "ppp-linkdown: executing on pppoe0 for inet6",
			want: map[string]string{
				"ppp.event":          "iface_down",
				"ppp.interface":      "pppoe0",
				"ppp.address_family": "inet6",
			},
		},
		{
			name: "reconnection attempt bare",
			msg:  "[opt7_link0] Link: reconnection attempt 1",
			want: map[string]string{
				"ppp.event":         "reconnecting",
				"ppp.link":          "opt7_link0",
				"ppp.retry_attempt": "1",
			},
		},
		{
			name: "reconnection attempt with delay",
			msg:  "[opt7_link0] Link: reconnection attempt 1 in 3 seconds",
			want: map[string]string{
				"ppp.event":               "reconnecting",
				"ppp.link":                "opt7_link0",
				"ppp.retry_attempt":       "1",
				"ppp.retry_delay_seconds": "3",
			},
		},
		{
			name: "bundle status singular link",
			msg:  "[opt7] Bundle: Status update: up 1 link, total bandwidth 64000 bps",
			want: map[string]string{
				"ppp.event":         "bundle_status",
				"ppp.bundle":        "opt7",
				"ppp.links_up":      "1",
				"ppp.bandwidth_bps": "64000",
			},
		},
		{
			name: "bundle status plural links",
			msg:  "[opt7] Bundle: Status update: up 0 links, total bandwidth 9600 bps",
			want: map[string]string{
				"ppp.event":         "bundle_status",
				"ppp.bundle":        "opt7",
				"ppp.links_up":      "0",
				"ppp.bandwidth_bps": "9600",
			},
		},
		{
			name: "LCP state change",
			msg:  "[opt7_link0] LCP: state change Ack-Sent --> Opened",
			want: map[string]string{
				"ppp.event":          "negotiation_state_change",
				"ppp.protocol":       "LCP",
				"ppp.link":           "opt7_link0",
				"ppp.state.previous": "Ack-Sent",
				"ppp.state.current":  "Opened",
			},
		},
		{
			name: "IPCP state change",
			msg:  "[opt7] IPCP: state change Req-Sent --> Ack-Sent",
			want: map[string]string{
				"ppp.event":          "negotiation_state_change",
				"ppp.protocol":       "IPCP",
				"ppp.bundle":         "opt7",
				"ppp.state.previous": "Req-Sent",
				"ppp.state.current":  "Ack-Sent",
			},
		},
		{
			name: "IPV6CP state change",
			msg:  "[opt7] IPV6CP: state change Starting --> Req-Sent",
			want: map[string]string{
				"ppp.event":          "negotiation_state_change",
				"ppp.protocol":       "IPV6CP",
				"ppp.bundle":         "opt7",
				"ppp.state.previous": "Starting",
				"ppp.state.current":  "Req-Sent",
			},
		},
		{
			name: "LCP terminate request received",
			msg:  "[opt7_link0] LCP: rec'd Terminate Request #0 (Opened)",
			want: map[string]string{
				"ppp.event":          "terminate_requested",
				"ppp.protocol":       "LCP",
				"ppp.link":           "opt7_link0",
				"ppp.state.previous": "Opened",
			},
		},
		{
			name: "IPCP send terminate request",
			msg:  "[opt7] IPCP: SendTerminateReq #4",
			want: map[string]string{
				"ppp.event":    "terminate_requested",
				"ppp.protocol": "IPCP",
				"ppp.bundle":   "opt7",
			},
		},
		{
			name: "IPV6CP send terminate request",
			msg:  "[opt7] IPV6CP: SendTerminateReq #2",
			want: map[string]string{
				"ppp.event":    "terminate_requested",
				"ppp.protocol": "IPV6CP",
				"ppp.bundle":   "opt7",
			},
		},
		{
			name: "PPPoE connection successful",
			msg:  "[opt7_link0] PPPoE: connection successful",
			want: map[string]string{
				"ppp.event": "session_established",
				"ppp.link":  "opt7_link0",
			},
		},
		{
			name: "PPPoE connection closed",
			msg:  "[opt7_link0] PPPoE: connection closed",
			want: map[string]string{
				"ppp.event": "session_closed",
				"ppp.link":  "opt7_link0",
			},
		},
		{
			name: "PPPoE can't connect failure",
			msg:  `[opt7_link0] PPPoE: can't connect "[2db79]:"->"mpd39598-0" and "[2db77]:"->"left": No such file or directory`,
			want: map[string]string{
				"ppp.event": "session_failed",
				"ppp.link":  "opt7_link0",
				"ppp.error": `can't connect "[2db79]:"->"mpd39598-0" and "[2db77]:"->"left": No such file or directory`,
			},
		},
		{
			name: "LCP authorization successful",
			msg:  "[opt7_link0] LCP: authorization successful",
			want: map[string]string{
				"ppp.event": "auth_success",
				"ppp.link":  "opt7_link0",
			},
		},
		{
			name: "IPv4 address assigned",
			msg:  "[opt7]   203.0.113.31 -> 198.51.100.187",
			want: map[string]string{
				"ppp.event":         "address_assigned",
				"ppp.bundle":        "opt7",
				"ppp.address.local": "203.0.113.31",
				"ppp.address.peer":  "198.51.100.187",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parsePPP(pppEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parsePPP(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestPPPIPv6InterfaceIdentifierIsNotAnAddress covers the format ambiguity in the
// capture: mpd emits the SAME "<a> -> <b>" bracketed shape for an assigned WAN
// address and for an IPv6 interface-identifier pair. The identifier form is 4 hex
// groups with no "::" — neither side is a parseable IP — so this line must NOT be
// reported as address_assigned, and (since nothing else about the line is
// meaningful) must fall through to a generic record entirely.
func TestPPPIPv6InterfaceIdentifierIsNotAnAddress(t *testing.T) {
	const msg = "[opt7]   9ab7:85ff:fe21:aff2 -> 9e89:1eff:fe2e:0000"

	env := pppEnv(t, msg)
	rec, parsed := buildRecord(env, nil, func(string) {})
	if parsed {
		t.Fatalf("buildRecord(%q) parsed an interface-identifier pair as an address", msg)
	}
	if rec.Body != msg {
		t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
	}
	assertNoAttrs(t, rec, "ppp.event", "ppp.address.local", "ppp.address.peer")
}

// Diagnostic protocol observations and known negotiation details are distinct
// from the session/lease events the original PPP parser produces. In particular,
// CHAP peer text must not be turned into an outcome or identity attribute.
func TestPPPDiagnosticsDoNotBecomeSessionEvents(t *testing.T) {
	tests := []string{
		`PPPoE: rec'd ACNAME "acc-aln3.elh"`,
		"[opt7]     198.51.100.187 is OK",
		"[opt7]   COMPPROTO VJCOMP, 16 comp. channels, no comp-cid",
		"[opt7] IFACE: Rename interface ng0 to pppoe0",
		`[opt7]   IPADDR 0.0.0.0`,
		`[opt7_link0]   AUTHPROTO CHAP MD5`,
		`[opt7_link0] CHAP: Using authname "rk83@a.1"`,
		"[opt7_link0] CHAP: rec'd CHALLENGE #1 len: 70",
		"[opt7_link0] CHAP: rec'd SUCCESS #1 len: 26",
		"[opt7_link0] CHAP: sending RESPONSE #1 len: 29",
		"[opt7_link0] LCP: Down event",
		"[opt7_link0] LCP: LayerDown",
		"[opt7_link0] LCP: LayerUp",
		"[opt7_link0] LCP: SendConfigAck #37",
		"[opt7_link0] LCP: SendConfigReq #4",
		"[opt7_link0] LCP: SendTerminateAck #3",
		"[opt7_link0] LCP: Up event",
		"[opt7_link0] LCP: auth: peer wants CHAP, I want nothing",
		"[opt7_link0] LCP: rec'd Configure Ack #5 (Ack-Sent)",
		`[opt7_link0] Link: Join bundle "opt7"`,
		`[opt7_link0] Link: Leave bundle "opt7"`,
		`[opt7_link0] Link: Matched action 'bundle "opt7" ""'`,
		"[opt7_link0]   MAGICNUM 0x478cdd1c",
		"[opt7_link0]   MESG: BBEU71092990 999999000",
		"[opt7_link0]   MRU 1500",
		`[opt7_link0]   Name: "acc-aln3.elh"`,
		"[opt7_link0] PPPoE: Connecting to ''",
		"[opt7_link0] PPPoE: Set PPP-Max-Payload to '1500'",
		"[opt7_link0] PPPoE: rec'd PPP-Max-Payload '1500'",
		"[opt7_link0]   PROTOCOMP",
		`[opt7_link0] can't remove hook mpd39598-0 from node "[2db79]:": No such file or directory`,
		"[opt7_link0] rec'd proto IP during terminate phase",
		"[opt7] Bundle: No NCPs left. Closing links...",
		// A malformed variant of a modelled shape must not partially match.
		"[opt7_link0] Link: reconnection attempt",
		"totally unrelated ppp chatter with no bracket at all",
	}

	for _, msg := range tests {
		t.Run(strings.ReplaceAll(msg, " ", "_"), func(t *testing.T) {
			env := pppEnv(t, msg)
			if _, parsed := parsePPP(env, nil, nil); parsed {
				t.Fatal("primary PPP parser claimed a diagnostic as a session event")
			}
			rec, _ := buildRecord(env, nil, func(string) {})
			if observeDerived(&fakeSink{}, "ppp", rec.Attributes) {
				t.Fatal("PPP diagnostic derived a metric")
			}
			if rec.Body != msg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
			}
			assertNoAttrs(t, rec, "ppp.event",
				"ppp.state.previous", "ppp.state.current", "ppp.retry_attempt",
				"ppp.retry_delay_seconds", "ppp.links_up", "ppp.bandwidth_bps",
				"ppp.address.local", "ppp.address.peer", "ppp.interface",
				"ppp.address_family", "ppp.error")
		})
	}
}

// TestPPPNeverEmitsAuthname is the privacy gate from #631: the CHAP authname is
// subscriber-identifying and must never reach an attribute value, even though the
// surrounding LCP authorization-success line IS parsed. This walks every attribute
// value on both the modelled and unmodelled captured lines and fails if the
// authname literal shows up anywhere.
func TestPPPNeverEmitsAuthname(t *testing.T) {
	const authname = "rk83@a.1"

	lines := []string{
		"[opt7_link0] LCP: authorization successful",
		`[opt7_link0] CHAP: Using authname "rk83@a.1"`,
		`[opt7_link0]   Name: "acc-aln3.elh"`,
		"[opt7_link0]   MAGICNUM 0x478cdd1c",
		"[opt7_link0]   MESG: BBEU71092990 999999000",
	}

	for _, msg := range lines {
		env := pppEnv(t, msg)
		rec, _ := buildRecord(env, nil, func(string) {})
		for k, v := range rec.Attributes {
			if strings.Contains(v, authname) {
				t.Errorf("line %q: attribute %q = %q leaked the CHAP authname", msg, k, v)
			}
		}
		if strings.Contains(rec.Body, authname) && rec.Attributes["ppp.event"] != "" {
			t.Errorf("line %q: authname present in body of a STRUCTURED record (ppp.event=%q)", msg, rec.Attributes["ppp.event"])
		}
	}
}
