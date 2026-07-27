package syslog

import (
	"strings"
	"testing"
	"time"
)

// charonIkeID is the connection identifier strongSwan stamps on an IKE_SA line.
// On OPNsense it is the `ikeid` UUID from ipsec/sessions/search_phase1 (see
// tunnels.go), which is why the retained sanitized templates rendered it as the
// placeholder token `UUID` — the wire value is a UUID and is never a label.
const charonIkeID = "5e891b0c-ca13-4e38-a7c0-a2aa891c30b4"

// charonCanaries are the identity-bearing values that appear in the captured
// charon lines and must never reach a record attribute this parser writes, nor a
// metric label. The raw body still ships verbatim, as it does for every program.
var charonCanaries = []string{
	"fixture-local-id",
	"fixture-remote-id",
	"192.0.2.1",
	"192.0.2.2",
	charonIkeID,
}

func charonEnvelope(message string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		Hostname:  "fixture-firewall",
		Program:   "charon",
		PID:       "1",
		Facility:  3,
		Severity:  6,
		Message:   message,
	}
}

func TestCharonRegisteredForItsProgram(t *testing.T) {
	if _, ok := parserFor("charon"); !ok {
		t.Fatal("no parser registered for charon")
	}
}

// The four canonical shapes captured on OPNsense 27.1.a_40 with strongSwan 6.0.7
// (#406). The strongSwan message prefix is a thread number plus a subsystem tag
// (00[ENC], 14[IKE], …); the thread number varies freely between lines for the
// same event, so every case here uses a different one on purpose.
func TestParseCharonCapturedLifecycleShapes(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantEvent string
		wantResp  string
	}{
		{
			name:      "generated IKE_AUTH response carrying AUTH_FAILED",
			message:   `00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]`,
			wantEvent: "authentication_failed",
			wantResp:  "failure",
		},
		{
			name:      "IKE_SA established",
			message:   `14[IKE] <` + charonIkeID + `|1> IKE_SA ` + charonIkeID + `[1] established between 192.0.2.1[fixture-local-id]...192.0.2.2[fixture-remote-id]`,
			wantEvent: "established",
			wantResp:  "success",
		},
		{
			name:      "giving up after retransmits",
			message:   `10[IKE] <` + charonIkeID + `|1> giving up after 5 retransmits`,
			wantEvent: "liveness_failed",
			wantResp:  "failure",
		},
		{
			name:      "IKE_SA deleted",
			message:   `07[IKE] <` + charonIkeID + `|1> IKE_SA deleted`,
			wantEvent: "terminated",
			wantResp:  "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseCharon(charonEnvelope(tt.message), nil, nil)
			if !ok {
				t.Fatalf("parseCharon returned ok=false for a captured shape: %q", tt.message)
			}
			assertAttr(t, rec, "vpn.backend", "ipsec")
			assertAttr(t, rec, "vpn.event", tt.wantEvent)
			assertAttr(t, rec, "vpn.result", tt.wantResp)
			if rec.Body != tt.message {
				t.Errorf("body = %q, want the message verbatim", rec.Body)
			}
			assertCharonAttributesCarryNoIdentity(t, rec.Attributes)
		})
	}
}

// The thread number is a strongSwan thread id, not a fixed token: a parser that
// anchors on 00[IKE] silently stops counting the moment the daemon is busy.
func TestParseCharonToleratesAnyThreadNumberAndSubsystemTag(t *testing.T) {
	for _, prefix := range []string{"00[IKE]", "07[IKE]", "14[IKE]", "9[IKE]", "128[IKE]", "05[CFG]", "11[NET]"} {
		message := prefix + ` <` + charonIkeID + `|1> IKE_SA deleted`
		rec, ok := parseCharon(charonEnvelope(message), nil, nil)
		if !ok {
			t.Fatalf("parseCharon returned ok=false for prefix %q", prefix)
		}
		assertAttr(t, rec, "vpn.event", "terminated")
	}
}

func TestParseCharonAcceptsAnyRetransmitCount(t *testing.T) {
	for _, count := range []string{"1", "5", "12"} {
		message := `10[IKE] <` + charonIkeID + `|1> giving up after ` + count + ` retransmits`
		rec, ok := parseCharon(charonEnvelope(message), nil, nil)
		if !ok {
			t.Fatalf("parseCharon returned ok=false for %q", message)
		}
		assertAttr(t, rec, "vpn.event", "liveness_failed")
		assertNoAttr(t, rec, "ipsec.retransmits")
	}
}

// AUTH_FAILED is counted whenever it rides in a GENERATED IKE_AUTH response's
// payload list, not only when it is the sole payload: requiring the exact
// single-notify list would silently drop a real authentication failure that
// happened to carry another notify alongside it.
//
// `generating` is still required, so this stays RESPONDER-side: the box rejected a
// peer. The initiator-side form — `parsed IKE_AUTH response … N(AUTH_FAILED)`,
// meaning OUR credentials were rejected by the far end — is a genuinely different
// event and was NOT captured, so it is deliberately not counted here. A future
// capture should add it as its own case rather than assume it was overlooked.
func TestParseCharonAuthFailedInAnyGeneratedResponsePayloadList(t *testing.T) {
	matching := []string{
		`00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]`,
		`00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ IDr N(AUTH_FAILED) ]`,
		`00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 2 [ N(AUTH_FAILED) N(TS_UNACCEPTABLE) ]`,
	}
	for _, message := range matching {
		rec, ok := parseCharon(charonEnvelope(message), nil, nil)
		if !ok {
			t.Fatalf("parseCharon returned ok=false for %q", message)
		}
		assertAttr(t, rec, "vpn.event", "authentication_failed")
		assertAttr(t, rec, "vpn.result", "failure")
	}

	notMatching := []string{
		// Initiator side: our credentials rejected by the peer. Not captured, and a
		// different event — must not fold into the responder-side counter.
		`00[ENC] <` + charonIkeID + `|1> parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]`,
		// A successful IKE_AUTH response carries no AUTH_FAILED notify at all.
		`00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ IDr AUTH SA TSi TSr ]`,
		// A different exchange entirely.
		`00[ENC] <` + charonIkeID + `|1> generating INFORMATIONAL response 3 [ N(AUTH_FAILED) ]`,
		// AUTH_FAILED as a substring of another token must not match.
		`00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ N(AUTH_FAILED_SOMETHING) ]`,
	}
	for _, message := range notMatching {
		if _, ok := parseCharon(charonEnvelope(message), nil, nil); ok {
			t.Errorf("parseCharon claimed an uncaptured AUTH_FAILED variant: %q", message)
		}
	}
}

// Everything else charon says stays generic. These are real strongSwan lines that
// LOOK adjacent to the captured vocabulary — a CHILD_SA establishment, a rekey, a
// DPD probe, a config load — and none of them was captured as one of the four
// events, so none may be inferred into one.
func TestParseCharonLeavesUncapturedLinesGeneric(t *testing.T) {
	messages := []string{
		`14[IKE] <` + charonIkeID + `|1> CHILD_SA fixture-child{1} established with SPIs c0ffee01_i deadbeef_o and TS 10.0.0.0/24 === 10.0.1.0/24`,
		`10[IKE] <` + charonIkeID + `|1> sending DPD request`,
		`10[IKE] <` + charonIkeID + `|1> retransmit 3 of request with message ID 12`,
		`14[IKE] <` + charonIkeID + `|1> IKE_SA fixture-conn[1] rekeyed between 192.0.2.1[fixture-local-id]...192.0.2.2[fixture-remote-id]`,
		`07[IKE] <` + charonIkeID + `|1> deleting IKE_SA`,
		`00[ENC] <` + charonIkeID + `|1> generating IKE_AUTH response 1 [ IDr AUTH SA TSi TSr ]`,
		`00[CFG] loaded IKE_SA config fixture-conn`,
		`00[LIB] plugin 'random': loaded successfully`,
		`IKE_SA deleted`,
		`something[IKE] <x|1> IKE_SA deleted`,
	}
	for _, message := range messages {
		if _, ok := parseCharon(charonEnvelope(message), nil, nil); ok {
			t.Errorf("parseCharon claimed an uncaptured line: %q", message)
		}
	}
}

// The captured lines carry an IKE identity, both tunnel endpoint addresses and the
// raw ikeid UUID. None of them may become an attribute this parser writes: nothing
// in the metric contract needs them, and the body already ships verbatim.
func TestParseCharonNeverExtractsIdentityOrAddresses(t *testing.T) {
	message := `14[IKE] <` + charonIkeID + `|1> IKE_SA ` + charonIkeID + `[1] established between 192.0.2.1[fixture-local-id]...192.0.2.2[fixture-remote-id]`
	rec, ok := parseCharon(charonEnvelope(message), nil, nil)
	if !ok {
		t.Fatal("parseCharon returned ok=false for the captured established shape")
	}
	assertCharonAttributesCarryNoIdentity(t, rec.Attributes)
	assertNoAttrs(t, rec,
		"ipsec.local_id", "ipsec.remote_id", "ipsec.local_addr", "ipsec.remote_addr",
		"ipsec.spi", "ipsec.connection_id", "peer.ip", "peer.2.ip", "user.name",
	)
}

func assertCharonAttributesCarryNoIdentity(t *testing.T, attrs map[string]string) {
	t.Helper()
	for key, value := range attrs {
		for _, canary := range charonCanaries {
			if strings.Contains(value, canary) {
				t.Errorf("attribute %q=%q carries identity canary %q", key, value, canary)
			}
		}
	}
}
