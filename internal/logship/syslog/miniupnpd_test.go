package syslog

import (
	"strings"
	"testing"
	"time"
)

// upnpEnv wraps a miniupnpd MSG field in the RFC5424 envelope the production scan
// showed: APP-NAME `miniupnpd`, a PID, and syslog-ng's own sequenceId structured
// data. Severity 5 (`<29>` = daemon.notice) is what 1,595 of the 1,598 production
// records carried; the four error records used `<27>` (daemon.err), and the
// severity-sensitive cases below set that explicitly.
func upnpEnv(t *testing.T, message string) Envelope {
	t.Helper()
	return upnpEnvPri(t, "<29>", message)
}

func upnpEnvPri(t *testing.T, pri, message string) Envelope {
	t.Helper()

	env, err := ParseEnvelope([]byte(pri+"1 2026-07-27T09:41:02+01:00 test-firewall miniupnpd 41210 - "+
		"[meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestUPnPRegistered(t *testing.T) {
	if _, ok := parserFor("miniupnpd"); !ok {
		t.Fatal("no parser registered for program miniupnpd")
	}
}

// Exact-name registration, with body enrichment kept.
//
// Exact rather than a prefix: `miniupnpd` is a fixed app-name (the plugin's
// syslog-ng template names it literally), and a prefix would also claim any future
// program merely starting with those letters.
//
// Body-enriching, because this parser extracts NO address of its own — an event, a
// result, a protocol and two port numbers. Without the opt-in, the generic body scan
// is suppressed for every line this parser matches, silently dropping the peer.* and
// interface.* attributes miniupnpd lines have carried since #250. Same reasoning as
// charon/openvpn in #406 and kernel/CARP in #405.
func TestUPnPRegistrationIsExactAndKeepsBodyEnrichment(t *testing.T) {
	if _, exact := parsers["miniupnpd"]; !exact {
		t.Error("miniupnpd is not registered as an EXACT program name")
	}
	if _, prefixed := parserPrefixes["miniupnpd"]; prefixed {
		t.Error("miniupnpd is registered as a program PREFIX; it is a fixed app-name")
	}
	if !parserEnrichesBody("miniupnpd") {
		t.Error("parserEnrichesBody(\"miniupnpd\") = false; this parser extracts no address " +
			"of its own, so the generic body scan must keep running")
	}
}

// miniupnpd had no subsystem entry at all before #409, so its records shipped with
// an empty `opnsense.subsystem` and no Loki query could select them as a family.
func TestUPnPSubsystem(t *testing.T) {
	if got := subsystemFor("miniupnpd"); got != "upnp" {
		t.Errorf("subsystemFor(\"miniupnpd\") = %q, want %q", got, "upnp")
	}
}

// THE FIVE CAPTURED GRAMMARS. Four come from a strictly read-only scan of
// production (OPNsense 26.7.1_1, miniupnpd 2.3.9_2,1, os-upnp 1.9): 1,598 real
// records over five days, of which 61 are genuine mapping-expiry events. The fifth —
// the redirect-rule cleanup failure — comes from the isolated testbed capture
// (27.1.a_40 / miniupnpd 2.3.9_2,1) and is the same event class as the production
// nat-rule variant, equally self-contained.
//
// A SUCCESSFUL ADD AND A SUCCESSFUL DELETE ARE DELIBERATELY ABSENT. miniupnpd logs
// those at a verbosity neither deployment emits, and no supported os-upnp 1.9 setting
// exposes a log level. No attempt line is treated as proof of success anywhere in
// this file.
func TestUPnPCapturedGrammars(t *testing.T) {
	tests := []struct {
		name string
		pri  string
		msg  string
		want map[string]string
	}{
		{
			// 61 production occurrences. The only real mapping-lifecycle event available.
			name: "expiry udp",
			pri:  "<29>",
			msg:  "remove port mapping 42891 UDP because it has expired",
			want: map[string]string{
				"upnp.event":         "expired",
				"upnp.result":        "ok",
				"upnp.protocol":      "udp",
				"upnp.port.external": "42891",
			},
		},
		{
			// The protocol is a closed two-value vocabulary, lowercased through a map. TCP
			// is not in the production sample (production serves NAT-PMP/PCP, and its
			// clients happened to map UDP), but miniupnpd's own format string emits either.
			name: "expiry tcp",
			pri:  "<29>",
			msg:  "remove port mapping 40119 TCP because it has expired",
			want: map[string]string{
				"upnp.event":         "expired",
				"upnp.result":        "ok",
				"upnp.protocol":      "tcp",
				"upnp.port.external": "40119",
			},
		},
		{
			// 1,527 production occurrences — the dominant record on the box, and the same
			// class #362's original capture found in the unparsed tail.
			name: "nat rule cleanup failure",
			pri:  "<29>",
			msg:  "could not find nat rule to delete iport=42891 addr=Ab3Kd9z",
			want: map[string]string{
				"upnp.event":         "cleanup_failed",
				"upnp.result":        "failure",
				"upnp.port.internal": "42891",
			},
		},
		{
			// #362's capture recorded this shape WITHOUT the addr= token, so the token is
			// optional rather than required. A required token would silently stop matching
			// on whatever build omits it.
			name: "nat rule cleanup failure without addr token",
			pri:  "<29>",
			msg:  "could not find nat rule to delete iport=42891",
			want: map[string]string{
				"upnp.event":         "cleanup_failed",
				"upnp.result":        "failure",
				"upnp.port.internal": "42891",
			},
		},
		{
			// From the isolated testbed capture. Same event class as the nat-rule variant,
			// but it names the EXTERNAL port — miniupnpd's redirect (rdr) rule is keyed on
			// eport where its nat rule is keyed on iport.
			name: "redirect rule cleanup failure",
			pri:  "<29>",
			msg:  "could not find redirect rule to delete eport=40119",
			want: map[string]string{
				"upnp.event":         "cleanup_failed",
				"upnp.result":        "failure",
				"upnp.port.external": "40119",
			},
		},
		{
			// One production occurrence, at daemon.err. PCP is what production actually
			// serves: its generated config has enable_upnp=no and enable_pcp_pmp=yes.
			name: "pcp unauthorized removal",
			pri:  "<27>",
			msg:  "Unauthorized to remove PCP mapping internal port 5353, protocol UDP",
			want: map[string]string{
				"upnp.event":         "unauthorized",
				"upnp.result":        "failure",
				"upnp.protocol":      "udp",
				"upnp.port.internal": "5353",
			},
		},
		{
			// Three production occurrences, at daemon.err.
			name: "lease file error",
			pri:  "<27>",
			msg:  "could not open lease file: /var/run/miniupnpd.leases-ipv4",
			want: map[string]string{
				"upnp.event":  "lease_file_error",
				"upnp.result": "failure",
			},
		},
		{
			name: "lease file error ipv6",
			pri:  "<27>",
			msg:  "could not open lease file: /var/run/miniupnpd.leases-ipv6",
			want: map[string]string{
				"upnp.event":  "lease_file_error",
				"upnp.result": "failure",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseMiniUPnPd(upnpEnvPri(t, tc.pri, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseMiniUPnPd(%q) returned ok=false", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want the message verbatim %q", rec.Body, tc.msg)
			}
		})
	}
}

// THE `addr=` TOKEN AND THE LEASE-FILE PATH ARE NEVER STRUCTURED ATTRIBUTES, and
// therefore can never become labels.
//
// The token is a fixed seven-character alphanumeric in all 1,528 production
// occurrences, not an address literal, so naming it as an attribute would assert a
// meaning the capture does not prove. The lease path is a fixed local path that adds
// no queryability the body does not already have. Both still ship — the body is the
// message verbatim, which the grammar test above asserts.
func TestUPnPOpaqueTokenAndPathAreNotStructured(t *testing.T) {
	cases := []struct{ msg, forbidden string }{
		{"could not find nat rule to delete iport=42891 addr=Ab3Kd9z", "Ab3Kd9z"},
		{"could not open lease file: /var/run/miniupnpd.leases-ipv4", "/var/run/miniupnpd.leases-ipv4"},
	}

	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			rec, ok := parseMiniUPnPd(upnpEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseMiniUPnPd(%q) returned ok=false", tc.msg)
			}
			for k, v := range rec.Attributes {
				if v == tc.forbidden {
					t.Errorf("attribute %q = %q; that value must stay in the body only", k, v)
				}
			}
			if !strings.Contains(rec.Body, tc.forbidden) {
				t.Errorf("Body = %q; it must still carry the raw text", rec.Body)
			}
		})
	}
}

// PORTS ARE ATTRIBUTES AND NEVER LABELS. #409's acceptance requires it: an
// ephemeral port is unbounded, and a per-port series would multiply with every
// client mapping. Asserted at the seam that decides — every value handed to
// ObserveUPnP is checked against the port text on the record.
func TestUPnPPortsAreNeverLabels(t *testing.T) {
	msgs := []string{
		"remove port mapping 42891 UDP because it has expired",
		"could not find nat rule to delete iport=42891 addr=Ab3Kd9z",
		"could not find redirect rule to delete eport=40119",
		"Unauthorized to remove PCP mapping internal port 5353, protocol UDP",
	}

	for _, msg := range msgs {
		t.Run(msg, func(t *testing.T) {
			rec, ok := parseMiniUPnPd(upnpEnv(t, msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseMiniUPnPd(%q) returned ok=false", msg)
			}

			ports := []string{rec.Attributes["upnp.port.external"], rec.Attributes["upnp.port.internal"]}
			if ports[0] == "" && ports[1] == "" {
				t.Fatal("neither port shipped as an attribute; each of these grammars names one")
			}

			sink := &fakeSink{}
			if !observeDerived(sink, "miniupnpd", rec.Attributes) {
				t.Fatal("observeDerived did not count a captured miniupnpd record")
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "upnp" {
				t.Fatalf("calls = %+v, want one upnp call", sink.calls)
			}
			for _, arg := range sink.calls[0].args {
				for _, port := range ports {
					if port != "" && arg == port {
						t.Errorf("label value %q is a port number; ports must never be labels", arg)
					}
				}
			}
		})
	}
}

// The frozen #409 label tuple at the deriver seam: event, result, protocol — in that
// order. protocol is EMPTY on the three grammars that name none, rather than guessed.
func TestObserveDerived_UPnP(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		wantArgs []string
	}{
		{
			name:     "expiry is the only ok result",
			msg:      "remove port mapping 42891 UDP because it has expired",
			wantArgs: []string{"expired", "ok", "udp"},
		},
		{
			name:     "nat cleanup failure names no protocol",
			msg:      "could not find nat rule to delete iport=42891 addr=Ab3Kd9z",
			wantArgs: []string{"cleanup_failed", "failure", ""},
		},
		{
			name:     "redirect cleanup failure names no protocol",
			msg:      "could not find redirect rule to delete eport=40119",
			wantArgs: []string{"cleanup_failed", "failure", ""},
		},
		{
			name:     "pcp unauthorized carries its protocol",
			msg:      "Unauthorized to remove PCP mapping internal port 5353, protocol TCP",
			wantArgs: []string{"unauthorized", "failure", "tcp"},
		},
		{
			name:     "lease file error names no protocol",
			msg:      "could not open lease file: /var/run/miniupnpd.leases-ipv4",
			wantArgs: []string{"lease_file_error", "failure", ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseMiniUPnPd(upnpEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseMiniUPnPd(%q) returned ok=false", tc.msg)
			}
			sink := &fakeSink{}
			if !observeDerived(sink, "miniupnpd", rec.Attributes) {
				t.Fatal("observeDerived did not count a captured miniupnpd record")
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "upnp" {
				t.Fatalf("calls = %+v, want one upnp call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tc.wantArgs)
		})
	}
}

// THE DELIBERATE EXCLUSIONS, so a successor cannot quietly widen the parser into
// them, plus the ordinary near-miss traffic.
//
// `Returning UPnPError <code>: <text>` is NOT parsed: those templates came only from
// the isolated IGD capture, production does not enable IGD at all, and a generic
// error response is not safely attributable to one preceding request in an
// interleaved stream.
//
// `AddPortMapping:`, `redirecting port`, `DeletePortMapping:` and `removing redirect
// rule port` are NOT parsed: they are REQUESTS AND ATTEMPTS, not outcomes. The
// isolated capture proved the point — a real add request logged all of
// AddPortMapping, redirecting port and then `Returning UPnPError 501: Action Failed`,
// having created no rule at all. Treating any of them as a success would have counted
// that failure as a mapping.
//
// `shutting down MiniUPnPd` and `Listening for NAT-PMP/PCP traffic on port <n>` are
// NOT parsed: daemon lifecycle, not mapping lifecycle.
//
// All of them keep shipping generically with the body verbatim, exactly as they did
// before this parser existed.
func TestUPnPExcludedAndUnrelatedLinesAreNotClaimed(t *testing.T) {
	lines := []string{
		// Captured on the isolated testbed, deliberately excluded.
		"AddPortMapping: ext port 40119 to 172.16.9.100:40119 protocol TCP for: issue409 leaseduration=60 rhost=",
		"redirecting port 40119 to 172.16.9.100:40119 protocol TCP for: issue409",
		"Returning UPnPError 501: Action Failed",
		"Returning UPnPError 714: NoSuchEntryInArray",
		"DeletePortMapping: external port: 40119, protocol: TCP",
		"removing redirect rule port 40119 TCP",
		// Captured in production, deliberately excluded as daemon lifecycle.
		"shutting down MiniUPnPd",
		"Listening for NAT-PMP/PCP traffic on port 5351",
		// Near misses: right subject, wrong shape. A non-numeric port or an unknown
		// protocol must degrade rather than mint a value outside a closed vocabulary.
		"remove port mapping 42891 SCTP because it has expired",
		"remove port mapping many UDP because it has expired",
		"remove port mapping 42891 UDP",
		"could not find nat rule to delete iport=",
		"could not find redirect rule to delete",
		"Unauthorized to remove PCP mapping internal port 5353, protocol SCTP",
		"Unauthorized to remove PCP mapping internal port 5353",
		"could not open lease file",
		// Ordinary miniupnpd startup chatter neither capture classified.
		"HTTP listening on port 2189",
		"version 2.3.9 started",
	}

	for _, msg := range lines {
		t.Run(strings.ReplaceAll(msg, " ", "_"), func(t *testing.T) {
			env := upnpEnv(t, msg)

			if _, ok := parseMiniUPnPd(env, nil, func(string) {}); ok {
				t.Fatalf("parseMiniUPnPd(%q) CLAIMED a line that is not one of the five captured grammars", msg)
			}

			rec, parsed := buildRecord(env, nil, func(string) {})
			if parsed {
				t.Fatalf("buildRecord(%q) reported a structured parse", msg)
			}
			if rec.Body != msg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
			}
			// The subsystem still applies — an unparsed line is still a UPnP line.
			assertAttrs(t, rec, map[string]string{"program": "miniupnpd", "opnsense.subsystem": "upnp"})
			for k := range rec.Attributes {
				if strings.HasPrefix(k, "upnp.") {
					t.Errorf("unparsed miniupnpd line carries UPnP attribute %q", k)
				}
			}

			// And it must never be sampled away: nothing counted its total.
			if !sampleKeep("miniupnpd", rec, false) {
				t.Error("sampleKeep dropped an uncounted miniupnpd line")
			}
		})
	}
}

// An unparsed miniupnpd line reaches observeDerived as a generic record (the family
// lookup succeeds for the program), and must not be counted: upnp.event is absent,
// and counting a blank tuple would invent a series while making the line eligible
// for sampling with nothing having captured its total.
func TestObserveDerived_UPnP_DoesNotCountUnparsedLines(t *testing.T) {
	env := upnpEnv(t, "Returning UPnPError 501: Action Failed")
	rec, parsed := buildRecord(env, nil, func(string) {})
	if parsed {
		t.Fatal("buildRecord structured an excluded miniupnpd line")
	}

	sink := &fakeSink{}
	if observeDerived(sink, "miniupnpd", rec.Attributes) {
		t.Error("observeDerived counted an excluded miniupnpd line")
	}
	if len(sink.calls) != 0 {
		t.Errorf("sink called %d times for an excluded line, want 0", len(sink.calls))
	}
}

// NO ACTIVE-MAPPING GAUGE. #409 forbids it outright: the plugin's own status page
// derives active mappings by running pfctl, an event stream cannot reconstruct
// authoritative state across a daemon restart, and no successful-add grammar is even
// available. The `expired` event is a DECREMENT with no matching increment, so any
// gauge built from this family would drift negative without bound.
//
// This test pins the property structurally — every value this family can put on a
// metric is one of the three closed vocabularies, so there is no numeric mapping
// count anywhere in the tuple to build a gauge from.
func TestUPnPDerivesNoMappingCount(t *testing.T) {
	events := map[string]bool{
		upnpEventExpired:        true,
		upnpEventCleanupFailed:  true,
		upnpEventUnauthorized:   true,
		upnpEventLeaseFileError: true,
	}
	results := map[string]bool{upnpResultOK: true, upnpResultFailure: true}
	protocols := map[string]bool{upnpProtocolTCP: true, upnpProtocolUDP: true, "": true}

	msgs := []string{
		"remove port mapping 42891 UDP because it has expired",
		"could not find nat rule to delete iport=42891 addr=Ab3Kd9z",
		"could not find redirect rule to delete eport=40119",
		"Unauthorized to remove PCP mapping internal port 5353, protocol TCP",
		"could not open lease file: /var/run/miniupnpd.leases-ipv4",
	}

	for _, msg := range msgs {
		rec, ok := parseMiniUPnPd(upnpEnv(t, msg), nil, func(string) {})
		if !ok {
			t.Fatalf("parseMiniUPnPd(%q) returned ok=false", msg)
		}
		sink := &fakeSink{}
		if !observeDerived(sink, "miniupnpd", rec.Attributes) {
			t.Fatalf("observeDerived did not count %q", msg)
		}
		args := sink.calls[0].args
		if len(args) != 3 {
			t.Fatalf("args = %v, want exactly the frozen three-value tuple", args)
		}
		if !events[args[0]] {
			t.Errorf("event %q is outside the closed vocabulary", args[0])
		}
		if !results[args[1]] {
			t.Errorf("result %q is outside the closed vocabulary", args[1])
		}
		if !protocols[args[2]] {
			t.Errorf("protocol %q is outside the closed vocabulary", args[2])
		}
	}
}
