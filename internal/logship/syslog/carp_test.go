package syslog

import (
	"strings"
	"testing"
	"time"
)

// carpEnv wraps a kernel MSG field in the RFC5424 envelope the retained-log capture
// showed, APP-NAME `kernel`. The `<6>[754] ` prefix is part of the MSG, not the
// envelope: the kernel writes its own priority and monotonic counter ahead of its
// text and OPNsense's syslog-ng forwards it verbatim.
func carpEnv(t *testing.T, message string) Envelope {
	t.Helper()

	env, err := ParseEnvelope([]byte("<6>1 2026-07-26T20:45:31+01:00 test-firewall kernel - - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestCARPRegistered(t *testing.T) {
	if _, ok := parserFor("kernel"); !ok {
		t.Fatal("no parser registered for program kernel")
	}
}

// The registration must be the EXACT-name, body-enriching form.
//
// Exact, not a prefix: `kernel` is a fixed app-name, and a "kernel" PREFIX would also
// claim any future program merely starting with those letters.
//
// Body-enriching, because this parser extracts no address of its own — a vhid, an OS
// device and a free-text cause. Without the opt-in, the generic body scan is
// suppressed for every kernel line the parser matches, silently dropping the peer.*
// and interface.* attributes kernel lines have carried since #250. That is the same
// regression charon/openvpn opted out of in #406.
func TestCARPRegistrationIsExactAndKeepsBodyEnrichment(t *testing.T) {
	if _, exact := parsers["kernel"]; !exact {
		t.Error("kernel is not registered as an EXACT program name")
	}
	if _, prefixed := parserPrefixes["kernel"]; prefixed {
		t.Error("kernel is registered as a program PREFIX; it is a fixed app-name")
	}
	if !parserEnrichesBody("kernel") {
		t.Error("parserEnrichesBody(\"kernel\") = false; the CARP parser extracts no address " +
			"of its own, so the generic body scan must keep running")
	}
}

// The three captured state-change shapes, verbatim from the development box's
// retained logs (OPNsense 27.1.a_40 / FreeBSD 15, net.inet.carp.log=1).
func TestCARPCapturedStateChanges(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "init to backup",
			msg:  "<6>[754] carp: 9@vtnet2: INIT -> BACKUP (initialization complete)",
			want: map[string]string{
				"carp.event":          "state_changed",
				"carp.state.previous": "init",
				"carp.state.current":  "backup",
				"carp.interface":      "vtnet2",
				"carp.vhid":           "9",
				"carp.reason":         "initialization complete",
			},
		},
		{
			name: "backup to master",
			msg:  "<6>[757] carp: 9@vtnet2: BACKUP -> MASTER (master timed out)",
			want: map[string]string{
				"carp.event":          "state_changed",
				"carp.state.previous": "backup",
				"carp.state.current":  "master",
				"carp.interface":      "vtnet2",
				"carp.vhid":           "9",
				"carp.reason":         "master timed out",
			},
		},
		{
			name: "master to init",
			msg:  "<6>[369283] carp: 9@vtnet2: MASTER -> INIT (hardware interface up)",
			want: map[string]string{
				"carp.event":          "state_changed",
				"carp.state.previous": "master",
				"carp.state.current":  "init",
				"carp.interface":      "vtnet2",
				"carp.vhid":           "9",
				"carp.reason":         "hardware interface up",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseCARP(carpEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
			assertNoAttrs(t, rec, "carp.demotion.delta", "carp.demotion.total")
		})
	}
}

// The two captured demotion shapes. A demotion record names NO interface and NO
// vhid — FreeBSD's carp_demote_adj is global to the node — so those attributes must
// be absent rather than guessed, and their labels are empty.
func TestCARPCapturedDemotions(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			name: "pfsync bulk start demotes",
			msg:  "<6>[754] carp: demoted by 240 to 240 (pfsync bulk start)",
			want: map[string]string{
				"carp.event":          "demoted",
				"carp.demotion.delta": "240",
				"carp.demotion.total": "240",
				"carp.reason":         "pfsync bulk start",
			},
		},
		{
			name: "pfsync bulk fail promotes",
			msg:  "<6>[819] carp: demoted by -240 to 0 (pfsync bulk fail)",
			want: map[string]string{
				"carp.event":          "promoted",
				"carp.demotion.delta": "-240",
				"carp.demotion.total": "0",
				"carp.reason":         "pfsync bulk fail",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseCARP(carpEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
			assertNoAttrs(t, rec, "carp.state.previous", "carp.state.current",
				"carp.interface", "carp.vhid")
		})
	}
}

// The SIGN of the delta is the only thing that separates a demotion from a
// promotion: FreeBSD has no separate "promoted" line, carp_demote_adj just logs a
// negative adjustment. Zero is not a promotion — it raises nothing — so it stays
// `demoted`, the neutral name for "an adjustment was logged".
func TestCARPDemotionSignDecidesEvent(t *testing.T) {
	tests := []struct {
		delta string
		want  string
	}{
		{"240", "demoted"},
		{"1", "demoted"},
		{"0", "demoted"},
		{"-1", "promoted"},
		{"-240", "promoted"},
	}

	for _, tc := range tests {
		t.Run(tc.delta, func(t *testing.T) {
			msg := "<6>[900] carp: demoted by " + tc.delta + " to 0 (pfsync bulk start)"
			rec, ok := parseCARP(carpEnv(t, msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false", msg)
			}
			if got := rec.Attributes["carp.event"]; got != tc.want {
				t.Errorf("carp.event for delta %s = %q, want %q", tc.delta, got, tc.want)
			}
		})
	}
}

// The kernel prefix is load-bearing and OPTIONAL. `<6>` is the kernel's own
// priority and `[754]` its monotonic counter; both numbers vary freely across
// records, and a regex anchored directly on `carp:` would match none of the 44
// captured lines. A setup whose syslog path strips the prefix must still parse, so
// every combination has to work.
func TestCARPKernelPrefixIsToleratedAndOptional(t *testing.T) {
	const suffix = "carp: 9@vtnet2: BACKUP -> MASTER (master timed out)"
	prefixes := []string{
		"<6>[757] ", // the captured form
		"<3>[1] ",   // different priority, single-digit counter
		"<6>",       // priority only
		"[757] ",    // counter only
		"",          // stripped entirely
	}

	for _, prefix := range prefixes {
		t.Run("prefix="+prefix, func(t *testing.T) {
			rec, ok := parseCARP(carpEnv(t, prefix+suffix), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false", prefix+suffix)
			}
			assertAttrs(t, rec, map[string]string{
				"carp.event":          "state_changed",
				"carp.state.previous": "backup",
				"carp.state.current":  "master",
				"carp.interface":      "vtnet2",
				"carp.vhid":           "9",
				"carp.reason":         "master timed out",
			})
		})
	}
}

// DOCUMENTATION-DERIVED REASONS INSIDE A CAPTURED SHAPE — not a new shape.
//
// OPNsense's CARP documentation describes demotion causes beyond the two the
// retained logs happened to contain (service disruption, service recovery). Because
// the regex captures the cause as FREE TEXT and never turns it into a label, those
// reasons are handled automatically by the captured `demoted by <delta> to <total>
// (<reason>)` structure — there is nothing to add and nothing to enumerate.
//
// That is the whole point of this test: it pins that property, so a future change
// that tried to close the reason into a vocabulary (or bucket it into a
// reason_class) would break here. The STRUCTURE under test is captured; only the
// reason strings are documentation-derived, and no grammar whose shape comes from
// documentation is parsed anywhere in this file.
func TestCARPDocumentedReasonsRideTheCapturedShape(t *testing.T) {
	reasons := []string{
		"service disruption",
		"service recovery",
		// And a reason no source names at all, to show the field really is open.
		"some future freebsd cause nobody has written down",
	}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			msg := "<6>[754] carp: demoted by 240 to 240 (" + reason + ")"
			rec, ok := parseCARP(carpEnv(t, msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false; the reason must be free text", msg)
			}
			assertAttrs(t, rec, map[string]string{
				"carp.event":          "demoted",
				"carp.demotion.delta": "240",
				"carp.demotion.total": "240",
				"carp.reason":         reason,
			})
		})
	}
}

// THE CAUSE IS AN ATTRIBUTE AND NEVER A LABEL. #405's acceptance requires it: the
// kernel cause is open-ended free text across FreeBSD versions, so putting it on the
// metric would make the label set unbounded, and bucketing it into a reason_class
// would invent a taxonomy no capture supports.
//
// This asserts it end to end at the seam that decides: every value handed to
// ObserveCARP is checked against the reason text, and the numeric demotion delta and
// total are checked too — they are the "why a node demoted" data, and they are
// attributes for the same reason.
func TestCARPReasonAndDemotionValuesAreNeverLabels(t *testing.T) {
	const reason = "pfsync bulk start"
	msgs := []string{
		"<6>[754] carp: 9@vtnet2: BACKUP -> MASTER (master timed out)",
		"<6>[754] carp: demoted by 240 to 137 (" + reason + ")",
	}

	for _, msg := range msgs {
		t.Run(msg, func(t *testing.T) {
			rec, ok := parseCARP(carpEnv(t, msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false", msg)
			}

			// The record MUST carry the cause as structured metadata...
			if rec.Attributes["carp.reason"] == "" {
				t.Fatal("carp.reason is absent; the cause must ship as a log attribute")
			}

			// ...and the metric MUST NOT.
			sink := &fakeSink{}
			if !observeDerived(sink, "kernel", rec.Attributes) {
				t.Fatal("observeDerived did not count a captured CARP record")
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "carp" {
				t.Fatalf("calls = %+v, want one carp call", sink.calls)
			}
			forbidden := []string{
				rec.Attributes["carp.reason"],
				rec.Attributes["carp.demotion.delta"],
				rec.Attributes["carp.demotion.total"],
			}
			for _, arg := range sink.calls[0].args {
				for _, bad := range forbidden {
					if bad != "" && arg == bad {
						t.Errorf("label value %q is the cause/demotion metadata %q; it must never be a label", arg, bad)
					}
				}
			}
		})
	}
}

// The frozen #405 label tuple, at the deriver seam: event, from, to, interface,
// vhid — in that order. A demotion names no interface and no vhid, so those three
// are EMPTY rather than guessed.
func TestObserveDerived_CARP(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		wantArgs []string
	}{
		{
			name:     "state change carries interface and vhid",
			msg:      "<6>[757] carp: 9@vtnet2: BACKUP -> MASTER (master timed out)",
			wantArgs: []string{"state_changed", "backup", "master", "vtnet2", "9"},
		},
		{
			name:     "demotion carries neither state nor interface nor vhid",
			msg:      "<6>[754] carp: demoted by 240 to 240 (pfsync bulk start)",
			wantArgs: []string{"demoted", "", "", "", ""},
		},
		{
			name:     "promotion is a negative delta",
			msg:      "<6>[819] carp: demoted by -240 to 0 (pfsync bulk fail)",
			wantArgs: []string{"promoted", "", "", "", ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseCARP(carpEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseCARP(%q) returned ok=false", tc.msg)
			}
			sink := &fakeSink{}
			if !observeDerived(sink, "kernel", rec.Attributes) {
				t.Fatal("observeDerived did not count a captured CARP record")
			}
			if len(sink.calls) != 1 || sink.calls[0].method != "carp" {
				t.Fatalf("calls = %+v, want one carp call", sink.calls)
			}
			assertArgs(t, sink.calls[0].args, tc.wantArgs)
		})
	}
}

// An unrelated kernel line reaches observeDerived as a GENERIC record (the family is
// now familyCARP for every kernel line, so the family lookup succeeds). It must not
// be counted: carp.event is absent, and counting a blank tuple would both invent a
// series and — via sampleKeep — make the line eligible for sampling when nothing
// captured its total.
func TestObserveDerived_CARP_DoesNotCountUnrelatedKernelLines(t *testing.T) {
	env := carpEnv(t, "<6>[369283] vtnet2: link state changed to DOWN")
	rec, parsed := buildRecord(env, nil, func(string) {})
	if parsed {
		t.Fatal("buildRecord structured an unrelated kernel line")
	}

	sink := &fakeSink{}
	if observeDerived(sink, "kernel", rec.Attributes) {
		t.Error("observeDerived counted an unrelated kernel line")
	}
	if len(sink.calls) != 0 {
		t.Errorf("sink called %d times for an unrelated kernel line, want 0", len(sink.calls))
	}

	// And it must therefore never be sampled away.
	if !sampleKeep("kernel", rec, false) {
		t.Error("sampleKeep dropped an uncounted kernel line")
	}
}

// THE HIGHEST-RISK TEST IN THIS FILE. Claiming APP-NAME `kernel` puts EVERY kernel
// line on the box through this parser, and the overwhelming majority are nothing to
// do with CARP. Each of these must return ok=false and keep shipping generically
// exactly as it did before the parser existed — a greedy kernel parser would
// silently restructure unrelated records and nothing else in the pipeline would
// notice.
//
// The link-state, watchdog, arp, ZFS, USB, pf and process lines are the ordinary
// traffic of a FreeBSD kernel log. The `carp0` and `pfsync`/`sysctl` entries are
// DELIBERATELY ADVERSARIAL SYNTHETIC STRINGS, not captured records: they exist to
// prove the regexes anchor on the full `carp: <shape>` form rather than merely
// containing the substring "carp", which is the shortcut a tolerant-prefix
// implementation is most likely to reach for.
//
// The final group are NEAR-MISS CARP lines — right subject, wrong shape (no cause,
// an unknown state, a missing vhid, a non-numeric delta, trailing junk). Those must
// degrade too: an unknown state that matched would mint a label value outside the
// closed from/to vocabulary, which is exactly what must not happen.
func TestCARPUnrelatedKernelLinesAreNotClaimed(t *testing.T) {
	lines := []string{
		// A REAL captured kernel line from this repo's own fixtures
		// (debugcapture_test.go), on a box with no CARP involvement whatsoever. Note it
		// carries the counter prefix WITHOUT the `<pri>` part, which is why
		// carpKernelPrefix makes the two halves independently optional.
		"[367650] arpresolve: can't allocate llinfo for 86.31.203.100",
		// Ordinary FreeBSD kernel traffic.
		"<6>[369283] vtnet2: link state changed to DOWN",
		"<6>[369285] vtnet2: link state changed to UP",
		"<6>[100] lo0: link state changed to UP",
		"<6>[104] wg0: link state changed to UP",
		"<6>[12] em0: Watchdog timeout -- resetting",
		// NOTE: `arp: <ip> moved from <mac> to <mac> on <iface>` USED to sit in this
		// list. It moved out in #536, which models it as a real kernel grammar — see
		// TestARPCapturedAddressMoves. It is still not a CARP line and parseCARP must
		// still decline it, which the parseCARP assertion below covers; what changed is
		// that buildRecord now legitimately reports a structured parse for it, so it can
		// no longer be asserted generic here.
		"<6>[8] ZFS filesystem version: 5",
		"<6>[9] ugen0.3: <Generic Flash Disk> at usbus0",
		"<6>[70] pflog0: promiscuous mode enabled",
		"<6>[102] igb0: promiscuous mode enabled",
		"<4>[103] Limiting closed port RST response from 300 to 200 packets/sec",
		"<3>[71] pid 12345 (php), jid 0, uid 0: exited on signal 11",
		"<6>[105] Waiting (max 60 seconds) for system process 'vnlru' to stop... done",
		// Adversarial synthetic strings mentioning carp without being either shape.
		"<6>[101] carp0: link state changed to UP",
		"<6>[106] pfsync: bulk update complete, carp demotion cleared",
		"<6>[107] sysctl net.inet.carp.log: 0 -> 1",
		// Near-miss CARP lines: right subject, wrong shape.
		"<6>[754] carp: 9@vtnet2: INIT -> BACKUP",
		"<6>[754] carp: 9@vtnet2: BACKUP -> DEMOTED (something new)",
		"<6>[754] carp: vtnet2: INIT -> BACKUP (initialization complete)",
		"<6>[754] carp: 9@vtnet2: INIT -> BACKUP (initialization complete) trailing junk",
		"<6>[754] carp: demoted by two to 240 (pfsync bulk start)",
		"<6>[754] carp: demoted to 240 (pfsync bulk start)",
		"<6>[754] carp: demoted by 240 to 240",
	}

	for _, msg := range lines {
		t.Run(strings.ReplaceAll(msg, " ", "_"), func(t *testing.T) {
			env := carpEnv(t, msg)

			if _, ok := parseCARP(env, nil, func(string) {}); ok {
				t.Fatalf("parseCARP(%q) CLAIMED a line that is not one of the two captured CARP shapes", msg)
			}

			// And end to end: it must still reach the generic record it has always
			// shipped as, body verbatim, with no carp.* attribute anywhere on it.
			rec, parsed := buildRecord(env, nil, func(string) {})
			if parsed {
				t.Fatalf("buildRecord(%q) reported a structured parse", msg)
			}
			if rec.Body != msg {
				t.Errorf("Body = %q, want generic body %q", rec.Body, msg)
			}
			assertAttrs(t, rec, map[string]string{"program": "kernel", "opnsense.subsystem": "kernel"})
			for k := range rec.Attributes {
				if strings.HasPrefix(k, "carp.") {
					t.Errorf("unrelated kernel line carries CARP attribute %q", k)
				}
			}
		})
	}
}
