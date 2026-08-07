package syslog

import (
	"testing"
	"time"
)

// kernelEnv wraps a kernel MSG field in the RFC5424 envelope the production capture
// showed, APP-NAME `kernel`. The `<6>[754] ` or `[205991] ` prefix is part of the
// MSG, not the envelope: the kernel writes its own priority and monotonic counter
// ahead of its text and OPNsense's syslog-ng forwards it verbatim.
func kernelEnv(t *testing.T, message string) Envelope {
	t.Helper()

	env, err := ParseEnvelope([]byte("<13>1 2026-07-24T18:20:54+01:00 test-firewall kernel - - [meta sequenceId=\"sanitized-sequence\"] "+message), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

// One registration for `kernel`, owned by kernel.go, chaining all three grammars.
// The CARP tests assert the same registration from the other side; this asserts the
// chain reaches netmap and ARP, which is what would silently regress if a future
// edit gave carp.go its init() back and left kernel.go's shadowed.
func TestKernelRegistrationChainsAllThreeGrammars(t *testing.T) {
	if _, exact := parsers["kernel"]; !exact {
		t.Fatal("kernel is not registered as an EXACT program name")
	}
	if !parserEnrichesBody("kernel") {
		t.Error("parserEnrichesBody(\"kernel\") = false; kernel lines have carried peer.*/interface.* since #250")
	}

	// One line per grammar, all through the single registered entry point.
	for _, tc := range []struct {
		name     string
		message  string
		eventKey string
	}{
		{"carp", "<6>[754] carp: 9@vtnet2: INIT -> BACKUP (initialization complete)", attrCARPEvent},
		{"netmap", "[205991] 654.637689 [4335] netmap_transmit           ixl0 full hwcur 973 hwtail 973 qlen 1023", attrNetmapEvent},
		{"arp", "<6>[1147742] arp: 10.0.90.130 moved from bc:24:11:82:d2:5f to bc:24:11:aa:12:01 on ixl0_vlan90", attrARPEvent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseKernel(kernelEnv(t, tc.message), nil, nil)
			if !ok {
				t.Fatalf("parseKernel() ok = false, want true")
			}
			if rec.Attributes[tc.eventKey] == "" {
				t.Errorf("%s not set; got attributes %v", tc.eventKey, rec.Attributes)
			}
		})
	}
}

// The netmap grammar, from lines captured verbatim on production (OPNsense
// 26.7.1_1, ixl0). The runs of multiple spaces after the function name are REAL —
// netmap column-pads it — and a single-space pattern matches none of these.
func TestNetmapCapturedRingFullLines(t *testing.T) {
	tests := []struct {
		name    string
		message string
		device  string
		hwcur   string
		hwtail  string
		qlen    string
	}{
		{
			name:    "completely full ring, hwcur == hwtail",
			message: "[205991] 654.637689 [4335] netmap_transmit           ixl0 full hwcur 973 hwtail 973 qlen 1023",
			device:  "ixl0", hwcur: "973", hwtail: "973", qlen: "1023",
		},
		{
			name:    "partially drained ring, qlen well below the 1024 ring size",
			message: "[217920] 583.465780 [4335] netmap_transmit           ixl0 full hwcur 132 hwtail 533 qlen 622",
			device:  "ixl0", hwcur: "132", hwtail: "533", qlen: "622",
		},
		{
			name:    "hwtail behind hwcur - the ring index wrapped",
			message: "[222903] 565.803198 [4335] netmap_transmit           ixl0 full hwcur 495 hwtail 474 qlen 20",
			device:  "ixl0", hwcur: "495", hwtail: "474", qlen: "20",
		},
		{
			name:    "space-padded source-line field",
			message: "[1016] 100.204884 [ 902] netmap_transmit           ixl0 full hwcur 736 hwtail 736 qlen 1023",
			device:  "ixl0", hwcur: "736", hwtail: "736", qlen: "1023",
		},
		// #610's line, pinned because that issue asserted this grammar "does not match"
		// any real line and named the run of spaces as the prime suspect. It DOES match,
		// and always did: the counter carries 952 samples over 7d on the live stack with
		// device="ixl0". Both halves of the kernel's rate-limited pair are here — see
		// TestNetmapRateLimitedPairCountsTwice for why they are two events and not one.
		{
			name:    "#610 prod line, first of the rate-limited pair",
			message: "[232659] 743.279886 [4335] netmap_transmit           ixl0 full hwcur 839 hwtail 842 qlen 1020",
			device:  "ixl0", hwcur: "839", hwtail: "842", qlen: "1020",
		},
		{
			name:    "#610 prod line, second of the pair - 70us later, same ring state",
			message: "[232659] 743.279956 [4335] netmap_transmit           ixl0 full hwcur 839 hwtail 842 qlen 1020",
			device:  "ixl0", hwcur: "839", hwtail: "842", qlen: "1020",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseKernel(kernelEnv(t, tt.message), nil, nil)
			if !ok {
				t.Fatal("parseKernel() ok = false, want true")
			}
			for key, want := range map[string]string{
				attrNetmapEvent:  netmapEventRingFull,
				attrNetmapDevice: tt.device,
				attrNetmapHWCur:  tt.hwcur,
				attrNetmapHWTail: tt.hwtail,
				attrNetmapQLen:   tt.qlen,
			} {
				if got := rec.Attributes[key]; got != want {
					t.Errorf("attribute %s = %q, want %q", key, got, want)
				}
			}
			if rec.Body != tt.message {
				t.Errorf("Body = %q, want the message verbatim", rec.Body)
			}
		})
	}
}

// THE DUPLICATE-EMISSION DECISION (#610): the pair counts TWICE, once per emitted
// kernel line, and this test is the decision rather than an observation of it.
//
// #610 read the pair as "identical content ... the kernel's own double-log" and
// argued for de-duplicating within a scrape interval. The premise is wrong on the
// capture: the two lines differ in their UPTIME field — 743.279886 against
// 743.279956, 70us apart — so they are two distinct netmap_transmit() calls that
// each found the host ring full and each passed nm_prlim's limiter, not one event
// logged twice. Their hwcur/hwtail/qlen agree because the ring state had not moved
// in 70us, which is what you would expect of a ring that is full.
//
// Counting once per line is also the only reading consistent with the metric's own
// help text, which documents the ceiling as "FLAT-TOPS at 2/s" — nm_prlim(2, ...)
// permits two lines per second, so a per-second dedupe would make the true ceiling
// 1/s and the documented one wrong. The value carries no severity information
// either way (1 and 2 both mean "the ring was full during that second"); what is
// read is the SHAPE of the rise, and halving it buys nothing while costing
// per-(device, second) state in the store.
func TestNetmapRateLimitedPairCountsTwice(t *testing.T) {
	pair := []string{
		"[232659] 743.279886 [4335] netmap_transmit           ixl0 full hwcur 839 hwtail 842 qlen 1020",
		"[232659] 743.279956 [4335] netmap_transmit           ixl0 full hwcur 839 hwtail 842 qlen 1020",
	}

	sink := &fakeSink{}
	for _, line := range pair {
		rec, ok := parseKernel(kernelEnv(t, line), nil, nil)
		if !ok {
			t.Fatalf("parseKernel(%q) ok = false, want true", line)
		}
		if !observeDerived(sink, "kernel", rec.Attributes) {
			t.Fatalf("observeDerived(%q) counted = false, want true", line)
		}
	}

	if len(sink.calls) != 2 {
		t.Fatalf("calls = %d, want 2 - the rate-limited pair is two events, not one", len(sink.calls))
	}
	for i, call := range sink.calls {
		if call.method != "netmap" {
			t.Errorf("call %d method = %q, want netmap", i, call.method)
		}
		if len(call.args) != 1 || call.args[0] != "ixl0" {
			t.Errorf("call %d args = %v, want exactly [ixl0]", i, call.args)
		}
	}
}

// The ring indices are diagnostics on the record and must NEVER reach a label: they
// change on every occurrence, so a label built from any of them mints a series per
// log line. The device is the only thing that reaches the sink.
func TestNetmapRingIndicesAreNeverLabels(t *testing.T) {
	rec, ok := parseKernel(kernelEnv(t,
		"[205991] 654.637689 [4335] netmap_transmit           ixl0 full hwcur 973 hwtail 973 qlen 1023"), nil, nil)
	if !ok {
		t.Fatal("parseKernel() ok = false, want true")
	}

	sink := &fakeSink{}
	if !observeDerived(sink, "kernel", rec.Attributes) {
		t.Fatal("observeDerived() counted = false, want true")
	}
	if len(sink.calls) != 1 || sink.calls[0].method != "netmap" {
		t.Fatalf("calls = %+v, want exactly one netmap call", sink.calls)
	}
	if got := sink.calls[0].args; len(got) != 1 || got[0] != "ixl0" {
		t.Errorf("netmap labels = %v, want exactly [ixl0]", got)
	}
	for _, forbidden := range []string{"973", "1023"} {
		for _, arg := range sink.calls[0].args {
			if arg == forbidden {
				t.Errorf("ring index %q reached a label", forbidden)
			}
		}
	}
}

// The ARP grammar, captured flapping on production.
func TestARPCapturedAddressMoves(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		address  string
		previous string
		current  string
		iface    string
	}{
		{
			name:     "vlan interface, first direction",
			message:  "<6>[1147742] arp: 10.0.90.130 moved from bc:24:11:82:d2:5f to bc:24:11:aa:12:01 on ixl0_vlan90",
			address:  "10.0.90.130",
			previous: "bc:24:11:82:d2:5f",
			current:  "bc:24:11:aa:12:01",
			iface:    "ixl0_vlan90",
		},
		{
			name:     "the same address flapping back",
			message:  "<6>[1147743] arp: 10.0.90.130 moved from bc:24:11:aa:12:01 to bc:24:11:82:d2:5f on ixl0_vlan90",
			address:  "10.0.90.130",
			previous: "bc:24:11:aa:12:01",
			current:  "bc:24:11:82:d2:5f",
			iface:    "ixl0_vlan90",
		},
		{
			name:     "no kernel prefix at all - a syslog path that strips it",
			message:  "arp: 10.0.0.20 moved from 00:11:22:33:44:55 to 00:11:22:33:44:66 on ixl0",
			address:  "10.0.0.20",
			previous: "00:11:22:33:44:55",
			current:  "00:11:22:33:44:66",
			iface:    "ixl0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseKernel(kernelEnv(t, tt.message), nil, nil)
			if !ok {
				t.Fatal("parseKernel() ok = false, want true")
			}
			for key, want := range map[string]string{
				attrARPEvent:       arpEventAddressMoved,
				attrARPAddress:     tt.address,
				attrARPMACPrevious: tt.previous,
				attrARPMACCurrent:  tt.current,
				attrARPInterface:   tt.iface,
			} {
				if got := rec.Attributes[key]; got != want {
					t.Errorf("attribute %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

// The contested IP and both MACs are unbounded and PII-shaped. Only the interface
// may reach a label.
func TestARPAddressesAreNeverLabels(t *testing.T) {
	rec, ok := parseKernel(kernelEnv(t,
		"<6>[1147742] arp: 10.0.90.130 moved from bc:24:11:82:d2:5f to bc:24:11:aa:12:01 on ixl0_vlan90"), nil, nil)
	if !ok {
		t.Fatal("parseKernel() ok = false, want true")
	}

	sink := &fakeSink{}
	if !observeDerived(sink, "kernel", rec.Attributes) {
		t.Fatal("observeDerived() counted = false, want true")
	}
	if len(sink.calls) != 1 || sink.calls[0].method != "arp" {
		t.Fatalf("calls = %+v, want exactly one arp call", sink.calls)
	}
	if got := sink.calls[0].args; len(got) != 1 || got[0] != "ixl0_vlan90" {
		t.Errorf("arp labels = %v, want exactly [ixl0_vlan90]", got)
	}
	for _, forbidden := range []string{"10.0.90.130", "bc:24:11:82:d2:5f", "bc:24:11:aa:12:01"} {
		for _, arg := range sink.calls[0].args {
			if arg == forbidden {
				t.Errorf("%q reached a label", forbidden)
			}
		}
	}
}

// FACILITY-14 CONSOLE OUTPUT IS MIS-ATTRIBUTED TO `kernel` ON OPNSENSE. rc-script
// output, interface summaries, SSH host-key fingerprints and Zenarmor's embedded
// Elasticsearch startup banner all arrive under this app-name. None is a kernel
// message; none may be claimed, restructured or mangled. Every one of these keeps
// shipping as the generic record it always was.
func TestKernelConsoleOutputIsNotClaimed(t *testing.T) {
	lines := []string{
		// Console output mis-tagged as kernel.
		"Configuring LAN interface...done.",
		"2048 SHA256:mzPBTmDPPXRRhSA4dfMe8mObpWNlJdrbSaVwF9BjkQE root@opnsense.rob-knight.net (RSA)",
		"[2026-07-24T18:20:54,123][INFO ][o.e.n.Node               ] [opnsense] initialized",
		"*** opnsense.rob-knight.net: OPNsense 26.7.1 ***",

		// Real kernel lines that are not one of our four grammars. These sit next to
		// the netmap grammar in the same capture and share its prefix shape, which is
		// exactly why a loose netmap pattern would eat them.
		"[102019] 108.204884 [ 902] freebsd_generic_rx_handler Warning: RX packet intercepted, but no emulated adapter",
		"[102020] 108.204900 [1234] generic_netmap_dtor       Native netmap adapter for ixl0 restored",
		"[102021] 108.204910 [1235] generic_netmap_attach     Emulated adapter for ixl0 created (prev was ixl0)",
		"<6>[211556] ixl0: link state changed to DOWN",
		"<6>[211557] ixl0: Link is up, 10 Gbps Full Duplex, Requested FEC: None, Negotiated FEC: None, Autoneg: False, Flow Control: None",
		"<6>[211558] nd6_dad_timer: called with non-tentative address fe80:f::4ab1:2ff:fe03:aff1(pppoe0)",

		// Near misses on our own grammars.
		"[205991] 654.637689 [4335] netmap_transmit           ixl0 full hwcur 973 hwtail 973",
		"[205991] 654.637689 [4335] netmap_transmit_something ixl0 full hwcur 973 hwtail 973 qlen 1023",
		"<6>[1147742] arp: 10.0.90.130 is on ixl0_vlan90",
		"<6>[1147742] arping: 10.0.90.130 moved from a to b on ixl0",

		// Near misses on the promiscuous-mode grammar (#669): wrong verb form and a
		// missing device prefix.
		"<6>[211555] tailscale0: promiscuous mode is enabled",
		"<6>[211555] tailscale0: promiscuous mode enable",
		"promiscuous mode enabled",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			if _, ok := parseKernel(kernelEnv(t, line), nil, nil); ok {
				t.Errorf("parseKernel() claimed a line it must leave generic: %q", line)
			}

			// And it must not be COUNTED either: a generic kernel record reaches
			// observeDerived through familyKernel, and only the event attributes gate it.
			rec := genericRecord(kernelEnv(t, line))
			sink := &fakeSink{}
			if observeDerived(sink, "kernel", rec.Attributes) {
				t.Errorf("observeDerived() counted an unmodelled kernel line: %q", line)
			}
			if len(sink.calls) != 0 {
				t.Errorf("sink calls = %+v, want none", sink.calls)
			}
		})
	}
}

// The promiscuous-mode grammar (#669), captured verbatim on production
// (OPNsense 26.7.1_1): two enable/disable pairs on ixl1, ~45s and ~20s apart.
func TestKernelPromiscuousCapturedLines(t *testing.T) {
	tests := []struct {
		name    string
		message string
		device  string
		event   string
	}{
		{
			name:    "enabled, captured",
			message: "<6>[331947] ixl1: promiscuous mode enabled",
			device:  "ixl1", event: kernelPromiscEnabled,
		},
		{
			name:    "disabled, captured",
			message: "<6>[331992] ixl1: promiscuous mode disabled",
			device:  "ixl1", event: kernelPromiscDisabled,
		},
		{
			name:    "second captured pair, enabled",
			message: "<6>[340117] ixl1: promiscuous mode enabled",
			device:  "ixl1", event: kernelPromiscEnabled,
		},
		{
			name:    "second captured pair, disabled",
			message: "<6>[340137] ixl1: promiscuous mode disabled",
			device:  "ixl1", event: kernelPromiscDisabled,
		},
		{
			// Same shape, a different device: the near-miss list above pins the
			// verb-form/prefix cases this line was moved out of (#669).
			name:    "different device, no counter prefix",
			message: "tailscale0: promiscuous mode enabled",
			device:  "tailscale0", event: kernelPromiscEnabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := parseKernel(kernelEnv(t, tt.message), nil, nil)
			if !ok {
				t.Fatal("parseKernel() ok = false, want true")
			}
			for key, want := range map[string]string{
				attrKernelEvent:  tt.event,
				attrKernelDevice: tt.device,
			} {
				if got := rec.Attributes[key]; got != want {
					t.Errorf("attribute %s = %q, want %q", key, got, want)
				}
			}
			if rec.Body != tt.message {
				t.Errorf("Body = %q, want the message verbatim", rec.Body)
			}
		})
	}
}
