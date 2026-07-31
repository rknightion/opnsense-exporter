package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
)

// kernel.go owns the `kernel` program registration and chains the three kernel
// grammars this package models: CARP transitions (carp.go, #405), netmap
// host-ring-full reports and ARP address moves (both #536).
//
// ONE registration, not three: RegisterParser panics on a duplicate program, and
// `kernel` is a single fixed app-name. carp.go therefore no longer registers itself
// — parseKernel calls it. The order below is by SPECIFICITY, not by volume: each
// grammar anchors on its own literal prefix (`carp: `, `netmap_transmit`, `arp: `)
// and they cannot overlap, so the order is documentation rather than a tie-break.
//
// CLAIMING `kernel` IS THE RISK THIS FILE MANAGES, and #536 widened it. A kernel
// parser sees every kernel line on the box, and on OPNsense it sees more than that:
// FACILITY-14 CONSOLE OUTPUT IS MIS-ATTRIBUTED TO `kernel`. rc-script output,
// interface summaries, SSH host-key fingerprints and Zenarmor's embedded
// Elasticsearch startup banner all arrive under this app-name. None of them is a
// kernel message and none may be restructured or mangled: every grammar below is
// fully anchored, and anything unmatched returns ok=false so it keeps shipping as
// the generic record it always was. TestKernelConsoleOutputIsNotClaimed is the
// guard.
//
// Volume justification for the netmap grammar: kernel lines on production are 65%
// netmap — 3,601 of 5,578 over seven days.
var (
	// The kernel's own line prefix ahead of its text: an optional priority in angle
	// brackets and an optional monotonic counter in square brackets. Shared with
	// carpKernelPrefix's reasoning (carp.go) — both parts are optional because a
	// syslog path that strips them must still parse.
	//
	// NOTE the netmap grammar does NOT use this: netmap lines carry the counter but no
	// `<pri>`, and they put a SECOND bracketed number (the source line) after the
	// uptime. See reNetmapRingFull.
	kernelPrefix = `^(?:<\d+>)?(?:\[\d+\] )?`

	// `[<counter>] <uptime> [<srcline>] netmap_transmit<spaces><device> full hwcur <n> hwtail <n> qlen <n>`
	//
	// Captured verbatim on production (OPNsense 26.7.1_1, ixl0, 52 occurrences in one
	// capture window), e.g.:
	//
	//	[205991] 654.637689 [4335] netmap_transmit           ixl0 full hwcur 973 hwtail 973 qlen 1023
	//	[217920] 583.465780 [4335] netmap_transmit           ixl0 full hwcur 132 hwtail 533 qlen 622
	//
	// THE RUN OF SPACES AFTER THE FUNCTION NAME IS REAL and is ` +`, not ` `: netmap's
	// nm_prlim macro column-pads the function name (`%-25s`-shaped), so a
	// single-space regex matches NONE of the captured lines. The leading `[counter]`
	// and the `[srcline]` are both `\[ *\d+\]` — the source-line field is
	// space-padded on some lines (`[ 902]` appears on the sibling generic_netmap_*
	// grammars in the same capture), and matching only the unpadded form would fail
	// the moment netmap.c's line numbers shift into a narrower column.
	//
	// The whole prefix is OPTIONAL for the same reason carpKernelPrefix is.
	reNetmapRingFull = regexp.MustCompile(
		`(?:\[ *\d+\] )?(?:[0-9.]+ )?(?:\[ *\d+\] )?netmap_transmit +([0-9A-Za-z._-]+) full hwcur (\d+) hwtail (\d+) qlen (\d+)$`)

	// `arp: <ip> moved from <mac> to <mac> on <iface>`
	//
	// Captured verbatim on production, flapping repeatedly:
	//
	//	<6>[1147742] arp: 10.0.90.130 moved from bc:24:11:82:d2:5f to bc:24:11:aa:12:01 on ixl0_vlan90
	//
	// This is the kernel's own duplicate-address / MAC-flap / ARP-spoof detector, and
	// it is the ONLY way to see a sub-poll-interval flap: polling the ARP table cannot
	// catch one, because by scrape time the table holds a single MAC and looks healthy.
	//
	// The address groups are deliberately loose (`\S+`) rather than strict IPv4/MAC
	// patterns. Neither becomes a label and neither is interpreted — they ship verbatim
	// on the record — so a strict pattern would only buy the ability to silently stop
	// matching. The INTERFACE, which is the one label, is anchored to the OS device
	// character set.
	reARPMoved = regexp.MustCompile(kernelPrefix +
		`arp: (\S+) moved from (\S+) to (\S+) on ([0-9A-Za-z._-]+)$`)
)

func init() {
	// WithBodyEnrichment, inherited from the CARP registration this replaces (#405).
	// Kernel lines have carried peer.*/interface.* from the generic body scan since
	// #250, and suppressing it the moment a kernel line starts parsing structurally
	// would drop those attributes from any existing Loki query.
	//
	// The ARP grammar does extract a positional address, which is normally the reason a
	// parser stays OUT of this opt-in (see bodyEnrichedPrograms). It is kept here
	// anyway, deliberately: the alternative suppresses the body scan for CARP and
	// netmap lines too, and an ARP line's address appearing both as arp.address and
	// under peer.* is exactly what it does TODAY while the line is unparsed. Nothing
	// regresses; one attribute is redundant.
	RegisterParserWithBodyEnrichment(parseKernel, "kernel")
}

// parseKernel dispatches one kernel line across the modelled grammars, in order.
// Everything else — the overwhelming majority, plus the mis-attributed console
// output — returns false and ships generically.
func parseKernel(env Envelope, snap *enrich.Snapshot, miss func(table string)) (logship.Record, bool) {
	if rec, ok := parseCARP(env, snap, miss); ok {
		return rec, true
	}
	if rec, ok := parseNetmap(env); ok {
		return rec, true
	}
	if rec, ok := parseARPMove(env); ok {
		return rec, true
	}
	return logship.Record{}, false
}

// parseNetmap structures one netmap host-ring-full report.
//
// WHAT THIS LINE DOES AND DOES NOT MEAN. netmap_transmit() logs through
// nm_prlim(2, ...) (sys/dev/netmap/netmap.c ~4330-4349; the `[4335]` in the line IS
// that source line number), which RATE-LIMITS the output to 2 lines per second. So
// the line is a REPORT of a condition, not a record of a packet: the derived metric
// is an occurrence counter that saturates at 2/s and under-reports hardest exactly
// when the problem is worst. That is why nothing here is named `drops` — see the
// metric's help text in internal/collector/logevents.go.
//
// hwcur, hwtail and qlen ship as attributes because they are genuinely diagnostic:
// hwcur == hwtail is a completely full ring, and qlen is how deep the host ring was
// at the moment of the report. They are never labels — they change on every
// occurrence, so a label built from any of them mints a series per log line.
func parseNetmap(env Envelope) (logship.Record, bool) {
	m := reNetmapRingFull.FindStringSubmatch(env.Message)
	if m == nil {
		return logship.Record{}, false
	}
	rec, set := newRecord(env)
	set(attrNetmapEvent, netmapEventRingFull)
	set(attrNetmapDevice, m[1])
	set(attrNetmapHWCur, m[2])
	set(attrNetmapHWTail, m[3])
	set(attrNetmapQLen, m[4])
	return rec, true
}

// parseARPMove structures one kernel ARP address-move report.
//
// The IP and BOTH MAC addresses are attributes and never labels: a duplicate-address
// event names whichever hosts are fighting over the address, so the value set is
// unbounded and PII-shaped. Only the interface is a label.
func parseARPMove(env Envelope) (logship.Record, bool) {
	m := reARPMoved.FindStringSubmatch(env.Message)
	if m == nil {
		return logship.Record{}, false
	}
	rec, set := newRecord(env)
	set(attrARPEvent, arpEventAddressMoved)
	set(attrARPAddress, m[1])
	set(attrARPMACPrevious, m[2])
	set(attrARPMACCurrent, m[3])
	set(attrARPInterface, m[4])
	return rec, true
}
