package syslog

import (
	"regexp"
	"strconv"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// CARP is the FreeBSD kernel half of #405's HA evidence. The grammar comes from
// FreeBSD's own carp.c — the CARP_LOG calls in carp_set_state and carp_demote_adj —
// so it is KERNEL-derived, not OPNsense-derived, and it arrives under APP-NAME
// `kernel`.
//
// The ONLY grammar parsed here is what a strictly read-only scan of the development
// box's retained system logs found: 44 real records on OPNsense 27.1.a_40
// (FreeBSD 15) with net.inet.carp.log=1, newest 2026-07-26T20:45:31+01:00, so
// current-generation. Verbatim, INCLUDING the kernel's own prefix:
//
//	<6>[754] carp: 9@vtnet2: INIT -> BACKUP (initialization complete)
//	<6>[757] carp: 9@vtnet2: BACKUP -> MASTER (master timed out)
//	<6>[369283] carp: 9@vtnet2: MASTER -> INIT (hardware interface up)
//	<6>[754] carp: demoted by 240 to 240 (pfsync bulk start)
//	<6>[819] carp: demoted by -240 to 0 (pfsync bulk fail)
//
// Observed counts: INIT -> BACKUP 10, BACKUP -> MASTER 10, MASTER -> INIT 2,
// positive demotion 11, negative demotion 11. All three states appear as real
// observed endpoints, so none of the state vocabulary is inferred.
//
// PRODUCTION HAS NO CARP AT ALL. A read-only check of OPNsense 26.7.1_1 found zero
// configured CARP VIPs and zero retained kernel `carp:` records with
// net.inet.carp.log=1, so there is no stable-release CARP evidence to obtain and
// none is inferred here — the same precedent the shipped dpinger parser set.
//
// OPNsense's own CARP syshook ALSO logs transitions, under APP-NAME `opnsense`,
// carrying the admin's VIP description. That source is deliberately NOT parsed:
// `opnsense` is the catch-all app-name for every log_msg() call on the box, so
// claiming it would put an unbounded variety of unrelated lines through a CARP
// matcher, and each line is prefixed by whichever syshook script emitted it.
//
// CLAIMING `kernel` IS THE RISK THIS FILE MANAGES. A kernel parser sees every
// kernel line on the box — link-state changes, interface up/down, ZFS, USB, pf, em0
// watchdogs — and the overwhelming majority have nothing to do with CARP. Both
// regexes below therefore anchor on the full `carp: ` shape, and anything else
// returns ok=false so it keeps shipping generically exactly as it did before this
// parser existed. A greedy kernel parser would silently restructure unrelated
// records; TestCARPUnrelatedKernelLinesAreNotClaimed is the guard.
var (
	// carpKernelPrefix is the kernel's own line prefix ahead of its text: a priority
	// in angle brackets and a monotonic counter in square brackets, e.g. `<6>[754] `.
	// Both digits vary freely, and the whole prefix is OPTIONAL because a setup whose
	// syslog path strips it must still be parsed. A regex anchored directly on `carp:`
	// would match NONE of the captured records, which is why this exists.
	carpKernelPrefix = `^(?:<\d+>)?(?:\[\d+\] )?`

	// A state change: `carp: <vhid>@<device>: <FROM> -> <TO> (<reason>)`.
	//
	// The two state groups are anchored to the three literal FreeBSD states rather
	// than a general `\w+`. That is the closed `from`/`to` label vocabulary being
	// enforced at the point of extraction: a future kernel state would fail to match
	// and ship generically, instead of silently minting a new label value. FreeBSD's
	// carp_states[] holds exactly these three.
	reCARPStateChange = regexp.MustCompile(carpKernelPrefix +
		`carp: (\d+)@([0-9A-Za-z._-]+): (MASTER|BACKUP|INIT) -> (MASTER|BACKUP|INIT) \((.+)\)$`)

	// A demotion adjustment: `carp: demoted by <delta> to <total> (<reason>)`.
	//
	// The delta is SIGNED and both values may be negative, so both groups allow a
	// leading minus. Neither is a label — they are the "why a node demoted" numbers
	// #405 says the current-state gauges do not retain, and they ship as record
	// attributes. This shape names NO interface and NO vhid: FreeBSD's
	// carp_demote_adj is global to the node, which is why the interface and vhid
	// labels are empty for it rather than guessed.
	reCARPDemotion = regexp.MustCompile(carpKernelPrefix +
		`carp: demoted by (-?\d+) to (-?\d+) \((.+)\)$`)
)

// carpStates is the closed, code-defined mapping from the kernel's upper-case state
// names onto the lower-case label vocabulary. A map rather than strings.ToLower so
// the vocabulary stays closed by construction: an unrecognised state cannot become
// a label even if the regex above is ever loosened.
var carpStates = map[string]string{
	"MASTER": carpStateMaster,
	"BACKUP": carpStateBackup,
	"INIT":   carpStateInit,
}

// THERE IS NO init() HERE, and its absence is deliberate (#536). `kernel` is a
// single fixed app-name and RegisterParser panics on a duplicate program, so the
// three kernel grammars — CARP, netmap and ARP — cannot each register themselves.
// kernel.go owns the one registration (still WithBodyEnrichment, for the reason
// below) and calls parseCARP first. Re-adding a registration here panics at startup.
//
// The body-enrichment opt-in this parser needs: it extracts no address of its own —
// a vhid, an OS device name and a free-text cause — so the generic body scan must
// keep running. Kernel lines have carried peer.*/interface.* since #250 and must not
// lose them the moment a CARP line starts parsing structurally.

func parseCARP(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reCARPStateChange.FindStringSubmatch(env.Message); m != nil {
		from, fromOK := carpStates[m[3]]
		to, toOK := carpStates[m[4]]
		if !fromOK || !toOK {
			return logship.Record{}, false
		}
		rec, set := newRecord(env)
		set(attrCARPEvent, carpEventStateChanged)
		set(attrCARPStatePrevious, from)
		set(attrCARPStateCurrent, to)
		set(attrCARPInterface, m[2])
		set(attrCARPVHID, m[1])
		set(attrCARPReason, m[5])
		return rec, true
	}
	if m := reCARPDemotion.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set(attrCARPEvent, carpDemotionEvent(m[1]))
		set(attrCARPDemotionDelta, m[1])
		set(attrCARPDemotionTotal, m[2])
		set(attrCARPReason, m[3])
		return rec, true
	}
	// EVERY other kernel line — the vast majority of them — is not ours. Returning
	// false is what keeps it shipping as the generic record it has always been.
	return logship.Record{}, false
}

// carpDemotionEvent resolves the closed demoted/promoted vocabulary from the SIGN of
// the kernel's demotion delta. Positive raises the node's demotion total (it becomes
// less willing to be master); negative lowers it. FreeBSD emits no separate
// "promoted" line — a promotion IS a negative `demoted by`, which is why the sign is
// the whole decision.
//
// Zero stays `demoted`: nothing was raised, but nothing was lowered either, so
// calling it a promotion would be wrong. It is the neutral name for "an adjustment
// was logged". The delta is matched by `-?\d+`, so it always parses; a parse failure
// could only mean the regex changed, and the safe reading of an unknown adjustment is
// the neutral one.
func carpDemotionEvent(delta string) string {
	if n, err := strconv.Atoi(delta); err == nil && n < 0 {
		return carpEventPromoted
	}
	return carpEventDemoted
}
