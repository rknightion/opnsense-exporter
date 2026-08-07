package syslog

import "regexp"

// Kea's Lease File Cleanup helper (#664). `DhcpLFC` runs as its own process —
// its own syslog program name, no subsystem of its own until this issue — but
// speaks the exact same log envelope as kea-dhcp4/kea-dhcp6/kea-ctrl-agent/
// kea-dhcp-ddns:
//
//	<SEVERITY>  [<logger-hierarchy>.<0xADDR>] <MESSAGE_ID> <free text>
//
// `<MESSAGE_ID>` is a closed, upstream-generated vocabulary (Kea's *_messages.h),
// which is what makes this cheap and stable to parse. The `0x...` component is a
// thread/context pointer with no operational meaning, and — same reasoning as
// the deliberately-dropped unbound pid at unbound.go:112 — it must never be
// captured; parseKeaEnvelope strips it out of the logger hierarchy before
// emitting kea.component.
//
// Triaged from the camden capture archive (#664; 2026-08-04 08:46 → 2026-08-07
// 16:33 UTC), read as shape samples per Capturer.CaptureShape, not frequencies.
// All nine lines below are verbatim captures, none synthetic.
//
// All seven DhcpLFC shapes:
//
//	INFO  [DhcpLFC.0x10b74225f010] LFC_START Starting lease file cleanup
//	INFO  [DhcpLFC.0x10b74225f010] LFC_PROCESSING Previous file: /var/db/kea/kea-leases6.csv.2, copy file: /var/db/kea/kea-leases6.csv.1
//	INFO  [DhcpLFC.dhcpsrv.0x378a5665f010] DHCPSRV_MEMFILE_LEASE_FILE_LOAD loading leases from file /var/db/kea/kea-leases6.csv.1
//	INFO  [DhcpLFC.0x10b74225f010] LFC_READ_STATS Leases: 162, attempts: 164, errors: 0.
//	INFO  [DhcpLFC.0x10b74225f010] LFC_WRITE_STATS Leases: 21, attempts: 21, errors: 0.
//	INFO  [DhcpLFC.0x10b74225f010] LFC_ROTATING LFC rotating files
//	INFO  [DhcpLFC.0x10b74225f010] LFC_TERMINATE LFC finished processing
//
// Both captured kea-dhcp6 LFC shapes (kea-dhcp6's other message ids — lease
// events, packet lifecycle, control-plane — are already structured above by
// parseKeaDHCP's earlier branches; only its LFC-launch pair was unmodelled):
//
//	INFO  [kea-dhcp6.dhcpsrv.0x3fa9c3469010] DHCPSRV_MEMFILE_LFC_START starting Lease File Cleanup
//	INFO  [kea-dhcp6.dhcpsrv.0x3fa9c3469010] DHCPSRV_MEMFILE_LFC_EXECUTE executing Lease File Cleanup using: /usr/local/sbin/kea-lfc -6 -x /var/db/kea/kea-leases6.csv.2 -i /var/db/kea/kea-leases6.csv.1 -o /var/db/kea/kea-leases6.csv.output -f /var/db/kea/kea-leases6.csv.completed -p /var/db/kea/kea-leases6.csv.pid -c ignored-path
//
// Verdict (#664): worth structuring the envelope (msg id + component) for the
// whole family, plus the LFC_READ_STATS/LFC_WRITE_STATS counters specifically —
// `errors:` there is silent-lease-file-corruption signal nothing else on the box
// reports, and `attempts - leases` is a read-integrity ratio. LFC_PROCESSING,
// DHCPSRV_MEMFILE_LEASE_FILE_LOAD and DHCPSRV_MEMFILE_LFC_EXECUTE carry only file
// paths fixed by Kea's own layout (and, for LFC_EXECUTE, the kea-lfc argv) — the
// message id is captured but those paths/argv deliberately stay in the body, not
// parsed into attributes.
//
// One generic envelope parser covers the whole family rather than one regex per
// message id: any Kea message id this file does not special-case (today or in a
// future Kea release) still emits kea.msg_id/kea.component instead of falling
// through fully unparsed. It only fires as parseKeaDHCP's last-resort branch —
// see the "Kea-wide envelope fallback" comment in dhcp.go — so it never
// second-guesses the lease/packet/alloc-fail/command branches that already
// structure a message id.
var (
	// keaEnvelopeRE matches the shared Kea/DhcpLFC envelope, capturing the raw
	// logger hierarchy (still carrying its trailing 0x-context address), the
	// message id, and the free-text remainder.
	keaEnvelopeRE = regexp.MustCompile(`^(?:INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\s+\[([^\]]+)\]\s+([A-Z][A-Z0-9_]*)\s*(.*)$`)

	// keaComponentSuffixRE strips the trailing ".0xADDR" thread/context pointer
	// off a logger hierarchy, e.g. "DhcpLFC.dhcpsrv.0x378a5665f010" ->
	// "DhcpLFC.dhcpsrv". Kept as its own pattern so a hierarchy that (unexpectedly)
	// carries no context address is passed through unchanged rather than dropped.
	keaComponentSuffixRE = regexp.MustCompile(`^(.*)\.0x[0-9a-fA-F]+$`)

	// keaLFCStatsRE reads the read/write pass counters off an LFC_READ_STATS or
	// LFC_WRITE_STATS line's free text ("Leases: 162, attempts: 164, errors: 0.").
	keaLFCStatsRE = regexp.MustCompile(`^Leases:\s*(\d+),\s*attempts:\s*(\d+),\s*errors:\s*(\d+)\.?$`)
)

// parseKeaEnvelope structures the shared Kea envelope. Returns ok=false when msg
// does not carry the envelope shape at all (no level word, no bracketed logger
// hierarchy) — the caller then ships it fully generic, same as any other
// unrecognised line.
func parseKeaEnvelope(msg string) (dhcpFields, bool) {
	m := keaEnvelopeRE.FindStringSubmatch(msg)
	if m == nil {
		return dhcpFields{}, false
	}

	f := dhcpFields{keaMsgID: m[2]}
	if cm := keaComponentSuffixRE.FindStringSubmatch(m[1]); cm != nil {
		f.keaComponent = cm[1]
	} else {
		f.keaComponent = m[1]
	}

	switch f.keaMsgID {
	case "LFC_READ_STATS", "LFC_WRITE_STATS":
		if sm := keaLFCStatsRE.FindStringSubmatch(m[3]); sm != nil {
			f.keaLFCLeases = sm[1]
			f.keaLFCAttempts = sm[2]
			f.keaLFCErrors = sm[3]
			if f.keaMsgID == "LFC_READ_STATS" {
				f.keaLFCPhase = "read"
			} else {
				f.keaLFCPhase = "write"
			}
		}
	}

	return f, true
}
