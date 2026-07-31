package syslog

import "github.com/rknightion/opnsense2otel/v4/internal/logship"

// sampleKeep decides whether a record should still ship after observeDerived
// has (or has not) counted it. The binding rule: a line observeDerived did
// NOT count is NEVER dropped — sampling only thins lines whose totals are
// already captured in a Prometheus counter, so nothing is lost outright, only
// the redundant raw copy of the routine, already-counted cases.
func sampleKeep(program string, rec logship.Record, counted bool) bool {
	if !counted {
		return true
	}

	fam, ok := deriveFamily(program)
	if !ok {
		return true
	}

	switch fam {
	case familyFirewall:
		// The bulk of firewall traffic is routine "pass" — drop it once counted,
		// but keep every block/reject so an investigation never loses a denied
		// connection.
		return rec.Attributes["action"] != "pass"
	case familyHAProxy:
		// Keep only the interesting transitions (server down, no server
		// available, 4xx/5xx) — the routine "Connect from" line and healthy
		// 2xx/3xx traffic are dropped once counted.
		return rec.Severity >= logship.SeverityWarn
	default:
		// sshd, dhcp, audit, ids, gateway, radius, vpn, carp and upnp: low-volume
		// security/operational trails, keep all of them — the counters capture
		// totals, but every line still matters here. It matters most for vpn and
		// carp: those counters deliberately carry no identity and no cause, so the
		// raw line is the ONLY place the IKE identity, username or certificate
		// subject behind a VPN failure — or the kernel's reason for a CARP
		// transition — can be read.
		//
		// familyCARP reaching here is ALWAYS a genuine CARP transition, never one of
		// the many unrelated kernel lines that share its family: an uncounted line
		// returned true at the top of this function, and carp.go only lets a captured
		// CARP shape be counted.
		//
		// familyUPnP (#409) belongs here for the same reason as vpn and carp, and it is
		// the family whose raw line matters MOST relative to its counter: the counter
		// carries only event/result/protocol, so the ports and the daemon's addr= token —
		// the only things that identify WHICH mapping failed to clean up — exist nowhere
		// but the shipped record. Volume is not a concern either: the five-day production
		// sample was 1,598 records in total, a few hundred a day.
		return true
	}
}
