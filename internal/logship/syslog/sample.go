package syslog

import "github.com/rknightion/opnsense-exporter/internal/logship"

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
		// sshd, dhcp, audit, ids: low-volume security/audit trail, keep all of
		// it — the counter captures totals, but every line still matters here.
		return true
	}
}
