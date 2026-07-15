package syslog

import (
	"strconv"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// BuildRecord turns one parsed syslog Envelope into a logship.Record.
//
// Dispatch is by program, through the parser registry (registry.go): each parser
// lane registers itself from an init() in its own file. A program with no
// registered parser -- or whose parser cannot make sense of the line -- ships as a
// generic record carrying the message verbatim. AN UNKNOWN PROGRAM IS NEVER
// DROPPED: shipping it is the entire point of a catch-all receiver, and a box runs
// plugins we have never heard of.
//
// Every record, structured or generic, then gets:
//   - a `subsystem` attribute, so Loki can select "everything DHCP" without
//     enumerating the three backends that might be serving it;
//   - universal enrichment of any address or interface device mentioned in the
//     message (see enrichgeneric.go). Structured parsers that already resolved
//     their own positional addresses (filterlog's src/dst) skip this.
func BuildRecord(env Envelope, snap *enrich.Snapshot, miss func(table string)) logship.Record {
	if p, ok := parserFor(env.Program); ok {
		if rec, ok := p(env, snap, miss); ok {
			addCommon(&rec, env, snap, false)
			return rec
		}
		// A line the parser could not make sense of degrades to generic, carrying the
		// raw body -- never a drop.
	}
	rec := genericRecord(env)
	addCommon(&rec, env, snap, true)
	return rec
}

// addCommon adds the attributes every record gets regardless of how it was parsed.
// enrichBody is false for parsers that already emitted positional addresses of
// their own (filterlog's src.*/dst.*): re-scanning their body would emit the same
// addresses a second time under peer.* keys.
func addCommon(rec *logship.Record, env Envelope, snap *enrich.Snapshot, enrichBody bool) {
	if rec.Attributes == nil {
		rec.Attributes = make(map[string]string, 4)
	}
	set := func(k, v string) {
		if v != "" {
			rec.Attributes[k] = v
		}
	}
	set(logship.AttrSubsystem, subsystemFor(env.Program))
	if enrichBody {
		enrichMessage(env.Message, snap, set)
	}
	// Tunnel/instance UUIDs are resolved for structured and generic records alike:
	// an IPsec or OpenVPN line names its tunnel as a bare UUID wherever it appears,
	// and no parser is going to make that readable on its own.
	enrichTunnels(env.Program, env.Message, snap, set)
}

// genericRecord ships the message verbatim with the syslog envelope as
// structured metadata.
func genericRecord(env Envelope) logship.Record {
	attrs := make(map[string]string, 8)
	set := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	set("program", env.Program)
	set("host", env.Hostname)
	set("pid", env.PID)
	attrs["facility"] = strconv.Itoa(env.Facility)
	attrs["severity"] = strconv.Itoa(env.Severity)

	return logship.Record{
		Timestamp:  env.Timestamp,
		Body:       env.Message,
		Attributes: attrs,
		Severity:   syslogSeverity(env.Severity),
	}
}

// newRecord is the helper every structured parser uses to build its record, so
// they all carry the same envelope metadata (program/host/pid/facility/severity)
// as a generic record does. A parser then adds its own structured attributes on
// top.
func newRecord(env Envelope) (logship.Record, func(k, v string)) {
	rec := genericRecord(env)
	set := func(k, v string) {
		if v != "" {
			rec.Attributes[k] = v
		}
	}
	return rec, set
}

// syslogSeverity maps an RFC5424 severity (0 emerg … 7 debug) onto the pipeline's
// severity. emerg/alert/crit map to Fatal rather than being folded into Error —
// folding them would throw information away. An out-of-range value degrades to
// Info; it is never a reason to drop a line.
func syslogSeverity(sev int) logship.Severity {
	switch {
	case sev >= 0 && sev <= 2:
		return logship.SeverityFatal
	case sev == 3:
		return logship.SeverityError
	case sev == 4:
		return logship.SeverityWarn
	case sev == 5 || sev == 6:
		return logship.SeverityInfo
	case sev == 7:
		return logship.SeverityDebug
	default:
		return logship.SeverityInfo
	}
}
