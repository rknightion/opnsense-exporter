package syslog

import (
	"strconv"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// BuildRecord turns one parsed syslog Envelope into a logship.Record, dispatching
// on the program (app-name / tag).
//
// Only filterlog gets a structured parser in v1. Everything else — including
// Suricata — ships as a generic record with its message body verbatim: an
// unknown program is NEVER dropped, since shipping it is the entire point of a
// catch-all receiver.
//
// Suricata is deliberately generic. internal/logship/ids.go already ships full
// EVE alert records from the file-based eve.json, which is richer than the
// syslog copy (alerts-only, payload-free). Parsing EVE here as well would ship
// every alert TWICE into Loki with no dedupe, so structured EVE-over-syslog is a
// v2 item that needs a dedupe story first.
func BuildRecord(env Envelope, snap *enrich.Snapshot, miss func(table string)) logship.Record {
	if env.Program == "filterlog" {
		if rec, ok := parseFilterlog(env, snap, miss); ok {
			return rec
		}
		// A row we could not parse degrades to a generic record carrying the
		// raw body — never a drop.
	}
	return genericRecord(env)
}

// genericRecord ships the message verbatim with the syslog envelope as
// structured metadata.
func genericRecord(env Envelope) logship.Record {
	attrs := make(map[string]string, 5)
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
