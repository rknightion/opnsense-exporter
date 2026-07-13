// Package logship is the exporter's opt-in log/event shipping pipeline. It is a
// long-lived background loop (never a Prometheus CollectorInstance): registered
// Sources poll structured events from the OPNsense API on their own cadence, a
// bounded drop-oldest queue provides counted backpressure, and an emitter ships
// batches to a Sink (OTLP logs or stdout).
//
// Delivery semantics are honest and bounded: at-least-once within a run (each
// Source owns its cursor + dedup ring), at-most-once across restarts (in-memory
// cursors resume from now unless --logs.state-file persists them), never
// exactly-once. High-cardinality data (IPs, ports, SIDs, domains) travels as
// structured metadata / body and NEVER as a Loki label — the only labels are the
// resource identity (service.name + service.instance.id) plus the promotable
// `source` attribute.
package logship

import "time"

// Severity is an optional per-record severity. The zero value (SeverityInfo) is
// used when a Source does not classify a line. Values map to OTLP/Loki severity
// numbers in the OTLP sink.
type Severity int8

const (
	// SeverityInfo is the default (zero value) severity.
	SeverityInfo Severity = iota
	SeverityTrace
	SeverityDebug
	SeverityWarn
	SeverityError
	SeverityFatal
)

// Reserved attribute keys are owned by the pipeline and stripped from any
// Record.Attributes a Source sets, so a lane cannot accidentally forge the
// resource identity or the source stamp (which would corrupt the fixed Loki
// label set). The pipeline sets `source` itself from Source.Name(); the resource
// identity keys are set on the OTLP resource, never per record.
const (
	attrSource            = "source"
	attrServiceName       = "service.name"
	attrServiceInstanceID = "service.instance.id"
)

// reservedAttributeKeys is the set the pipeline defensively removes from every
// Record.Attributes before shipping. Kept as a package var so tests assert the
// exact set.
var reservedAttributeKeys = []string{attrSource, attrServiceName, attrServiceInstanceID}

// Record is one log/event line produced by a Source. Source lanes construct
// these in Poll.
//
// Attributes become Loki structured metadata (never labels): put IPs, ports,
// SIDs, domains, rule ids here. The keys "source", "service.name" and
// "service.instance.id" are RESERVED — the pipeline strips them from Attributes
// and sets them itself, so do not use them.
type Record struct {
	// Timestamp is the event's own time. A zero value is stamped at emit time.
	Timestamp time.Time
	// Body is the raw line (firewall/backend) or a compact JSON encoding (IDS).
	Body string
	// Attributes are shipped as Loki structured metadata. NEVER labels.
	Attributes map[string]string
	// Severity is optional; the zero value is SeverityInfo.
	Severity Severity
}

// Entry is a Record paired with its resolved source name, as handed to a Sink.
// The pipeline builds these; Sinks consume them.
type Entry struct {
	Source string
	Record Record
}

// sanitizeAttributes returns attrs with every reserved key removed. It never
// mutates the caller's map: when a reserved key is present a fresh map is
// allocated, otherwise the original is returned unchanged. A nil input yields a
// nil output.
func sanitizeAttributes(attrs map[string]string) map[string]string {
	if attrs == nil {
		return nil
	}
	hasReserved := false
	for _, k := range reservedAttributeKeys {
		if _, ok := attrs[k]; ok {
			hasReserved = true
			break
		}
	}
	if !hasReserved {
		return attrs
	}
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	for _, k := range reservedAttributeKeys {
		delete(out, k)
	}
	return out
}
