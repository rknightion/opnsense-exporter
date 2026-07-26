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
// structured metadata / body and can NEVER become a Loki label, because Loki only
// ever promotes RESOURCE attributes and those stay on the record. The resource
// carries just four things: the identity (service.name, service.instance.id,
// service.version) plus the two closed, code-defined keys worth selecting a stream
// on — `source` and `subsystem`. Promoting those to index labels is a tenant-side
// opt-in that costs the exporter nothing; see sink_otlp.go.
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
	// attrSource is namespaced (opnsense.source, not a bare "source") so the custom
	// resource key can never collide with a semconv/Loki-reserved key. Promote it as
	// `opnsense.source` in the tenant otlp_config. service.* stay semconv-standard.
	attrSource            = "opnsense.source"
	attrServiceName       = "service.name"
	attrServiceInstanceID = "service.instance.id"
)

// attrSubsystem is a coarse, CODE-DEFINED grouping a Source may set on a Record
// ("firewall", "dns", "auth", …). Unlike the keys above it is NOT reserved —
// Sources are expected to set it.
//
// The OTLP sink HOISTS it, along with `source`, off the record and onto the OTLP
// resource. That is not cosmetic: Loki can only promote a RESOURCE attribute to an
// index label — `otlp_config` has no index_label action for log attributes — so an
// attribute left on the record can never be indexed, whatever the tenant config
// says. See sink_otlp.go.
//
// Only put a CLOSED, code-defined set of values behind this key. Anything derived
// from the wire (a syslog program name, an IP) would become unbounded label
// cardinality the moment a tenant promotes it.
//
// Namespaced (opnsense.subsystem, not a bare "subsystem") for the same
// collision-safety reason as attrSource; promote it as `opnsense.subsystem`.
//
// EXPORTED because Sources live in sibling packages (e.g. internal/logship/syslog)
// and must set it under exactly this key — the OTLP sink only hoists THIS key onto
// the resource, so a source using a bare "subsystem" literal would silently leave it
// on the record, unpromotable. Set it via logship.AttrSubsystem, never a literal.
const AttrSubsystem = "opnsense.subsystem"

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
	// Source, when non-empty, overrides the emitting source's Name() as this record's
	// `source`. It lets one receiver emit records attributed to a different logical
	// source — Zenarmor data delivered through the shared syslog receiver still ships as
	// source="zenarmor". Empty means "use the emitter's Name()".
	Source string
}

// Entry is a Record paired with its resolved source name, as handed to a Sink.
// The pipeline builds these; Sinks consume them.
type Entry struct {
	Source string
	Record Record
	// Received is the EXPORTER-clock instant this record was admitted to the shipping
	// queue. It lives on Entry rather than Record deliberately: Record is what a Source
	// (and, for the syslog receiver, ultimately a sender on the network) constructs, so
	// a field there could be forged. Entry is built by the pipeline, and the stamp is
	// taken in exactly one place — pipeline.enqueue, the single ingest gate — so it is
	// taken once per record and never re-taken.
	//
	// That "once" is the point (#394). It becomes the OTLP ObservedTimestamp, which the
	// log data model defines as when the collection system observed the event; setting
	// it per export ATTEMPT (as the sink used to) made it change on every retry, so the
	// same record shipped with a different observed time each time it was resent. It is
	// also what the receive-freshness gauge reads, which is why no sender-supplied
	// timestamp can move that gauge.
	//
	// A zero value means "not stamped by the pipeline" — a Sink constructed directly in
	// a test, or any future caller that bypasses enqueue. Sinks fall back to their own
	// clock rather than shipping a 1970 observed time.
	Received time.Time
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
