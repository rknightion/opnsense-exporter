package logship

// AttrAction is the normalised, CODE-DEFINED disposition a Source may set on a
// Record: did this firewall let the thing through, or stop it?
//
// The OTLP sink HOISTS it onto the resource alongside AttrSubsystem and attrSource,
// so it can be promoted to a Loki index label — which makes
// {opnsense_action="block"} a stream SELECTION rather than a scan of every record
// shipped. Promote it as `opnsense.action` in the tenant otlp_config. Namespaced,
// like the other two, so it can never collide with a semconv/Loki-reserved key.
//
// The vocabulary is deliberately BINARY. Each lane's own richer verb
// (action=reject, alert_action=blocked, decision_type=captcha) stays on the record
// as structured metadata, where it is still filterable with `|` and cannot affect
// label cardinality. Two reasons this matters:
//
//  1. The lanes do not agree with each other. filterlog says pass/block/reject,
//     unbound says Pass/Block/Drop, suricata says allowed/blocked, crowdsec says
//     ban/captcha. A label whose values are "block" or "blocked" or "Block"
//     depending on which engine decided is not a usable label.
//  2. action multiplies the sink's resource-key count (source x subsystem x
//     action) against maxLogResources. Binary keeps that budget affordable; a
//     four- or five-value vocabulary would not, for no query benefit.
const AttrAction = "opnsense.action"

// The complete AttrAction vocabulary. Anything else is a bug. Adding a third value
// means re-checking the sink's maxLogResources budget.
const (
	ActionPass  = "pass"
	ActionBlock = "block"
)

// MapFilterlogAction maps pf's filterlog verb onto the AttrAction vocabulary.
//
// It returns "" for anything unrecognised, and callers MUST then leave AttrAction
// unset. This is not defensive padding: filterlog's action is a raw wire
// passthrough (`action := f[fAction]`, syslog/filterlog.go:89) — the parser does
// not constrain the vocabulary, and NAT/rdr rules can emit verbs that are neither a
// pass nor a deny. Mapping an unknown verb to "block" would silently mislabel it as
// a security event, and a wrong security label is worse than an absent one. An
// unset AttrAction simply means the record is not selectable by action; it stays
// fully filterable on the lane's own `action` key.
func MapFilterlogAction(v string) string {
	switch v {
	case "pass":
		return ActionPass
	case "block", "reject":
		return ActionBlock
	default:
		return ""
	}
}

// MapUnboundAction maps the unbound reporting DB's verb onto AttrAction. Its values
// are Capitalised — "Pass" | "Block" | "Drop", documented at
// opnsense/unbound_search_queries.go:39 and exercised by its tests. (unboundSeverity
// only proves "Block" and "Drop"; it is not the source of truth for the full set.)
func MapUnboundAction(v string) string {
	switch v {
	case "Pass":
		return ActionPass
	case "Block", "Drop":
		return ActionBlock
	default:
		return ""
	}
}

// MapSuricataAction maps a Suricata EVE alert action onto AttrAction. Shared by the
// syslog suricata parser and the ids poll lane, which read the same EVE field.
func MapSuricataAction(v string) string {
	switch v {
	case "allowed":
		return ActionPass
	case "blocked":
		return ActionBlock
	default:
		return ""
	}
}
