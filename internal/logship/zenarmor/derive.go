package zenarmor

import (
	"strconv"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// observeDerived counts one record against sink.
//
// Every field it fills is a bounded, code-or-taxonomy-defined value. Zenarmor is the
// highest-cardinality data this exporter touches, and the per-flow fields sitting
// right next to these in the same map — app_name, any IP or port, hostname, MAC,
// ja3, session_id, community_id, conn_uuid, server_name, uri, query — must never
// reach a label. They stay on the shipped record, where they are still filterable.
//
// Unlike syslog, Zenarmor does not sample raw records, but the acceptance result is
// still propagated so callers and tests cannot mistake a full handoff for a counted
// observation. Every document is offered under its family even when parsing failed,
// so sum(rate(...zenarmor_total)) stays equal to the accepted document rate.
func observeDerived(sink logship.MetricSink, family string, attrs map[string]string) bool {
	if sink == nil {
		return false
	}
	o := logship.ZenarmorObservation{
		Family: family,
		Action: attrs[logship.AttrAction],
		// The friendly name when enrichment resolved it, else the raw device (ixl0).
		Interface: firstNonEmpty(attrs[attrInterfaceName], attrs[attrInterfaceDev]),
	}
	switch family {
	case "flow":
		o.Category = attrs[attrAppCategory]
	case "dns":
		o.Category = attrs[attrDomainCategory]
		o.RCode = attrs[attrRCode]
	case "tls":
		o.Category = attrs[attrDomainCategory]
	case "web":
		o.StatusClass = statusClass(attrs[attrHTTPStatus])
	case "ids":
		o.Category = attrs[attrAlertCategory]
		o.Severity = attrs[attrAlertSeverity]
	}
	return sink.ObserveZenarmor(o)
}

// statusClass buckets an HTTP status code into "2xx".."5xx". Empty or unparseable
// input (including anything outside 100-599) yields "", which keeps a malformed
// status out of the label rather than inventing a bucket for it.
func statusClass(status string) string {
	if status == "" {
		return ""
	}
	code, err := strconv.Atoi(status)
	if err != nil || code < 100 || code > 599 {
		return ""
	}
	return strconv.Itoa(code/100) + "xx"
}

// firstNonEmpty returns a, falling back to b when a is empty.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
