package logship

// MetricSink receives one call per parsed log record from the six programs the
// receiver derives Prometheus counters from (#258). It is the seam between the
// syslog receiver goroutine (which knows each program's attribute keys) and the
// `log_events` collector (which owns the metric definitions and running totals).
//
// It lives in package logship — not in the syslog package — so logship.Deps can
// carry it without logship importing the syslog package back (the syslog package
// already imports logship for Record/PushSource, so the interface must sit here to
// avoid a cycle). The concrete implementation is *collector.LogEventStore, wired in
// by main.go; the receiver only ever sees this interface.
//
// Every method takes a small, fixed, low-cardinality set of label values. An
// implementation MUST treat these purely as counter labels: no IP, port, SID, MAC,
// hostname, username or free-text rule description is ever passed here, and none may
// be added — those stay as structured metadata on the shipped log line.
//
// Calls happen on the receiver read goroutine, so an implementation must be
// non-blocking and safe for concurrent use with its own scrape-time reads.
type MetricSink interface {
	// ObserveFirewall counts one filterlog line. ruleID is the OPNsense rule id
	// (rid) or the rulenr ref; ruleName is the rule's description text used as its
	// human name (1:1 with ruleID, so it does not multiply cardinality).
	ObserveFirewall(action, iface, ruleID, ruleName, scope string)
	// ObserveHAProxy counts one HAProxy line. statusClass is "2xx"/"3xx"/"4xx"/"5xx"
	// or "" when the line carries no HTTP status.
	ObserveHAProxy(event, backend, server, state, statusClass string)
	// ObserveSSHD counts one sshd auth line (result = accepted/failed/invalid-user/…).
	ObserveSSHD(result, method, scope string)
	// ObserveDHCP counts one DHCP lease line (action = ack/nak/offer/…).
	ObserveDHCP(action, iface, server string)
	// ObserveAudit counts one audit line (event = config_change/authorization/…).
	ObserveAudit(event, result string)
	// ObserveIDS counts one Suricata EVE line. sid and signature text are NEVER
	// passed — only the bounded category/action/severity/event_type.
	ObserveIDS(eventType, action, category, severity string)
	// ObserveZenarmor counts one Zenarmor record, from any of its families.
	ObserveZenarmor(o ZenarmorObservation)
}

// ZenarmorObservation carries one Zenarmor record's bounded dimensions. Fields
// that do not apply to a family stay empty.
//
// A struct rather than positional arguments, unlike its siblings above: this
// carries seven dimensions, and a seven-string call site is precisely where a
// dimension goes missing unnoticed.
//
// Zenarmor is the highest-cardinality data this exporter touches — every field
// here is a deliberate, bounded choice. app_name, any IP or port, hostname, MAC,
// ja3, session_id, community_id, conn_uuid, signature, uri, query and server_name
// are NOT represented and must never be added; they stay as structured metadata on
// the shipped record, where they are still filterable and cannot become labels.
type ZenarmorObservation struct {
	// Family is the record's subsystem: flow | dns | tls | web | ids | voip.
	Family string
	// Action is the normalised AttrAction: pass | block | "" (unknown).
	Action string
	// Category is the family's bounded classification: app_category (flow),
	// domain_category (dns, tls) or alert_category (ids).
	Category string
	// Interface is the friendly interface name.
	Interface string
	// RCode is the DNS response code. dns only.
	RCode string
	// Severity is the alert severity. ids only.
	Severity string
	// StatusClass buckets the HTTP status: 2xx | 3xx | 4xx | 5xx. web only.
	StatusClass string
}

// NopMetricSink is the MetricSink used when metric derivation is disabled (the
// log_events collector is turned off). Every method is a no-op.
type NopMetricSink struct{}

func (NopMetricSink) ObserveFirewall(_, _, _, _, _ string)  {}
func (NopMetricSink) ObserveHAProxy(_, _, _, _, _ string)   {}
func (NopMetricSink) ObserveSSHD(_, _, _ string)            {}
func (NopMetricSink) ObserveDHCP(_, _, _ string)            {}
func (NopMetricSink) ObserveAudit(_, _ string)              {}
func (NopMetricSink) ObserveIDS(_, _, _, _ string)          {}
func (NopMetricSink) ObserveZenarmor(_ ZenarmorObservation) {}
