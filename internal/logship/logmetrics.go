package logship

// MetricSink receives one call per parsed log record from the nine derived
// metric families (#258). It is the seam between the
// syslog receiver goroutine (which knows each program's attribute keys) and the
// `log_events` collector (which owns the metric definitions and running totals).
//
// It lives in package logship — not in the syslog package — so logship.Deps can
// carry it without logship importing the syslog package back (the syslog package
// already imports logship for Record/PushSource, so the interface must sit here to
// avoid a cycle). The concrete implementation is *collector.LogEventStore, wired in
// by main.go; the receiver only ever sees this interface.
//
// Every method takes a small, FIXED set of label values. An implementation MUST
// treat these purely as counter labels: no IP, port, SID, MAC, hostname, username or
// free-text rule description is ever passed here, and none may be added — those stay
// as structured metadata on the shipped log line.
//
// Fixed in ARITY, though, not in cardinality. Some of these values are closed
// vocabularies the deriver resolves in code (action, DHCP action, auth result, status
// class, EVE event type and severity); the rest — rule id, interface, HAProxy
// backend and server, IDS category — are free-form on the wire, and both receivers
// are push-based, with syslog over UDP carrying a spoofable source address. So the
// caller cannot promise a low-cardinality tuple, and an earlier version of this
// comment promising one was describing expected traffic rather than anything
// enforced. An implementation MUST bound its own key growth; collector.LogEventStore
// does it with a per-family insert-time budget (--logs.max-metric-keys) that folds
// refused tuples into a counted overflow rather than dropping them.
//
// Calls happen on the receiver read goroutine, so an implementation must be
// non-blocking and safe for concurrent use with its own scrape-time reads. A false
// result means the observation was not accepted; callers that sample raw records
// must retain that record rather than treating its total as safely captured.
type MetricSink interface {
	// ObserveFirewall counts one filterlog line. ruleID is the OPNsense rule id
	// (rid) or the rulenr ref; ruleName is the rule's description text used as its
	// human name (1:1 with ruleID, so it does not multiply cardinality).
	ObserveFirewall(action, iface, ruleID, ruleName, scope string) bool
	// ObserveHAProxy counts one HAProxy line. statusClass is "2xx"/"3xx"/"4xx"/"5xx"
	// or "" when the line carries no HTTP status.
	ObserveHAProxy(event, backend, server, state, statusClass string) bool
	// ObserveSSHD counts one sshd auth line (result = accepted/failed/invalid-user/…).
	ObserveSSHD(result, method, scope string) bool
	// ObserveDHCP counts one DHCP lease line (action = ack/nak/offer/…).
	ObserveDHCP(action, iface, server string) bool
	// ObserveAudit counts one audit line (event = config_change/authorization/…).
	ObserveAudit(event, result string) bool
	// ObserveIDS counts one Suricata EVE line. sid and signature text are NEVER
	// passed. eventType, action and severity are closed vocabularies resolved by the
	// deriver; category is the rule author's own text and is bounded only by the
	// implementation's key budget.
	ObserveIDS(eventType, action, category, severity string) bool
	// ObserveGateway counts a dpinger transition. event is the parser's closed
	// vocabulary; gateway is the configured monitor name and is bounded by the
	// implementation's per-family key budget.
	ObserveGateway(event, gateway string) bool
	// ObserveRADIUS counts one FreeRADIUS access decision.
	ObserveRADIUS(event, result, clientScope string) bool
	// ObserveZenarmor counts one Zenarmor record, from any of its families.
	ObserveZenarmor(o ZenarmorObservation) bool
}

// ZenarmorObservation carries the seven dimensions of one Zenarmor record that may
// become labels. Fields that do not apply to a family stay empty.
//
// A struct rather than positional arguments, unlike its siblings above: this
// carries seven dimensions, and a seven-string call site is precisely where a
// dimension goes missing unnoticed.
//
// Zenarmor is the highest-cardinality data this exporter touches — every field
// here is a deliberate inclusion, and the omissions are the point. app_name, any IP or port, hostname, MAC,
// ja3, session_id, community_id, conn_uuid, signature, uri, query and server_name
// are NOT represented and must never be added; they stay as structured metadata on
// the shipped record, where they are still filterable and cannot become labels.
type ZenarmorObservation struct {
	// Family is the record's subsystem: flow | dns | tls | web | ids | voip.
	Family string
	// Action is the normalised AttrAction: pass | block | "" (unknown).
	Action string
	// Category is the family's classification: app_category (flow),
	// domain_category (dns, tls) or alert_category (ids). Zenarmor's own taxonomies
	// are closed sets, but alert_category is named by whoever wrote the rule, so
	// this dimension is free-form and is bounded only by the sink's key budget.
	Category string
	// Interface is the friendly interface name, falling back to the raw device.
	// Deployment-scale, not code-defined.
	Interface string
	// RCode is the DNS response code, clamped to the 4-bit RCODE range plus
	// Zenarmor's -1 "no response yet" sentinel. dns only.
	RCode string
	// Severity is the alert severity, clamped to the 1-4 scale. ids only.
	Severity string
	// StatusClass buckets the HTTP status: 2xx | 3xx | 4xx | 5xx. web only.
	StatusClass string
}

// NopMetricSink is the MetricSink used when metric derivation is disabled (the
// log_events collector is turned off). Every method is a no-op.
type NopMetricSink struct{}

func (NopMetricSink) ObserveFirewall(_, _, _, _, _ string) bool  { return true }
func (NopMetricSink) ObserveHAProxy(_, _, _, _, _ string) bool   { return true }
func (NopMetricSink) ObserveSSHD(_, _, _ string) bool            { return true }
func (NopMetricSink) ObserveDHCP(_, _, _ string) bool            { return true }
func (NopMetricSink) ObserveAudit(_, _ string) bool              { return true }
func (NopMetricSink) ObserveIDS(_, _, _, _ string) bool          { return true }
func (NopMetricSink) ObserveGateway(_, _ string) bool            { return true }
func (NopMetricSink) ObserveRADIUS(_, _, _ string) bool          { return true }
func (NopMetricSink) ObserveZenarmor(_ ZenarmorObservation) bool { return true }
