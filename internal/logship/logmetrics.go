package logship

// MetricSink receives one call per parsed log record from the derived
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
	// ObserveVPN counts one IPsec or OpenVPN lifecycle transition (#406). backend,
	// event and result are CLOSED code-defined vocabularies resolved by the deriver
	// (backend = ipsec|openvpn; event = established|terminated|
	// authentication_failed|liveness_failed|certificate_failed; result =
	// success|failure). connection is the API-resolved CONFIGURED tunnel or instance
	// name, EMPTY when unresolved and NEVER a raw UUID — it is bounded by the
	// implementation's per-family key budget.
	//
	// Usernames, certificate subjects/CNs/serials, IKE identities, peer addresses and
	// ports, SPIs and daemon error text are NEVER passed here and must never be
	// added; they stay in the shipped log line's body.
	ObserveVPN(backend, event, result, connection string) bool
	// ObserveCARP counts one FreeBSD kernel CARP transition (#405). event, from and to
	// are CLOSED code-defined vocabularies resolved by the parser and deriver
	// (event = state_changed|demoted|promoted; from/to = master|backup|init,
	// lowercased). iface is the OS device (vtnet2) and vhid the configured VHID as a
	// string; both are configuration-scale and bounded by the implementation's
	// per-family key budget.
	//
	// from, to, iface and vhid are ALL EMPTY on a demotion record: FreeBSD's
	// carp_demote_adj is global to the node and names neither an interface nor a vhid,
	// so an empty value there is the honest answer, not a missing one.
	//
	// The kernel's CAUSE string is NEVER passed here and must never be added — not
	// even bucketed into a reason_class. It is open-ended free text across FreeBSD
	// versions, so any label built from it is unbounded and any bucketing of it is a
	// taxonomy no capture supports. The signed demotion delta and the resulting total
	// are likewise never passed: they are unbounded integers. All three stay as
	// structured attributes on the shipped log record, where they are still queryable.
	ObserveCARP(event, from, to, iface, vhid string) bool
	// ObserveUPnP counts one miniupnpd mapping event (#409). All three values are
	// CLOSED code-defined vocabularies resolved by the parser and deriver: event =
	// expired|cleanup_failed|unauthorized|lease_file_error; result = ok (expired only)
	// |failure; protocol = tcp|udp|"". protocol is EMPTY on the two cleanup-failure
	// grammars and the lease-file error, which name none — the honest answer, not a
	// missing one.
	//
	// Port numbers are NEVER passed here and must never be added: an ephemeral client
	// port is unbounded and would multiply a series per mapping. Neither is the
	// daemon's opaque `addr=` token, the lease-file path, a mapping description or any
	// client identity; those stay in the shipped log line's body.
	//
	// There is deliberately NO mapping-count observation of any kind. An event stream
	// cannot reconstruct authoritative active-mapping state (the plugin's own status
	// page runs pfctl for it, restarts and pre-existing mappings are invisible), and
	// `expired` is a decrement with no matching increment, so anything gauge-shaped
	// built from this family would drift negative without bound.
	ObserveUPnP(event, result, protocol string) bool
	// ObserveZenarmor counts one Zenarmor record, from any of its families.
	ObserveZenarmor(o ZenarmorObservation) bool
	// ObserveZenarmorDevice records a sighting of one client device Zenarmor
	// attributed traffic to, for the bounded device INVENTORY (#474) — a distinct
	// metric from the counter above, not an extra dimension on it.
	//
	// It is a separate method precisely so device_name stays off ZenarmorObservation.
	// That struct is the counter's label tuple and carries an explicit rule that
	// device_name must never join it; a third field there would multiply an unbounded
	// name through all seven counter dimensions. Here it costs one series per live
	// device, expired and capped by the implementation.
	//
	// An empty name is not a device and must be ignored by implementations.
	ObserveZenarmorDevice(name, category, iface string) bool
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
func (NopMetricSink) ObserveVPN(_, _, _, _ string) bool          { return true }
func (NopMetricSink) ObserveCARP(_, _, _, _, _ string) bool      { return true }
func (NopMetricSink) ObserveUPnP(_, _, _ string) bool            { return true }
func (NopMetricSink) ObserveZenarmor(_ ZenarmorObservation) bool { return true }
func (NopMetricSink) ObserveZenarmorDevice(_, _, _ string) bool  { return true }
