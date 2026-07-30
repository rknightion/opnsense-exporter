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
	// ObserveNetmapRingFull counts ONE kernel report that a netmap host TX ring was
	// full (#536). device is the OS device the ring belongs to (ixl0) and is the only
	// label; it is configuration-scale and bounded by the implementation's per-family
	// key budget.
	//
	// THIS IS AN OCCURRENCE COUNT, NOT A PACKET COUNT, and an implementation's help
	// text must say so. netmap_transmit() logs through nm_prlim(2, ...), which
	// rate-limits the kernel to 2 lines per second, so this counter FLAT-TOPS at 2/s
	// and under-reports hardest exactly when the condition is worst. Naming anything
	// derived from it `drops` is forbidden: it would produce a number that looks like
	// packets and is not.
	//
	// hwcur, hwtail and qlen are NEVER passed here and must never be added. They are
	// ring indices that change on every occurrence, so a label built from any of them
	// mints a series per log line; they stay on the shipped record, where they are
	// still the diagnostic (hwcur == hwtail is a completely full ring).
	ObserveNetmapRingFull(device string) bool
	// ObserveARPMove counts ONE kernel report that an IP address moved from one MAC to
	// another (#536) — the kernel's own duplicate-address / MAC-flap / ARP-spoof
	// detector. iface is the OS device and is the ONLY label.
	//
	// The contested IP and BOTH MAC addresses are NEVER passed here and must never be
	// added: they name whichever hosts are fighting over the address, so the value set
	// is unbounded and PII-shaped. They stay on the shipped log record.
	//
	// Polling the ARP table cannot replace this. A flap that resolves inside one poll
	// interval leaves a single MAC in the table, so the scrape sees a healthy entry;
	// only the kernel's own event names the transition.
	ObserveARPMove(iface string) bool
	// ObserveDHCPClient counts ONE DHCP message the firewall's own WAN client sent or
	// received (#541). msgType is a CLOSED code-defined vocabulary resolved from
	// dhclient's wire verb through a map (discover, request, ack, nak, offer, decline,
	// release, inform); an unrecognised verb never reaches a label.
	//
	// iface is EMPTY on a received message that named none. dhclient's `DHCPACK from
	// <ip>` carries no interface, and it is resolved by correlating the daemon's PID
	// with the interface its preceding `DHCPREQUEST on <iface>` named; when the
	// exporter started mid-lease and never saw that line, empty is the honest answer
	// rather than a guess.
	//
	// The DHCP SERVER's address is NEVER passed here and must never be added: it
	// changes when the ISP re-homes the circuit, which is one of the conditions this
	// counter is watching for. It stays on the shipped record.
	//
	// This is a separate family from ObserveDHCP, which counts the DHCP SERVERS this
	// firewall runs. Folding the two together would make a WAN renewal storm
	// indistinguishable from LAN lease churn.
	ObserveDHCPClient(iface, msgType string) bool
	// ObserveDHCPClientScript counts ONE dhclient-script invocation (#541). reason is
	// dhclient-script(8)'s OWN closed vocabulary, lowercased (bound, renew, rebind,
	// reboot, expire, fail, timeout, stop, release, preinit, arpcheck, arpsend, medium,
	// nbi) — resolved through a code-defined map, so a wire token can never become a
	// label. iface is the interface the script was invoked for.
	ObserveDHCPClientScript(iface, reason string) bool
	// ObserveDHCPClientLease records the firewall's OWN WAN lease state (#541). Unlike
	// every other method here this feeds GAUGES, not counters: bound and renewal are
	// absolute Unix seconds — the time of the last successful bind, and the time the
	// next renewal is due — already computed by the parser from the log line's own
	// timestamp plus dhclient's `renewal in N seconds`.
	//
	// TIMESTAMPS RATHER THAN A COUNTDOWN, deliberately. A countdown gauge has to be
	// recomputed against wall-clock at scrape time, and a stale countdown is
	// indistinguishable from a fresh one — which is the exact failure the metric exists
	// to catch. An absolute deadline survives a scrape gap unchanged and makes "the
	// countdown stopped" directly expressible as `renewal_timestamp - time() < 0`.
	//
	// The two are set TOGETHER or not at all: they come from one `bound to` line, and a
	// bind time with no renewal deadline leaves that query with nothing to compare
	// against. The leased address and the DHCP server's address are NEVER passed here —
	// the leased address is this firewall's own public IP and both change under exactly
	// the conditions this metric is watching for. They stay on the shipped record.
	ObserveDHCPClientLease(iface string, bound, renewal float64) bool
	// ObserveDHCP6CMessage counts ONE DHCPv6 message this firewall's own WAN client
	// (dhcp6c) sent or received (#546). direction is sent|received; msgType is a CLOSED
	// code-defined vocabulary folded from dhcp6c's two spellings of the same exchange
	// (solicit, request, renew, rebind, release, information_request), so a Renew and
	// the REPLY answering it share a type.
	//
	// iface is the WAN interface, EMPTY on a `Received REPLY` whose daemon PID could
	// not be correlated back to the `Sending … on <iface>` that named it — the honest
	// answer when the exporter started mid-lease, not a guess.
	//
	// This is a SEPARATE family from ObserveDHCPClient, which is the IPv4 WAN client. A
	// v4 and a v6 uplink fail independently, and the two message vocabularies do not
	// overlap.
	ObserveDHCP6CMessage(iface, direction, msgType string) bool
	// ObserveDHCP6CEvent counts ONE dhcp6c configuration or script event (#546). event
	// is a CLOSED code-defined vocabulary: prefix_created, prefix_updated,
	// address_added, address_removed, script_executing, script_connected,
	// script_prefix_updated, script_ignored. reason is the OPNsense dhcp6c_script
	// REASON, from the script's own `case` set and lowercased onto the same vocabulary
	// as msgType above; it is EMPTY on the prefix and address events, which have none,
	// and on script_ignored, whose REASON is by definition a token nobody has closed.
	//
	// iface MEANS DIFFERENT THINGS PER EVENT, and the event label says which: for the
	// prefix and script events it is the WAN interface dhcp6c is renewing on, and for
	// the address events it is the DOWNSTREAM interface the delegated prefix was
	// applied to (ixl0, ixl0_vlan100). That is the honest reading of each line — an
	// address really is configured on the LAN device — and the tuple is self-describing
	// because address_* is exactly the set with downstream semantics.
	//
	// The configured address and the delegated prefix are NEVER passed here and must
	// never be added; they stay on the shipped log record.
	ObserveDHCP6CEvent(iface, event, reason string) bool
	// ObserveDHCP6CPrefix records this firewall's DELEGATED PREFIX state (#546) — the
	// IPv6 signal with no IPv4 equivalent, because a PD's lifetimes are independent of
	// the WAN address and every downstream network's addressing is derived from it.
	// Like ObserveDHCPClientLease this feeds GAUGES: updated, preferredExpiry and
	// validExpiry are absolute Unix seconds already computed by the parser from the log
	// line's own timestamp plus dhcp6c's pltime and vltime.
	//
	// TIMESTAMPS RATHER THAN COUNTDOWNS, for the reason ObserveDHCPClientLease states.
	// All three are set TOGETHER or not at all: they come from one line, and a refresh
	// time with no deadlines leaves the "it stopped renewing" query nothing to compare
	// against.
	//
	// THE PREFIX ITSELF IS NEVER PASSED HERE and must never be added — not even though
	// it is the firewall's own rather than a client's. It changes on re-delegation,
	// which is precisely the event this metric watches for, so it would churn the
	// series set during the incident. prefixLength IS passed: it is the delegation
	// SIZE, it does not change when the prefix does, and it is what distinguishes a
	// second delegation of a different size on the same WAN. Two delegations of the
	// SAME size on one WAN collapse onto one series, last write wins.
	ObserveDHCP6CPrefix(iface, prefixLength string, updated, preferredExpiry, validExpiry float64) bool
	// ObserveDHCP6CAddress records this firewall's OWN WAN IPv6 ADDRESS lease state
	// (#560) — the IA_NA twin of ObserveDHCP6CPrefix, for a WAN that takes its address
	// directly by DHCPv6 (addrconf.c's `create|update an address %s pltime=%u,
	// vltime=%u`) rather than only a delegated prefix. Same GAUGE shape: updated,
	// preferredExpiry and validExpiry are absolute Unix seconds already computed by
	// the parser from the log line's own timestamp plus dhcp6c's pltime/vltime.
	//
	// TIMESTAMPS RATHER THAN COUNTDOWNS, for the reason ObserveDHCPClientLease states.
	// All three are set TOGETHER or not at all: they come from one line.
	//
	// Labelled {interface} ONLY — there is no prefix_length dimension for a single
	// address. THE ADDRESS ITSELF IS NEVER PASSED HERE and must never be added: it is
	// this firewall's own WAN address and changes on re-bind, which is one of the
	// conditions this metric watches for. It stays on the shipped record as
	// dhcp6c.address.
	ObserveDHCP6CAddress(iface string, updated, preferredExpiry, validExpiry float64) bool
	// ClearDHCP6CAddress removes iface's address-lease gauges (#560) when dhcp6c
	// reports the WAN address REMOVED. Unlike every gauge above, this one is
	// deliberately allowed to make a series disappear: a frozen lifetime gauge reads
	// as a healthy lease that simply stopped being renewed, which is a worse failure
	// mode than the series going absent when the exporter is told the lease is gone.
	ClearDHCP6CAddress(iface string) bool
	// ObserveDHCP6AllocFail counts ONE failed DHCPv6 lease allocation by this
	// firewall's kea-dhcp6 SERVER (#546) — a v6 client that was refused a lease.
	// reason is a CLOSED code-defined vocabulary of exactly two values: no_pools (not
	// one configured pool was usable for this client) and exhausted (pools were tried
	// and every candidate was taken).
	//
	// EXACTLY ONE CALL PER FAILED ALLOCATION, and that is the whole design. Kea emits a
	// BURST of up to three ALLOC_ENGINE_V6_ALLOC_FAIL_* lines for one failure, sharing
	// one transaction id; counting all of them would triple-report. The deriver counts
	// only the CAUSE line, which alloc_engine.cc guarantees fires exactly once per
	// failure and which is the one that carries the reason.
	//
	// THE DUID, THE TRANSACTION ID AND THE SUBNET ARE NEVER PASSED HERE and must never
	// be added: a DUID is unbounded and identifies a client, a tid is unique per
	// exchange, and the subnet is an IPv6 prefix. All three stay on the shipped record.
	ObserveDHCP6AllocFail(reason string) bool
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

func (NopMetricSink) ObserveFirewall(_, _, _, _, _ string) bool { return true }
func (NopMetricSink) ObserveHAProxy(_, _, _, _, _ string) bool  { return true }
func (NopMetricSink) ObserveSSHD(_, _, _ string) bool           { return true }
func (NopMetricSink) ObserveDHCP(_, _, _ string) bool           { return true }
func (NopMetricSink) ObserveAudit(_, _ string) bool             { return true }
func (NopMetricSink) ObserveIDS(_, _, _, _ string) bool         { return true }
func (NopMetricSink) ObserveGateway(_, _ string) bool           { return true }
func (NopMetricSink) ObserveRADIUS(_, _, _ string) bool         { return true }
func (NopMetricSink) ObserveVPN(_, _, _, _ string) bool         { return true }
func (NopMetricSink) ObserveCARP(_, _, _, _, _ string) bool     { return true }
func (NopMetricSink) ObserveNetmapRingFull(_ string) bool       { return true }
func (NopMetricSink) ObserveARPMove(_ string) bool              { return true }
func (NopMetricSink) ObserveDHCPClient(_, _ string) bool        { return true }
func (NopMetricSink) ObserveDHCPClientScript(_, _ string) bool  { return true }

func (NopMetricSink) ObserveDHCPClientLease(_ string, _, _ float64) bool { return true }

func (NopMetricSink) ObserveDHCP6CMessage(_, _, _ string) bool { return true }
func (NopMetricSink) ObserveDHCP6CEvent(_, _, _ string) bool   { return true }
func (NopMetricSink) ObserveDHCP6AllocFail(_ string) bool      { return true }

func (NopMetricSink) ObserveDHCP6CPrefix(_, _ string, _, _, _ float64) bool { return true }

func (NopMetricSink) ObserveDHCP6CAddress(_ string, _, _, _ float64) bool { return true }
func (NopMetricSink) ClearDHCP6CAddress(_ string) bool                    { return true }

func (NopMetricSink) ObserveUPnP(_, _, _ string) bool            { return true }
func (NopMetricSink) ObserveZenarmor(_ ZenarmorObservation) bool { return true }
func (NopMetricSink) ObserveZenarmorDevice(_, _, _ string) bool  { return true }
