package collector

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// LogEvents is the process-wide store of counters derived from received syslog
// lines (#258). The syslog receiver feeds it out of band via its Observe* methods
// (it satisfies logship.MetricSink, wired in by main); the log_events collector
// reads the running totals on each scrape and emits them as const counter metrics.
//
// It is a singleton because the collector self-registers via init() while the
// receiver is constructed separately — a shared package-level value is the seam
// that lets both reach the same totals without one package importing the other.
var LogEvents = newLogEventStore()

// Label tuples. Each is the full label set for one derived metric family.
// Deliberately no IP, port, SID, MAC, hostname, username or free-text rule
// description — those would be unbounded and must stay as log-line metadata.
//
// The dimensions that remain are either closed vocabularies resolved in code
// (action, result, status class, DNS rcode, IDS severity, EVE event type) or
// deployment-scale free-form values a sender still controls: iface and ruleID here,
// backend and server on haproxy, iface and server on dhcp, category on ids and
// zenarmor. The second group is what LogEventStore's per-family key budget bounds.
type (
	fwKey    struct{ action, iface, ruleID, ruleName, scope string }
	haKey    struct{ event, backend, server, state, statusClass string }
	sshKey   struct{ result, method, scope string }
	dhcpKey  struct{ action, iface, server string }
	auditKey struct{ event, result string }
	idsKey   struct{ eventType, action, category, severity string }
	// gatewayKey deliberately carries only the parser's closed event vocabulary
	// and the configured dpinger monitor name. Address, alarm state, RTT, loss and
	// message text remain structured log fields, never labels.
	gatewayKey struct{ event, gateway string }
	radiusKey  struct{ event, result, clientScope string }
	// vpnKey is the frozen #406 tuple. backend, event and result are closed
	// code-defined vocabularies; connection is the API-RESOLVED configured tunnel or
	// instance name, empty when unresolved and NEVER a raw UUID — it is the one
	// deployment-scale dimension the key budget exists for. Usernames, certificate
	// subjects/CNs/serials, IKE identities, peer addresses and ports, SPIs and daemon
	// error text are deliberately absent and must stay absent; they remain on the
	// shipped log line.
	vpnKey struct{ backend, event, result, connection string }
	// carpKey is the frozen #405 tuple. event, from and to are closed code-defined
	// vocabularies (event = state_changed|demoted|promoted; from/to =
	// master|backup|init, lowercased); iface is the OS device and vhid the configured
	// VHID, the configuration-scale pair the key budget exists for. All four of from,
	// to, iface and vhid are EMPTY on a demotion record, which names none of them.
	//
	// The kernel's CAUSE string is deliberately absent and must stay absent: it is
	// open-ended free text across FreeBSD versions, so it would be an unbounded label,
	// and bucketing it into a reason_class would invent a taxonomy no capture
	// supports. The signed demotion delta and resulting total are absent for the same
	// reason - unbounded integers. All three remain structured fields on the shipped
	// log record.
	carpKey struct{ event, from, to, iface, vhid string }
	// upnpKey is the frozen #409 tuple, and all three dimensions are CLOSED
	// code-defined vocabularies (event = expired|cleanup_failed|unauthorized|
	// lease_file_error; result = ok on expired, failure otherwise; protocol = tcp|udp|"",
	// empty on the grammars that name none). It is the only family here whose key cannot
	// grow past its own vocabulary, so the key budget never binds on it.
	//
	// PORT NUMBERS ARE DELIBERATELY ABSENT AND MUST STAY ABSENT: an ephemeral client
	// port is unbounded and would mint a series per mapping. So are the daemon's opaque
	// addr= token, the lease-file path, mapping descriptions and client identities - all
	// of which remain on the shipped log record. There is likewise no mapping COUNT of
	// any kind: an event stream cannot reconstruct authoritative active-mapping state,
	// and expired is a decrement with no matching increment.
	upnpKey struct{ event, result, protocol string }
	// netmapKey carries the OS device alone (#536). hwcur, hwtail and qlen are
	// deliberately absent and must stay absent: they are ring indices that change on
	// every occurrence, so any of them as a label mints a series per log line. They
	// remain structured fields on the shipped record, where they are still the
	// diagnostic.
	netmapKey struct{ device string }
	// arpKey carries the OS interface alone (#536). THE CONTESTED IP AND BOTH MAC
	// ADDRESSES ARE DELIBERATELY ABSENT AND MUST STAY ABSENT: a duplicate-address event
	// names whichever hosts are fighting over the address, so the value set is
	// unbounded and PII-shaped. They remain on the shipped log record.
	arpKey struct{ iface string }
	// dhcpClientKey is the WAN DHCP CLIENT tuple (#541), distinct from dhcpKey, which
	// is the DHCP SERVERS this firewall runs. msgType is a closed code-defined
	// vocabulary; iface is deployment-scale and EMPTY on a received message whose PID
	// could not be correlated to an interface. The DHCP server's address is
	// deliberately absent — it changes when the ISP re-homes the circuit, which is one
	// of the conditions this counter watches for.
	dhcpClientKey struct{ iface, msgType string }
	// dhcpClientScriptKey pairs the interface with dhclient-script(8)'s OWN closed
	// reason vocabulary, lowercased. Neither dimension is free text.
	dhcpClientScriptKey struct{ iface, reason string }
	// dhcpClientLeaseKey is the WAN lease GAUGE family's key — the interface alone.
	// Its value is a pair of absolute Unix timestamps, not a running total, which is
	// why it lives in a cappedGauge rather than a cappedCounter.
	dhcpClientLeaseKey struct{ iface string }
	// zenKey is Zenarmor's tuple, and Zenarmor is the highest-cardinality data this
	// exporter touches: app_name, IPs, ports, ja3, session_id, community_id and
	// conn_uuid are deliberately absent and must stay absent. Of what is left,
	// category and iface are the free-form pair the key budget exists for.
	zenKey struct{ family, action, category, iface, rcode, severity, statusClass string }
	// The Zenarmor device inventory is deliberately NOT in this block. It is keyed on
	// the device name alone with its attributes as a VALUE (see zenDeviceAttrs in
	// boundedinventory.go), because it is an inventory rather than a counter: an
	// attribute that changes must update the device's row, not fork a second one (#476).
	//
	// device_name is the one unbounded value that reaches a metric anywhere here, and it
	// is safe only in that shape — entries expire, so a name seen once does not persist
	// forever, and it is a single info metric rather than a dimension multiplied across
	// every other label. It must stay off zenKey, where it would multiply through
	// family x action x category x iface x rcode x severity x status_class. Promoting it
	// to a Loki index label was rejected in #473 for the same unboundedness: 273 stream
	// combinations at 1h, with live values like 10-0-0-5.<hash>.plex.direct.
)

// Family label values for the saturation metrics below. CODE-DEFINED constants, one
// per counter family and spelled the same as that family's metric name — a label
// value must never be a wire value, least of all on the metric whose job is to say
// that wire values are being refused.
const (
	logFamilyFirewall = "firewall"
	logFamilyHAProxy  = "haproxy"
	logFamilySSHD     = "sshd"
	logFamilyDHCP     = "dhcp"
	logFamilyAudit    = "audit"
	logFamilyIDS      = "ids"
	logFamilyGateway  = "gateway"
	logFamilyRADIUS   = "radius"
	logFamilyVPN      = "vpn"
	logFamilyCARP     = "carp"
	logFamilyUPnP     = "upnp"
	logFamilyZenarmor = "zenarmor"

	logFamilyNetmap           = "netmap"
	logFamilyARP              = "arp"
	logFamilyDHCPClient       = "dhcp_client"
	logFamilyDHCPClientScript = "dhcp_client_script"
	logFamilyDHCPClientLease  = "dhcp_client_lease"
	// logFamilyZenarmorDevice reports the device inventory's saturation through the
	// same cardinality_capped/keys metrics as every counter family, so a truncated
	// inventory is visible without a metric of its own.
	logFamilyZenarmorDevice = "zenarmor_device"

	// logEventObservationDropReasonHandoffFull is deliberately code-defined: it
	// describes the only possible receiver-side refusal, never an unbounded value
	// received from a log record.
	logEventObservationDropReasonHandoffFull = "handoff_full"
)

// defaultMaxLogEventKeys is the per-family key budget a store starts with, matching
// the default of --logs.max-metric-keys. main overrides it via SetMaxKeys once flags
// are parsed; this value only governs the window before that call, and exists so the
// store is never unbounded by accident.
const (
	defaultMaxLogEventKeys = 5000
	// logEventHandoffCapacity covers a sizeable burst while keeping admission
	// bounded and preallocated. Receiver calls never wait: once this queue is full,
	// they return false and retain any sample-eligible raw record.
	logEventHandoffCapacity = 65536
)

// The device inventory's two bounds (#474). Both are stated here rather than derived
// from --logs.max-metric-keys because they answer a different question: that budget
// is per-family cardinality for cumulative counters, this is "how many devices can
// plausibly be on one network, and how long after a device goes quiet should the
// dashboard still offer it".
const (
	// maxZenarmorDevices caps the tracked device set. device_name measured 154
	// distinct over 24h on the live box and was saturating (119 -> 145 -> 154), so
	// this is ~3x the observed steady state — enough headroom for a larger network,
	// low enough that a churning DNS-derived name cannot grow the series set without
	// limit. Refusals are counted under logFamilyZenarmorDevice.
	maxZenarmorDevices = 512
	// zenarmorDeviceTTL retires a device that has not been seen for a day. It is
	// deliberately long: the picker's job is to list devices an operator might want
	// to investigate, and a laptop that was on the network this morning is still
	// worth offering this evening. Shorter and the dropdown empties overnight;
	// unbounded and a device that visited once reads as present forever.
	zenarmorDeviceTTL = 24 * time.Hour
)

// dhcpClientLeaseValue is the pair of absolute Unix timestamps one WAN interface's
// lease is described by (#541): when it last bound, and when its renewal is due.
//
// A pair rather than two families because they are set by ONE `bound to` log line
// and are only meaningful together — a bind time with no deadline leaves "the
// renewal stopped" with nothing to compare against, and a deadline with no bind time
// cannot be distinguished from one left over from a previous process.
type dhcpClientLeaseValue struct{ bound, renewal float64 }

// cappedGauge is a LAST-VALUE map with the same insert-time key budget as
// cappedCounter, for families whose observation is current state rather than a
// running total.
//
// It exists because LogEventStore was counter-shaped and the WAN lease timestamps do
// not fit that shape: a lease deadline is not something you add up, and faking it as
// a counter (or dropping it) would have been the two wrong answers. `set` OVERWRITES
// rather than accumulating, and the snapshot is NOT drained — a gauge that vanished
// between scrapes would read as "the interface went away", not "no new bind
// happened", and nothing re-emits it.
//
// The budget is insert-time for the same reason cappedCounter's is: the receivers are
// push-based and syslog over UDP has a spoofable source, so a sender must not be able
// to grow this map for the life of the process. A refused NOVEL key folds into a
// counted overflow, reported through the same
// opnsense_log_events_cardinality_capped_total{family} as every counter family — so
// saturation here is visible on exactly the same alert. Keys already present keep
// being updated, so a steady-state working set is never affected.
//
// Not safe for concurrent use on its own: every caller is on LogEventStore's single
// map-owning goroutine.
type cappedGauge[K comparable, V any] struct {
	m        map[K]V
	max      int
	overflow float64
}

func newCappedGauge[K comparable, V any](max int) *cappedGauge[K, V] {
	return &cappedGauge[K, V]{m: map[K]V{}, max: max}
}

// set records the latest value for k, folding into the overflow total when k is
// novel and the budget is already met. max <= 0 disables the budget.
func (g *cappedGauge[K, V]) set(k K, v V) {
	if _, ok := g.m[k]; !ok && g.max > 0 && len(g.m) >= g.max {
		g.overflow++
		return
	}
	g.m[k] = v
}

// snapshot returns the live keys and the folded overflow total. Same contract as
// cappedCounter.snapshot: the map is the live one and the caller copies out of it on
// the owning goroutine.
func (g *cappedGauge[K, V]) snapshot() (map[K]V, float64) { return g.m, g.overflow }

// setMax retunes the budget in place. Lowering it below the current size does not
// evict, mirroring cappedCounter.setMax — and here eviction would be worse than a
// counter reset, because a dropped gauge series simply disappears from the dashboard.
func (g *cappedGauge[K, V]) setMax(max int) { g.max = max }

type logEventCommandKind uint8

const (
	logEventObserveFirewall logEventCommandKind = iota
	logEventObserveHAProxy
	logEventObserveSSHD
	logEventObserveDHCP
	logEventObserveAudit
	logEventObserveIDS
	logEventObserveGateway
	logEventObserveRADIUS
	logEventObserveVPN
	logEventObserveCARP
	logEventObserveUPnP
	logEventObserveNetmap
	logEventObserveARP
	logEventObserveDHCPClient
	logEventObserveDHCPClientScript
	logEventObserveDHCPClientLease
	logEventObserveZenarmor
	logEventObserveZenarmorDevice
	logEventSetMaxKeys
	logEventSetClock
	logEventTakeSnapshot
	logEventSync
)

type logEventCommand struct {
	kind   logEventCommandKind
	values [7]string
	// nums carries the numeric payload of a GAUGE observation (#541). The existing
	// families are all counters, whose entire payload is their label tuple, so this is
	// zero for every one of them.
	nums     [2]float64
	maxKeys  int
	clock    func() time.Time
	snapshot chan<- logEventSnapshot
	ack      chan<- struct{}
}

type logEventSnapshot struct {
	fw      []keyed[fwKey]
	ha      []keyed[haKey]
	ssh     []keyed[sshKey]
	dhcp    []keyed[dhcpKey]
	audit   []keyed[auditKey]
	ids     []keyed[idsKey]
	gateway []keyed[gatewayKey]
	radius  []keyed[radiusKey]
	vpn     []keyed[vpnKey]
	carp    []keyed[carpKey]
	upnp    []keyed[upnpKey]
	netmap  []keyed[netmapKey]
	arp     []keyed[arpKey]
	dhcpCli []keyed[dhcpClientKey]
	dhcpScr []keyed[dhcpClientScriptKey]
	// dhcpLease is the one GAUGE family: current state, so it is not drained.
	dhcpLease []keyedValue[dhcpClientLeaseKey, dhcpClientLeaseValue]
	zen       []keyed[zenKey]
	zenDevs   []inventoryEntry[string, zenDeviceAttrs]
	sat       []familySaturation
	dropped   uint64
}

// LogEventStore hands receiver observations to one goroutine that owns every map.
// Observe* only performs a non-blocking send to the bounded, preallocated queue;
// scrape snapshots and configuration changes are ordered commands on that queue.
// Totals reset to zero only on process restart, like any process counter.
//
// Each family is a cappedCounter with a per-family INSERT-TIME key budget
// (--logs.max-metric-keys, 0 disables), because the label values are not ours: both
// receivers are push-based, syslog over UDP is on by default with a spoofable source
// address, and several dimensions are genuinely free-form on the wire (rule id,
// interface, HAProxy backend/server, IDS category). An earlier version of this
// comment claimed the maps were "bounded by the ruleset/interface/backend
// inventory" — that described the traffic we expected, not anything the code
// enforced, and nothing stopped a sender from growing these maps for the life of the
// process. Saturation is visible and lossless: refused tuples fold into a per-family
// overflow total emitted as opnsense_log_events_cardinality_capped_total, so the
// live series plus the overflow still sum to the true observed count.
type LogEventStore struct {
	commands chan logEventCommand
	stop     chan struct{}
	done     chan struct{}
	close    sync.Once
	// beforeSnapshot is a test seam used to hold the map-owning goroutine in actual
	// snapshot work. Production stores leave it nil.
	beforeSnapshot func()

	// observationDrops counts observations refused only because the bounded handoff
	// was full. It is atomic so recording saturation is itself non-blocking.
	observationDrops atomic.Uint64
	fw               *cappedCounter[fwKey]
	ha               *cappedCounter[haKey]
	ssh              *cappedCounter[sshKey]
	dhcp             *cappedCounter[dhcpKey]
	audit            *cappedCounter[auditKey]
	ids              *cappedCounter[idsKey]
	gateway          *cappedCounter[gatewayKey]
	radius           *cappedCounter[radiusKey]
	vpn              *cappedCounter[vpnKey]
	carp             *cappedCounter[carpKey]
	upnp             *cappedCounter[upnpKey]
	netmap           *cappedCounter[netmapKey]
	arp              *cappedCounter[arpKey]
	dhcpCli          *cappedCounter[dhcpClientKey]
	dhcpScr          *cappedCounter[dhcpClientScriptKey]
	dhcpLease        *cappedGauge[dhcpClientLeaseKey, dhcpClientLeaseValue]
	zen              *cappedCounter[zenKey]
	zenDevs          *boundedInventory[string, zenDeviceAttrs]
	// now is the inventory clock, a test seam. Production stores leave it nil and
	// fall back to time.Now.
	now func() time.Time
}

func newLogEventStore() *LogEventStore {
	return newLogEventStoreWithCapacity(logEventHandoffCapacity, nil)
}

func newLogEventStoreWithCapacity(capacity int, beforeSnapshot func()) *LogEventStore {
	s := &LogEventStore{
		commands:       make(chan logEventCommand, capacity),
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
		beforeSnapshot: beforeSnapshot,
		fw:             newCappedCounter[fwKey](defaultMaxLogEventKeys),
		ha:             newCappedCounter[haKey](defaultMaxLogEventKeys),
		ssh:            newCappedCounter[sshKey](defaultMaxLogEventKeys),
		dhcp:           newCappedCounter[dhcpKey](defaultMaxLogEventKeys),
		audit:          newCappedCounter[auditKey](defaultMaxLogEventKeys),
		ids:            newCappedCounter[idsKey](defaultMaxLogEventKeys),
		gateway:        newCappedCounter[gatewayKey](defaultMaxLogEventKeys),
		radius:         newCappedCounter[radiusKey](defaultMaxLogEventKeys),
		vpn:            newCappedCounter[vpnKey](defaultMaxLogEventKeys),
		carp:           newCappedCounter[carpKey](defaultMaxLogEventKeys),
		upnp:           newCappedCounter[upnpKey](defaultMaxLogEventKeys),
		netmap:         newCappedCounter[netmapKey](defaultMaxLogEventKeys),
		arp:            newCappedCounter[arpKey](defaultMaxLogEventKeys),
		dhcpCli:        newCappedCounter[dhcpClientKey](defaultMaxLogEventKeys),
		dhcpScr:        newCappedCounter[dhcpClientScriptKey](defaultMaxLogEventKeys),
		dhcpLease:      newCappedGauge[dhcpClientLeaseKey, dhcpClientLeaseValue](defaultMaxLogEventKeys),
		zen:            newCappedCounter[zenKey](defaultMaxLogEventKeys),
		zenDevs:        newBoundedInventory[string, zenDeviceAttrs](maxZenarmorDevices, zenarmorDeviceTTL, compareZenDeviceName),
	}
	go s.run()
	return s
}

// SetMaxKeys applies the per-family key budget from --logs.max-metric-keys; 0
// disables the cap. main calls it once at startup, before the receivers start.
//
// The budget is PER FAMILY, not shared across them: one noisy program must not be
// able to starve another family's legitimate tuples out of existence.
//
// Lowering it does not evict tuples already tracked — see cappedCounter.setMax.
func (s *LogEventStore) SetMaxKeys(max int) {
	ack := make(chan struct{})
	if !s.sendControl(logEventCommand{kind: logEventSetMaxKeys, maxKeys: max, ack: ack}) {
		return
	}
	select {
	case <-ack:
	case <-s.stop:
	}
}

func (s *LogEventStore) sendControl(cmd logEventCommand) bool {
	select {
	case s.commands <- cmd:
		return true
	case <-s.stop:
		return false
	}
}

func (s *LogEventStore) observe(cmd logEventCommand) bool {
	select {
	case <-s.stop:
		return false
	default:
	}
	select {
	case s.commands <- cmd:
		return true
	default:
		s.observationDrops.Add(1)
		return false
	}
}

// ObserveFirewall implements logship.MetricSink.
func (s *LogEventStore) ObserveFirewall(action, iface, ruleID, ruleName, scope string) bool {
	return s.observe(logEventCommand{kind: logEventObserveFirewall, values: [7]string{action, iface, ruleID, ruleName, scope}})
}

// ObserveHAProxy implements logship.MetricSink.
func (s *LogEventStore) ObserveHAProxy(event, backend, server, state, statusClass string) bool {
	return s.observe(logEventCommand{kind: logEventObserveHAProxy, values: [7]string{event, backend, server, state, statusClass}})
}

// ObserveSSHD implements logship.MetricSink.
func (s *LogEventStore) ObserveSSHD(result, method, scope string) bool {
	return s.observe(logEventCommand{kind: logEventObserveSSHD, values: [7]string{result, method, scope}})
}

// ObserveDHCP implements logship.MetricSink.
func (s *LogEventStore) ObserveDHCP(action, iface, server string) bool {
	return s.observe(logEventCommand{kind: logEventObserveDHCP, values: [7]string{action, iface, server}})
}

// ObserveAudit implements logship.MetricSink.
func (s *LogEventStore) ObserveAudit(event, result string) bool {
	return s.observe(logEventCommand{kind: logEventObserveAudit, values: [7]string{event, result}})
}

// ObserveIDS implements logship.MetricSink.
func (s *LogEventStore) ObserveIDS(eventType, action, category, severity string) bool {
	return s.observe(logEventCommand{kind: logEventObserveIDS, values: [7]string{eventType, action, category, severity}})
}

// ObserveGateway implements logship.MetricSink.
func (s *LogEventStore) ObserveGateway(event, gateway string) bool {
	return s.observe(logEventCommand{kind: logEventObserveGateway, values: [7]string{event, gateway}})
}

// ObserveRADIUS implements logship.MetricSink.
func (s *LogEventStore) ObserveRADIUS(event, result, clientScope string) bool {
	return s.observe(logEventCommand{kind: logEventObserveRADIUS, values: [7]string{event, result, clientScope}})
}

// ObserveVPN implements logship.MetricSink.
func (s *LogEventStore) ObserveVPN(backend, event, result, connection string) bool {
	return s.observe(logEventCommand{kind: logEventObserveVPN, values: [7]string{backend, event, result, connection}})
}

// ObserveCARP implements logship.MetricSink.
func (s *LogEventStore) ObserveCARP(event, from, to, iface, vhid string) bool {
	return s.observe(logEventCommand{kind: logEventObserveCARP, values: [7]string{event, from, to, iface, vhid}})
}

// ObserveUPnP implements logship.MetricSink.
func (s *LogEventStore) ObserveUPnP(event, result, protocol string) bool {
	return s.observe(logEventCommand{kind: logEventObserveUPnP, values: [7]string{event, result, protocol}})
}

// ObserveNetmapRingFull implements logship.MetricSink.
func (s *LogEventStore) ObserveNetmapRingFull(device string) bool {
	return s.observe(logEventCommand{kind: logEventObserveNetmap, values: [7]string{device}})
}

// ObserveARPMove implements logship.MetricSink.
func (s *LogEventStore) ObserveARPMove(iface string) bool {
	return s.observe(logEventCommand{kind: logEventObserveARP, values: [7]string{iface}})
}

// ObserveDHCPClient implements logship.MetricSink.
func (s *LogEventStore) ObserveDHCPClient(iface, msgType string) bool {
	return s.observe(logEventCommand{kind: logEventObserveDHCPClient, values: [7]string{iface, msgType}})
}

// ObserveDHCPClientScript implements logship.MetricSink.
func (s *LogEventStore) ObserveDHCPClientScript(iface, reason string) bool {
	return s.observe(logEventCommand{kind: logEventObserveDHCPClientScript, values: [7]string{iface, reason}})
}

// ObserveDHCPClientLease implements logship.MetricSink. The only GAUGE observation:
// bound and renewal are absolute Unix seconds and OVERWRITE the interface's previous
// pair rather than accumulating.
func (s *LogEventStore) ObserveDHCPClientLease(iface string, bound, renewal float64) bool {
	return s.observe(logEventCommand{
		kind:   logEventObserveDHCPClientLease,
		values: [7]string{iface},
		nums:   [2]float64{bound, renewal},
	})
}

// ObserveZenarmor implements logship.MetricSink.
func (s *LogEventStore) ObserveZenarmor(o logship.ZenarmorObservation) bool {
	return s.observe(logEventCommand{kind: logEventObserveZenarmor, values: [7]string{o.Family, o.Action, o.Category, o.Interface, o.RCode, o.Severity, o.StatusClass}})
}

// ObserveZenarmorDevice implements logship.MetricSink.
//
// Separate from ObserveZenarmor on purpose: ZenarmorObservation is the COUNTER's
// label tuple and carries an explicit "never add device_name here" rule, which a
// third field on it would quietly erode. This feeds the inventory instead — a
// different metric, a different bound, and no multiplication through the counter's
// seven dimensions. See zenDeviceAttrs.
func (s *LogEventStore) ObserveZenarmorDevice(name, category, iface string) bool {
	if name == "" {
		return false
	}
	return s.observe(logEventCommand{kind: logEventObserveZenarmorDevice, values: [7]string{name, category, iface}})
}

// clock reads the inventory clock. It is only ever called from the map-owning
// goroutine, so the seam needs no synchronisation.
func (s *LogEventStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *LogEventStore) run() {
	defer close(s.done)
	for {
		select {
		case cmd := <-s.commands:
			s.apply(cmd)
		case <-s.stop:
			return
		}
	}
}

func (s *LogEventStore) apply(cmd logEventCommand) {
	v := cmd.values
	switch cmd.kind {
	case logEventObserveFirewall:
		s.fw.inc(fwKey{v[0], v[1], v[2], v[3], v[4]})
	case logEventObserveHAProxy:
		s.ha.inc(haKey{v[0], v[1], v[2], v[3], v[4]})
	case logEventObserveSSHD:
		s.ssh.inc(sshKey{v[0], v[1], v[2]})
	case logEventObserveDHCP:
		s.dhcp.inc(dhcpKey{v[0], v[1], v[2]})
	case logEventObserveAudit:
		s.audit.inc(auditKey{v[0], v[1]})
	case logEventObserveIDS:
		s.ids.inc(idsKey{v[0], v[1], v[2], v[3]})
	case logEventObserveGateway:
		s.gateway.inc(gatewayKey{v[0], v[1]})
	case logEventObserveRADIUS:
		s.radius.inc(radiusKey{v[0], v[1], v[2]})
	case logEventObserveVPN:
		s.vpn.inc(vpnKey{v[0], v[1], v[2], v[3]})
	case logEventObserveCARP:
		s.carp.inc(carpKey{v[0], v[1], v[2], v[3], v[4]})
	case logEventObserveUPnP:
		s.upnp.inc(upnpKey{v[0], v[1], v[2]})
	case logEventObserveNetmap:
		s.netmap.inc(netmapKey{v[0]})
	case logEventObserveARP:
		s.arp.inc(arpKey{v[0]})
	case logEventObserveDHCPClient:
		s.dhcpCli.inc(dhcpClientKey{v[0], v[1]})
	case logEventObserveDHCPClientScript:
		s.dhcpScr.inc(dhcpClientScriptKey{v[0], v[1]})
	case logEventObserveDHCPClientLease:
		s.dhcpLease.set(dhcpClientLeaseKey{v[0]}, dhcpClientLeaseValue{bound: cmd.nums[0], renewal: cmd.nums[1]})
	case logEventObserveZenarmor:
		s.zen.inc(zenKey{v[0], v[1], v[2], v[3], v[4], v[5], v[6]})
	case logEventObserveZenarmorDevice:
		s.zenDevs.seen(v[0], zenDeviceAttrs{category: v[1], iface: v[2]}, s.clock())
	case logEventSetMaxKeys:
		s.fw.setMax(cmd.maxKeys)
		s.ha.setMax(cmd.maxKeys)
		s.ssh.setMax(cmd.maxKeys)
		s.dhcp.setMax(cmd.maxKeys)
		s.audit.setMax(cmd.maxKeys)
		s.ids.setMax(cmd.maxKeys)
		s.gateway.setMax(cmd.maxKeys)
		s.radius.setMax(cmd.maxKeys)
		s.vpn.setMax(cmd.maxKeys)
		s.carp.setMax(cmd.maxKeys)
		s.upnp.setMax(cmd.maxKeys)
		s.netmap.setMax(cmd.maxKeys)
		s.arp.setMax(cmd.maxKeys)
		s.dhcpCli.setMax(cmd.maxKeys)
		s.dhcpScr.setMax(cmd.maxKeys)
		s.dhcpLease.setMax(cmd.maxKeys)
		s.zen.setMax(cmd.maxKeys)
		close(cmd.ack)
	case logEventTakeSnapshot:
		if s.beforeSnapshot != nil {
			s.beforeSnapshot()
		}
		cmd.snapshot <- s.buildSnapshot()
	case logEventSetClock:
		s.now = cmd.clock
		close(cmd.ack)
	case logEventSync:
		close(cmd.ack)
	}
}

func (s *LogEventStore) buildSnapshot() logEventSnapshot {
	var snap logEventSnapshot
	var sat familySaturation
	snap.fw, sat = drainFamily(logFamilyFirewall, s.fw)
	snap.sat = append(snap.sat, sat)
	snap.ha, sat = drainFamily(logFamilyHAProxy, s.ha)
	snap.sat = append(snap.sat, sat)
	snap.ssh, sat = drainFamily(logFamilySSHD, s.ssh)
	snap.sat = append(snap.sat, sat)
	snap.dhcp, sat = drainFamily(logFamilyDHCP, s.dhcp)
	snap.sat = append(snap.sat, sat)
	snap.audit, sat = drainFamily(logFamilyAudit, s.audit)
	snap.sat = append(snap.sat, sat)
	snap.ids, sat = drainFamily(logFamilyIDS, s.ids)
	snap.sat = append(snap.sat, sat)
	snap.gateway, sat = drainFamily(logFamilyGateway, s.gateway)
	snap.sat = append(snap.sat, sat)
	snap.radius, sat = drainFamily(logFamilyRADIUS, s.radius)
	snap.sat = append(snap.sat, sat)
	snap.vpn, sat = drainFamily(logFamilyVPN, s.vpn)
	snap.sat = append(snap.sat, sat)
	snap.carp, sat = drainFamily(logFamilyCARP, s.carp)
	snap.sat = append(snap.sat, sat)
	snap.upnp, sat = drainFamily(logFamilyUPnP, s.upnp)
	snap.sat = append(snap.sat, sat)
	snap.netmap, sat = drainFamily(logFamilyNetmap, s.netmap)
	snap.sat = append(snap.sat, sat)
	snap.arp, sat = drainFamily(logFamilyARP, s.arp)
	snap.sat = append(snap.sat, sat)
	snap.dhcpCli, sat = drainFamily(logFamilyDHCPClient, s.dhcpCli)
	snap.sat = append(snap.sat, sat)
	snap.dhcpScr, sat = drainFamily(logFamilyDHCPClientScript, s.dhcpScr)
	snap.sat = append(snap.sat, sat)
	// The lease GAUGES are copied, not drained: they are current state. A gauge that
	// disappeared between scrapes would read as "the interface went away" rather than
	// "no new bind happened", and only a `bound to` line ever re-sets it.
	snap.dhcpLease, sat = copyGaugeFamily(logFamilyDHCPClientLease, s.dhcpLease)
	snap.sat = append(snap.sat, sat)
	snap.zen, sat = drainFamily(logFamilyZenarmor, s.zen)
	snap.sat = append(snap.sat, sat)
	// The inventory is NOT drained: it is current state, not a cumulative total, so
	// live() prunes what has expired and leaves the rest in place for the next scrape.
	snap.zenDevs = s.zenDevs.live(s.clock())
	snap.sat = append(snap.sat, familySaturation{
		family: logFamilyZenarmorDevice,
		capped: s.zenDevs.refused(),
		keys:   float64(len(snap.zenDevs)),
	})
	snap.dropped = s.observationDrops.Load()
	return snap
}

func (s *LogEventStore) snapshot() (logEventSnapshot, bool) {
	reply := make(chan logEventSnapshot, 1)
	if !s.sendControl(logEventCommand{kind: logEventTakeSnapshot, snapshot: reply}) {
		return logEventSnapshot{}, false
	}
	select {
	case snap := <-reply:
		return snap, true
	case <-s.stop:
		return logEventSnapshot{}, false
	}
}

// setClock installs the inventory clock through the command queue, so the field is
// only ever written on the map-owning goroutine — the same reason SetMaxKeys is a
// command rather than a plain assignment. Test-only; production stores leave it nil
// and clock() falls back to time.Now.
func (s *LogEventStore) setClock(now func() time.Time) {
	ack := make(chan struct{})
	if !s.sendControl(logEventCommand{kind: logEventSetClock, clock: now, ack: ack}) {
		return
	}
	select {
	case <-ack:
	case <-s.stop:
	}
}

func (s *LogEventStore) sync() {
	ack := make(chan struct{})
	if !s.sendControl(logEventCommand{kind: logEventSync, ack: ack}) {
		return
	}
	select {
	case <-ack:
	case <-s.stop:
	}
}

func (s *LogEventStore) Close() {
	s.close.Do(func() {
		// Close is called only after receiver producers have stopped. Drain every
		// observation they were told was accepted before terminating the owner.
		s.sync()
		close(s.stop)
	})
	<-s.done
}

type logEventsCollector struct {
	store     *LogEventStore
	log       *slog.Logger
	subsystem string
	instance  string

	firewall    *prometheus.Desc
	haproxy     *prometheus.Desc
	sshd        *prometheus.Desc
	dhcp        *prometheus.Desc
	audit       *prometheus.Desc
	ids         *prometheus.Desc
	gateway     *prometheus.Desc
	radius      *prometheus.Desc
	vpn         *prometheus.Desc
	carp        *prometheus.Desc
	upnp        *prometheus.Desc
	zenarmor    *prometheus.Desc
	zenarmorDev *prometheus.Desc

	netmapRingFull *prometheus.Desc
	arpMoves       *prometheus.Desc
	dhcpClient     *prometheus.Desc
	dhcpClientScr  *prometheus.Desc
	dhcpLeaseBound *prometheus.Desc
	dhcpLeaseRenew *prometheus.Desc

	capped  *prometheus.Desc
	keys    *prometheus.Desc
	dropped *prometheus.Desc
}

func init() {
	collectorInstances = append(collectorInstances, &logEventsCollector{
		store:     LogEvents,
		subsystem: LogEventsSubsystem,
	})
}

func (c *logEventsCollector) Name() string { return c.subsystem }

func (c *logEventsCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.firewall = buildPrometheusDesc(c.subsystem, "firewall_total",
		"Firewall (filterlog) events derived from received syslog, by action, interface, rule and scope. "+
			"Counts every line including passes; the raw pass lines may be sampled away (--logs.syslog.sample) "+
			"while this counter still counts them.",
		[]string{"action", "interface", "rule_id", "rule_name", "scope"},
	)
	c.haproxy = buildPrometheusDesc(c.subsystem, "haproxy_total",
		"HAProxy events derived from received syslog, by event, backend, server, state and HTTP status class.",
		[]string{"event", "backend", "server", "state", "status_class"},
	)
	c.sshd = buildPrometheusDesc(c.subsystem, "sshd_total",
		"sshd authentication events derived from received syslog, by result, method and source scope.",
		[]string{"result", "method", "scope"},
	)
	c.dhcp = buildPrometheusDesc(c.subsystem, "dhcp_total",
		"DHCP lease events derived from received syslog, by action, interface and server.",
		[]string{"action", "interface", "server"},
	)
	c.audit = buildPrometheusDesc(c.subsystem, "audit_total",
		"Audit/config events derived from received syslog, by event and result.",
		[]string{"event", "result"},
	)
	c.ids = buildPrometheusDesc(c.subsystem, "ids_total",
		"Suricata IDS/IPS events derived from received syslog, by event type, action, category and severity. "+
			"Signature text and SID are never labels.",
		[]string{"event_type", "action", "category", "severity"},
	)
	c.gateway = buildPrometheusDesc(c.subsystem, "gateway_total",
		"dpinger gateway alarm transitions derived from received syslog, by closed event and configured gateway monitor name. "+
			"Address, alarm state, RTT and loss stay on the structured log record and are never labels.",
		[]string{"event", "gateway"},
	)
	c.radius = buildPrometheusDesc(c.subsystem, "radius_total",
		"FreeRADIUS access decisions derived from received syslog, by event, result and client scope.",
		[]string{"event", "result", "client_scope"},
	)
	c.vpn = buildPrometheusDesc(c.subsystem, "vpn_total",
		"IPsec (charon) and OpenVPN tunnel lifecycle transitions derived from received syslog, by "+
			"backend, closed event, result and configured connection name. event is one of "+
			"established, terminated, authentication_failed, liveness_failed or certificate_failed; "+
			"result is success for the first two and failure for the other three. connection is the "+
			"name configured on the firewall, resolved from the IPsec connection or OpenVPN instance "+
			"id, and is EMPTY when the id could not be resolved - never a raw UUID. Usernames, "+
			"certificate subjects and serials, IKE identities, peer addresses and ports, SPIs and "+
			"daemon error text are never labels; they stay on the shipped log record. Only the "+
			"grammar captured on OPNsense 27.1.a_40 (strongSwan 6.0.7, OpenVPN 2.7.5) is counted - "+
			"any other line still ships as a log record but is not counted as an inferred transition.",
		[]string{"backend", "event", "result", "connection"},
	)
	c.carp = buildPrometheusDesc(c.subsystem, "carp_total",
		"FreeBSD kernel CARP transitions derived from received syslog, by closed event, "+
			"previous and current state, OS interface device and VHID. event is one of "+
			"state_changed, demoted or promoted; from and to are master, backup or init, "+
			"lowercased. A demotion record leaves from, to, interface and vhid EMPTY - the "+
			"kernel's demotion adjustment is global to the node and names neither an "+
			"interface nor a VHID. demoted and promoted are distinguished by the SIGN of the "+
			"kernel's demotion delta: positive raises the node's demotion total, negative "+
			"lowers it. The kernel's CAUSE for the transition (initialization complete, "+
			"master timed out, hardware interface up, pfsync bulk start, pfsync bulk fail, "+
			"service disruption, ...) is deliberately NOT a label: it is open-ended free "+
			"text across FreeBSD versions. It ships as carp.reason on the log record, "+
			"alongside carp.demotion.delta and carp.demotion.total - which are the numbers "+
			"explaining WHY a node demoted, and which opnsense_carp_demotion (a current-state "+
			"gauge) does not retain. Read this beside the CARP VIP Status timeline: that shows "+
			"what state the node is in now, this shows the transitions that got it there. "+
			"Only the grammar captured on OPNsense 27.1.a_40 (FreeBSD 15, net.inet.carp.log=1) "+
			"is counted - any other kernel line still ships as a log record but is never "+
			"counted as an inferred transition.",
		[]string{"event", "from", "to", "interface", "vhid"},
	)
	c.upnp = buildPrometheusDesc(c.subsystem, "upnp_total",
		"miniupnpd UPnP IGD / NAT-PMP / PCP mapping events derived from received syslog, by "+
			"closed event, result and protocol. event is one of expired (a mapping reached the "+
			"end of its lease and was torn down - the only event whose result is ok), "+
			"cleanup_failed (the daemon could not find the pf nat or redirect rule it was "+
			"deleting), unauthorized (a PCP client asked to remove a mapping it does not own) "+
			"or lease_file_error. protocol is tcp or udp, and EMPTY on the two cleanup-failure "+
			"grammars and the lease-file error, which name none. Port numbers, the daemon's "+
			"opaque addr= token, lease-file paths, mapping descriptions and client identities "+
			"are deliberately NOT labels - an ephemeral port would mint a series per mapping - "+
			"and ship as upnp.port.external / upnp.port.internal or inside the log record's "+
			"body. THERE IS NO ACTIVE-MAPPING GAUGE and none can be derived from this: the "+
			"plugin's own status page runs pfctl to list mappings rather than exposing them "+
			"through an API, an event stream cannot see pre-existing mappings or survive a "+
			"daemon restart, and expired is a decrement with no matching increment. A "+
			"SUCCESSFUL add or delete is likewise absent - miniupnpd logs those at a verbosity "+
			"OPNsense's os-upnp plugin does not expose, and no attempt line is treated as proof "+
			"of success. Only the grammar captured on OPNsense 26.7.1_1 and 27.1.a_40 "+
			"(miniupnpd 2.3.9_2,1) is counted; any other miniupnpd line still ships as a log "+
			"record but is never counted.",
		[]string{"event", "result", "protocol"},
	)
	c.zenarmor = buildPrometheusDesc(c.subsystem, "zenarmor_total",
		"Zenarmor events received over the Elasticsearch receiver, by family (flow/dns/tls/web/ids/voip), "+
			"action, category, interface, DNS rcode, alert severity and HTTP status class. Fields that do "+
			"not apply to a family are empty. Zenarmor ships ~2.5-3.3M records/day, so these counters are "+
			"the way to ask rate questions without querying the raw log stream - and they outlive Loki's "+
			"retention. Application name, IPs, ports, hostnames, MACs, JA3, session/community/connection "+
			"ids, URIs and DNS queries are never labels; they stay as structured metadata on the record.",
		[]string{"family", "action", "category", "interface", "rcode", "severity", "status_class"},
	)

	c.zenarmorDev = buildPrometheusDesc(c.subsystem, "zenarmor_device_info",
		"Client devices Zenarmor has attributed traffic to recently, one series per device with a "+
			"constant value of 1. It exists so a dashboard can ENUMERATE devices: device_name is Loki "+
			"structured metadata, which label_values() cannot list and which was rejected as a Loki index "+
			"label in #473 because it is not a closed set (live values include Plex-generated DNS names). "+
			"Bounded on both axes - at most 512 devices tracked, and a device is retired 24h after it was "+
			"last seen - so a churning name cannot grow the series set without limit; refusals surface as "+
			"cardinality_capped_total{family=\"zenarmor_device\"}. Filter the log stream itself on the "+
			"device_name structured metadata field, not on this metric.",
		[]string{"device_name", "device_category", "interface"},
	)

	c.netmapRingFull = buildPrometheusDesc(c.subsystem, "netmap_ring_full_events_total",
		"Intervals in which the FreeBSD kernel reported a netmap host transmit ring full on this "+
			"device - Zenarmor's packet-capture datapath having nowhere to put a packet. "+
			"THIS COUNTS OCCURRENCES, NOT DROPPED PACKETS, and the difference matters: "+
			"netmap_transmit() logs through nm_prlim(2, ...), which rate-limits the kernel to 2 "+
			"lines per second, so this counter FLAT-TOPS at 2/s and under-reports hardest exactly "+
			"when the condition is worst. Read a rise as 'the ring is filling', never as a packet "+
			"count, and read a flat 2/s as saturation rather than as a bounded problem. Absence of "+
			"growth means no report, NOT no drops. There is no true drop counter available for "+
			"this: the kernel bumps IFCOUNTER_OQDROPS, but the ixl driver overrides that counter in "+
			"its own if_get_counter, so netmap's increment is invisible on the exact 10G interface "+
			"that drops - live-corroborated, 14 kernel reports since boot against an API-reported "+
			"dropped-packets of 0. The ring indices from the log line (hwcur, hwtail, qlen) are NOT "+
			"labels - they change on every occurrence and would mint a series per line - and ship "+
			"as netmap.hwcur / netmap.hwtail / netmap.qlen on the log record, where hwcur == hwtail "+
			"is a completely full ring.",
		[]string{"device"},
	)
	c.arpMoves = buildPrometheusDesc(c.subsystem, "arp_address_moves_total",
		"Times the FreeBSD kernel reported an IP address moving from one MAC address to another on "+
			"this interface - its own duplicate-address, MAC-flap and ARP-spoof detector. Polling "+
			"the ARP table CANNOT replace this: a flap that resolves inside one poll interval "+
			"leaves a single MAC in the table, so the scrape sees a perfectly healthy entry and the "+
			"event is invisible. A steady rate usually means two hosts claiming one address, a "+
			"gateway failing over, or a VM live-migrating; a burst on a user VLAN is worth "+
			"investigating. The contested IP and BOTH MAC addresses are deliberately NOT labels - "+
			"they name whichever hosts are fighting over the address, so the value set is unbounded "+
			"and identifies individual machines - and ship as arp.address / arp.mac.previous / "+
			"arp.mac.current on the log record, which is where to look to find out who.",
		[]string{"interface"},
	)
	c.dhcpClient = buildPrometheusDesc(c.subsystem, "dhcp_client_total",
		"DHCP messages this firewall's OWN WAN client sent or received, by interface and message "+
			"type. This is the CLIENT holding the firewall's uplink address, not the DHCP servers it "+
			"runs for the LAN - those are opnsense_log_events_dhcp_total, and folding the two "+
			"together would make a WAN renewal storm indistinguishable from LAN lease churn. type is "+
			"a closed vocabulary resolved in code: discover, request, ack, nak, offer, decline, "+
			"release, inform. The signal to watch is the REQUEST rate: a healthy lease renews at "+
			"T1, so a sustained rise is a retransmit storm and a leading indicator of losing the WAN "+
			"address hours before the lease actually expires (production ran an 11-12 hour storm at "+
			"~100x baseline on 2026-07-30 with no telemetry at all). Any nak deserves attention on "+
			"its own. interface is EMPTY on a received message that named none - dhclient's 'DHCPACK "+
			"from <ip>' carries no interface, and it is resolved by correlating the daemon PID with "+
			"the interface its preceding DHCPREQUEST named; empty means the exporter never saw that "+
			"line, not that the message had no interface. The DHCP server's address is NOT a label "+
			"and ships as dhcp_client.server on the record.",
		[]string{"interface", "type"},
	)
	c.dhcpClientScr = buildPrometheusDesc(c.subsystem, "dhcp_client_script_total",
		"dhclient-script invocations on this firewall's WAN client, by interface and reason. reason "+
			"is dhclient-script(8)'s OWN closed vocabulary, lowercased (bound, renew, rebind, "+
			"reboot, expire, fail, timeout, stop, release, preinit, arpcheck, arpsend, medium, nbi); "+
			"an unrecognised token is never turned into a label. This is the lease STATE MACHINE "+
			"rather than the wire traffic: renew is the healthy steady state, while expire and fail "+
			"mean the client has given up on the lease and the uplink address is gone or going. "+
			"Only renew is observed on the production box - a working WAN never reaches the failure "+
			"reasons - so the rest are modelled from dhclient-script's documented set, not from "+
			"capture.",
		[]string{"interface", "reason"},
	)
	c.dhcpLeaseBound = buildPrometheusDesc(c.subsystem, "dhcp_client_lease_bound_timestamp_seconds",
		"Unix time at which this interface's WAN DHCP lease last successfully bound, from dhclient's "+
			"'bound to <address> -- renewal in <n> seconds' line. Set only by an actual bind, so it "+
			"stands still between renewals by design - time() minus this is how long the current "+
			"lease has been held. Read it alongside "+
			"opnsense_log_events_dhcp_client_lease_renewal_timestamp_seconds, which is set from the "+
			"same line. The leased address itself is deliberately NOT a label (it is this "+
			"firewall's own public IP and changes on re-bind) and ships as dhcp_client.address on "+
			"the log record.",
		[]string{"interface"},
	)
	c.dhcpLeaseRenew = buildPrometheusDesc(c.subsystem, "dhcp_client_lease_renewal_timestamp_seconds",
		"Unix time at which this interface's WAN DHCP lease renewal is next due: the time of the "+
			"last 'bound to' line plus the renewal interval that line carried. A DEADLINE, not a "+
			"countdown, on purpose - a countdown gauge has to be recomputed against wall-clock at "+
			"scrape time and a stale one is indistinguishable from a fresh one, which is the exact "+
			"failure this metric exists to catch. Alert on it directly: "+
			"'<metric> - time() < 0' means the renewal deadline passed without dhclient reporting a "+
			"new bind, which is the WAN losing its address in slow motion. This is a deliberate "+
			"deviation from #541's proposed dhcp_client_lease_expiry_seconds countdown. Note this is "+
			"the RENEWAL (T1) deadline dhclient reports, not the absolute lease expiry - dhclient "+
			"does not log the latter, so it is not invented here.",
		[]string{"interface"},
	)

	c.capped = buildPrometheusDesc(c.subsystem, "cardinality_capped_total",
		"Log events counted into a family's overflow total instead of their own series, because the "+
			"label tuple was new and the family already held --logs.max-metric-keys distinct tuples. "+
			"Both receivers are push-based (and syslog over UDP has a spoofable source), so tuple "+
			"values are sender-controlled and the budget is what stops one sender growing metric state "+
			"for the life of the process. Nothing is lost: this plus the family's own series is the "+
			"true event count. Non-zero and rising means the family is saturated and new tuples are no "+
			"longer individually visible - raise the budget or find what is minting them.",
		[]string{"family"},
	)
	c.keys = buildPrometheusDesc(c.subsystem, "cardinality_keys",
		"Distinct label tuples currently tracked for each log_events family. Compare against "+
			"--logs.max-metric-keys to see saturation coming before "+
			"opnsense_log_events_cardinality_capped_total starts rising. Tuples are never evicted, so "+
			"this only grows within a process lifetime.",
		[]string{"family"},
	)
	c.dropped = buildPrometheusDesc(c.subsystem, "observation_dropped_total",
		"Derived log-metric observations refused by the non-blocking receiver handoff. A refused syslog observation retains its raw record so sampling cannot discard an uncounted event.",
		[]string{"reason"},
	)
}

func (c *logEventsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.firewall
	ch <- c.haproxy
	ch <- c.sshd
	ch <- c.dhcp
	ch <- c.audit
	ch <- c.ids
	ch <- c.gateway
	ch <- c.radius
	ch <- c.vpn
	ch <- c.carp
	ch <- c.upnp
	ch <- c.zenarmor
	ch <- c.zenarmorDev
	ch <- c.netmapRingFull
	ch <- c.arpMoves
	ch <- c.dhcpClient
	ch <- c.dhcpClientScr
	ch <- c.dhcpLeaseBound
	ch <- c.dhcpLeaseRenew
	ch <- c.capped
	ch <- c.keys
	ch <- c.dropped
}

// keyed is one family's series: a label tuple and its running total, copied out of
// the store so the emit loop runs without the lock held.
type keyed[K comparable] struct {
	k K
	v float64
}

// keyedValue is keyed for a GAUGE family: a label tuple and its last-observed value,
// which is a struct rather than a float because one interface's lease is described
// by a PAIR of timestamps set together.
type keyedValue[K comparable, V any] struct {
	k K
	v V
}

// familySaturation is one family's cardinality state, emitted under the family label.
type familySaturation struct {
	family string
	capped float64
	keys   float64
}

// drainFamily copies one family's live series and saturation state. It only runs on
// the store's map-owning goroutine.
func drainFamily[K comparable](family string, c *cappedCounter[K]) ([]keyed[K], familySaturation) {
	m, overflow := c.snapshot()
	out := make([]keyed[K], 0, len(m))
	for k, v := range m {
		out = append(out, keyed[K]{k, v})
	}
	return out, familySaturation{family: family, capped: overflow, keys: float64(len(m))}
}

// copyGaugeFamily is drainFamily for a cappedGauge. It reports its saturation through
// the SAME familySaturation shape, so a capped gauge family shows up on the existing
// opnsense_log_events_cardinality_capped_total alert with no special case.
func copyGaugeFamily[K comparable, V any](family string, g *cappedGauge[K, V]) ([]keyedValue[K, V], familySaturation) {
	m, overflow := g.snapshot()
	out := make([]keyedValue[K, V], 0, len(m))
	for k, v := range m {
		out = append(out, keyedValue[K, V]{k, v})
	}
	return out, familySaturation{family: family, capped: overflow, keys: float64(len(m))}
}

// Update emits the current running totals as const counter metrics. It ignores the
// client: this collector never calls the API — the syslog receiver feeds the store.
// The map owner produces an immutable snapshot before emission. A slow metric
// channel cannot stall receiver admission; only a full bounded handoff can refuse it.
func (c *logEventsCollector) Update(_ context.Context, _ *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	snap, ok := c.store.snapshot()
	if !ok {
		return nil
	}

	// Published for every family on every scrape, including the zeros: a saturation
	// counter that only materialises once it is non-zero cannot be alerted on until
	// after it has already mattered.
	for _, f := range snap.sat {
		ch <- prometheus.MustNewConstMetric(c.capped, prometheus.CounterValue, f.capped, f.family, c.instance)
		ch <- prometheus.MustNewConstMetric(c.keys, prometheus.GaugeValue, f.keys, f.family, c.instance)
	}
	ch <- prometheus.MustNewConstMetric(c.dropped, prometheus.CounterValue, float64(snap.dropped), logEventObservationDropReasonHandoffFull, c.instance)

	for _, p := range snap.fw {
		ch <- prometheus.MustNewConstMetric(c.firewall, prometheus.CounterValue, p.v,
			p.k.action, p.k.iface, p.k.ruleID, p.k.ruleName, p.k.scope, c.instance)
	}
	for _, p := range snap.ha {
		ch <- prometheus.MustNewConstMetric(c.haproxy, prometheus.CounterValue, p.v,
			p.k.event, p.k.backend, p.k.server, p.k.state, p.k.statusClass, c.instance)
	}
	for _, p := range snap.ssh {
		ch <- prometheus.MustNewConstMetric(c.sshd, prometheus.CounterValue, p.v,
			p.k.result, p.k.method, p.k.scope, c.instance)
	}
	for _, p := range snap.dhcp {
		ch <- prometheus.MustNewConstMetric(c.dhcp, prometheus.CounterValue, p.v,
			p.k.action, p.k.iface, p.k.server, c.instance)
	}
	for _, p := range snap.audit {
		ch <- prometheus.MustNewConstMetric(c.audit, prometheus.CounterValue, p.v,
			p.k.event, p.k.result, c.instance)
	}
	for _, p := range snap.ids {
		ch <- prometheus.MustNewConstMetric(c.ids, prometheus.CounterValue, p.v,
			p.k.eventType, p.k.action, p.k.category, p.k.severity, c.instance)
	}
	for _, p := range snap.gateway {
		ch <- prometheus.MustNewConstMetric(c.gateway, prometheus.CounterValue, p.v,
			p.k.event, p.k.gateway, c.instance)
	}
	for _, p := range snap.radius {
		ch <- prometheus.MustNewConstMetric(c.radius, prometheus.CounterValue, p.v,
			p.k.event, p.k.result, p.k.clientScope, c.instance)
	}
	for _, p := range snap.vpn {
		ch <- prometheus.MustNewConstMetric(c.vpn, prometheus.CounterValue, p.v,
			p.k.backend, p.k.event, p.k.result, p.k.connection, c.instance)
	}
	for _, p := range snap.carp {
		ch <- prometheus.MustNewConstMetric(c.carp, prometheus.CounterValue, p.v,
			p.k.event, p.k.from, p.k.to, p.k.iface, p.k.vhid, c.instance)
	}
	for _, p := range snap.upnp {
		ch <- prometheus.MustNewConstMetric(c.upnp, prometheus.CounterValue, p.v,
			p.k.event, p.k.result, p.k.protocol, c.instance)
	}
	for _, p := range snap.netmap {
		ch <- prometheus.MustNewConstMetric(c.netmapRingFull, prometheus.CounterValue, p.v,
			p.k.device, c.instance)
	}
	for _, p := range snap.arp {
		ch <- prometheus.MustNewConstMetric(c.arpMoves, prometheus.CounterValue, p.v,
			p.k.iface, c.instance)
	}
	for _, p := range snap.dhcpCli {
		ch <- prometheus.MustNewConstMetric(c.dhcpClient, prometheus.CounterValue, p.v,
			p.k.iface, p.k.msgType, c.instance)
	}
	for _, p := range snap.dhcpScr {
		ch <- prometheus.MustNewConstMetric(c.dhcpClientScr, prometheus.CounterValue, p.v,
			p.k.iface, p.k.reason, c.instance)
	}
	// The two lease GAUGES come from one stored pair per interface, so they are emitted
	// together — a bind time published without its deadline is exactly the half-state
	// the pair exists to prevent.
	for _, p := range snap.dhcpLease {
		ch <- prometheus.MustNewConstMetric(c.dhcpLeaseBound, prometheus.GaugeValue, p.v.bound,
			p.k.iface, c.instance)
		ch <- prometheus.MustNewConstMetric(c.dhcpLeaseRenew, prometheus.GaugeValue, p.v.renewal,
			p.k.iface, c.instance)
	}
	for _, p := range snap.zen {
		ch <- prometheus.MustNewConstMetric(c.zenarmor, prometheus.CounterValue, p.v,
			p.k.family, p.k.action, p.k.category, p.k.iface, p.k.rcode, p.k.severity,
			p.k.statusClass, c.instance)
	}
	for _, d := range snap.zenDevs {
		// An info metric: the labels are the payload, the value is always 1.
		ch <- prometheus.MustNewConstMetric(c.zenarmorDev, prometheus.GaugeValue, 1,
			d.key, d.val.category, d.val.iface, c.instance)
	}
	return nil
}
