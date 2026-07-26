package collector

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

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
	// zenKey is Zenarmor's tuple, and Zenarmor is the highest-cardinality data this
	// exporter touches: app_name, IPs, ports, ja3, session_id, community_id and
	// conn_uuid are deliberately absent and must stay absent. Of what is left,
	// category and iface are the free-form pair the key budget exists for.
	zenKey struct{ family, action, category, iface, rcode, severity, statusClass string }
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
	logFamilyZenarmor = "zenarmor"

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

type logEventCommandKind uint8

const (
	logEventObserveFirewall logEventCommandKind = iota
	logEventObserveHAProxy
	logEventObserveSSHD
	logEventObserveDHCP
	logEventObserveAudit
	logEventObserveIDS
	logEventObserveGateway
	logEventObserveZenarmor
	logEventSetMaxKeys
	logEventTakeSnapshot
	logEventSync
)

type logEventCommand struct {
	kind     logEventCommandKind
	values   [7]string
	maxKeys  int
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
	zen     []keyed[zenKey]
	sat     []familySaturation
	dropped uint64
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
	zen              *cappedCounter[zenKey]
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
		zen:            newCappedCounter[zenKey](defaultMaxLogEventKeys),
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

// ObserveZenarmor implements logship.MetricSink.
func (s *LogEventStore) ObserveZenarmor(o logship.ZenarmorObservation) bool {
	return s.observe(logEventCommand{kind: logEventObserveZenarmor, values: [7]string{o.Family, o.Action, o.Category, o.Interface, o.RCode, o.Severity, o.StatusClass}})
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
	case logEventObserveZenarmor:
		s.zen.inc(zenKey{v[0], v[1], v[2], v[3], v[4], v[5], v[6]})
	case logEventSetMaxKeys:
		s.fw.setMax(cmd.maxKeys)
		s.ha.setMax(cmd.maxKeys)
		s.ssh.setMax(cmd.maxKeys)
		s.dhcp.setMax(cmd.maxKeys)
		s.audit.setMax(cmd.maxKeys)
		s.ids.setMax(cmd.maxKeys)
		s.gateway.setMax(cmd.maxKeys)
		s.zen.setMax(cmd.maxKeys)
		close(cmd.ack)
	case logEventTakeSnapshot:
		if s.beforeSnapshot != nil {
			s.beforeSnapshot()
		}
		cmd.snapshot <- s.buildSnapshot()
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
	snap.zen, sat = drainFamily(logFamilyZenarmor, s.zen)
	snap.sat = append(snap.sat, sat)
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

	firewall *prometheus.Desc
	haproxy  *prometheus.Desc
	sshd     *prometheus.Desc
	dhcp     *prometheus.Desc
	audit    *prometheus.Desc
	ids      *prometheus.Desc
	gateway  *prometheus.Desc
	zenarmor *prometheus.Desc

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
	c.zenarmor = buildPrometheusDesc(c.subsystem, "zenarmor_total",
		"Zenarmor events received over the Elasticsearch receiver, by family (flow/dns/tls/web/ids/voip), "+
			"action, category, interface, DNS rcode, alert severity and HTTP status class. Fields that do "+
			"not apply to a family are empty. Zenarmor ships ~2.5-3.3M records/day, so these counters are "+
			"the way to ask rate questions without querying the raw log stream - and they outlive Loki's "+
			"retention. Application name, IPs, ports, hostnames, MACs, JA3, session/community/connection "+
			"ids, URIs and DNS queries are never labels; they stay as structured metadata on the record.",
		[]string{"family", "action", "category", "interface", "rcode", "severity", "status_class"},
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
	ch <- c.zenarmor
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
	for _, p := range snap.zen {
		ch <- prometheus.MustNewConstMetric(c.zenarmor, prometheus.CounterValue, p.v,
			p.k.family, p.k.action, p.k.category, p.k.iface, p.k.rcode, p.k.severity,
			p.k.statusClass, c.instance)
	}
	return nil
}
