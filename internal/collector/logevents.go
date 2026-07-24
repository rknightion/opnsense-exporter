package collector

import (
	"context"
	"log/slog"
	"sync"

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
	logFamilyZenarmor = "zenarmor"
)

// defaultMaxLogEventKeys is the per-family key budget a store starts with, matching
// the default of --logs.max-metric-keys. main overrides it via SetMaxKeys once flags
// are parsed; this value only governs the window before that call, and exists so the
// store is never unbounded by accident.
const defaultMaxLogEventKeys = 5000

// LogEventStore holds the monotonic per-family counters. Observe* run on the
// receiver read goroutine; the collector reads under the same mutex at scrape time.
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
	mu    sync.Mutex
	fw    *cappedCounter[fwKey]
	ha    *cappedCounter[haKey]
	ssh   *cappedCounter[sshKey]
	dhcp  *cappedCounter[dhcpKey]
	audit *cappedCounter[auditKey]
	ids   *cappedCounter[idsKey]
	zen   *cappedCounter[zenKey]
}

func newLogEventStore() *LogEventStore {
	return &LogEventStore{
		fw:    newCappedCounter[fwKey](defaultMaxLogEventKeys),
		ha:    newCappedCounter[haKey](defaultMaxLogEventKeys),
		ssh:   newCappedCounter[sshKey](defaultMaxLogEventKeys),
		dhcp:  newCappedCounter[dhcpKey](defaultMaxLogEventKeys),
		audit: newCappedCounter[auditKey](defaultMaxLogEventKeys),
		ids:   newCappedCounter[idsKey](defaultMaxLogEventKeys),
		zen:   newCappedCounter[zenKey](defaultMaxLogEventKeys),
	}
}

// SetMaxKeys applies the per-family key budget from --logs.max-metric-keys; 0
// disables the cap. main calls it once at startup, before the receivers start.
//
// The budget is PER FAMILY, not shared across them: one noisy program must not be
// able to starve another family's legitimate tuples out of existence.
//
// Lowering it does not evict tuples already tracked — see cappedCounter.setMax.
func (s *LogEventStore) SetMaxKeys(max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fw.setMax(max)
	s.ha.setMax(max)
	s.ssh.setMax(max)
	s.dhcp.setMax(max)
	s.audit.setMax(max)
	s.ids.setMax(max)
	s.zen.setMax(max)
}

// ObserveFirewall implements logship.MetricSink.
func (s *LogEventStore) ObserveFirewall(action, iface, ruleID, ruleName, scope string) {
	s.mu.Lock()
	s.fw.inc(fwKey{action, iface, ruleID, ruleName, scope})
	s.mu.Unlock()
}

// ObserveHAProxy implements logship.MetricSink.
func (s *LogEventStore) ObserveHAProxy(event, backend, server, state, statusClass string) {
	s.mu.Lock()
	s.ha.inc(haKey{event, backend, server, state, statusClass})
	s.mu.Unlock()
}

// ObserveSSHD implements logship.MetricSink.
func (s *LogEventStore) ObserveSSHD(result, method, scope string) {
	s.mu.Lock()
	s.ssh.inc(sshKey{result, method, scope})
	s.mu.Unlock()
}

// ObserveDHCP implements logship.MetricSink.
func (s *LogEventStore) ObserveDHCP(action, iface, server string) {
	s.mu.Lock()
	s.dhcp.inc(dhcpKey{action, iface, server})
	s.mu.Unlock()
}

// ObserveAudit implements logship.MetricSink.
func (s *LogEventStore) ObserveAudit(event, result string) {
	s.mu.Lock()
	s.audit.inc(auditKey{event, result})
	s.mu.Unlock()
}

// ObserveIDS implements logship.MetricSink.
func (s *LogEventStore) ObserveIDS(eventType, action, category, severity string) {
	s.mu.Lock()
	s.ids.inc(idsKey{eventType, action, category, severity})
	s.mu.Unlock()
}

// ObserveZenarmor implements logship.MetricSink.
func (s *LogEventStore) ObserveZenarmor(o logship.ZenarmorObservation) {
	s.mu.Lock()
	s.zen.inc(zenKey{o.Family, o.Action, o.Category, o.Interface, o.RCode, o.Severity, o.StatusClass})
	s.mu.Unlock()
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
	zenarmor *prometheus.Desc

	capped *prometheus.Desc
	keys   *prometheus.Desc
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
}

func (c *logEventsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.firewall
	ch <- c.haproxy
	ch <- c.sshd
	ch <- c.dhcp
	ch <- c.audit
	ch <- c.ids
	ch <- c.zenarmor
	ch <- c.capped
	ch <- c.keys
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

// drainFamily copies one family's live series and its saturation state out of the
// store. The CALLER holds the store mutex — cappedCounter is not internally locked,
// and snapshot returns the live map, so the copy must happen before the unlock.
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
// The maps are snapshotted under lock and emitted after unlocking, so a slow metric
// channel can never stall an Observe call on the receiver goroutine.
func (c *logEventsCollector) Update(_ context.Context, _ *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	var sat []familySaturation

	c.store.mu.Lock()
	fw, s := drainFamily(logFamilyFirewall, c.store.fw)
	sat = append(sat, s)
	ha, s := drainFamily(logFamilyHAProxy, c.store.ha)
	sat = append(sat, s)
	ssh, s := drainFamily(logFamilySSHD, c.store.ssh)
	sat = append(sat, s)
	dhcp, s := drainFamily(logFamilyDHCP, c.store.dhcp)
	sat = append(sat, s)
	audit, s := drainFamily(logFamilyAudit, c.store.audit)
	sat = append(sat, s)
	ids, s := drainFamily(logFamilyIDS, c.store.ids)
	sat = append(sat, s)
	zen, s := drainFamily(logFamilyZenarmor, c.store.zen)
	sat = append(sat, s)
	c.store.mu.Unlock()

	// Published for every family on every scrape, including the zeros: a saturation
	// counter that only materialises once it is non-zero cannot be alerted on until
	// after it has already mattered.
	for _, f := range sat {
		ch <- prometheus.MustNewConstMetric(c.capped, prometheus.CounterValue, f.capped, f.family, c.instance)
		ch <- prometheus.MustNewConstMetric(c.keys, prometheus.GaugeValue, f.keys, f.family, c.instance)
	}

	for _, p := range fw {
		ch <- prometheus.MustNewConstMetric(c.firewall, prometheus.CounterValue, p.v,
			p.k.action, p.k.iface, p.k.ruleID, p.k.ruleName, p.k.scope, c.instance)
	}
	for _, p := range ha {
		ch <- prometheus.MustNewConstMetric(c.haproxy, prometheus.CounterValue, p.v,
			p.k.event, p.k.backend, p.k.server, p.k.state, p.k.statusClass, c.instance)
	}
	for _, p := range ssh {
		ch <- prometheus.MustNewConstMetric(c.sshd, prometheus.CounterValue, p.v,
			p.k.result, p.k.method, p.k.scope, c.instance)
	}
	for _, p := range dhcp {
		ch <- prometheus.MustNewConstMetric(c.dhcp, prometheus.CounterValue, p.v,
			p.k.action, p.k.iface, p.k.server, c.instance)
	}
	for _, p := range audit {
		ch <- prometheus.MustNewConstMetric(c.audit, prometheus.CounterValue, p.v,
			p.k.event, p.k.result, c.instance)
	}
	for _, p := range ids {
		ch <- prometheus.MustNewConstMetric(c.ids, prometheus.CounterValue, p.v,
			p.k.eventType, p.k.action, p.k.category, p.k.severity, c.instance)
	}
	for _, p := range zen {
		ch <- prometheus.MustNewConstMetric(c.zenarmor, prometheus.CounterValue, p.v,
			p.k.family, p.k.action, p.k.category, p.k.iface, p.k.rcode, p.k.severity,
			p.k.statusClass, c.instance)
	}
	return nil
}
