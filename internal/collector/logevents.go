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

// Label tuples. Each is the full, bounded label set for one derived metric family.
// Deliberately no IP, port, SID, MAC, hostname, username or free-text rule
// description — those would be unbounded and must stay as log-line metadata.
type (
	fwKey    struct{ action, iface, ruleID, ruleName, scope string }
	haKey    struct{ event, backend, server, state, statusClass string }
	sshKey   struct{ result, method, scope string }
	dhcpKey  struct{ action, iface, server string }
	auditKey struct{ event, result string }
	idsKey   struct{ eventType, action, category, severity string }
	// zenKey is Zenarmor's bounded tuple. Zenarmor is the highest-cardinality data
	// this exporter touches: app_name, IPs, ports, ja3, session_id, community_id and
	// conn_uuid are deliberately absent and must stay absent.
	zenKey struct{ family, action, category, iface, rcode, severity, statusClass string }
)

// LogEventStore holds the monotonic per-family counters. Observe* run on the
// receiver read goroutine; the collector reads under the same mutex at scrape time.
// The maps are bounded by the ruleset/interface/backend inventory, so they do not
// grow without limit. Totals reset to zero only on process restart, like any
// process counter.
type LogEventStore struct {
	mu    sync.Mutex
	fw    map[fwKey]float64
	ha    map[haKey]float64
	ssh   map[sshKey]float64
	dhcp  map[dhcpKey]float64
	audit map[auditKey]float64
	ids   map[idsKey]float64
	zen   map[zenKey]float64
}

func newLogEventStore() *LogEventStore {
	return &LogEventStore{
		fw:    map[fwKey]float64{},
		ha:    map[haKey]float64{},
		ssh:   map[sshKey]float64{},
		dhcp:  map[dhcpKey]float64{},
		audit: map[auditKey]float64{},
		ids:   map[idsKey]float64{},
		zen:   map[zenKey]float64{},
	}
}

// ObserveFirewall implements logship.MetricSink.
func (s *LogEventStore) ObserveFirewall(action, iface, ruleID, ruleName, scope string) {
	s.mu.Lock()
	s.fw[fwKey{action, iface, ruleID, ruleName, scope}]++
	s.mu.Unlock()
}

// ObserveHAProxy implements logship.MetricSink.
func (s *LogEventStore) ObserveHAProxy(event, backend, server, state, statusClass string) {
	s.mu.Lock()
	s.ha[haKey{event, backend, server, state, statusClass}]++
	s.mu.Unlock()
}

// ObserveSSHD implements logship.MetricSink.
func (s *LogEventStore) ObserveSSHD(result, method, scope string) {
	s.mu.Lock()
	s.ssh[sshKey{result, method, scope}]++
	s.mu.Unlock()
}

// ObserveDHCP implements logship.MetricSink.
func (s *LogEventStore) ObserveDHCP(action, iface, server string) {
	s.mu.Lock()
	s.dhcp[dhcpKey{action, iface, server}]++
	s.mu.Unlock()
}

// ObserveAudit implements logship.MetricSink.
func (s *LogEventStore) ObserveAudit(event, result string) {
	s.mu.Lock()
	s.audit[auditKey{event, result}]++
	s.mu.Unlock()
}

// ObserveIDS implements logship.MetricSink.
func (s *LogEventStore) ObserveIDS(eventType, action, category, severity string) {
	s.mu.Lock()
	s.ids[idsKey{eventType, action, category, severity}]++
	s.mu.Unlock()
}

// ObserveZenarmor implements logship.MetricSink.
func (s *LogEventStore) ObserveZenarmor(o logship.ZenarmorObservation) {
	s.mu.Lock()
	s.zen[zenKey{o.Family, o.Action, o.Category, o.Interface, o.RCode, o.Severity, o.StatusClass}]++
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
			"the way to ask rate questions without querying the raw log stream — and they outlive Loki's "+
			"retention. Application name, IPs, ports, hostnames, MACs, JA3, session/community/connection "+
			"ids, URIs and DNS queries are never labels; they stay as structured metadata on the record.",
		[]string{"family", "action", "category", "interface", "rcode", "severity", "status_class"},
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
}

// Update emits the current running totals as const counter metrics. It ignores the
// client: this collector never calls the API — the syslog receiver feeds the store.
// The maps are snapshotted under lock and emitted after unlocking, so a slow metric
// channel can never stall an Observe call on the receiver goroutine.
func (c *logEventsCollector) Update(_ context.Context, _ *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	type fwPair struct {
		k fwKey
		v float64
	}
	type haPair struct {
		k haKey
		v float64
	}
	type sshPair struct {
		k sshKey
		v float64
	}
	type dhcpPair struct {
		k dhcpKey
		v float64
	}
	type auditPair struct {
		k auditKey
		v float64
	}
	type idsPair struct {
		k idsKey
		v float64
	}
	type zenPair struct {
		k zenKey
		v float64
	}

	c.store.mu.Lock()
	fw := make([]fwPair, 0, len(c.store.fw))
	for k, v := range c.store.fw {
		fw = append(fw, fwPair{k, v})
	}
	ha := make([]haPair, 0, len(c.store.ha))
	for k, v := range c.store.ha {
		ha = append(ha, haPair{k, v})
	}
	ssh := make([]sshPair, 0, len(c.store.ssh))
	for k, v := range c.store.ssh {
		ssh = append(ssh, sshPair{k, v})
	}
	dhcp := make([]dhcpPair, 0, len(c.store.dhcp))
	for k, v := range c.store.dhcp {
		dhcp = append(dhcp, dhcpPair{k, v})
	}
	audit := make([]auditPair, 0, len(c.store.audit))
	for k, v := range c.store.audit {
		audit = append(audit, auditPair{k, v})
	}
	ids := make([]idsPair, 0, len(c.store.ids))
	for k, v := range c.store.ids {
		ids = append(ids, idsPair{k, v})
	}
	zen := make([]zenPair, 0, len(c.store.zen))
	for k, v := range c.store.zen {
		zen = append(zen, zenPair{k, v})
	}
	c.store.mu.Unlock()

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
