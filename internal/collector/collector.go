package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// namespace is the prefix for all metrics.
const namespace = "opnsense"

// instanceLabelName is the label name for the current instance that is used
// to identify the instance in the metrics when there are
// multiple instances of the exporter running.
const instanceLabelName = "opnsense_instance"

const (
	ArpTableSubsystem          = "arp_table"
	GatewaysSubsystem          = "gateways"
	GatewayGroupsSubsystem     = "gateway_groups"
	FirewallMigrationSubsystem = "firewall_migration"
	CronTableSubsystem         = "cron"
	WireguardSubsystem         = "wireguard"
	IPsecSubsystem             = "ipsec"
	UnboundDNSSubsystem        = "unbound_dns"
	InterfacesSubsystem        = "interfaces"
	ProtocolSubsystem          = "protocol"
	OpenVPNSubsystem           = "openvpn"
	ServicesSubsystem          = "services"
	FirewallSubsystem          = "firewall"
	FirmwareSubsystem          = "firmware"
	DnsmasqSubsystem           = "dnsmasq"
	SystemSubsystem            = "system"
	TemperatureSubsystem       = "temperature"
	FirewallRulesSubsystem     = "firewall_rule"
	MbufSubsystem              = "mbuf"
	KernelMemorySubsystem      = "kernel_memory"
	NTPSubsystem               = "ntp"
	CertificatesSubsystem      = "certificate"
	CARPSubsystem              = "carp"
	ActivitySubsystem          = "activity"
	CPUSubsystem               = "cpu"
	KeaSubsystem               = "kea"
	Dhcpv4Subsystem            = "dhcpv4"
	NetworkDiagSubsystem       = "network_diag"
	NetflowSubsystem           = "netflow"
	PftopSubsystem             = "pftop"
	PFStatsSubsystem           = "pf_stats"
	NDPSubsystem               = "ndp"
	ACMESubsystem              = "acme"
	SMARTSubsystem             = "smart"
	DynDNSSubsystem            = "dyndns"
	SyslogSubsystem            = "syslog"
	QFeedsSubsystem            = "qfeeds"
	TailscaleSubsystem         = "tailscale"
	AliasSubsystem             = "alias"
	HAProxySubsystem           = "haproxy"
	NginxSubsystem             = "nginx"
	FRRSubsystem               = "frr"
	MonitSubsystem             = "monit"
	CrowdSecSubsystem          = "crowdsec"
	NUTSubsystem               = "nut"
	ApcupsdSubsystem           = "apcupsd"
	CaptivePortalSubsystem     = "captiveportal"
	TrafficShaperSubsystem     = "trafficshaper"
	HasyncSubsystem            = "hasync"
	ChronySubsystem            = "chrony"
	Dhcpv6Subsystem            = "dhcpv6"
	BPFSubsystem               = "bpf"
	BackupSubsystem            = "backup"
	SnapshotsSubsystem         = "snapshots"
	ClamAVSubsystem            = "clamav"
	IDSSubsystem               = "ids"
	LLDPSubsystem              = "lldp"
	HardwareSubsystem          = "hardware"
	VnstatSubsystem            = "vnstat"
	NetbirdSubsystem           = "netbird"
	BeatsSubsystem             = "beats"
	CollectdSubsystem          = "collectd"
	MuninNodeSubsystem         = "munin_node"
	NetSNMPSubsystem           = "net_snmp"
	NetdataSubsystem           = "netdata"
	NodeExporterSubsystem      = "node_exporter"
	NRPESubsystem              = "nrpe"
	PuppetAgentSubsystem       = "puppet_agent"
	QemuGuestAgentSubsystem    = "qemu_guest_agent"
	TelegrafSubsystem          = "telegraf"
	WazuhAgentSubsystem        = "wazuh_agent"
	ZabbixAgentSubsystem       = "zabbix_agent"
	ZabbixProxySubsystem       = "zabbix_proxy"
	ZeroTierSubsystem          = "zerotier"
	TorSubsystem               = "tor"
	AuthSubsystem              = "auth"
	HostDiscoverySubsystem     = "hostdiscovery"
	RelaydSubsystem            = "relayd"
	SiproxdSubsystem           = "siproxd"
	// LogEventsSubsystem holds the counters derived from received syslog lines
	// (#258). Unlike every other collector it does not poll an API on Update: the
	// syslog receiver feeds its running totals out of band via collector.LogEvents,
	// and Update simply emits the current totals as const metrics.
	LogEventsSubsystem = "log_events"
	// FlowSubsystem holds byte and packet volume rolled up from flow records
	// (#346) — Zenarmor conn documents today, plus a NetFlow receiver from phase 2.
	// Like log_events it never polls an API: the receiver lanes feed collector.Flow
	// out of band and Update emits the accumulator's current totals.
	FlowSubsystem = "flow"
	// FeatureAvailabilitySubsystem (#517) is deliberately short: the metric this
	// collector emits must be EXACTLY opnsense_feature_available, and
	// prometheus.BuildFQName joins namespace_subsystem_name, so the subsystem
	// has to be "feature" for the metric name "available" to land there. Must
	// live in THIS const block (not availability.go, where the rest of its
	// probe logic lives): scripts/docgen's parseSubsystemConstants only reads
	// collector.go's const declarations to resolve a collector file's
	// `subsystem: XxxSubsystem` init() literal back to a string.
	FeatureAvailabilitySubsystem = "feature"
)

// SubsystemDisplayNames maps every collector subsystem to the human-readable
// name used in generated documentation. A unit test and scripts/docgen fail
// when a registered collector has no entry, so a new collector without a
// display name breaks the build instead of rendering a raw slug.
var SubsystemDisplayNames = map[string]string{
	ArpTableSubsystem:            "ARP Table",
	GatewaysSubsystem:            "Gateways",
	GatewayGroupsSubsystem:       "Gateway Groups",
	FirewallMigrationSubsystem:   "Firewall Migration Debt",
	CronTableSubsystem:           "Cron",
	WireguardSubsystem:           "Wireguard",
	IPsecSubsystem:               "IPsec",
	UnboundDNSSubsystem:          "Unbound DNS",
	InterfacesSubsystem:          "Interfaces",
	ProtocolSubsystem:            "Protocol Statistics",
	OpenVPNSubsystem:             "OpenVPN",
	ServicesSubsystem:            "Services",
	FirewallSubsystem:            "Firewall",
	FirmwareSubsystem:            "Firmware",
	DnsmasqSubsystem:             "Dnsmasq DHCP",
	SystemSubsystem:              "System",
	TemperatureSubsystem:         "Temperature",
	FirewallRulesSubsystem:       "Firewall Rules",
	MbufSubsystem:                "Mbuf",
	KernelMemorySubsystem:        "Kernel Memory (UMA zones and malloc types)",
	NTPSubsystem:                 "NTP",
	CertificatesSubsystem:        "Certificates",
	CARPSubsystem:                "CARP",
	ActivitySubsystem:            "Activity",
	CPUSubsystem:                 "CPU",
	KeaSubsystem:                 "Kea DHCP",
	Dhcpv4Subsystem:              "ISC DHCPv4",
	NetworkDiagSubsystem:         "Network Diagnostics",
	NetflowSubsystem:             "NetFlow",
	PftopSubsystem:               "pfTop Diagnostics",
	PFStatsSubsystem:             "PF Statistics",
	NDPSubsystem:                 "NDP",
	ACMESubsystem:                "ACME Client",
	SMARTSubsystem:               "SMART Disk Health",
	DynDNSSubsystem:              "DynDNS",
	SyslogSubsystem:              "Syslog",
	QFeedsSubsystem:              "Q-Feeds",
	TailscaleSubsystem:           "Tailscale",
	AliasSubsystem:               "Firewall Aliases",
	HAProxySubsystem:             "HAProxy",
	NginxSubsystem:               "Nginx",
	FRRSubsystem:                 "FRR Routing (BGP/OSPF/BFD)",
	MonitSubsystem:               "Monit",
	CrowdSecSubsystem:            "CrowdSec",
	NUTSubsystem:                 "NUT UPS",
	ApcupsdSubsystem:             "APC UPS (apcupsd)",
	CaptivePortalSubsystem:       "Captive Portal",
	TrafficShaperSubsystem:       "Traffic Shaper",
	HasyncSubsystem:              "HA Sync Status",
	ChronySubsystem:              "Chrony",
	Dhcpv6Subsystem:              "ISC DHCPv6",
	BPFSubsystem:                 "BPF Statistics",
	BackupSubsystem:              "Config Backup",
	SnapshotsSubsystem:           "ZFS Boot Environments",
	ClamAVSubsystem:              "ClamAV",
	IDSSubsystem:                 "IDS/IPS (Suricata)",
	LLDPSubsystem:                "LLDP Neighbors",
	HardwareSubsystem:            "Hardware",
	VnstatSubsystem:              "Vnstat Traffic Accounting",
	NetbirdSubsystem:             "NetBird",
	BeatsSubsystem:               "Beats",
	CollectdSubsystem:            "Collectd",
	MuninNodeSubsystem:           "Munin Node",
	NetSNMPSubsystem:             "Net-SNMP",
	NetdataSubsystem:             "Netdata",
	NodeExporterSubsystem:        "Node Exporter",
	NRPESubsystem:                "NRPE",
	PuppetAgentSubsystem:         "Puppet Agent",
	QemuGuestAgentSubsystem:      "QEMU Guest Agent",
	TelegrafSubsystem:            "Telegraf",
	WazuhAgentSubsystem:          "Wazuh Agent",
	ZabbixAgentSubsystem:         "Zabbix Agent",
	ZabbixProxySubsystem:         "Zabbix Proxy",
	ZeroTierSubsystem:            "ZeroTier",
	TorSubsystem:                 "Tor",
	AuthSubsystem:                "Local Auth",
	HostDiscoverySubsystem:       "Host Discovery",
	RelaydSubsystem:              "Relayd Load Balancer",
	SiproxdSubsystem:             "Siproxd",
	LogEventsSubsystem:           "Log-derived Events",
	FlowSubsystem:                "Flow Volume",
	FeatureAvailabilitySubsystem: "Feature Availability",
}

// AllCollectors returns a copy of every collector instance registered via
// init(), regardless of enable/disable switches. Consumed by scripts/docgen.
func AllCollectors() []CollectorInstance {
	return append([]CollectorInstance(nil), collectorInstances...)
}

// CollectorInstance is the interface a service specific collectors must implement.
type CollectorInstance interface {
	Register(namespace, isntance string, log *slog.Logger)
	Name() string
	Describe(ch chan<- *prometheus.Desc)
	Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError
}

// collectorInstances is a list of collectorInstances that will be registered
// from the init() function in each collector file
var collectorInstances []CollectorInstance

type Collector struct {
	Client *opnsense.Client
	mutex  sync.RWMutex
	log    *slog.Logger

	isUp                 prometheus.Gauge
	firewallHealthStatus prometheus.Gauge
	crashReporterStatus  prometheus.Gauge
	systemStatusCode     prometheus.Gauge
	subsystemStatusCode  *prometheus.GaugeVec
	scrapes              prometheus.CounterVec
	endpointErrors       prometheus.CounterVec
	partialFetchFailures prometheus.CounterVec
	apiRequests          prometheus.CounterVec
	apiRequestDuration   prometheus.HistogramVec
	apiCacheHits         prometheus.CounterVec
	apiCacheMisses       prometheus.CounterVec
	instanceLabel        string
	collectors           []CollectorInstance

	// version is the exporter build version, surfaced via opnsense_exporter_build_info.
	version string
	// collectorStates maps every registered collector subsystem name to whether it
	// is enabled in this exporter instance, surfaced via opnsense_exporter_collector_enabled.
	collectorStates map[string]bool

	// routeStatus records, per endpoint PATH, whether that route exists, as
	// observed by the request and cache observers. Read by the availability
	// prober so an enabled collector's endpoint is never probed twice (#525).
	routeMu          sync.Mutex
	routeStatus      map[string]bool
	buildInfo        *prometheus.Desc
	collectorEnabled *prometheus.Desc
	// scrapeDuration / scrapeSuccess retain the historical node_exporter-compatible
	// metric names, but describe scheduled collector polls. They are emitted as const
	// metrics around every sub-collector Update.
	scrapeDuration *prometheus.Desc
	scrapeSuccess  *prometheus.Desc
	// pollInterval / lastPollTs / nextPollTs surface the poll scheduler's per-collector
	// timing (#336): the configured interval and the last/next poll timestamps, so
	// dashboards and the operator console can show freshness and a next-run countdown.
	//
	// snapshotTs / lastSuccessTs are the two data clocks added by #382. lastPollTs is
	// scheduler liveness and says NOTHING about how old the replayed values are: a
	// collector failing every minute for six hours keeps refreshing it while serving
	// 10:00 data. Anything asking "how stale is this data?" must read snapshotTs (or
	// lastSuccessTs), never lastPollTs.
	pollInterval  *prometheus.Desc
	lastPollTs    *prometheus.Desc
	nextPollTs    *prometheus.Desc
	snapshotTs    *prometheus.Desc
	lastSuccessTs *prometheus.Desc
	// apiCacheFetchedTs is the per-endpoint time the response cache's held body was
	// fetched from the firewall (OPN-0095, GitHub issue 724). lastSuccessTs advances
	// on a poll served from that cache, so it alone cannot tell a live fetch from a
	// replay; this gauge is the clock that does not move on a replay.
	apiCacheFetchedTs *prometheus.Desc

	// seriesTotal backs opnsense_exporter_series (#494): the most recent
	// total collector-registry series count observed by metricsnap's
	// Tee/TeeLane on a real scrape or OTLP export, so the soft
	// --exporter.series-budget check is alertable rather than only visible in
	// logs and the web UI. Nil until New() sets it (guarded at every emit site
	// so a Collector built by test helpers via struct literal, which never set
	// it, never panics). observedSeriesTotal is written from
	// SetObservedSeriesTotal, called asynchronously to Collect() from
	// metricsnap's SeriesBudget.Observed callback, hence atomic.
	seriesTotal         *prometheus.Desc
	observedSeriesTotal atomic.Int64

	// maxScrapeDuration is the legacy field name for the per-poll timeout configured
	// by --exporter.max-scrape-duration. Serving /metrics only replays snapshots and
	// never uses this as an API deadline. Zero selects defaultMaxScrapeDuration.
	maxScrapeDuration time.Duration
	// otlpGatherTimeout, when > 0, is the deadline applied to the OTLP-bridge gather
	// path (Collect), derived from the OTLP export interval. It does not control
	// background API polling.
	otlpGatherTimeout time.Duration

	// statusTracker, when non-nil, passively records per-collector run history for
	// the operator console. It is updated from pollOnce on every poll; it never
	// influences collection. Injected via WithStatusTracker.
	statusTracker *StatusTracker

	// --- internal poll scheduler (#336) ---
	// store holds the latest poll result per collector; the serving path (collect)
	// replays it instead of running collectors live on each scrape.
	store *snapshotStore
	// pollGlobal is the default poll interval for collectors that declare no tier;
	// zero means IntervalMedium. Set via WithPollInterval.
	pollGlobal time.Duration
	// healthPollGlobal is the health poller's own interval; zero means IntervalMedium.
	// It is deliberately NOT pollGlobal (#386): the health poll owns the process-wide
	// unreachable circuit, so tying it to the untiered-collector default made
	// --collector.poll-interval secretly control recovery latency — raising it to 15m
	// for firewall load also bought up to 15m of every-collector-paused after the box
	// came back. Set via WithHealthPollInterval.
	healthPollGlobal time.Duration
	// pollOverrides maps a collector name to an operator-supplied interval that wins
	// over both its code tier and the global default. Set via WithPollIntervalOverrides.
	pollOverrides map[string]time.Duration
	// laneBase / laneFast are the OTLP export-lane intervals that CONSUME the
	// snapshot (#550): --otlp.export-interval and the optional
	// --otlp.fast-export-interval. Both zero means OTLP is not a delivery path, so
	// no lane clamp applies. Set via WithExportLanes; read only by poll_lane.go,
	// which owns the declared-vs-effective split.
	laneBase time.Duration
	laneFast time.Duration
	// pollCancel / pollWG / pollSem are the scheduler lifecycle + concurrency cap,
	// initialised by StartPolling.
	pollCancel context.CancelFunc
	pollWG     sync.WaitGroup
	pollSem    chan struct{}
	// unreachable is set by the health poller on a transport-level failure so
	// collector pollers skip (retaining last-good) until the box recovers (#127).
	unreachable atomic.Bool
	// healthOK records whether the last health poll reached and parsed the box.
	// emitHealth gates the non-isUp health gauges on it so that during an outage
	// (or before the first poll) they stay ABSENT rather than emitting a misleading
	// 0 — 0 is the WARNING status code, not "unknown". Guarded by mutex.
	healthOK bool
	// healthPolled records whether the health poller has completed a poll at all,
	// regardless of outcome. Unlike healthOK it never goes back to false, and it is
	// the health half of SnapshotWarm. Guarded by mutex.
	healthPolled bool
	// healthCheckedAt / healthLastError complete the passive upstream-health seam the
	// operator console reads (#384). healthLastError is a bounded reason string, never
	// a label. Guarded by mutex.
	healthCheckedAt time.Time
	healthLastError string
}

// HealthSnapshot is a passive copy of the scheduler's upstream-health state, taken
// without an API call or a registry gather (#384).
//
// The console's top-level badge used to be derived purely from collector run
// history, which is silent during exactly the outage it most needs to report: when
// the box is unreachable the scheduler SKIPS collector polls, so no failed run is
// ever recorded and the last successful runs keep the badge green while opnsense_up
// is zero and readiness is failing.
//
// CheckOK and Unreachable are separate on purpose. CheckOK is false for any failed
// health poll; Unreachable is true only for a transport-level failure (nothing
// answered). A box that is reachable but returning HTTP 500 must degrade the verdict
// without being described as unreachable.
type HealthSnapshot struct {
	Polled      bool      // a health poll has completed at least once
	CheckOK     bool      // the last health poll reached AND parsed the box
	Unreachable bool      // the last failure was transport-level (nothing answered)
	CheckedAt   time.Time // when the last health poll completed; zero if never
	LastError   string    // bounded reason; empty when CheckOK
}

// HealthSnapshot returns the current upstream-health state. It is passive: it makes
// no API call and never gathers the registry, so the console can call it per page
// render without scraping the firewall.
func (c *Collector) HealthSnapshot() HealthSnapshot {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return HealthSnapshot{
		Polled:      c.healthPolled,
		CheckOK:     c.healthOK,
		Unreachable: c.unreachable.Load(),
		CheckedAt:   c.healthCheckedAt,
		LastError:   c.healthLastError,
	}
}

// AllRegisteredCollectorNames returns the sorted subsystem names of every collector
// compiled into the binary, regardless of enable/disable switches. It is the
// validation domain for operator-supplied collector names (#387): a name must be
// checked against the FULL set, not the enabled set, so one declarative config can
// be reused across deployments whose feature flags differ.
func AllRegisteredCollectorNames() []string {
	names := make([]string, 0, len(collectorInstances))
	for _, coll := range collectorInstances {
		names = append(names, coll.Name())
	}
	sort.Strings(names)
	return names
}

// ValidatePollOverrideNames checks --collector.poll-interval-override keys against
// every registered collector and fails closed on any unknown name (#387).
//
// Before this, only the duration half was validated: a typo'd collector name was
// accepted at startup and then silently ignored forever, because the scheduler
// consults the map by exact current collector name and unmatched entries simply
// never match. The operator got no warning that the rate/cost control they
// configured was doing nothing. Unknown names are now a startup failure, matching
// the existing fail-fast treatment of a malformed duration.
func ValidatePollOverrideNames(names []string) error {
	if len(names) == 0 {
		return nil
	}
	valid := AllRegisteredCollectorNames()
	known := make(map[string]bool, len(valid))
	for _, n := range valid {
		known[n] = true
	}
	var unknown []string
	for _, n := range names {
		if !known[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf(
		"unknown collector name(s) in --collector.poll-interval-override: %s; valid names are: %s",
		strings.Join(unknown, ", "), strings.Join(valid, ", "),
	)
}

// defaultMaxScrapeDuration retains the public flag's historical name but is the
// fallback bound for one scheduled collector poll.
const defaultMaxScrapeDuration = 50 * time.Second

type Option func(*Collector) error

// WithMaxScrapeDuration sets the bound applied to each scheduled collector poll.
func WithMaxScrapeDuration(d time.Duration) Option {
	return func(o *Collector) error {
		o.maxScrapeDuration = d
		return nil
	}
}

// WithStatusTracker injects a StatusTracker so pollOnce records per-collector
// run history for the operator console.
func WithStatusTracker(t *StatusTracker) Option {
	return func(o *Collector) error {
		o.statusTracker = t
		return nil
	}
}

// WithPollInterval sets the global default poll interval used by the internal poll
// scheduler for collectors that declare no tier of their own (#336). Zero leaves the
// built-in IntervalMedium default. The value is clamped to [IntervalFloor, IntervalCeil].
//
// Since #386 this no longer affects the health poller — see WithHealthPollInterval.
func WithPollInterval(d time.Duration) Option {
	return func(o *Collector) error {
		o.pollGlobal = d
		return nil
	}
}

// WithHealthPollInterval sets the health poller's own interval (#386), independent of
// the collector default. Zero leaves the built-in IntervalMedium (60s) default, which
// is exactly the previous effective behaviour, so this is backward compatible. The
// value is clamped to [IntervalFloor, IntervalCeil].
//
// This is the circuit-breaker cadence: the health poll is what sets and clears the
// process-wide unreachable flag, so it bounds how quickly every collector resumes
// after the firewall comes back.
func WithHealthPollInterval(d time.Duration) Option {
	return func(o *Collector) error {
		o.healthPollGlobal = d
		return nil
	}
}

// WithPollIntervalOverrides sets per-collector poll-interval overrides (by collector
// name) that win over the code tier and the global default. Each is clamped to
// [IntervalFloor, IntervalCeil].
func WithPollIntervalOverrides(m map[string]time.Duration) Option {
	return func(o *Collector) error {
		o.pollOverrides = m
		return nil
	}
}

// WithExportLanes tells the collector which OTLP export lanes consume its snapshot
// (#550): base is --otlp.export-interval, fast is the optional
// --otlp.fast-export-interval (zero when the second lane is off). Leave both zero —
// the default — for a Prometheus-scrape-only deployment, where there is no lane to
// clamp against and tier intervals stand exactly.
//
// Poll cadence is then max(declared tier, consuming lane), so a collector never
// polls the firewall faster than the thing that reads the result. See poll_lane.go
// for why this must not be folded into resolveInterval.
func WithExportLanes(base, fast time.Duration) Option {
	return func(o *Collector) error {
		o.laneBase, o.laneFast = base, fast
		return nil
	}
}

// WithOTLPGatherTimeout sets the deadline applied to the OTLP-bridge gather path,
// derived by the caller from the OTLP export interval (#128).
func WithOTLPGatherTimeout(d time.Duration) Option {
	return func(o *Collector) error {
		o.otlpGatherTimeout = d
		return nil
	}
}

// withoutCollectorInstance removes a collector by given name from the list of collectors
// that are registered from their init functions.
func withoutCollectorInstance(name string) Option {
	return func(o *Collector) error {
		for i, collector := range o.collectors {
			if collector.Name() == name {
				o.collectors = append(o.collectors[:i], o.collectors[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("collector %s not found", name)
	}
}

// WithoutArpTableCollector Option
// removes the arp_table collector from the list of collectors
func WithoutArpTableCollector() Option {
	return withoutCollectorInstance(ArpTableSubsystem)
}

// WithoutInterfacesCollector removes the interfaces collector (#143).
func WithoutInterfacesCollector() Option {
	return withoutCollectorInstance(InterfacesSubsystem)
}

// WithoutProtocolCollector removes the protocol-statistics collector (#143).
func WithoutProtocolCollector() Option {
	return withoutCollectorInstance(ProtocolSubsystem)
}

// WithoutServicesCollector removes the services collector (#143).
func WithoutServicesCollector() Option {
	return withoutCollectorInstance(ServicesSubsystem)
}

// WithoutCronCollector Option
// removes the cron collector from the list of collectors
func WithoutCronCollector() Option {
	return withoutCollectorInstance(CronTableSubsystem)
}

// WithoutWireguardCollector Option
// removes the wireguard collector from the list of collectors
func WithoutWireguardCollector() Option {
	return withoutCollectorInstance(WireguardSubsystem)
}

// WithoutIPsecCollector Option
// removes the ipsec collector from the list of collectors
func WithoutIPsecCollector() Option {
	return withoutCollectorInstance(IPsecSubsystem)
}

// WithoutUnboundCollector Option
// removes the unbound_dns collector from the list of collectors
func WithoutUnboundCollector() Option {
	return withoutCollectorInstance(UnboundDNSSubsystem)
}

// WithoutFirewallCollector Option
// removes the firewall (pf) collector from the list of collectors
func WithoutFirewallCollector() Option {
	return withoutCollectorInstance(FirewallSubsystem)
}

// WithoutFirmwareCollector Option
// removes the firmware collector from the list of collectors
func WithoutFirmwareCollector() Option { return withoutCollectorInstance(FirmwareSubsystem) }

// WithoutOpenVPNCollector Option
// removes the openvpn collector from the list of collectors
func WithoutOpenVPNCollector() Option {
	return withoutCollectorInstance(OpenVPNSubsystem)
}

// WithoutDnsmasqCollector Option
// removes the dnsmasq collector from the list of collectors
func WithoutDnsmasqCollector() Option {
	return withoutCollectorInstance(DnsmasqSubsystem)
}

// WithoutSystemCollector Option
// removes the system collector from the list of collectors
func WithoutSystemCollector() Option {
	return withoutCollectorInstance(SystemSubsystem)
}

// WithoutTemperatureCollector Option
// removes the temperature collector from the list of collectors
func WithoutTemperatureCollector() Option {
	return withoutCollectorInstance(TemperatureSubsystem)
}

// WithoutFirewallRulesCollector Option
// removes the firewall_rule collector from the list of collectors
func WithoutFirewallRulesCollector() Option {
	return withoutCollectorInstance(FirewallRulesSubsystem)
}

// WithoutMbufCollector Option
// removes the mbuf collector from the list of collectors
func WithoutMbufCollector() Option {
	return withoutCollectorInstance(MbufSubsystem)
}

// WithoutKernelMemoryCollector Option
// removes the kernel_memory collector from the list of collectors
func WithoutKernelMemoryCollector() Option {
	return withoutCollectorInstance(KernelMemorySubsystem)
}

// WithoutNTPCollector Option
// removes the ntp collector from the list of collectors
func WithoutNTPCollector() Option {
	return withoutCollectorInstance(NTPSubsystem)
}

// WithoutCertificatesCollector Option
// removes the certificate collector from the list of collectors
func WithoutCertificatesCollector() Option {
	return withoutCollectorInstance(CertificatesSubsystem)
}

// WithoutCARPCollector Option
// removes the carp collector from the list of collectors
func WithoutCARPCollector() Option {
	return withoutCollectorInstance(CARPSubsystem)
}

// WithoutCPUCollector Option
// removes the cpu collector from the list of collectors
func WithoutCPUCollector() Option {
	return withoutCollectorInstance(CPUSubsystem)
}

// WithoutActivityCollector Option
// removes the activity collector from the list of collectors
func WithoutActivityCollector() Option {
	return withoutCollectorInstance(ActivitySubsystem)
}

// WithoutKeaCollector Option
// removes the kea collector from the list of collectors
func WithoutKeaCollector() Option {
	return withoutCollectorInstance(KeaSubsystem)
}

// WithoutNetworkDiagnosticsCollector Option
// removes the network_diag collector from the list of collectors
func WithoutNetworkDiagnosticsCollector() Option {
	return withoutCollectorInstance(NetworkDiagSubsystem)
}

// WithoutNetisrPerCPU turns OFF the per-workstream netisr series, leaving the
// per-protocol aggregates, the derived summaries and netisr_protocol_info in
// place. Default-ON and opt-OUT, deliberately: the per-CPU dimension is the whole
// diagnosis for a netisr drop. Collapsed to protocol alone, a firewall dropping
// every packet on one saturated workstream while eleven others sit idle looks
// identical to one that is uniformly overloaded, and the two have opposite
// remedies (CPU affinity vs queue size). Shipping that off by default would mean
// the operator who most needs the data is the one least likely to have it.
func WithoutNetisrPerCPU() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if nd, ok := c.(*networkDiagCollector); ok {
				nd.SetNetisrPerCPUEnabled(false)
				return nil
			}
		}
		return nil
	}
}

// WithoutNetflowCollector Option
// removes the netflow collector from the list of collectors
func WithoutNetflowCollector() Option {
	return withoutCollectorInstance(NetflowSubsystem)
}

// WithoutPftopCollector removes the opt-in pfTop diagnostics collector.
func WithoutPftopCollector() Option {
	return withoutCollectorInstance(PftopSubsystem)
}

// WithoutPFStatsCollector Option
// removes the pf_stats collector from the list of collectors
func WithoutPFStatsCollector() Option {
	return withoutCollectorInstance(PFStatsSubsystem)
}

// WithoutNDPCollector Option
// removes the ndp collector from the list of collectors
func WithoutNDPCollector() Option {
	return withoutCollectorInstance(NDPSubsystem)
}

// WithoutDhcpv4Collector Option
// removes the dhcpv4 collector from the list of collectors
func WithoutDhcpv4Collector() Option {
	return withoutCollectorInstance(Dhcpv4Subsystem)
}

// WithoutACMECollector Option
// removes the acme collector from the list of collectors
func WithoutACMECollector() Option {
	return withoutCollectorInstance(ACMESubsystem)
}

// WithoutSMARTCollector Option
// removes the smart collector from the list of collectors
func WithoutSMARTCollector() Option {
	return withoutCollectorInstance(SMARTSubsystem)
}

// WithoutDynDNSCollector Option
// removes the dyndns collector from the list of collectors
func WithoutDynDNSCollector() Option {
	return withoutCollectorInstance(DynDNSSubsystem)
}

// WithoutGatewaysCollector Option
// removes the gateways collector from the list of collectors
func WithoutGatewaysCollector() Option {
	return withoutCollectorInstance(GatewaysSubsystem)
}

// WithoutGatewayGroupsCollector removes the gateway-groups collector.
func WithoutGatewayGroupsCollector() Option {
	return withoutCollectorInstance(GatewayGroupsSubsystem)
}

// WithoutFirewallMigrationCollector removes the firewall-migration collector.
func WithoutFirewallMigrationCollector() Option {
	return withoutCollectorInstance(FirewallMigrationSubsystem)
}

// WithoutSyslogCollector Option
// removes the syslog collector from the list of collectors
func WithoutSyslogCollector() Option {
	return withoutCollectorInstance(SyslogSubsystem)
}

// WithoutQFeedsCollector Option
// removes the qfeeds collector from the list of collectors
func WithoutQFeedsCollector() Option {
	return withoutCollectorInstance(QFeedsSubsystem)
}

// WithoutTailscaleCollector Option
// removes the tailscale collector from the list of collectors
func WithoutTailscaleCollector() Option {
	return withoutCollectorInstance(TailscaleSubsystem)
}

// WithoutAliasCollector Option
// removes the alias collector from the list of collectors
func WithoutAliasCollector() Option {
	return withoutCollectorInstance(AliasSubsystem)
}

// WithoutHAProxyCollector Option
// removes the haproxy collector from the list of collectors
func WithoutHAProxyCollector() Option {
	return withoutCollectorInstance(HAProxySubsystem)
}

// WithoutNginxCollector Option
// removes the nginx collector from the list of collectors
func WithoutNginxCollector() Option {
	return withoutCollectorInstance(NginxSubsystem)
}

// WithoutFRRCollector Option
// removes the frr collector from the list of collectors
func WithoutFRRCollector() Option {
	return withoutCollectorInstance(FRRSubsystem)
}

// WithFRRRoutesEnabled enables the opt-in FRR routing-state volume gauges
// (zebra RIB / OSPF route table / LSDB counts; default-off; #199).
func WithFRRRoutesEnabled() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if fc, ok := c.(*frrCollector); ok {
				fc.SetRoutesEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithoutMonitCollector Option
// removes the monit collector from the list of collectors
func WithoutMonitCollector() Option {
	return withoutCollectorInstance(MonitSubsystem)
}

// WithoutCrowdSecCollector Option
// removes the crowdsec collector from the list of collectors
func WithoutCrowdSecCollector() Option {
	return withoutCollectorInstance(CrowdSecSubsystem)
}

// WithoutNUTCollector Option
// removes the nut collector from the list of collectors
func WithoutNUTCollector() Option {
	return withoutCollectorInstance(NUTSubsystem)
}

// WithoutApcupsdCollector Option
// removes the apcupsd collector from the list of collectors
func WithoutApcupsdCollector() Option {
	return withoutCollectorInstance(ApcupsdSubsystem)
}

// WithoutCaptivePortalCollector Option
// removes the captiveportal collector from the list of collectors
func WithoutCaptivePortalCollector() Option {
	return withoutCollectorInstance(CaptivePortalSubsystem)
}

// WithoutTrafficShaperCollector Option
// removes the trafficshaper collector from the list of collectors
func WithoutTrafficShaperCollector() Option {
	return withoutCollectorInstance(TrafficShaperSubsystem)
}

// WithoutHasyncCollector Option
// removes the hasync collector from the list of collectors
func WithoutHasyncCollector() Option {
	return withoutCollectorInstance(HasyncSubsystem)
}

// WithoutChronyCollector Option
// removes the chrony collector from the list of collectors
func WithoutChronyCollector() Option {
	return withoutCollectorInstance(ChronySubsystem)
}

// WithoutDhcpv6Collector Option
// removes the dhcpv6 collector from the list of collectors
func WithoutDhcpv6Collector() Option {
	return withoutCollectorInstance(Dhcpv6Subsystem)
}

// WithoutBPFCollector Option
// removes the bpf collector from the list of collectors
func WithoutBPFCollector() Option {
	return withoutCollectorInstance(BPFSubsystem)
}

// WithoutBackupCollector Option
// removes the backup collector from the list of collectors
func WithoutBackupCollector() Option {
	return withoutCollectorInstance(BackupSubsystem)
}

// WithoutSnapshotsCollector Option
// removes the snapshots (ZFS boot environment) collector from the list of collectors
func WithoutSnapshotsCollector() Option {
	return withoutCollectorInstance(SnapshotsSubsystem)
}

// WithoutClamAVCollector Option
// removes the clamav collector from the list of collectors
func WithoutClamAVCollector() Option {
	return withoutCollectorInstance(ClamAVSubsystem)
}

// WithoutLLDPCollector Option
// removes the lldp (LLDP neighbor table) collector from the list of collectors
func WithoutLLDPCollector() Option {
	return withoutCollectorInstance(LLDPSubsystem)
}

// WithoutHardwareCollector Option
// removes the hardware collector from the list of collectors
func WithoutHardwareCollector() Option {
	return withoutCollectorInstance(HardwareSubsystem)
}

// WithoutVnstatCollector Option
// removes the vnstat collector from the list of collectors
func WithoutVnstatCollector() Option {
	return withoutCollectorInstance(VnstatSubsystem)
}

// WithoutNetbirdCollector Option
// removes the netbird collector from the list of collectors
func WithoutNetbirdCollector() Option {
	return withoutCollectorInstance(NetbirdSubsystem)
}

// WithoutBeatsCollector removes the Beats collector.
func WithoutBeatsCollector() Option { return withoutCollectorInstance(BeatsSubsystem) }

// WithoutCollectdCollector removes the collectd collector.
func WithoutCollectdCollector() Option { return withoutCollectorInstance(CollectdSubsystem) }

// WithoutMuninNodeCollector removes the Munin Node collector.
func WithoutMuninNodeCollector() Option { return withoutCollectorInstance(MuninNodeSubsystem) }

// WithoutNetSNMPCollector removes the Net-SNMP collector.
func WithoutNetSNMPCollector() Option { return withoutCollectorInstance(NetSNMPSubsystem) }

// WithoutNetdataCollector removes the Netdata collector.
func WithoutNetdataCollector() Option { return withoutCollectorInstance(NetdataSubsystem) }

// WithoutNodeExporterCollector removes the node_exporter collector.
func WithoutNodeExporterCollector() Option { return withoutCollectorInstance(NodeExporterSubsystem) }

// WithoutNRPECollector removes the NRPE collector.
func WithoutNRPECollector() Option { return withoutCollectorInstance(NRPESubsystem) }

// WithoutPuppetAgentCollector removes the Puppet Agent collector.
func WithoutPuppetAgentCollector() Option { return withoutCollectorInstance(PuppetAgentSubsystem) }

// WithoutQemuGuestAgentCollector removes the QEMU Guest Agent collector.
func WithoutQemuGuestAgentCollector() Option {
	return withoutCollectorInstance(QemuGuestAgentSubsystem)
}

// WithoutTelegrafCollector removes the Telegraf collector.
func WithoutTelegrafCollector() Option { return withoutCollectorInstance(TelegrafSubsystem) }

// WithoutWazuhAgentCollector removes the Wazuh Agent collector.
func WithoutWazuhAgentCollector() Option { return withoutCollectorInstance(WazuhAgentSubsystem) }

// WithoutZabbixAgentCollector removes the Zabbix Agent collector.
func WithoutZabbixAgentCollector() Option { return withoutCollectorInstance(ZabbixAgentSubsystem) }

// WithoutZabbixProxyCollector removes the Zabbix Proxy collector.
func WithoutZabbixProxyCollector() Option { return withoutCollectorInstance(ZabbixProxySubsystem) }

// WithoutZeroTierCollector removes the ZeroTier collector.
func WithoutZeroTierCollector() Option {
	return withoutCollectorInstance(ZeroTierSubsystem)
}

// WithoutTorCollector Option
// removes the tor collector from the list of collectors
func WithoutTorCollector() Option {
	return withoutCollectorInstance(TorSubsystem)
}

// WithoutFeatureAvailabilityCollector Option
// removes the feature-availability collector (#517) from the list of collectors
func WithoutFeatureAvailabilityCollector() Option {
	return withoutCollectorInstance(FeatureAvailabilitySubsystem)
}

// WithoutAuthCollector Option
// removes the auth collector from the list of collectors
func WithoutAuthCollector() Option {
	return withoutCollectorInstance(AuthSubsystem)
}

// WithoutHostDiscoveryCollector Option
// removes the hostdiscovery collector from the list of collectors
func WithoutHostDiscoveryCollector() Option {
	return withoutCollectorInstance(HostDiscoverySubsystem)
}

// WithoutRelaydCollector Option
// removes the relayd collector from the list of collectors
func WithoutRelaydCollector() Option {
	return withoutCollectorInstance(RelaydSubsystem)
}

// WithoutSiproxdCollector Option
// removes the siproxd (SIP registration count) collector from the list of collectors
func WithoutSiproxdCollector() Option {
	return withoutCollectorInstance(SiproxdSubsystem)
}

// WithoutLogEventsCollector Option
// removes the log_events collector (metrics derived from received syslog lines, #258).
// Disabling it also stops the syslog receiver deriving those metrics: main wires the
// receiver's MetricSink to nil when this collector is off.
func WithoutLogEventsCollector() Option {
	return withoutCollectorInstance(LogEventsSubsystem)
}

// WithoutFlowCollector Option
// removes the flow collector (byte/packet volume rolled up from flow records, #346).
// Disabling it also stops the receiver lanes deriving flow records at all: main
// leaves logship.Deps.FlowSink nil when this collector is off.
func WithoutFlowCollector() Option {
	return withoutCollectorInstance(FlowSubsystem)
}

// WithFirmwarePackageDetails enables per-package detail metrics for the
// firmware collector (pending package updates + installed plugin inventory).
func WithFirmwarePackageDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if fc, ok := c.(*firmwareCollector); ok {
				fc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithKeaDetails enables per-lease detail metrics for the kea collector
func WithKeaDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if kc, ok := c.(*keaCollector); ok {
				kc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithIPsecLeaseDetails enables per-lease detail metrics for the ipsec collector
func WithIPsecLeaseDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if ic, ok := c.(*ipsecCollector); ok {
				ic.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithFirewallRulesDetails enables per-rule detail metrics for the firewall rules collector
func WithFirewallRulesDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if frc, ok := c.(*firewallRulesCollector); ok {
				frc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithDhcpv4Details enables per-lease detail metrics for the dhcpv4 collector
func WithDhcpv4Details() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if dc, ok := c.(*dhcpv4Collector); ok {
				dc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithDnsmasqDetails enables per-lease detail metrics for the dnsmasq collector
func WithDnsmasqDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if dc, ok := c.(*dnsmasqCollector); ok {
				dc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithOpenVPNDetails enables per-session detail metrics for the OpenVPN collector
func WithOpenVPNDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if oc, ok := c.(*openVPNCollector); ok {
				oc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithUnboundInfra enables per-upstream infra cache RTT metrics for the
// unbound_dns collector
func WithUnboundInfra() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if uc, ok := c.(*unboundDNSCollector); ok {
				uc.SetInfraEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithUnboundQStats enables the DNSBL query-stats totals, blocklist size,
// and local-zone/data/insecure-domain rider metrics for the unbound_dns
// collector (#209).
func WithUnboundQStats() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if uc, ok := c.(*unboundDNSCollector); ok {
				uc.SetQStatsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithTailscalePeerDetails enables per-peer detail metrics for the tailscale collector
func WithTailscalePeerDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if tc, ok := c.(*tailscaleCollector); ok {
				tc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithNetbirdPeerDetails enables per-peer detail metrics for the netbird collector
func WithNetbirdPeerDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if nc, ok := c.(*netbirdCollector); ok {
				nc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithDhcpv6Details enables per-lease detail metrics for the dhcpv6 collector
func WithDhcpv6Details() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if dc, ok := c.(*dhcpv6Collector); ok {
				dc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithArpDetails enables per-entry ARP metrics (default-off; #125).
func WithArpDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if ac, ok := c.(*arpTableCollector); ok {
				ac.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithNdpDetails enables per-entry NDP metrics (default-off; #125).
func WithNdpDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if nc, ok := c.(*ndpCollector); ok {
				nc.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithAliasDetails enables per-table pf counter metrics for the alias collector
func WithAliasDetails() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if ac, ok := c.(*aliasCollector); ok {
				ac.SetDetailsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithFirewallNATCounts enables the opt-in NAT rule inventory count metric on
// the firewall collector (four extra GETs per scheduled poll; #221).
func WithFirewallNATCounts() Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if fc, ok := c.(*firewallCollector); ok {
				fc.SetNATCountsEnabled(true)
				return nil
			}
		}
		return nil
	}
}

// WithoutIDSCollector Option
// removes the ids collector from the list of collectors
func WithoutIDSCollector() Option {
	return withoutCollectorInstance(IDSSubsystem)
}

// WithIDSAlerts enables the opt-in Suricata recent-alerts series on the ids
// collector, counting alerts within the given lookback window from query_alerts
// (an extra reverse read of eve.json per scheduled poll).
func WithIDSAlerts(lookback time.Duration) Option {
	return func(o *Collector) error {
		for _, c := range o.collectors {
			if ic, ok := c.(*idsCollector); ok {
				ic.SetAlertsEnabled(true, lookback)
				return nil
			}
		}
		return nil
	}
}

// WithBuildInfo sets the exporter build version surfaced via
// opnsense_exporter_build_info.
func WithBuildInfo(version string) Option {
	return func(o *Collector) error {
		o.version = version
		return nil
	}
}

// SetObservedSeriesTotal records the most recent total collector-registry
// series count observed by metricsnap's Tee/TeeLane on a real scrape or OTLP
// export (#494), surfaced via opnsense_exporter_series on the next
// Collect. Safe to call concurrently with Collect(). Wired as
// metricsnap.SeriesBudget.Observed by main.go — this package never imports
// metricsnap, so the wiring lives at the composition root, not here.
func (c *Collector) SetObservedSeriesTotal(total int) {
	c.observedSeriesTotal.Store(int64(total))
}

// firewallIsHealthy reports whether the OPNsense firewall subsystem is healthy, tolerating
// both the legacy (<25.1) top-level string status and the 25.1+ metadata status. On 25.1+ a
// healthy box reports an OK overall system status and OMITS any per-Firewall entry (the
// subsystems list is empty), so an absent metadata firewall status must be treated as healthy
// — otherwise opnsense_firewall_status reads 0 on a perfectly healthy firewall. The metadata
// status may arrive as a JSON number (e.g. 2), a string ("OK"), or be absent.
func firewallIsHealthy(resp opnsense.HealthCheckResponse) bool {
	return resp.FirewallIsHealthy()
}

// deriveCollectorStates maps every registered collector subsystem name to whether
// it remains enabled (present in the enabled subset) for this exporter instance.
// It is a pure helper so the enable/disable accounting can be unit-tested without
// constructing a Collector (which registers metrics on the global registry).
func deriveCollectorStates(all, enabled []CollectorInstance) map[string]bool {
	enabledSet := make(map[string]bool, len(enabled))
	for _, c := range enabled {
		enabledSet[c.Name()] = true
	}
	states := make(map[string]bool, len(all))
	for _, c := range all {
		states[c.Name()] = enabledSet[c.Name()]
	}
	return states
}

// New creates a new Collector instance.
func New(client *opnsense.Client, log *slog.Logger, instanceName string, options ...Option) (*Collector, error) {
	// Snapshot the full registered set before any option removes collectors, and
	// give the Collector its own copy so the WithoutXCollector options never mutate
	// the package-global collectorInstances backing array.
	allCollectors := append([]CollectorInstance(nil), collectorInstances...)

	c := Collector{
		Client:        client,
		log:           log,
		instanceLabel: instanceName,
		collectors:    append([]CollectorInstance(nil), collectorInstances...),
		store:         newSnapshotStore(),
	}

	for _, option := range options {
		if err := option(&c); err != nil {
			return nil, errors.Join(err, fmt.Errorf("failed to apply collector option"))
		}
	}

	c.collectorStates = deriveCollectorStates(allCollectors, c.collectors)

	// Wire the availability collector's two out-of-band inputs here rather than in
	// main: collectorStates IS the authoritative per-subsystem enabled state, and
	// routeStatus is this Collector's own observation. Doing it in main meant a
	// hand-written subsystem-to-switch mapping that covered three of thirty
	// families and had to be extended by hand for each new one.
	SetFeatureEnabled(func(feature string) bool { return c.collectorStates[feature] })
	SetRouteObserved(c.RouteObserved)

	c.buildInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "build_info"),
		"Build information of opnsense2otel (value is always 1; see labels)",
		[]string{"version", "goversion", instanceLabelName},
		nil,
	)

	c.collectorEnabled = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_enabled"),
		"Whether a collector is enabled (1) or disabled (0) in this exporter instance, by subsystem",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.scrapeDuration = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "scrape_collector_duration_seconds"),
		"Duration of the latest scheduled sub-collector poll in seconds. The metric name retains its historical scrape_collector prefix for compatibility",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.scrapeSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "scrape_collector_success"),
		"Whether the latest scheduled sub-collector poll succeeded (1 = ok, 0 = error or panic). The metric name retains its historical scrape_collector prefix for compatibility",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.pollInterval = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_poll_interval_seconds"),
		"Configured poll interval of a collector in seconds (the internal poll scheduler runs each collector on its own interval; #336)",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.lastPollTs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_last_poll_timestamp_seconds"),
		"Unix timestamp of a collector's last poll ATTEMPT, successful or not; scheduler liveness, not data freshness — a collector failing every poll keeps advancing this while replaying old data. Use collector_snapshot_timestamp_seconds for data age. Absent until the collector has polled at least once (#336, #382)",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.nextPollTs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_next_poll_timestamp_seconds"),
		"Unix timestamp of a collector's next scheduled poll, read from the scheduler's actual fixed-cadence deadline (not derived from last poll + interval); absent when no poller is running for the collector (#336, #385)",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.snapshotTs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_snapshot_timestamp_seconds"),
		"Unix timestamp at which a collector's stored metric buffer was last REPLACED — the true age of the data a scrape replays. Advances on a successful poll and on a partial-error poll that still emitted data; does NOT advance when a failed poll emitted nothing and the last-good buffer was retained. Absent until the collector has stored data at least once (#382)",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.lastSuccessTs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_last_success_timestamp_seconds"),
		"Unix timestamp of a collector's last fully successful poll. Unlike collector_snapshot_timestamp_seconds this does NOT advance on a partial-error poll, so the two together distinguish 'refreshed but degraded' from 'fully healthy'. Absent until the collector has succeeded at least once (#382). A poll served from the API response cache is a successful poll and DOES advance this clock: the data behind it is as old as opnsense_exporter_api_cache_fetched_timestamp_seconds for the endpoints the collector reads, not as old as this timestamp.",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.apiCacheFetchedTs = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "api_cache_fetched_timestamp_seconds"),
		"Unix timestamp of the live firewall fetch that produced the response body the API response cache currently holds, by endpoint (api/* path). Present only while a success body is held under a configured TTL (--exporter.cache-ttl / --exporter.firmware-cache-ttl); a cached 404 and an uncached endpoint publish nothing. This is the clock that does NOT move when a poll is served from cache: time() minus this value is how stale the data behind a fresh-looking collector_last_success_timestamp_seconds can be, bounded by the endpoint's TTL. A firmware status body with an empty last_check is never cached, so it never appears here (OPN-0095).",
		[]string{"endpoint", instanceLabelName},
		nil,
	)

	c.seriesTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "series"),
		"Current number of Prometheus series produced by the COLLECTOR registry on the most recent real /metrics scrape or OTLP export (#494) — the same set --exporter.series-budget is compared against, and what metricsnap replays to the web UI's /cardinality report. Self-metrics on the separate self registry (process_*/go_*, the opnsense_exporter_otlp_* delivery-health family, and this gauge itself) are NOT included, so this reads lower than a full scrape's total series count; see --exporter.series-budget's flag help for the same caveat. This gauge is itself exactly one series, so it cannot meaningfully move the number it reports. Reads 0 before the first real scrape/export has completed.",
		[]string{instanceLabelName},
		nil,
	)

	for _, collector := range c.collectors {
		collector.Register(namespace, instanceName, c.log)
	}

	c.isUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "up",
		Help:      "Whether the OPNsense API was reachable on the last health poll (1 = reachable, 0 = unreachable), updated on --collector.poll-interval independently of scrapes. A reachable box reporting a degraded subsystem stays 1; see opnsense_system_status_code and the per-subsystem status metrics.",
		ConstLabels: prometheus.Labels{
			instanceLabelName: instanceName,
		},
	})

	c.firewallHealthStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "firewall_status",
		Help:      "Status of the firewall reported by the system health check (1 = ok, 0 = errors)",
		ConstLabels: prometheus.Labels{
			instanceLabelName: instanceName,
		},
	})

	c.crashReporterStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "crash_reporter_status",
		Help:      "Status of the crash reporter reported by the system health check (1 = ok/no crash reports, 0 = crash reports present)",
		ConstLabels: prometheus.Labels{
			instanceLabelName: instanceName,
		},
	})

	c.systemStatusCode = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "system_status_code",
		Help:      "Numeric OPNsense system status code from the health check (2 = OK, 1 = NOTICE, 0 = WARNING, -1 = ERROR; OPNsense >= 25.1)",
		ConstLabels: prometheus.Labels{
			instanceLabelName: instanceName,
		},
	})

	c.subsystemStatusCode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "system_subsystem_status_code",
		Help:      "Numeric OPNsense SystemStatusCode (2 = OK, 1 = NOTICE, 0 = WARNING, -1 = ERROR) for every health-check subsystem present in the response, by subsystem short name (e.g. diskspace, rootlock, crashreporter, firewall, plus any plugin-contributed key). OPNsense omits healthy subsystems from the report, so a subsystem's series is present only while it is unhealthy; absence should be read as healthy, the same convention as opnsense_firewall_status and opnsense_crash_reporter_status.",
		ConstLabels: prometheus.Labels{
			instanceLabelName: instanceName,
		},
	}, []string{"subsystem"})

	c.scrapes = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_scrapes_total",
		Help:      "Total number of times this exporter served a /metrics scrape. Since #336 a scrape replays the in-memory poll snapshot and makes no OPNsense API call, so this counts SERVING, not collection: it tracks how often Prometheus asked, never how often the firewall was polled. For polling use opnsense_exporter_collector_last_poll_timestamp_seconds and opnsense_exporter_api_requests_total.",
	}, []string{"opnsense_instance"})

	c.endpointErrors = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_endpoint_errors_total",
		Help:      "Total number of top-level sub-collector Update errors and recovered sub-collector panics. The endpoint label is normally an api/* path for a returned Update error, or 'panic:<collector>' for a recovered panic; tolerated secondary fetch failures are excluded and counted by opnsense_exporter_partial_fetch_failures_total.",
	}, []string{"endpoint", "opnsense_instance"})

	c.partialFetchFailures = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_partial_fetch_failures_total",
		Help:      "Total number of failed OPNsense API calls tolerated by a sub-collector while its scheduled poll otherwise succeeded, by collector. Plugin-absent 404s are excluded.",
	}, []string{"collector", "opnsense_instance"})

	c.apiRequests = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_api_requests_total",
		Help:      "Total number of OPNsense API requests made, by endpoint (api/* path) and HTTP response code (0 = no response, e.g. network error or context cancellation). Provides the denominator for a per-endpoint error rate alongside opnsense_exporter_endpoint_errors_total.",
	}, []string{"endpoint", "code", "opnsense_instance"})

	c.apiRequestDuration = *prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "exporter_api_request_duration_seconds",
		Help:      "Duration of individual OPNsense API requests in seconds, by endpoint (api/* path). Lets operators see which underlying endpoint call regressed when a collector's scheduled poll duration spikes.",
		Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15},
	}, []string{"endpoint", "opnsense_instance"})

	c.apiCacheHits = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_api_cache_hits_total",
		Help:      "Total number of OPNsense API calls served from the response cache instead of the firewall, by endpoint (api/* path) and kind. kind=\"body\" is a replayed payload from a slow-moving endpoint (--exporter.cache-ttl / --exporter.firmware-cache-ttl); kind=\"absent\" is a replayed 404 from a plugin-gated endpoint, meaning the plugin is not installed. Only endpoints with a configured TTL are counted, so this and opnsense_exporter_api_cache_misses_total form a hit rate for the cache itself.",
	}, []string{"endpoint", "kind", "opnsense_instance"})

	c.apiCacheMisses = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_api_cache_misses_total",
		Help:      "Total number of OPNsense API calls that went to the firewall and populated the response cache - a cold cache or an expired TTL. This is the denominator for a cache hit rate alongside opnsense_exporter_api_cache_hits_total. A call whose response was never cacheable is NOT counted: notably a 200 from a plugin-gated endpoint whose plugin IS installed, whose live payload is fetched on every scheduled poll by design (only its 404 would be cached).",
	}, []string{"endpoint", "opnsense_instance"})

	// isUp, scrapes and endpointErrors are exposed through this Collector's own
	// Describe/Collect (see Describe and collect), so they reach /metrics via the
	// registry the Collector is registered on. They are deliberately NOT registered
	// on the global default registry: doing so exposed them twice and made New
	// non-idempotent (a second New panicked on duplicate registration), which is
	// why several tests previously avoided calling New.
	c.scrapes.WithLabelValues(c.instanceLabel).Add(0)

	for _, path := range c.Client.Endpoints() {
		c.endpointErrors.WithLabelValues(string(path), c.instanceLabel).Add(0)
		// Pre-create the per-endpoint duration histogram (zero observations) so the
		// series exists before the first request, mirroring endpointErrors. The
		// api_requests counter is not pre-initialised — its `code` label is unknown
		// until a real response arrives.
		c.apiRequestDuration.WithLabelValues(string(path), c.instanceLabel)
	}
	for _, coll := range c.collectors {
		c.partialFetchFailures.WithLabelValues(coll.Name(), c.instanceLabel).Add(0)
	}

	// Install this Collector as the client's per-request observer so api_requests_total
	// / api_request_duration_seconds are recorded at the single request choke point.
	// &c is the pointer returned below, and the client is shared across every scheduled
	// poll (WithContext clones copy the observer field), so the wiring outlives New (#126).
	c.Client.SetRequestObserver(&c)

	// Likewise for the response cache: a cache hit issues no request, so it is invisible
	// to the request observer above (by design — that is what makes api_requests_total
	// drop when caching works). These counters make it visible directly.
	c.Client.SetCacheObserver(&c)
	return &c, nil
}

// ObserveAPIRequest implements opnsense.RequestObserver: it records one API call's
// count (by endpoint + HTTP code) and duration (by endpoint) into this Collector's
// self-metrics. Called from the client choke point on every request, concurrently
// across sub-collector goroutines — the prometheus vecs are safe for concurrent use.
func (c *Collector) ObserveAPIRequest(endpoint string, statusCode int, duration time.Duration) {
	c.apiRequests.WithLabelValues(endpoint, strconv.Itoa(statusCode), c.instanceLabel).Inc()
	c.apiRequestDuration.WithLabelValues(endpoint, c.instanceLabel).Observe(duration.Seconds())
	c.noteRouteStatus(endpoint, statusCode)
}

// noteRouteStatus records whether a route EXISTS, from a status code the client
// was going to report anyway.
//
// It is what lets the availability prober skip every endpoint an enabled
// collector already calls (#525). Only two codes say anything: 404 means the
// plugin is absent, and a 2xx means it is present. Everything else - a 500, an
// auth failure, a network error reported as 0 - says nothing about the route and
// must leave the previous verdict alone, or a firewall reboot would read as every
// plugin being uninstalled and then reinstalled.
func (c *Collector) noteRouteStatus(endpoint string, statusCode int) {
	var exists bool
	switch {
	case statusCode == http.StatusNotFound:
		exists = false
	case statusCode >= 200 && statusCode < 300:
		exists = true
	default:
		return
	}
	c.routeMu.Lock()
	// Created here rather than only in New: a Collector assembled as a struct
	// literal (several tests, and anything wiring observers before New finishes)
	// would otherwise panic writing to a nil map, on a path whose whole purpose is
	// to be a harmless side effect of a metric we were recording anyway.
	if c.routeStatus == nil {
		c.routeStatus = make(map[string]bool)
	}
	c.routeStatus[endpoint] = exists
	c.routeMu.Unlock()
}

// RouteObserved reports what the collectors' own traffic has established about an
// endpoint's route. The second return distinguishes "known to be absent" from
// "never called", which the prober must not conflate.
func (c *Collector) RouteObserved(name opnsense.EndpointName) (bool, bool) {
	path, ok := c.Client.EndpointPathFor(name)
	if !ok {
		return false, false
	}
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	exists, known := c.routeStatus[string(path)]
	return exists, known
}

// ObserveCacheHit implements opnsense.CacheObserver: it counts one API call served
// from the response cache, by endpoint and kind ("body" = replayed payload, "absent"
// = replayed 404 from an uninstalled plugin). Called from the client choke point,
// concurrently across sub-collector goroutines — the prometheus vecs are concurrency-safe.
func (c *Collector) ObserveCacheHit(endpoint, kind string) {
	c.apiCacheHits.WithLabelValues(endpoint, kind, c.instanceLabel).Inc()
	// A cache hit issues no request, so the request observer never sees it - but a
	// replayed 404 is still evidence the plugin is absent, and a replayed body is
	// still evidence the route exists.
	switch kind {
	case opnsense.CacheHitAbsent:
		c.noteRouteStatus(endpoint, http.StatusNotFound)
	case opnsense.CacheHitBody:
		c.noteRouteStatus(endpoint, http.StatusOK)
	}
}

// ObserveCacheMiss implements opnsense.CacheObserver: it counts one API call for a
// cacheable endpoint that had to go to the firewall (cold cache or expired TTL).
func (c *Collector) ObserveCacheMiss(endpoint string) {
	c.apiCacheMisses.WithLabelValues(endpoint, c.instanceLabel).Inc()
}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.scrapes.Describe(ch)
	c.endpointErrors.Describe(ch)
	c.partialFetchFailures.Describe(ch)
	c.apiRequests.Describe(ch)
	c.apiRequestDuration.Describe(ch)
	c.apiCacheHits.Describe(ch)
	c.apiCacheMisses.Describe(ch)
	ch <- c.apiCacheFetchedTs
	c.isUp.Describe(ch)
	ch <- c.buildInfo
	ch <- c.collectorEnabled
	ch <- c.scrapeDuration
	ch <- c.scrapeSuccess
	ch <- c.pollInterval
	ch <- c.lastPollTs
	ch <- c.nextPollTs
	ch <- c.snapshotTs
	ch <- c.lastSuccessTs
	if c.seriesTotal != nil {
		ch <- c.seriesTotal
	}

	for _, collector := range c.collectors {
		collector.Describe(ch)
	}
}

// collectExporterInfo emits the static exporter build/version metric and the
// per-collector enabled state, so dashboards can pin the running version and
// distinguish "collector disabled" from "feature absent / no data".
func (c *Collector) collectExporterInfo(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo, prometheus.GaugeValue, 1,
		c.version, runtime.Version(), c.instanceLabel,
	)
	for name, enabled := range c.collectorStates {
		value := 0.0
		if enabled {
			value = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.collectorEnabled, prometheus.GaugeValue, value,
			name, c.instanceLabel,
		)
	}
}

// boolToGauge maps a health predicate to the 1 (ok) / 0 (problem) gauge convention.
func boolToGauge(ok bool) float64 {
	if ok {
		return 1
	}
	return 0
}

// Collect implements the prometheus.Collector interface. Registry-driven
// callers such as the OTLP bridge replay the full snapshot; /metrics goes through
// ScrapeView instead. A deadline derived from the OTLP export interval remains a
// bound on the bridge gather itself. It does not bound or trigger any OPNsense API
// call.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()
	if c.otlpGatherTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.otlpGatherTimeout)
		defer cancel()
	}
	c.collect(ctx, ch, nil)
}

// collectAlwaysOn emits the cumulative exporter-meta metrics that every scrape path
// (normal replay, unreachable short-circuit) must surface so they stay present at
// their current values. The scrapes counter is incremented by the caller before this
// is called.
//
// #439 removed opnsense_exporter_scrape_skips_total from this set. It described
// scrapes skipped because a collection deadline expired before the collector lock
// could be acquired — a condition that stopped existing at #336, when serving became
// a lock-free replay of the poll snapshot. It had no increment site and could only
// ever read 0.
func (c *Collector) collectAlwaysOn(ch chan<- prometheus.Metric) {
	c.scrapes.Collect(ch)
	c.endpointErrors.Collect(ch)
	if c.partialFetchFailures.MetricVec != nil {
		c.partialFetchFailures.Collect(ch)
	}
	c.apiRequests.Collect(ch)
	c.apiRequestDuration.Collect(ch)
	c.apiCacheHits.Collect(ch)
	c.apiCacheMisses.Collect(ch)
	// Read from the cache's own snapshot rather than an observer callback: the
	// gauge must describe what is HELD now, and an entry that expired or was
	// evicted has no fetch time to report.
	for _, entry := range c.Client.CacheSnapshot() {
		// An expired entry lingers until the next get/put evicts it; nothing is
		// served from it, so it has no fetch time worth reporting.
		if entry.StatusCode < 200 || entry.StatusCode >= 300 || entry.StoredAt.IsZero() || entry.Remaining <= 0 {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.apiCacheFetchedTs, prometheus.GaugeValue, float64(entry.StoredAt.Unix()),
			entry.Path, c.instanceLabel,
		)
	}
	c.collectExporterInfo(ch)
	if c.seriesTotal != nil {
		ch <- prometheus.MustNewConstMetric(
			c.seriesTotal, prometheus.GaugeValue, float64(c.observedSeriesTotal.Load()),
			c.instanceLabel,
		)
	}
}

// collect serves one scrape by replaying the latest poll snapshot (#336). It makes
// NO API call: the poll scheduler (StartPolling) keeps the snapshot fresh on each
// collector's own interval, so serving is a pure memory read — no shared-mutex API
// hold, no scrape deadline. include==nil replays every enabled collector; a non-nil
// map (even an empty one) restricts the replay to the named sub-collectors. The
// health gauges and always-on exporter metrics are emitted regardless of filtering.
//
// The ctx parameter is retained for the scrapeView/OTLP call sites but is unused now
// that serving performs no cancellable work.
func (c *Collector) collect(_ context.Context, ch chan<- prometheus.Metric, include map[string]bool) {
	c.collectLane(ch, include, true)
}

// collectLane is collect() with explicit control over the always-on block, so the
// optional two-lane OTLP split (#390) can guarantee no series identity is emitted
// twice.
//
// alwaysOn covers the health gauges, the scrape counter and collectAlwaysOn. Those
// are emitted regardless of the include filter, which is correct for a /metrics
// scrape (a filtered scrape still wants to know the box is up) but would DUPLICATE
// every one of them across two concurrently-exporting OTLP readers. The fast lane
// therefore passes false and carries only its collectors' own series.
//
// Per-collector scheduler metrics (interval, the poll clocks, scrape meta) travel
// with their collector into whichever lane owns it, rather than being pinned to one
// lane. They are per-collector by definition, so following the collector keeps them
// at the same resolution as the data they describe, and each is still emitted
// exactly once across the two lanes.
func (c *Collector) collectLane(ch chan<- prometheus.Metric, include map[string]bool, alwaysOn bool) {
	if alwaysOn {
		c.emitHealth(ch)
	}

	for _, coll := range c.collectors {
		name := coll.Name()
		if include != nil && !include[name] {
			continue
		}
		e := c.store.entry(name)
		for _, m := range e.metrics {
			ch <- m
		}
		// The configured interval is known even before the first poll, so it is
		// always emitted (feeds the console's Interval column + next-run math). It
		// is the EFFECTIVE interval (#550) — what the scheduler ticks on after the
		// export-lane clamp — not the declared tier, which would claim a 15s cadence
		// for a collector actually polling at 60s.
		interval := c.effectiveInterval(coll)
		ch <- prometheus.MustNewConstMetric(
			c.pollInterval, prometheus.GaugeValue,
			interval.Seconds(), name, c.instanceLabel,
		)
		// Per-collector scrape meta + poll timestamps reflect the last poll and are
		// present once a collector has polled at least once (node_exporter's pattern).
		if e.polled {
			success := 0.0
			if e.lastOK {
				success = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.scrapeDuration, prometheus.GaugeValue,
				e.durationMs/1000.0, name, c.instanceLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.scrapeSuccess, prometheus.GaugeValue,
				success, name, c.instanceLabel,
			)
			ch <- prometheus.MustNewConstMetric(
				c.lastPollTs, prometheus.GaugeValue,
				float64(e.lastPoll.Unix()), name, c.instanceLabel,
			)
			// The data clocks are emitted only once they mean something (#382). A
			// collector that has never stored data, or never succeeded, gets NO
			// series rather than a zero — epoch 0 would render as "56 years stale"
			// on every freshness panel and poison any age aggregation.
			if !e.snapshotAt.IsZero() {
				ch <- prometheus.MustNewConstMetric(
					c.snapshotTs, prometheus.GaugeValue,
					float64(e.snapshotAt.Unix()), name, c.instanceLabel,
				)
			}
			if !e.lastSuccess.IsZero() {
				ch <- prometheus.MustNewConstMetric(
					c.lastSuccessTs, prometheus.GaugeValue,
					float64(e.lastSuccess.Unix()), name, c.instanceLabel,
				)
			}
		}
		// The next-poll deadline comes from the scheduler, not from arithmetic on
		// the last poll (#385). It is therefore absent whenever no poller is running
		// for this collector — during shutdown, or in a test that polls directly —
		// which is honest: there is no next poll to report.
		if !e.nextDeadline.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				c.nextPollTs, prometheus.GaugeValue,
				float64(e.nextDeadline.Unix()), name, c.instanceLabel,
			)
		}
	}

	if alwaysOn {
		c.scrapes.WithLabelValues(c.instanceLabel).Inc()
		c.collectAlwaysOn(ch)
	}
}

// FastCollectorNames returns the sorted names of the enabled collectors whose
// DECLARED poll interval is at most IntervalFast — the membership of the optional
// fast OTLP lane (#390). It resolves through resolveInterval, so an operator
// override moves a collector between lanes in either direction; membership is never
// read off the static tier table.
//
// Declared, deliberately (#550). The export-lane clamp in effectiveInterval reads
// this membership to pick a lane, so reading the clamped interval back here would
// close the loop and leave any intermediate --otlp.fast-export-interval with a
// configured-but-empty lane. See poll_lane.go.
func (c *Collector) FastCollectorNames() []string {
	names := make([]string, 0, len(c.collectors))
	for _, coll := range c.collectors {
		if c.resolveInterval(coll) <= IntervalFast {
			names = append(names, coll.Name())
		}
	}
	sort.Strings(names)
	return names
}

// laneView is a prometheus.Collector over a fixed subset of sub-collectors, used to
// build the two disjoint OTLP lanes. Unlike scrapeView it is long-lived (one per
// reader, not one per request) and controls the always-on block explicitly.
type laneView struct {
	c        *Collector
	include  map[string]bool
	alwaysOn bool
}

func (v *laneView) Describe(ch chan<- *prometheus.Desc) { v.c.Describe(ch) }
func (v *laneView) Collect(ch chan<- prometheus.Metric) {
	v.c.collectLane(ch, v.include, v.alwaysOn)
}

// OTLPFastView returns the fast OTLP lane: ONLY the fast-tier collectors, with the
// always-on and health block suppressed so it cannot collide with the base lane
// (#390). Membership is resolved once, at construction, so the two lanes cannot
// disagree mid-flight if the map were ever mutated.
func (c *Collector) OTLPFastView() prometheus.Collector {
	include := make(map[string]bool)
	for _, n := range c.FastCollectorNames() {
		include[n] = true
	}
	// alwaysOn is false: the health/self/always-on block belongs to the base lane
	// alone, or both readers would export the same series identity.
	return &laneView{c: c, include: include, alwaysOn: false}
}

// OTLPBaseView returns the base OTLP lane: every NON-fast collector plus the
// always-on, health and self metrics. It is the complement of OTLPFastView, so the
// two together emit exactly what the single unfiltered view emits today (#390).
func (c *Collector) OTLPBaseView() prometheus.Collector {
	fast := make(map[string]bool)
	for _, n := range c.FastCollectorNames() {
		fast[n] = true
	}
	include := make(map[string]bool)
	for _, coll := range c.collectors {
		if !fast[coll.Name()] {
			include[coll.Name()] = true
		}
	}
	return &laneView{c: c, include: include, alwaysOn: true}
}

// EnabledCollectorNames returns the sorted subsystem names of the
// sub-collectors enabled in this exporter instance — the valid values for the
// /metrics collect[]/exclude[] query parameters.
func (c *Collector) EnabledCollectorNames() []string {
	names := make([]string, 0, len(c.collectors))
	for _, coll := range c.collectors {
		names = append(names, coll.Name())
	}
	sort.Strings(names)
	return names
}

// scrapeView is a per-request prometheus.Collector adapter over the shared
// Collector. It carries the request-scoped context and the collect[]/exclude[]-
// derived include set. Nothing is re-registered or polled per request:
// sub-collector descriptors and snapshots already exist; the view only subsets
// snapshot replay. The view lives for exactly one request.
type scrapeView struct {
	c       *Collector
	ctx     context.Context
	include map[string]bool
}

func (v *scrapeView) Describe(ch chan<- *prometheus.Desc) { v.c.Describe(ch) }
func (v *scrapeView) Collect(ch chan<- prometheus.Metric) { v.c.collect(v.ctx, ch, v.include) }

// ScrapeView returns a single-request view of this collector bound to ctx and
// optionally filtered to the named sub-collectors (nil = all enabled).
func (c *Collector) ScrapeView(ctx context.Context, include map[string]bool) prometheus.Collector {
	return &scrapeView{c: c, ctx: ctx, include: include}
}
