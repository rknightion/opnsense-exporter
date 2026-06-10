package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// namespace is the prefix for all metrics.
const namespace = "opnsense"

// instanceLabelName is the label name for the current instance that is used
// to identify the instance in the metrics when there are
// multiple instances of the exporter running.
const instanceLabelName = "opnsense_instance"

const (
	ArpTableSubsystem      = "arp_table"
	GatewaysSubsystem      = "gateways"
	CronTableSubsystem     = "cron"
	WireguardSubsystem     = "wireguard"
	IPsecSubsystem         = "ipsec"
	UnboundDNSSubsystem    = "unbound_dns"
	InterfacesSubsystem    = "interfaces"
	ProtocolSubsystem      = "protocol"
	OpenVPNSubsystem       = "openvpn"
	ServicesSubsystem      = "services"
	FirewallSubsystem      = "firewall"
	FirmwareSubsystem      = "firmware"
	DnsmasqSubsystem       = "dnsmasq"
	SystemSubsystem        = "system"
	TemperatureSubsystem   = "temperature"
	FirewallRulesSubsystem = "firewall_rule"
	MbufSubsystem          = "mbuf"
	NTPSubsystem           = "ntp"
	CertificatesSubsystem  = "certificate"
	CARPSubsystem          = "carp"
	ActivitySubsystem      = "activity"
	KeaSubsystem           = "kea"
	Dhcpv4Subsystem        = "dhcpv4"
	NetworkDiagSubsystem   = "network_diag"
	NetflowSubsystem       = "netflow"
	PFStatsSubsystem       = "pf_stats"
	NDPSubsystem           = "ndp"
	ACMESubsystem          = "acme"
	SMARTSubsystem         = "smart"
	DynDNSSubsystem        = "dyndns"
	SyslogSubsystem        = "syslog"
	QFeedsSubsystem        = "qfeeds"
	TailscaleSubsystem     = "tailscale"
	AliasSubsystem         = "alias"
	HAProxySubsystem       = "haproxy"
	NginxSubsystem         = "nginx"
	FRRSubsystem           = "frr"
	MonitSubsystem         = "monit"
	CrowdSecSubsystem      = "crowdsec"
	NUTSubsystem           = "nut"
	ApcupsdSubsystem       = "apcupsd"
	CaptivePortalSubsystem = "captiveportal"
)

// SubsystemDisplayNames maps every collector subsystem to the human-readable
// name used in generated documentation. A unit test and scripts/docgen fail
// when a registered collector has no entry, so a new collector without a
// display name breaks the build instead of rendering a raw slug.
var SubsystemDisplayNames = map[string]string{
	ArpTableSubsystem:      "ARP Table",
	GatewaysSubsystem:      "Gateways",
	CronTableSubsystem:     "Cron",
	WireguardSubsystem:     "Wireguard",
	IPsecSubsystem:         "IPsec",
	UnboundDNSSubsystem:    "Unbound DNS",
	InterfacesSubsystem:    "Interfaces",
	ProtocolSubsystem:      "Protocol Statistics",
	OpenVPNSubsystem:       "OpenVPN",
	ServicesSubsystem:      "Services",
	FirewallSubsystem:      "Firewall",
	FirmwareSubsystem:      "Firmware",
	DnsmasqSubsystem:       "Dnsmasq DHCP",
	SystemSubsystem:        "System",
	TemperatureSubsystem:   "Temperature",
	FirewallRulesSubsystem: "Firewall Rules",
	MbufSubsystem:          "Mbuf",
	NTPSubsystem:           "NTP",
	CertificatesSubsystem:  "Certificates",
	CARPSubsystem:          "CARP",
	ActivitySubsystem:      "Activity",
	KeaSubsystem:           "Kea DHCP",
	Dhcpv4Subsystem:        "ISC DHCPv4",
	NetworkDiagSubsystem:   "Network Diagnostics",
	NetflowSubsystem:       "NetFlow",
	PFStatsSubsystem:       "PF Statistics",
	NDPSubsystem:           "NDP",
	ACMESubsystem:          "ACME Client",
	SMARTSubsystem:         "SMART Disk Health",
	DynDNSSubsystem:        "DynDNS",
	SyslogSubsystem:        "Syslog",
	QFeedsSubsystem:        "Q-Feeds",
	TailscaleSubsystem:     "Tailscale",
	AliasSubsystem:         "Firewall Aliases",
	HAProxySubsystem:       "HAProxy",
	NginxSubsystem:         "Nginx",
	FRRSubsystem:           "FRR Routing (BGP/OSPF/BFD)",
	MonitSubsystem:         "Monit",
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
	scrapes              prometheus.CounterVec
	endpointErrors       prometheus.CounterVec
	instanceLabel        string
	collectors           []CollectorInstance

	// version is the exporter build version, surfaced via opnsense_exporter_build_info.
	version string
	// collectorStates maps every registered collector subsystem name to whether it
	// is enabled in this exporter instance, surfaced via opnsense_exporter_collector_enabled.
	collectorStates  map[string]bool
	buildInfo        *prometheus.Desc
	collectorEnabled *prometheus.Desc
	// scrapeDuration / scrapeSuccess mirror node_exporter's per-collector
	// scrape instrumentation (node_scrape_collector_*), emitted as const
	// metrics around every sub-collector Update.
	scrapeDuration *prometheus.Desc
	scrapeSuccess  *prometheus.Desc
}

type Option func(*Collector) error

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

// WithoutNetflowCollector Option
// removes the netflow collector from the list of collectors
func WithoutNetflowCollector() Option {
	return withoutCollectorInstance(NetflowSubsystem)
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

// WithoutMonitCollector Option
// removes the monit collector from the list of collectors
func WithoutMonitCollector() Option {
	return withoutCollectorInstance(MonitSubsystem)
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

// WithBuildInfo sets the exporter build version surfaced via
// opnsense_exporter_build_info.
func WithBuildInfo(version string) Option {
	return func(o *Collector) error {
		o.version = version
		return nil
	}
}

// firewallIsHealthy reports whether the OPNsense firewall subsystem is healthy, tolerating
// both the legacy (<25.1) top-level string status and the 25.1+ metadata status. On 25.1+ a
// healthy box reports an OK overall system status and OMITS any per-Firewall entry (the
// subsystems list is empty), so an absent metadata firewall status must be treated as healthy
// — otherwise opnsense_firewall_status reads 0 on a perfectly healthy firewall. The metadata
// status may arrive as a JSON number (e.g. 2), a string ("OK"), or be absent.
func firewallIsHealthy(resp opnsense.HealthCheckResponse) bool {
	// Legacy format: explicit string status that is present and not "OK".
	if s := resp.Firewall.Status; s != "" && s != opnsense.HealthCheckStatusOK {
		return false
	}
	// 25.1+ metadata format: only flag unhealthy when a status is actually reported.
	switch s := resp.Metadata.Firewall.Status.(type) {
	case string:
		if s == "" || s == opnsense.HealthCheckStatusOK {
			// healthy
		} else if i, err := strconv.Atoi(s); err == nil {
			// OPNsense 25.1+ can return the numeric status as a string (e.g. "2").
			if i != opnsense.HealthCheckStatusOK_v25_1 {
				return false
			}
		} else {
			return false
		}
	case float64:
		if int(s) != opnsense.HealthCheckStatusOK_v25_1 {
			return false
		}
	case int:
		if s != opnsense.HealthCheckStatusOK_v25_1 {
			return false
		}
	}
	return true
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
	}

	for _, option := range options {
		if err := option(&c); err != nil {
			return nil, errors.Join(err, fmt.Errorf("failed to apply collector option"))
		}
	}

	c.collectorStates = deriveCollectorStates(allCollectors, c.collectors)

	c.buildInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "build_info"),
		"Build information of the opnsense exporter (value is always 1; see labels)",
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
		"Duration of a sub-collector scrape in seconds",
		[]string{"collector", instanceLabelName},
		nil,
	)

	c.scrapeSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "scrape_collector_success"),
		"Whether a sub-collector scrape succeeded (1 = ok, 0 = error or panic)",
		[]string{"collector", instanceLabelName},
		nil,
	)

	for _, collector := range c.collectors {
		collector.Register(namespace, instanceName, c.log)
	}

	c.isUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "up",
		Help:      "Was the last scrape of OPNsense successful. (1 = yes, 0 = no)",
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
		Help:      "Numeric system status code from health check (2 = OK for OPNsense >= 25.1)",
		ConstLabels: prometheus.Labels{
			instanceLabelName: instanceName,
		},
	})

	c.scrapes = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_scrapes_total",
		Help:      "Total number of times OPNsense was scraped for metrics.",
	}, []string{"opnsense_instance"})

	c.endpointErrors = *prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_endpoint_errors_total",
		Help:      "Total number of errors by endpoint returned by the OPNsense API during data fetching",
	}, []string{"endpoint", "opnsense_instance"})

	for _, metric := range []prometheus.Collector{c.isUp, c.scrapes, c.endpointErrors} {
		prometheus.MustRegister(metric)
	}

	c.scrapes.WithLabelValues(c.instanceLabel).Add(0)

	for _, path := range c.Client.Endpoints() {
		c.endpointErrors.WithLabelValues(string(path), c.instanceLabel).Add(0)
	}
	return &c, nil
}

// Describe implements the prometheus.Collector interface.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.scrapes.Describe(ch)
	c.endpointErrors.Describe(ch)
	c.isUp.Describe(ch)
	ch <- c.buildInfo
	ch <- c.collectorEnabled
	ch <- c.scrapeDuration
	ch <- c.scrapeSuccess

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

func (c *Collector) collectHealthMetrics(client *opnsense.Client, ch chan<- prometheus.Metric) error {
	systemStatus, err := client.HealthCheck()
	if err != nil {
		c.isUp.Set(0)
		c.systemStatusCode.Set(0)
		c.isUp.Collect(ch)
		c.systemStatusCode.Collect(ch)
		return err
	}

	c.systemStatusCode.Set(float64(systemStatus.GetMetadataSystemStatus()))

	// Crash reporter health: healthy by default, flagged 0 only if either the
	// top-level or metadata CrashReporter status is present and not OK. A valid
	// health response is required to populate this, so it is left absent on the
	// unreachable path above rather than emitting a misleading 0.
	crashHealthy := 1.0
	if s := systemStatus.CrashReporter.Status; s != "" && s != opnsense.HealthCheckStatusOK {
		crashHealthy = 0
	}
	if s := systemStatus.Metadata.CrashReporter.Status; s != "" && s != opnsense.HealthCheckStatusOK {
		crashHealthy = 0
	}
	c.crashReporterStatus.Set(crashHealthy)

	if systemStatus.System.Status != opnsense.HealthCheckStatusOK &&
		systemStatus.GetMetadataSystemStatus() != opnsense.HealthCheckStatusOK_v25_1 {
		c.isUp.Set(0)
		c.isUp.Collect(ch)
		c.systemStatusCode.Collect(ch)
		c.crashReporterStatus.Collect(ch)
		return nil
	}

	c.isUp.Set(1)
	c.firewallHealthStatus.Set(1)

	if !firewallIsHealthy(systemStatus) {
		c.firewallHealthStatus.Set(0)
	}

	c.isUp.Collect(ch)
	c.firewallHealthStatus.Collect(ch)
	c.crashReporterStatus.Collect(ch)
	c.systemStatusCode.Collect(ch)
	return nil
}

// execute runs one sub-collector Update, records duration/success around it,
// and shields the scrape from panics (node_exporter's per-collector pattern).
func (c *Collector) execute(ctx context.Context, coll CollectorInstance, client *opnsense.Client, ch chan<- prometheus.Metric) {
	begin := time.Now()
	success := 1.0
	defer func() {
		if r := recover(); r != nil {
			c.log.Error(
				"panic in collector goroutine; skipping",
				"component", "collector",
				"collector_name", coll.Name(),
				"panic", fmt.Sprintf("%v", r),
			)
			c.endpointErrors.WithLabelValues(coll.Name(), c.instanceLabel).Inc()
			success = 0
		}
		ch <- prometheus.MustNewConstMetric(
			c.scrapeDuration, prometheus.GaugeValue,
			time.Since(begin).Seconds(), coll.Name(), c.instanceLabel,
		)
		ch <- prometheus.MustNewConstMetric(
			c.scrapeSuccess, prometheus.GaugeValue,
			success, coll.Name(), c.instanceLabel,
		)
	}()

	if err := coll.Update(ctx, client, ch); err != nil {
		c.log.Error(
			"failed to update",
			"component", "collector",
			"collector_name", coll.Name(),
			"err", err,
		)
		c.endpointErrors.WithLabelValues(err.Endpoint, c.instanceLabel).Inc()
		success = 0
	}
}

// Collect implements the prometheus.Collector interface. Registry-driven
// callers with no HTTP request (e.g. the OTLP bridge) scrape everything with
// no deadline; /metrics goes through ScrapeView instead.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.collect(context.Background(), ch, nil)
}

// collect runs one scrape. include==nil selects every enabled collector; a
// non-nil map (even an empty one) restricts the fan-out to the named
// sub-collectors. The always-on metrics (up, health, build_info,
// collector_enabled, scrape counters) are emitted regardless of filtering.
func (c *Collector) collect(ctx context.Context, ch chan<- prometheus.Metric, include map[string]bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// A scrape queued behind a slow one can acquire the lock after its own
	// deadline expired. Fanning out every sub-collector against a dead context
	// would error every endpoint (endpoint_errors_total spike, success=0 across
	// the board — indistinguishable from a firewall outage), so emit only the
	// always-on exporter metrics and bail.
	if ctx.Err() != nil {
		c.log.Warn("scrape deadline expired before collection started; skipping sub-collectors", "err", ctx.Err())
		c.scrapes.WithLabelValues(c.instanceLabel).Inc()
		c.scrapes.Collect(ch)
		c.endpointErrors.Collect(ch)
		c.collectExporterInfo(ch)
		return
	}

	client := c.Client.WithContext(ctx)

	if err := c.collectHealthMetrics(client, ch); err != nil {
		c.log.Error(
			"failed to fetch system health status; skipping other metrics",
			"err", err,
		)
	}

	selected := c.selectedCollectors(include)

	var wg sync.WaitGroup
	wg.Add(len(selected))

	for _, collector := range selected {
		go func(coll CollectorInstance) {
			defer wg.Done()
			c.execute(ctx, coll, client, ch)
		}(collector)
	}
	wg.Wait()

	c.scrapes.WithLabelValues(c.instanceLabel).Inc()
	c.scrapes.Collect(ch)
	c.endpointErrors.Collect(ch)
	c.collectExporterInfo(ch)
}

// selectedCollectors returns the sub-collectors to run for this scrape.
func (c *Collector) selectedCollectors(include map[string]bool) []CollectorInstance {
	if include == nil {
		return c.collectors
	}
	selected := make([]CollectorInstance, 0, len(include))
	for _, coll := range c.collectors {
		if include[coll.Name()] {
			selected = append(selected, coll)
		}
	}
	return selected
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
// Collector. It carries the request-scoped context (scrape deadline) and the
// collect[]/exclude[]-derived include set. Nothing is re-registered per
// request: sub-collector descriptors were built once at startup (Register in
// New); the view only subsets the fan-out. Storing ctx in the struct is the
// http.Request.WithContext pattern — the view lives for exactly one request.
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
