package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"sync"

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
	Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError
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

func (c *Collector) collectHealthMetrics(ch chan<- prometheus.Metric) error {
	systemStatus, err := c.Client.HealthCheck()
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

// Collect implements the prometheus.Collector interface.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := c.collectHealthMetrics(ch); err != nil {
		c.log.Error(
			"failed to fetch system health status; skipping other metrics",
			"err", err,
		)
	}

	var wg sync.WaitGroup
	wg.Add(len(c.collectors))

	for _, collector := range c.collectors {
		go func(coll CollectorInstance) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					c.log.Error(
						"panic in collector goroutine; skipping",
						"component", "collector",
						"collector_name", coll.Name(),
						"panic", fmt.Sprintf("%v", r),
					)
					c.endpointErrors.WithLabelValues(coll.Name(), c.instanceLabel).Inc()
				}
			}()
			if err := coll.Update(c.Client, ch); err != nil {
				c.log.Error(
					"failed to update",
					"component", "collector",
					"collector_name", coll.Name(),
					"err", err,
				)
				c.endpointErrors.WithLabelValues(err.Endpoint, c.instanceLabel).Inc()
			}
		}(collector)
	}
	wg.Wait()

	c.scrapes.WithLabelValues(c.instanceLabel).Inc()
	c.scrapes.Collect(ch)
	c.endpointErrors.Collect(ch)
	c.collectExporterInfo(ch)
}
