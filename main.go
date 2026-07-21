package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/flow"
	"github.com/rknightion/opnsense-exporter/internal/flow/netflow"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/capture"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
	_ "github.com/rknightion/opnsense-exporter/internal/logship/syslog"   // registers the syslog push source
	_ "github.com/rknightion/opnsense-exporter/internal/logship/zenarmor" // registers the zenarmor push source
	"github.com/rknightion/opnsense-exporter/internal/metricsnap"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/internal/profiling"
	"github.com/rknightion/opnsense-exporter/internal/server"
	"github.com/rknightion/opnsense-exporter/internal/telemetry"
	"github.com/rknightion/opnsense-exporter/internal/webui"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

var version = ""

// collector.LogEvents is handed to the syslog receiver as its logship.MetricSink
// (#258). Assert the seam here so a signature drift on either side fails the build.
var _ logship.MetricSink = collector.LogEvents

// otlpShutdownTimeout bounds the final OTLP flush on graceful shutdown so a dead
// export endpoint cannot hang process exit.
const otlpShutdownTimeout = 10 * time.Second

// logsShutdownTimeout bounds the log pipeline drain (queue flush + sink flush) on
// graceful shutdown so a dead logs endpoint cannot hang process exit.
const logsShutdownTimeout = 10 * time.Second

// httpShutdownTimeout bounds the graceful HTTP drain on SIGTERM/SIGINT so an in-flight
// scrape can finish, while staying comfortably under Kubernetes' default 30s
// termination grace period so the container is never SIGKILLed mid-drain (#161).
const httpShutdownTimeout = 10 * time.Second

// flowDedupeEntries bounds the VLAN de-duplication table. Sized above the observed
// in-flight instance count on the reference box (9,657 duplicate instances across a
// whole capture, only a fraction ever concurrent) so the bound is memory insurance
// rather than something steady-state traffic pushes against — at capacity the
// oldest entry goes and a later duplicate is no longer suppressed.
const flowDedupeEntries = 20000

// ifIndexRefreshInterval rebuilds the NetFlow ifIndex map. Frequent because the
// mapping is positional: an interface added or removed renumbers everything.
const ifIndexRefreshInterval = 60 * time.Second

// readyCacheTTL caches /-/ready probe results (success and failure). 10s
// matches the default kubelet probe period, bounding upstream health calls to
// roughly one per probe period regardless of how many probers hit the
// endpoint, while keeping readiness staleness within a single probe cycle.
const readyCacheTTL = 10 * time.Second

// errSnapshotWarming is the readiness failure raised while the poll scheduler is
// still filling its first snapshot: the box is reachable, but a scrape now would
// return only the collectors that have already polled (#341).
var errSnapshotWarming = errors.New("poll scheduler is still warming: not every collector has completed its first poll")

// resolveInstanceLabel deterministically chooses the opnsense_instance label
// value (baked into every metric, the OTLP resource identity and Pyroscope
// tags). An explicit --exporter.instance-label always wins. Otherwise the
// configured address is used — unless useHostname is set, in which case the
// OPNsense hostname is looked up and, if unavailable, startup fails rather than
// silently falling back to the address (which would make the label depend on
// startup timing and differ across restarts). See #75.
func resolveInstanceLabel(explicit, addr string, useHostname bool, lookup func() (string, error), logger *slog.Logger) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if !useHostname {
		logger.Info("instance label not set; using configured OPNsense address", "instance", addr)
		return addr, nil
	}
	hostname, err := lookup()
	if err != nil {
		return "", fmt.Errorf("hostname lookup failed (set --exporter.instance-label explicitly, "+
			"or unset --exporter.instance-use-hostname to use the configured address %q): %w", addr, err)
	}
	if hostname == "" {
		return "", fmt.Errorf("OPNsense reported an empty hostname (set --exporter.instance-label explicitly)")
	}
	logger.Info("instance label not set; using OPNsense hostname", "instance", hostname)
	return hostname, nil
}

// collectorNames returns the name of every registered collector (enabled or
// not), so the web UI can show which collectors are disabled/skipped.
func collectorNames() []string {
	all := collector.AllCollectors()
	names := make([]string, 0, len(all))
	for _, c := range all {
		names = append(names, c.Name())
	}
	return names
}

func main() {
	// Register --version before flag parsing so `opnsense-exporter --version`
	// prints the ldflags-embedded version and exits — used by the publish/CI
	// smoke check to prove the built image embeds a real version (see #79).
	kingpin.Version(version)
	// Fail fast on settings retired by the syslog receiver (#248) BEFORE parsing.
	// kingpin rejects an unknown --flag on its own, but a retired ENV VAR would just
	// be read by nothing — the user would get an empty log stream and no explanation.
	if err := options.CheckRemovedFlagsFromProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
	options.Init()
	logger := promslog.New(options.PromLogConfig)

	logger.Info("starting opnsense-exporter", "version", version)

	opnsConfig, err := options.OPNSense()
	if err != nil {
		logger.Error("failed to assemble OPNsense configuration", "err", err)
		os.Exit(1)
	}

	opnsenseClient, err := opnsense.NewClient(
		*opnsConfig,
		version,
		logger,
	)
	if err != nil {
		logger.Error("opnsense client build failed", "err", err)
		os.Exit(1)
	}

	logger.Debug(fmt.Sprintf("OPNsense registered endpoints %s", opnsenseClient.Endpoints()))

	// Slow-moving endpoints are served from an in-memory cache rather than re-fetched
	// every scrape. Must happen before the client is cloned per scrape (WithContext):
	// clones share the cache, but only one that already exists.
	for endpoint, ttl := range options.CacheTTLs() {
		opnsenseClient.SetEndpointCacheTTL(opnsense.EndpointName(endpoint), ttl)
		logger.Debug("caching API endpoint responses", "endpoint", endpoint, "ttl", ttl)
	}

	// Remember that a plugin-gated endpoint is absent (404) instead of re-asking on
	// every scrape. Only the 404 is cached: where these endpoints do answer, their
	// payload is live data and still fetched every scrape.
	if absentTTL := options.AbsentCacheTTL(); absentTTL > 0 {
		for _, endpoint := range opnsense.PluginGatedEndpoints() {
			opnsenseClient.SetEndpointAbsentTTL(endpoint, absentTTL)
		}
		logger.Info("caching plugin-absent (404) endpoint responses",
			"endpoints", len(opnsense.PluginGatedEndpoints()), "ttl", absentTTL)
	}

	// selfMetricsRegistry holds exporter self-metrics (process_*, go_*). It is
	// gathered on every /metrics request alongside the per-request collector view.
	selfMetricsRegistry := prometheus.NewRegistry()

	if !*options.DisableExporterMetrics {
		selfMetricsRegistry.MustRegister(
			promcollectors.NewProcessCollector(promcollectors.ProcessCollectorOpts{}),
		)
		selfMetricsRegistry.MustRegister(promcollectors.NewGoCollector())
	}

	startTime := time.Now()
	// statusTracker retains per-collector run history (recorded from every scrape)
	// for the web UI status page; it is also updated by on-demand Run Now triggers.
	statusTracker := collector.NewStatusTracker()

	collectorsSwitches := options.CollectorsSwitches()
	collectorOptionFuncs := []collector.Option{
		collector.WithBuildInfo(version),
		collector.WithStatusTracker(statusTracker),
	}

	if !collectorsSwitches.Unbound {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutUnboundCollector())
		logger.Info("unbound collector disabled")
	}
	if !collectorsSwitches.Wireguard {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutWireguardCollector())
		logger.Info("wireguard collector disabled")
	}
	if !collectorsSwitches.IPsec {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutIPsecCollector())
		logger.Info("ipsec collector disabled")
	}
	if collectorsSwitches.IPsecLeaseDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithIPsecLeaseDetails())
		logger.Info("ipsec per-lease details enabled")
	}
	if !collectorsSwitches.Cron {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCronCollector())
		logger.Info("cron collector disabled")
	}
	if !collectorsSwitches.ARP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutArpTableCollector())
		logger.Info("arp collector disabled")
	}
	if !collectorsSwitches.Interfaces {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutInterfacesCollector())
		logger.Info("interfaces collector disabled")
	}
	if !collectorsSwitches.Protocol {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutProtocolCollector())
		logger.Info("protocol collector disabled")
	}
	if !collectorsSwitches.Services {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutServicesCollector())
		logger.Info("services collector disabled")
	}
	if !collectorsSwitches.LogEvents {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutLogEventsCollector())
		logger.Info("log_events collector disabled")
	}
	// Flow rollups (#346). Resolved and SIZED HERE, before collector.New and
	// therefore before StartPolling launches a poller per collector. ConfigureFlow
	// is safe to call at any time — it retunes under the accumulator's own mutex
	// rather than replacing it — but doing it before the pollers exist keeps the
	// ordering obviously correct as well as actually correct.
	flowCfg, ferr := options.Flow()
	if ferr != nil {
		logger.Error("invalid flow configuration", "err", ferr)
		os.Exit(1)
	}
	if !collectorsSwitches.Flow {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFlowCollector())
		logger.Info("flow collector disabled")
	} else if flowCfg.Enabled {
		collector.ConfigureFlow(flowCfg.TopN, flowCfg.MaxKeys)
		logger.Info("flow rollups enabled", "top_n", flowCfg.TopN, "max_keys", flowCfg.MaxKeys)
	}
	if !collectorsSwitches.Firewall {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirewallCollector())
		logger.Info("firewall collector disabled")
	}
	if collectorsSwitches.FirewallNATCounts {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFirewallNATCounts())
		logger.Info("firewall NAT rule inventory counts enabled")
	}
	if !collectorsSwitches.FirewallRules {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirewallRulesCollector())
		logger.Info("firewall rules collector disabled")
	}
	if !collectorsSwitches.Firmware {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirmwareCollector())
		logger.Info("firmware collector disabled")
	}
	if collectorsSwitches.FirmwarePackageDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFirmwarePackageDetails())
		logger.Info("firmware per-package details enabled")
	}
	if !collectorsSwitches.OpenVPN {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutOpenVPNCollector())
		logger.Info("openvpn collector disabled")
	}
	if !collectorsSwitches.Gateways {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutGatewaysCollector())
		logger.Info("gateways collector disabled")
	}
	if collectorsSwitches.OpenVPNDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithOpenVPNDetails())
		logger.Info("openvpn per-session details enabled")
	}
	if collectorsSwitches.UnboundInfra {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithUnboundInfra())
		logger.Info("unbound per-upstream infra cache metrics enabled")
	}
	if collectorsSwitches.UnboundQStats {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithUnboundQStats())
		logger.Info("unbound DNSBL query-stats totals and blocklist size metrics enabled")
	}
	if !collectorsSwitches.Dnsmasq {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDnsmasqCollector())
		logger.Info("dnsmasq collector disabled")
	}
	if !collectorsSwitches.System {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSystemCollector())
		logger.Info("system collector disabled")
	}
	if !collectorsSwitches.Temperature {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTemperatureCollector())
		logger.Info("temperature collector disabled")
	}
	if !collectorsSwitches.Mbuf {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutMbufCollector())
		logger.Info("mbuf collector disabled")
	}
	if !collectorsSwitches.NTP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNTPCollector())
		logger.Info("ntp collector disabled")
	}
	if !collectorsSwitches.Certificates {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCertificatesCollector())
		logger.Info("certificates collector disabled")
	}
	if collectorsSwitches.DnsmasqDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithDnsmasqDetails())
		logger.Info("dnsmasq per-lease details enabled")
	}
	if !collectorsSwitches.CARP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCARPCollector())
		logger.Info("carp collector disabled")
	}
	if !collectorsSwitches.Activity {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutActivityCollector())
		logger.Info("activity collector disabled")
	}
	if !collectorsSwitches.Kea {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutKeaCollector())
		logger.Info("kea collector disabled")
	}
	if collectorsSwitches.KeaDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithKeaDetails())
		logger.Info("kea per-lease details enabled")
	}
	if collectorsSwitches.FirewallRulesDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFirewallRulesDetails())
		logger.Info("firewall rules per-rule details enabled")
	}
	if !collectorsSwitches.NetworkDiagnostics {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetworkDiagnosticsCollector())
	} else {
		logger.Info("network diagnostics collector enabled")
	}
	if !collectorsSwitches.Netflow {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetflowCollector())
	} else {
		logger.Info("netflow collector enabled")
	}
	if !collectorsSwitches.PFStats {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutPFStatsCollector())
		logger.Info("pf stats collector disabled")
	}
	if !collectorsSwitches.NDP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNDPCollector())
		logger.Info("ndp collector disabled")
	}
	if !collectorsSwitches.Dhcpv4 {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDhcpv4Collector())
		logger.Info("dhcpv4 collector disabled")
	}
	if collectorsSwitches.Dhcpv4Details {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithDhcpv4Details())
		logger.Info("dhcpv4 per-lease details enabled")
	}
	if !collectorsSwitches.ACME {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutACMECollector())
		logger.Info("acme collector disabled")
	}
	if !collectorsSwitches.SMART {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSMARTCollector())
		logger.Info("smart collector disabled (opt-in via --exporter.enable-smart)")
	}
	if !collectorsSwitches.Tor {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTorCollector())
		logger.Info("tor collector disabled (opt-in via --exporter.enable-tor)")
	} else {
		logger.Info("tor collector enabled")
	}
	if !collectorsSwitches.DynDNS {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDynDNSCollector())
		logger.Info("dyndns collector disabled")
	}
	if !collectorsSwitches.Syslog {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSyslogCollector())
		logger.Info("syslog collector disabled")
	}
	if !collectorsSwitches.QFeeds {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutQFeedsCollector())
		logger.Info("qfeeds collector disabled")
	}
	if !collectorsSwitches.Tailscale {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTailscaleCollector())
		logger.Info("tailscale collector disabled")
	}
	if collectorsSwitches.TailscalePeerDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithTailscalePeerDetails())
		logger.Info("tailscale per-peer details enabled")
	}
	if !collectorsSwitches.Alias {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutAliasCollector())
		logger.Info("alias collector disabled")
	}
	if collectorsSwitches.AliasDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithAliasDetails())
		logger.Info("alias per-table details enabled")
	}
	if !collectorsSwitches.HAProxy {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHAProxyCollector())
		logger.Info("haproxy collector disabled")
	}
	if !collectorsSwitches.Nginx {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNginxCollector())
		logger.Info("nginx collector disabled")
	}
	if !collectorsSwitches.FRR {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFRRCollector())
		logger.Info("frr collector disabled")
	}
	if collectorsSwitches.FRRRoutes {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFRRRoutesEnabled())
		logger.Info("frr routing-state volume gauges enabled")
	}
	if !collectorsSwitches.Monit {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutMonitCollector())
		logger.Info("monit collector disabled")
	}
	if !collectorsSwitches.CrowdSec {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCrowdSecCollector())
		logger.Info("crowdsec collector disabled")
	}
	if !collectorsSwitches.NUT {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNUTCollector())
		logger.Info("nut collector disabled")
	}
	if !collectorsSwitches.Apcupsd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutApcupsdCollector())
		logger.Info("apcupsd collector disabled")
	}
	if !collectorsSwitches.CaptivePortal {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCaptivePortalCollector())
		logger.Info("captiveportal collector disabled")
	}
	if !collectorsSwitches.TrafficShaper {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTrafficShaperCollector())
		logger.Info("trafficshaper collector disabled")
	}
	if !collectorsSwitches.Hasync {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHasyncCollector())
		logger.Info("hasync collector disabled (opt-in via --exporter.enable-hasync)")
	}
	if !collectorsSwitches.Chrony {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutChronyCollector())
		logger.Info("chrony collector disabled")
	}
	if !collectorsSwitches.Dhcpv6 {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDhcpv6Collector())
		logger.Info("dhcpv6 collector disabled")
	}
	if collectorsSwitches.Dhcpv6Details {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithDhcpv6Details())
		logger.Info("dhcpv6 per-lease details enabled")
	}
	if collectorsSwitches.ArpDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithArpDetails())
		logger.Info("arp per-entry details enabled")
	}
	if collectorsSwitches.NdpDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithNdpDetails())
		logger.Info("ndp per-entry details enabled")
	}
	if !collectorsSwitches.BPF {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutBPFCollector())
		logger.Info("bpf collector disabled")
	}
	if !collectorsSwitches.Backup {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutBackupCollector())
		logger.Info("backup collector disabled")
	}
	if !collectorsSwitches.Snapshots {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSnapshotsCollector())
		logger.Info("snapshots collector disabled")
	}
	if !collectorsSwitches.ClamAV {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutClamAVCollector())
		logger.Info("clamav collector disabled")
	}
	if !collectorsSwitches.IDS {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutIDSCollector())
		logger.Info("ids collector disabled")
	}
	if collectorsSwitches.IDSAlerts {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithIDSAlerts(*options.IDSAlertLookback))
		logger.Info("ids recent-alerts enabled", "lookback", options.IDSAlertLookback.String())
	}
	if !collectorsSwitches.LLDPD {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutLLDPCollector())
		logger.Info("lldpd collector disabled")
	}
	if !collectorsSwitches.Hardware {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHardwareCollector())
		logger.Info("hardware collector disabled")
	}
	if !collectorsSwitches.Vnstat {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutVnstatCollector())
		logger.Info("vnstat collector disabled (opt-in via --exporter.enable-vnstat)")
	}
	if !collectorsSwitches.Netbird {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetbirdCollector())
		logger.Info("netbird collector disabled")
	}
	if collectorsSwitches.NetbirdDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithNetbirdPeerDetails())
		logger.Info("netbird per-peer details enabled")
	}
	if !collectorsSwitches.Auth {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutAuthCollector())
		logger.Info("auth collector disabled")
	}
	if !collectorsSwitches.HostDiscovery {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHostDiscoveryCollector())
		logger.Info("hostdiscovery collector disabled")
	}
	if !collectorsSwitches.Relayd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutRelaydCollector())
		logger.Info("relayd collector disabled")
	}
	if !collectorsSwitches.Siproxd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSiproxdCollector())
		logger.Info("siproxd collector disabled")
	}

	// Resolve the instance label deterministically (see #75). The label is baked
	// once into every metric, the OTLP resource identity and Pyroscope tags, so it
	// must not depend on startup timing or the box's momentary reachability — that
	// would split a deployment's series across restarts.
	instanceLabel, err := resolveInstanceLabel(
		*options.InstanceLabel, opnsConfig.Host, *options.InstanceUseHostname,
		func() (string, error) {
			hostname, hErr := opnsenseClient.FetchSystemHostname()
			if hErr != nil {
				return "", hErr
			}
			return hostname, nil
		}, logger)
	if err != nil {
		logger.Error("could not resolve instance label", "err", err)
		os.Exit(1)
	}

	// Continuous profiling is opt-in: enabled only when a Pyroscope server
	// address is configured. An invalid configuration is fatal; a transient
	// start failure is logged but non-fatal so the exporter keeps serving
	// metrics. A stopProfiling closure (rather than a *pyroscope.Profiler) keeps
	// the SDK out of main's imports.
	pyroCfg, pyroEnabled, err := options.Pyroscope()
	if err != nil {
		logger.Error("invalid pyroscope configuration", "err", err)
		os.Exit(1)
	}
	var stopProfiling func()
	if pyroEnabled {
		profiler, perr := profiling.Start(pyroCfg, instanceLabel, version, logger)
		if perr != nil {
			logger.Error("failed to start pyroscope profiling", "err", perr)
		} else {
			stopProfiling = func() {
				// Flush the final profiling window before stopping — profiler.Stop()
				// alone drops the in-progress heap/alloc/mutex/block window (#121).
				profiling.Stop(profiler, logger)
			}
			logger.Info(
				"pyroscope continuous profiling enabled",
				"server", pyroCfg.ServerAddress,
				"application", pyroCfg.ApplicationName,
				"mutex_block", !pyroCfg.DisableMutexBlock,
				"goroutine_leak", profiling.GoroutineLeakAvailable(),
			)
		}
	}

	// Assemble the OTLP config before building the collector so the OTLP export
	// interval can bound the OTLP-bridge gather path. An invalid configuration is fatal.
	otlpCfg, otlpEnabled, err := options.OTLP()
	if err != nil {
		logger.Error("invalid otlp configuration", "err", err)
		os.Exit(1)
	}

	// Bound no-deadline collections so a stalled firewall can't hold the shared collector
	// lock unbounded and black out every concurrent deadline-bound scrape (#128). The
	// OTLP gather uses the smaller of the export interval and max-scrape-duration.
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithMaxScrapeDuration(*options.MaxScrapeDuration))
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithPollInterval(*options.CollectorPollInterval))
	pollOverrides := make(map[string]time.Duration)
	for name, v := range *options.CollectorPollIntervalOverrides {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			logger.Error("invalid --collector.poll-interval-override", "collector", name, "value", v, "err", perr)
			os.Exit(1)
		}
		pollOverrides[name] = d
	}
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithPollIntervalOverrides(pollOverrides))
	if otlpEnabled {
		gatherTimeout := *options.MaxScrapeDuration
		if otlpCfg.ExportInterval > 0 && otlpCfg.ExportInterval < gatherTimeout {
			gatherTimeout = otlpCfg.ExportInterval
		}
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithOTLPGatherTimeout(gatherTimeout))
	}

	collectorInstance, err := collector.New(&opnsenseClient, logger, instanceLabel, collectorOptionFuncs...)
	if err != nil {
		logger.Error("failed to construct the collector", "err", err)
		os.Exit(1)
	}

	// collectorRegistry holds the default (unfiltered, no-deadline) view of the
	// collector. It is never served over HTTP — /metrics builds a per-request
	// ScrapeView — but the OTLP bridge gathers it on its own export interval.
	collectorRegistry := prometheus.NewRegistry()
	collectorRegistry.MustRegister(collectorInstance)

	// Start the internal poll scheduler (#336): each collector now polls the OPNsense
	// API on its own interval into an in-memory snapshot, decoupled from the Prometheus
	// scrape. /metrics (ScrapeView) and the OTLP bridge both replay that snapshot with
	// no live API call. StopPolling is invoked from gracefulShutdown.
	collectorInstance.StartPolling(context.Background())

	// metricsRecorder passively captures the collector family set of each real
	// scrape (the unfiltered /metrics path and the OTLP bridge) so the web UI can
	// read a last-scrape snapshot without ever gathering — and thus re-scraping
	// the firewall — itself.
	metricsRecorder := metricsnap.New()

	// OTLP metrics export is opt-in (--otlp.enabled). It pushes the exact metrics
	// exposed at /metrics to an OTLP endpoint via a Prometheus bridge producer over
	// the same registry, so names, labels and values stay in parity. A transient
	// start/export failure is logged but non-fatal so the exporter keeps serving
	// /metrics. A stopOTLP closure (rather than the MeterProvider) keeps the OTEL SDK
	// out of main's imports beyond Start. (otlpCfg/otlpEnabled were assembled above so
	// the export interval could bound the OTLP-bridge gather.)
	var stopOTLP func()
	if otlpEnabled {
		shutdown, terr := telemetry.Start(context.Background(), []prometheus.Gatherer{selfMetricsRegistry, metricsRecorder.Tee(collectorRegistry)}, otlpCfg, version, instanceLabel, logger)
		if terr != nil {
			logger.Error("failed to start otlp metrics export", "err", terr)
		} else {
			stopOTLP = func() {
				ctx, cancel := context.WithTimeout(context.Background(), otlpShutdownTimeout)
				defer cancel()
				if err := shutdown(ctx); err != nil {
					logger.Error("failed to flush final otlp export", "err", err)
				}
			}
			logger.Info(
				"otlp metrics export enabled",
				"endpoint", otlpCfg.Endpoint,
				"protocol", otlpCfg.Protocol,
				"interval", otlpCfg.ExportInterval.String(),
			)
		}
	}

	// Log shipping is opt-in (--logs.enabled) and fully independent of OTLP metrics
	// (--otlp.enabled): registered sources poll OPNsense event APIs on a background
	// loop and ship to Loki via OTLP logs (reusing the --otlp.* transport) or stdout.
	// It is long-lived, never a scrape-time collector. An invalid configuration is
	// fatal; a transient sink outage degrades to counted loss (never blocks /metrics).
	logsCfg, logsEnabled, err := options.Logs()
	if err != nil {
		logger.Error("invalid logs configuration", "err", err)
		os.Exit(1)
	}
	var stopLogs func()
	// logThroughput feeds the console's emitted-throughput chart. It stays nil unless
	// a log pipeline actually starts: this is a Prometheus PULL exporter, so with log
	// shipping off there is no emit boundary at all, and the console must draw nothing
	// rather than a flat 0/s that would read as "shipping nothing".
	var logThroughput func() (shipped, dropped uint64)
	// Declared before the log pipeline so its shutdown closure can capture it: the
	// NetFlow lane reads the same enrichment snapshot, so it must be stopped BEFORE
	// the refresher that feeds it.
	var stopNetflow func()

	// Log enrichment is shared by the log pipeline and the NetFlow lane, and is built
	// at most ONCE: both want the same snapshot of interface names, local subnets and
	// hostnames, and giving them a refresher each would double the API poll for
	// identical data. Built lazily because the common case wants neither.
	var enrichCache *enrich.Cache
	var enrichRefresher *enrich.Refresher
	var stopEnrich context.CancelFunc
	ensureEnrich := func() *enrich.Cache {
		if enrichCache != nil {
			return enrichCache
		}
		enrichCache = enrich.NewCache()
		enrichRefresher = enrich.NewRefresher(
			&opnsenseClient, enrichCache, enrich.NewMetrics(selfMetricsRegistry), logger)
		ectx, cancel := context.WithCancel(context.Background())
		stopEnrich = cancel
		go enrichRefresher.Run(ectx)
		logger.Info("api enrichment enabled",
			"lookups", "rule descriptions, interface names, hostnames, MACs, scope, services")
		return enrichCache
	}

	if logsEnabled {
		var logsTransport *options.OTLPConfig
		if logsCfg.Sink == "otlp" {
			// Resolve the OTLP transport WITHOUT the --otlp.enabled gate so logs can
			// ship even when metrics OTLP export is off. A resolution error (e.g. a
			// Grafana Cloud id without a token) names the offending --otlp.* flag.
			logsTransport, err = options.OTLPTransport()
			if err != nil {
				logger.Error("invalid otlp transport for logs sink", "err", err)
				os.Exit(1)
			}
		}
		// Log enrichment: a lock-free snapshot of OPNsense API data (firewall rule
		// descriptions, interface names, DHCP hostnames, MACs, local subnets) that the
		// syslog receiver reads per log line. The refresher owns the network I/O on its
		// own goroutine; the receiver never makes an API call on its read path.
		deps := logship.Deps{
			Client:     &opnsenseClient,
			Logger:     logger,
			Registerer: selfMetricsRegistry,
		}
		// Feed the log_events collector's running totals from the syslog receiver
		// (#258), unless the collector is disabled — in which case the receiver sees a
		// nil sink and skips derivation entirely.
		if collectorsSwitches.LogEvents {
			deps.MetricSink = collector.LogEvents
		}
		// Flow records are derived only when something consumes them: the collector is
		// on, the feature is on, and this lane is selected. A nil sink means the
		// Zenarmor lane skips building records entirely rather than building them for
		// nobody.
		if collectorsSwitches.Flow && flowCfg.Enabled && flowCfg.Zenarmor {
			deps.FlowSink = collector.Flow
		}
		// Debug-capture sink (#330): shared across receivers, constructed once when
		// --logs.debug-capture.dir is set. A per-receiver --logs.<recv>.debug-capture is
		// what actually routes signals into it; a receiver that did not opt in never
		// touches it. A construction failure (unwritable dir) is fatal — the operator
		// asked for capture and must know it is not happening.
		var debugCapturer *capture.Capturer
		if options.LogsDebugCaptureEnabled() {
			dc, cerr := capture.New(capture.Config{
				Dir:      options.LogsDebugCaptureDir(),
				MaxBytes: options.LogsDebugCaptureMaxBytes(),
			}, selfMetricsRegistry, logger)
			if cerr != nil {
				logger.Error("invalid debug-capture configuration", "err", cerr)
				os.Exit(1)
			}
			debugCapturer = dc
			deps.DebugCapture = dc
			logger.Info("debug capture enabled",
				"dir", options.LogsDebugCaptureDir(), "max_bytes", options.LogsDebugCaptureMaxBytes())
		}
		syslogCfg, syslogEnabled, serr := options.LogsSyslog()
		if serr != nil {
			logger.Error("invalid syslog receiver configuration", "err", serr)
			os.Exit(1)
		}
		// Sampling drops raw lines only after their metrics are derived, so it is
		// meaningless (pure data loss) with the log_events collector off.
		if syslogEnabled && syslogCfg.Sample && !collectorsSwitches.LogEvents {
			logger.Error("invalid syslog receiver configuration",
				"err", "--logs.syslog.sample requires the log_events collector; remove --exporter.disable-log-events")
			os.Exit(1)
		}
		// Enrichment is shared by every receiver that wants it, so the gate must ask
		// about all of them. It used to ask only about syslog — which meant a
		// zenarmor-only box got a nil Cache, fell back to a cold one, and missed EVERY
		// lookup forever with no error, no log and no metric, while
		// --logs.zenarmor.enrich defaulted to true and said otherwise.
		// LogsZenarmorEnrichWanted() is transport-independent (elasticsearch or
		// syslog), so zenarmor-over-syslog enrichment is already covered here too —
		// no extra branch needed.
		if (syslogEnabled && syslogCfg.Enrich) || options.LogsZenarmorEnrichWanted() {
			deps.Cache = ensureEnrich()
			deps.Miss = enrichRefresher.NoteMiss
		}

		stop, lerr := logship.Start(
			context.Background(), logsCfg, logsTransport,
			deps,
			version, instanceLabel, selfMetricsRegistry,
		)
		if lerr != nil {
			if stopEnrich != nil {
				stopEnrich()
			}
			logger.Error("failed to start log shipping", "err", lerr)
			os.Exit(1)
		}
		logThroughput = logship.Throughput
		stopLogs = func() {
			ctx, cancel := context.WithTimeout(context.Background(), logsShutdownTimeout)
			defer cancel()
			if err := stop(ctx); err != nil {
				logger.Error("failed to flush log pipeline on shutdown", "err", err)
			}
			// Stop the enrichment refresher only after the pipeline has drained: records
			// still in flight are enriched from the snapshot, and a refresher torn down
			// first would strand them. The NetFlow lane reads the same snapshot, so it
			// stops here too, ahead of the refresher.
			if stopNetflow != nil {
				stopNetflow()
			}
			if stopEnrich != nil {
				stopEnrich()
			}
			// Flush and stop the debug-capture writer last: it is fed from the receiver
			// goroutines the pipeline drain has just quiesced, so closing it now cannot
			// drop an in-flight capture.
			if debugCapturer != nil {
				_ = debugCapturer.Close()
			}
		}
	}

	// NetFlow receiver (#346 phase 2). Opt-in, and bound EAGERLY so a port already in
	// use is a startup error rather than a receiver that is silently never there.
	//
	// It shares the enrichment snapshot with the log pipeline but does not depend on
	// it: with log shipping off entirely this still runs, which is the "works
	// standalone with Zenarmor absent" requirement.
	if collectorsSwitches.Flow && flowCfg.Enabled && flowCfg.NetflowEnabled {
		cache := ensureEnrich()
		repairer := flow.NewRepairer(flowDedupeEntries)
		proc := flow.NewProcessor(collector.Flow, repairer, cache)
		decoder := netflow.New()

		listener := netflow.NewListener(netflow.ListenerConfig{
			Addr:         flowCfg.NetflowListen,
			AllowedPeers: flowCfg.NetflowAllowedPeers,
		}, decoder, func(dg *netflow.Datagram, _ netip.Addr) {
			proc.ObserveDatagram(dg, time.Now())
		}, logger)
		if lerr := listener.Start(); lerr != nil {
			logger.Error("failed to start netflow receiver", "err", lerr)
			os.Exit(1)
		}
		go listener.Serve()

		// Rebuild the ifIndex map on a ticker. ng_netflow numbers interfaces
		// POSITIONALLY over ifinfo output, so adding or removing any interface
		// renumbers every index and silently remaps historical series; a map that
		// stops refreshing is a correctness problem, not a staleness nuisance.
		nfCtx, cancelNetflow := context.WithCancel(context.Background())
		go func() {
			ticker := time.NewTicker(ifIndexRefreshInterval)
			defer ticker.Stop()
			for {
				if snap := cache.Load(); snap != nil {
					proc.SetIfMap(flow.BuildIfMap(snap.Ifaces, flowCfg.NetflowIfIndexMap, time.Now()))
				}
				select {
				case <-nfCtx.Done():
					return
				case <-ticker.C:
				}
			}
		}()

		collector.Flow.SetNetflowStats(func() collector.NetflowStats {
			var mapStats flow.IfMapStats
			var age time.Duration
			if m := proc.IfMap(); m != nil {
				mapStats = m.Stats()
				age = m.Age(time.Now())
			}
			return collector.NetflowStats{
				Listener: listener.Stats(),
				Decoder:  decoder.Stats(),
				Pipeline: proc.Stats(),
				Repair:   repairer.Stats(),
				IfMap:    mapStats,
				IfMapAge: age,
			}
		})

		stopNetflow = func() {
			cancelNetflow()
			_ = listener.Close()
		}
		// An empty allowlist is legitimate but it is a decision, not a default to
		// drift into: NetFlow has no authentication, so anything that can reach this
		// port can inject flow records and move every number on the dashboard.
		if len(flowCfg.NetflowAllowedPeers) == 0 {
			logger.Warn("netflow receiver accepts records from ANY peer",
				"addr", listener.Addr(),
				"fix", "restrict with --flow.netflow.allowed-peers or firewall the port")
		}
		logger.Info("netflow receiver listening",
			"addr", listener.Addr(), "allowed_peers", len(flowCfg.NetflowAllowedPeers))
	}

	// With log shipping off, the NetFlow lane owns the enrichment refresher's
	// lifetime, so it borrows the pipeline's shutdown slot rather than leaking both.
	if stopNetflow != nil && stopLogs == nil {
		stopLogs = func() {
			stopNetflow()
			if stopEnrich != nil {
				stopEnrich()
			}
		}
	}

	// Validate the metrics path before registering it: net/http.ServeMux panics on an
	// empty/invalid pattern, and also on a duplicate pattern — so a templated-blank or a
	// reserved (/-/healthy, /-/ready) --web.telemetry-path would crash the process with a
	// raw stack trace. Fail through the normal logged config-error path instead.
	if err := options.ValidateMetricsPath(*options.MetricsPath, server.HealthyPath, server.ReadyPath); err != nil {
		logger.Error("invalid metrics path", "err", err)
		os.Exit(1)
	}

	// Register on a private mux rather than http.DefaultServeMux: all exporter-owned
	// routes are then explicit and self-contained, so a future fixed route can't collide
	// with the global mux via some other package's init, and the collision surface stays
	// exactly the reserved set validated above.
	mux := http.NewServeMux()

	metricsHandler := server.NewMetricsHandler(
		collectorInstance,
		selfMetricsRegistry,
		*options.ScrapeTimeoutOffset,
		logger,
		metricsRecorder,
	)
	mux.Handle(*options.MetricsPath, metricsHandler)

	mux.Handle(server.HealthyPath, server.Healthy())
	mux.Handle(server.ReadyPath, server.NewReady(func(ctx context.Context) error {
		if _, err := opnsenseClient.WithContext(ctx).HealthCheck(); err != nil {
			return err
		}
		// Reachable is not the same as serving a complete snapshot: since #336 the
		// scrape replays whatever the poll scheduler has filled in, so a just-started
		// exporter answers /metrics with only the collectors that have polled so far.
		// Readiness holds until every collector has had its first poll (#341).
		if !collectorInstance.SnapshotWarm() {
			return errSnapshotWarming
		}
		return nil
	}, readyCacheTTL, logger))

	// The console (like the stock landing page) can only own "/" when the metrics
	// path is not itself "/", else mux.Handle("/", …) double-registers and panics.
	if *options.MetricsPath != "/" && *options.MetricsPath != "" {
		if *options.WebUIEnabled {
			webSrv := webui.NewServer(webui.Deps{
				Version:         version,
				GoVersion:       runtime.Version(),
				Host:            opnsConfig.Host,
				InstanceLabel:   instanceLabel,
				StartTime:       startTime,
				Tracker:         statusTracker,
				Metrics:         metricsRecorder.Snapshot,
				Cache:           opnsenseClient.CacheSnapshot,
				EffectiveConfig: options.EffectiveConfig,
				Devices: func(ctx context.Context) (webui.DeviceReport, error) {
					return webui.FetchDevices(ctx, &opnsenseClient)
				},
				LogThroughput:     logThroughput,
				AllCollectorNames: collectorNames(),
				RefreshSeconds:    int((*options.WebUIRefreshInterval).Seconds()),
				DisableConfig:     *options.WebUIDisableConfig,
				DisableDevices:    *options.WebUIDisableDevices,
			})
			webSrv.StartBackground()
			defer webSrv.Close()
			mux.Handle("/", webSrv.Handler())
		} else {
			landingConfig := web.LandingConfig{
				Name:        "OPNsense Exporter",
				Description: "Prometheus OPNsense Firewall Exporter",
				Version:     version,
				Links: []web.LandingLinks{
					{Address: *options.MetricsPath, Text: "Metrics"},
					{Address: server.HealthyPath, Text: "Healthy"},
					{Address: server.ReadyPath, Text: "Ready"},
				},
			}
			landingPage, err := web.NewLandingPage(landingConfig)
			if err != nil {
				logger.Error("failed to construct landing page", "err", err)
				os.Exit(1)
			}
			mux.Handle("/", landingPage)
		}
	}

	term := make(chan os.Signal, 1)
	srvClose := make(chan struct{})
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	// ReadHeaderTimeout protects the metrics port against Slowloris-style
	// connection exhaustion; IdleTimeout reaps abandoned keep-alive connections.
	// WriteTimeout stays unset so large scrape responses are never cut short.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		// srv.Shutdown makes ListenAndServe return http.ErrServerClosed — that's the
		// normal graceful-exit path, not an error, so don't treat it as a crash.
		if err := web.ListenAndServe(srv, options.WebConfig, logger); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error received from the HTTP server", "err", err)
			close(srvClose)
		}
	}()

	for {
		select {
		case sig := <-term:
			gracefulShutdown(srv, sig, collectorInstance.StopPolling, stopLogs, stopOTLP, stopProfiling, logger)
			return
		case <-srvClose:
			os.Exit(1)
		}
	}
}

// gracefulShutdown drains in-flight scrapes with a bounded deadline before flushing
// telemetry and returning, so a scrape landing mid-response during a rollout/redeploy
// finishes instead of being severed (which Prometheus records as up=0). The log line
// reports the actual signal received rather than a hardcoded "SIGTERM" (#161).
func gracefulShutdown(srv *http.Server, sig os.Signal, stopPolling, stopLogs, stopOTLP, stopProfiling func(), logger *slog.Logger) {
	logger.Info("received signal, shutting down gracefully", "signal", sig.String())
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful HTTP shutdown failed; in-flight scrapes may have been cut", "err", err)
	}
	// Order: drain HTTP -> stop the poll scheduler (no new firewall API calls) -> stop
	// log pollers + flush the sink -> flush OTLP metrics -> flush profiling. Logs drain
	// before OTLP metrics so a final scrape's data and the last log batch both leave
	// before the process exits.
	if stopPolling != nil {
		stopPolling()
	}
	if stopLogs != nil {
		stopLogs()
	}
	if stopOTLP != nil {
		stopOTLP()
	}
	if stopProfiling != nil {
		stopProfiling()
	}
}
