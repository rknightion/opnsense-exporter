package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/internal/profiling"
	"github.com/rknightion/opnsense-exporter/internal/server"
	"github.com/rknightion/opnsense-exporter/internal/telemetry"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

var version = ""

// otlpShutdownTimeout bounds the final OTLP flush on graceful shutdown so a dead
// export endpoint cannot hang process exit.
const otlpShutdownTimeout = 10 * time.Second

// httpShutdownTimeout bounds the graceful HTTP drain on SIGTERM/SIGINT so an in-flight
// scrape can finish, while staying comfortably under Kubernetes' default 30s
// termination grace period so the container is never SIGKILLed mid-drain (#161).
const httpShutdownTimeout = 10 * time.Second

// readyCacheTTL caches /-/ready probe results (success and failure). 10s
// matches the default kubelet probe period, bounding upstream health calls to
// roughly one per probe period regardless of how many probers hit the
// endpoint, while keeping readiness staleness within a single probe cycle.
const readyCacheTTL = 10 * time.Second

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

func main() {
	// Register --version before flag parsing so `opnsense-exporter --version`
	// prints the ldflags-embedded version and exits — used by the publish/CI
	// smoke check to prove the built image embeds a real version (see #79).
	kingpin.Version(version)
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

	collectorsSwitches := options.CollectorsSwitches()
	collectorOptionFuncs := []collector.Option{
		collector.WithBuildInfo(version),
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
	if !collectorsSwitches.Firewall {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirewallCollector())
		logger.Info("firewall collector disabled")
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
				"mutex_block", pyroCfg.EnableMutexBlock,
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

	// OTLP metrics export is opt-in (--otlp.enabled). It pushes the exact metrics
	// exposed at /metrics to an OTLP endpoint via a Prometheus bridge producer over
	// the same registry, so names, labels and values stay in parity. A transient
	// start/export failure is logged but non-fatal so the exporter keeps serving
	// /metrics. A stopOTLP closure (rather than the MeterProvider) keeps the OTEL SDK
	// out of main's imports beyond Start. (otlpCfg/otlpEnabled were assembled above so
	// the export interval could bound the OTLP-bridge gather.)
	var stopOTLP func()
	if otlpEnabled {
		shutdown, terr := telemetry.Start(context.Background(), []prometheus.Gatherer{selfMetricsRegistry, collectorRegistry}, otlpCfg, version, instanceLabel, logger)
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

	// Validate the metrics path before registering it: net/http.ServeMux panics on an
	// empty/invalid pattern, so a templated-blank --web.telemetry-path would crash the
	// process with a raw stack trace. Fail through the normal logged config-error path.
	if err := options.ValidateMetricsPath(*options.MetricsPath); err != nil {
		logger.Error("invalid metrics path", "err", err)
		os.Exit(1)
	}

	metricsHandler := server.NewMetricsHandler(
		collectorInstance,
		selfMetricsRegistry,
		*options.ScrapeTimeoutOffset,
		logger,
	)
	http.Handle(*options.MetricsPath, metricsHandler)

	http.Handle("/-/healthy", server.Healthy())
	http.Handle("/-/ready", server.NewReady(func(ctx context.Context) error {
		if _, err := opnsenseClient.WithContext(ctx).HealthCheck(); err != nil {
			return err
		}
		return nil
	}, readyCacheTTL, logger))

	if *options.MetricsPath != "/" && *options.MetricsPath != "" {
		landingConfig := web.LandingConfig{
			Name:        "OPNsense Exporter",
			Description: "Prometheus OPNsense Firewall Exporter",
			Version:     version,
			Links: []web.LandingLinks{
				{
					Address: *options.MetricsPath,
					Text:    "Metrics",
				},
				{
					Address: "/-/healthy",
					Text:    "Healthy",
				},
				{
					Address: "/-/ready",
					Text:    "Ready",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			logger.Error("failed to construct landing page", "err", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	term := make(chan os.Signal, 1)
	srvClose := make(chan struct{})
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	// ReadHeaderTimeout protects the metrics port against Slowloris-style
	// connection exhaustion; IdleTimeout reaps abandoned keep-alive connections.
	// WriteTimeout stays unset so large scrape responses are never cut short.
	srv := &http.Server{
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
			gracefulShutdown(srv, sig, stopOTLP, stopProfiling, logger)
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
func gracefulShutdown(srv *http.Server, sig os.Signal, stopOTLP, stopProfiling func(), logger *slog.Logger) {
	logger.Info("received signal, shutting down gracefully", "signal", sig.String())
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful HTTP shutdown failed; in-flight scrapes may have been cut", "err", err)
	}
	if stopOTLP != nil {
		stopOTLP()
	}
	if stopProfiling != nil {
		stopProfiling()
	}
}
