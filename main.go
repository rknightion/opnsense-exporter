package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

// instanceLabelLookupTimeout bounds the best-effort startup hostname lookup used
// to derive a default instance label, so an unreachable OPNsense box (which the
// API client would otherwise retry for up to ~45s) never delays startup.
const instanceLabelLookupTimeout = 5 * time.Second

// otlpShutdownTimeout bounds the final OTLP flush on graceful shutdown so a dead
// export endpoint cannot hang process exit.
const otlpShutdownTimeout = 10 * time.Second

// readyCacheTTL caches /-/ready probe results (success and failure). 10s
// matches the default kubelet probe period, bounding upstream health calls to
// roughly one per probe period regardless of how many probers hit the
// endpoint, while keeping readiness staleness within a single probe cycle.
const readyCacheTTL = 10 * time.Second

func main() {
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
		logger.Info("ipesc collector disabled")
	}
	if !collectorsSwitches.Cron {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCronCollector())
		logger.Info("cron collector disabled")
	}
	if !collectorsSwitches.ARP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutArpTableCollector())
		logger.Info("arp collector disabled")
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
		logger.Info("smart collector disabled")
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

	// Resolve the instance label. When the user does not set one, default to the
	// OPNsense hostname reported by the API so single-instance deployments work
	// out of the box, falling back to the configured address if the lookup fails.
	instanceLabel := *options.InstanceLabel
	if instanceLabel == "" {
		// Default to the configured address, then try to upgrade to the OPNsense
		// hostname. The lookup runs in a goroutine bounded by a short timeout so an
		// unreachable box never blocks startup; a late result is simply ignored.
		instanceLabel = opnsConfig.Host

		type hostnameResult struct {
			hostname string
			err      *opnsense.APICallError
		}
		resCh := make(chan hostnameResult, 1)
		go func() {
			hostname, hErr := opnsenseClient.FetchSystemHostname()
			resCh <- hostnameResult{hostname: hostname, err: hErr}
		}()

		select {
		case res := <-resCh:
			if res.err == nil && res.hostname != "" {
				instanceLabel = res.hostname
				logger.Info("instance label not set; using OPNsense hostname", "instance", instanceLabel)
			} else {
				logger.Warn(
					"instance label not set and hostname lookup failed; falling back to configured address",
					"instance", instanceLabel,
					"err", res.err,
				)
			}
		case <-time.After(instanceLabelLookupTimeout):
			logger.Warn(
				"instance label not set and hostname lookup timed out; falling back to configured address",
				"instance", instanceLabel,
				"timeout", instanceLabelLookupTimeout.String(),
			)
		}
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
				if err := profiler.Stop(); err != nil {
					logger.Error("failed to flush final pyroscope profile", "err", err)
				}
			}
			logger.Info(
				"pyroscope continuous profiling enabled",
				"server", pyroCfg.ServerAddress,
				"application", pyroCfg.ApplicationName,
				"mutex_block", pyroCfg.EnableMutexBlock,
			)
		}
	}

	collectorInstance, err := collector.New(&opnsenseClient, logger, instanceLabel, collectorOptionFuncs...)
	if err != nil {
		logger.Error("failed to construct the collecotr", "err", err)
		os.Exit(1)
	}

	// collectorRegistry holds the default (unfiltered, no-deadline) view of the
	// collector. It is never served over HTTP — /metrics builds a per-request
	// ScrapeView — but the OTLP bridge gathers it on its own export interval.
	collectorRegistry := prometheus.NewRegistry()
	collectorRegistry.MustRegister(collectorInstance)

	// OTLP metrics export is opt-in (--otlp.enabled). It pushes the exact metrics
	// exposed at /metrics to an OTLP endpoint via a Prometheus bridge producer over
	// the same registry, so names, labels and values stay in parity. An invalid
	// configuration is fatal; a transient start/export failure is logged but
	// non-fatal so the exporter keeps serving /metrics. A stopOTLP closure (rather
	// than the MeterProvider) keeps the OTEL SDK out of main's imports beyond Start.
	otlpCfg, otlpEnabled, err := options.OTLP()
	if err != nil {
		logger.Error("invalid otlp configuration", "err", err)
		os.Exit(1)
	}
	var stopOTLP func()
	if otlpEnabled {
		shutdown, terr := telemetry.Start(context.Background(), prometheus.Gatherers{selfMetricsRegistry, collectorRegistry}, otlpCfg, version, instanceLabel, logger)
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
		if err := web.ListenAndServe(srv, options.WebConfig, logger); err != nil {
			logger.Error("Error received from the HTTP server", "err", err)
			close(srvClose)
		}
	}()

	for {
		select {
		case <-term:
			logger.Info("Received SIGTERM, exiting gracefully...")
			if stopOTLP != nil {
				stopOTLP()
			}
			if stopProfiling != nil {
				stopProfiling()
			}
			os.Exit(0)
		case <-srvClose:
			os.Exit(1)
		}
	}
}
