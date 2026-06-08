package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

var version = ""

// instanceLabelLookupTimeout bounds the best-effort startup hostname lookup used
// to derive a default instance label, so an unreachable OPNsense box (which the
// API client would otherwise retry for up to ~45s) never delays startup.
const instanceLabelLookupTimeout = 5 * time.Second

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

	registry := prometheus.NewRegistry()

	if !*options.DisableExporterMetrics {
		registry.MustRegister(
			promcollectors.NewProcessCollector(promcollectors.ProcessCollectorOpts{}),
		)
		registry.MustRegister(promcollectors.NewGoCollector())
	}

	collectorsSwitches := options.CollectorsSwitches()
	collectorOptionFuncs := []collector.Option{}

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
	if !collectorsSwitches.OpenVPN {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutOpenVPNCollector())
		logger.Info("openvpn collector disabled")
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

	collectorInstance, err := collector.New(&opnsenseClient, logger, instanceLabel, collectorOptionFuncs...)
	if err != nil {
		logger.Error("failed to construct the collecotr", "err", err)
		os.Exit(1)
	}

	registry.MustRegister(collectorInstance)
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle(*options.MetricsPath, handler)

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

	srv := &http.Server{}
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
			os.Exit(0)
		case <-srvClose:
			os.Exit(1)
		}
	}
}
