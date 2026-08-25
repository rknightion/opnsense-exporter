package options

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

// The syslog receiver is a PUSH source: OPNsense forwards its logs to us (System ->
// Settings -> Logging -> Targets) instead of the exporter polling the API for them.
// It supersedes the old firewall/diaglog poll lanes, which spawned configd on the box
// and re-read log files the firewall would happily push.
//
// Off by default like every log source (see logs.go): --logs.enabled only starts the
// pipeline; a source must also opt in before anything ships.
var (
	logsSyslogEnabled = kingpin.Flag(
		"logs.syslog.enabled",
		"Enable the syslog receiver: listens for logs pushed by OPNsense (RFC5424 or RFC3164, "+
			"UDP and/or TCP) and ships them enriched with rule descriptions, interface names and "+
			"hostnames. Off by default. Requires --logs.enabled. Configure a matching target on the "+
			"firewall under System > Settings > Logging > Targets.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_ENABLED").Default("false").Bool()

	// 5514, not 514: 514 is a privileged port and the container runs as a non-root
	// user (distroless nonroot), so it cannot bind it.
	logsSyslogListenUDP = kingpin.Flag(
		"logs.syslog.listen-udp",
		"UDP listen address for the syslog receiver. Empty disables the UDP listener. "+
			"Port 5514 (not 514) because 514 is privileged and the container runs non-root.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_LISTEN_UDP").Default(":5514").String()

	logsSyslogListenTCP = kingpin.Flag(
		"logs.syslog.listen-tcp",
		"TCP listen address for the syslog receiver. Empty disables the TCP listener. "+
			"Prefer TCP for firewall logs: UDP datagram loss is silent and unrecoverable.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_LISTEN_TCP").Default(":5514").String()

	logsSyslogAllowPlaintextWithTLS = kingpin.Flag(
		"logs.syslog.allow-plaintext-with-tls",
		"Explicitly allow plaintext UDP/TCP listeners alongside TLS for a mixed-mode migration.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_ALLOW_PLAINTEXT_WITH_TLS").Default("false").Bool()

	// Syslog is UNAUTHENTICATED: anything that can reach the port can inject arbitrary
	// log records into the user's observability stack. On a shared network, restrict
	// senders to the firewall.
	logsSyslogAllowedPeers = kingpin.Flag(
		"logs.syslog.allowed-peers",
		"Comma-separated CIDR allowlist of hosts permitted to send syslog (e.g. "+
			"10.0.0.254/32). Empty accepts any sender. Syslog is unauthenticated, so set this "+
			"on a shared network.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_ALLOWED_PEERS").Default("").String()

	logsSyslogMaxConns = kingpin.Flag(
		"logs.syslog.max-conns",
		"Maximum concurrent connections to the syslog receiver, applied PER TRANSPORT: plain TCP and "+
			"TLS each get this budget from a separate pool. They are separate so a plaintext flood "+
			"cannot starve authenticated mTLS senders out of the capacity they need. Bounds goroutine "+
			"growth on an unauthenticated ingress; with both transports enabled the worst-case "+
			"connection count is twice this value.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_MAX_CONNS").Default("64").Int()

	// Filtering is OPT-IN. The receiver's contract is that nothing is silently
	// discarded; a user with no ingest limits would rather have the data than have
	// the exporter decide for them.
	logsSyslogExclude = kingpin.Flag(
		"logs.syslog.exclude-programs",
		"Comma-separated syslog programs to DROP (e.g. radvd,cron). Empty ships everything. "+
			"Dropped records are counted in opnsense_exporter_logs_rejected_total{reason=\"filtered\"} "+
			"- never silently discarded.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_EXCLUDE_PROGRAMS").Default("").String()

	logsSyslogInclude = kingpin.Flag(
		"logs.syslog.include-programs",
		"Comma-separated syslog programs to ship, dropping everything else. Empty ships "+
			"everything. Mutually exclusive with --logs.syslog.exclude-programs.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_INCLUDE_PROGRAMS").Default("").String()

	logsSyslogMinSeverity = kingpin.Flag(
		"logs.syslog.min-severity",
		"Drop records less severe than this (emerg, alert, crit, err, warning, notice, info, "+
			"debug). E.g. notice drops info and debug. Empty ships every severity.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_MIN_SEVERITY").Default("").String()

	logsSyslogEnrich = kingpin.Flag(
		"logs.syslog.enrich",
		"Enrich received syslog records from the OPNsense API: firewall rule descriptions "+
			"(including auto-generated system rules), friendly interface names, DHCP hostnames, "+
			"MAC addresses, local/remote scope and well-known service names.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_ENRICH").Default("true").Bool()

	// GeoIP on logs (#528) is the PER-LANE OPT-OUT --geoip.enabled's own help text
	// promises: turning --geoip.enabled on now covers filterlog, sshd/auth and
	// Suricata log lines too, not only flow records, and filterlog is the
	// highest-volume stream on the box -- see the geoip.enabled flag and
	// docs/geoip.md for why that upgrade behaviour is deliberate. Set this to false
	// to keep GeoIP on flow records while opting these log lines back out.
	logsSyslogGeoIP = kingpin.Flag(
		"logs.syslog.geoip",
		"Add GeoIP country/continent/ASN/as_org attributes (identical keys to the flow lane) to "+
			"filterlog, sshd/auth and Suricata log lines, for the remote peer's address. Needs no "+
			"database of its own: it reuses whatever --geoip.enabled already loaded. On by default "+
			"WHENEVER --geoip.enabled is set -- BEHAVIOUR CHANGE ON UPGRADE for any deployment "+
			"already running --geoip.enabled for flow records, since filterlog is the highest-volume "+
			"log stream on the box. Set to false to keep GeoIP on flow records only.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_GEOIP").Default("true").Bool()

	// Sampling is OPT-IN. Metric derivation (the log_events collector) is on by
	// default and additive; sampling is what actually DROPS raw lines, so it stays
	// off until asked. It requires the log_events collector so every dropped line was
	// counted first — main errors if --logs.syslog.sample is set with the collector off.
	logsSyslogSample = kingpin.Flag(
		"logs.syslog.sample",
		"Sample (drop) high-volume raw log lines AFTER their metrics have been derived: "+
			"keep firewall block/reject lines and drop passes, keep HAProxy state changes and "+
			"errors and drop the per-connection noise. Low-volume programs (sshd, dhcp, audit, "+
			"ids) are kept in full. Off by default. Requires the log_events collector "+
			"(exporter.disable-log-events must not be set) so every dropped line is counted first.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_SAMPLE").Default("false").Bool()

	logsSyslogSampledAttr = kingpin.Flag(
		"logs.syslog.sampled-attribute",
		"When sampling is on, stamp a sampled=\"true\" attribute on every shipped line so "+
			"consumers know the log stream is incomplete and must use the derived counters for "+
			"totals. On by default; only takes effect when --logs.syslog.sample is set.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_SAMPLED_ATTRIBUTE").Default("true").Bool()

	logsSyslogDebugCapture = kingpin.Flag(
		"logs.syslog.debug-capture",
		"Dump syslog lines this receiver cannot parse (unknown program, no matching parser, or an "+
			"unparseable envelope) to --logs.debug-capture.dir for inspection. Requires "+
			"--logs.debug-capture.dir. Additive - these lines still ship as generic records.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_DEBUG_CAPTURE").Default("false").Bool()

	// TLS is a third listener feeding the same handler. For most users the firewall
	// link is LAN-local and TLS is unnecessary; it matters when shipping across an
	// untrusted segment, and client-cert verification is the only real sender
	// authentication (the peer allowlist filters by IP, it does not authenticate).
	logsSyslogListenTLS = kingpin.Flag(
		"logs.syslog.listen-tls",
		"TLS listen address for the syslog receiver (RFC5424 over TLS, OPNsense tls4/tls6). "+
			"Empty disables the TLS listener. Requires --logs.syslog.tls-cert-file and "+
			"--logs.syslog.tls-key-file.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_LISTEN_TLS").Default("").String()

	logsSyslogTLSCertFile = kingpin.Flag(
		"logs.syslog.tls-cert-file",
		"PEM server certificate for the TLS syslog listener.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_TLS_CERT_FILE").Default("").String()

	logsSyslogTLSKeyFile = kingpin.Flag(
		"logs.syslog.tls-key-file",
		"PEM private key for the TLS syslog listener.",
	).Envar("OPN2OTEL_LOGS_SYSLOG_TLS_KEY_FILE").Default("").String()

	logsSyslogTLSClientCAFile = kingpin.Flag(
		"logs.syslog.tls-client-ca-file",
		"PEM CA bundle to verify sender client certificates on the TLS syslog listener. When "+
			"set, a sender MUST present a certificate signed by this CA - the only real sender "+
			"authentication syslog offers. Empty accepts any TLS client (encryption only).",
	).Envar("OPN2OTEL_LOGS_SYSLOG_TLS_CLIENT_CA_FILE").Default("").String()
)

// SyslogConfig is the resolved configuration for the syslog receiver.
type SyslogConfig struct {
	UDPAddr      string
	TCPAddr      string
	TLSAddr      string
	TLSConfig    *tls.Config
	AllowedPeers []netip.Prefix
	MaxConns     int
	Enrich       bool
	// GeoIP is the per-lane opt-out for --geoip.enabled on filterlog/sshd/Suricata
	// log lines (#528). Independent of Enrich: GeoIP reads a local MaxMind database,
	// never the OPNsense API, so it is not part of the API-enrichment toggle above.
	GeoIP           bool
	IncludePrograms []string
	ExcludePrograms []string
	MinSeverity     int
	HasMinSeverity  bool
	// Sample drops high-volume raw lines after their metrics are derived (#258).
	Sample bool
	// SampledAttr stamps sampled="true" on shipped lines while Sample is on.
	SampledAttr bool
	// DebugCapture opts this receiver into the shared debug-capture sink
	// (--logs.debug-capture.dir). Validated against that dir being set.
	DebugCapture bool
}

// severityNames maps RFC5424 severity keywords to their numeric level. LOWER IS
// WORSE (0 emerg … 7 debug), which is the opposite of most people's intuition and is
// why --logs.syslog.min-severity takes a name rather than a number.
var severityNames = map[string]int{
	"emerg": 0, "emergency": 0, "panic": 0,
	"alert": 1,
	"crit":  2, "critical": 2,
	"err": 3, "error": 3,
	"warning": 4, "warn": 4,
	"notice": 5,
	"info":   6, "informational": 6,
	"debug": 7,
}

// LogsSyslogEnabled reports whether the syslog receiver is enabled.
func LogsSyslogEnabled() bool {
	return *logsSyslogEnabled
}

// LogsSyslog assembles and validates the syslog receiver configuration. The
// returned bool reports whether the receiver is enabled.
func LogsSyslog() (*SyslogConfig, bool, error) {
	if !*logsSyslogEnabled {
		return nil, false, nil
	}
	cfg := &SyslogConfig{
		UDPAddr:      strings.TrimSpace(*logsSyslogListenUDP),
		TCPAddr:      strings.TrimSpace(*logsSyslogListenTCP),
		TLSAddr:      strings.TrimSpace(*logsSyslogListenTLS),
		MaxConns:     *logsSyslogMaxConns,
		Enrich:       *logsSyslogEnrich,
		GeoIP:        *logsSyslogGeoIP,
		Sample:       *logsSyslogSample,
		SampledAttr:  *logsSyslogSampledAttr,
		DebugCapture: *logsSyslogDebugCapture,
	}
	if cfg.TLSAddr != "" && (cfg.UDPAddr != "" || cfg.TCPAddr != "") && !*logsSyslogAllowPlaintextWithTLS {
		return nil, false, fmt.Errorf(
			"logs.syslog: TLS and plaintext listeners are both enabled; disable listen-udp/listen-tcp or set --logs.syslog.allow-plaintext-with-tls for an intentional migration")
	}

	if cfg.DebugCapture && !LogsDebugCaptureEnabled() {
		return nil, false, fmt.Errorf(
			"logs.syslog: --logs.syslog.debug-capture needs a capture directory: set " +
				"--logs.debug-capture.dir (otherwise capture is on but writes nowhere)")
	}
	tlsConfig, err := buildSyslogServerTLS(
		cfg.TLSAddr,
		strings.TrimSpace(*logsSyslogTLSCertFile),
		strings.TrimSpace(*logsSyslogTLSKeyFile),
		strings.TrimSpace(*logsSyslogTLSClientCAFile),
	)
	if err != nil {
		return nil, false, err
	}
	cfg.TLSConfig = tlsConfig
	if cfg.UDPAddr == "" && cfg.TCPAddr == "" && cfg.TLSAddr == "" {
		return nil, false, fmt.Errorf(
			"logs.syslog: at least one of --logs.syslog.listen-udp / --logs.syslog.listen-tcp / " +
				"--logs.syslog.listen-tls must be set when --logs.syslog.enabled is set (otherwise " +
				"nothing can be received)")
	}
	if cfg.MaxConns < 1 {
		return nil, false, fmt.Errorf("logs.syslog.max-conns must be positive, got %d", cfg.MaxConns)
	}
	peers, err := parseCIDRList(*logsSyslogAllowedPeers)
	if err != nil {
		return nil, false, err
	}
	cfg.AllowedPeers = peers

	cfg.IncludePrograms = splitList(*logsSyslogInclude)
	cfg.ExcludePrograms = splitList(*logsSyslogExclude)
	if len(cfg.IncludePrograms) > 0 && len(cfg.ExcludePrograms) > 0 {
		// Silently picking a precedence would leave the user with a log stream they
		// cannot explain. Make them say what they mean.
		return nil, false, fmt.Errorf(
			"logs.syslog: --logs.syslog.include-programs and --logs.syslog.exclude-programs " +
				"are mutually exclusive; set one or the other")
	}
	// The syslog receiver parses Suricata EVE alerts when the box forwards them
	// (the box's `syslog_eve` setting). The `ids` poll lane ships the SAME alerts from
	// the file-based eve.json. Running both means every alert lands in Loki TWICE,
	// with no dedupe -- and a duplicated security alert is worse than a missing one,
	// because it silently inflates every count anyone builds on it.
	//
	// We cannot detect from here whether the box actually has syslog_eve on, so we
	// refuse the ambiguous configuration rather than guess. The user picks a path.
	if LogsIDSEnabled() {
		return nil, false, fmt.Errorf(
			"logs.syslog + logs.ids: both the syslog receiver and the IDS poll lane are " +
				"enabled. If the box forwards Suricata EVE over syslog (the IDS 'syslog_eve' " +
				"setting), every alert would be shipped TWICE with no dedupe. Choose one: " +
				"drop --logs.ids.enabled and let the receiver take the alerts (push, lossless, " +
				"but alerts-only and payload-free), or keep --logs.ids.enabled and leave " +
				"syslog_eve off on the firewall")
	}

	if sev := strings.TrimSpace(strings.ToLower(*logsSyslogMinSeverity)); sev != "" {
		n, ok := severityNames[sev]
		if !ok {
			return nil, false, fmt.Errorf(
				"logs.syslog.min-severity: unknown severity %q (want one of: emerg, alert, "+
					"crit, err, warning, notice, info, debug)", sev)
		}
		cfg.MinSeverity = n
		cfg.HasMinSeverity = true
	}
	return cfg, true, nil
}

// buildSyslogServerTLS assembles the server-side *tls.Config for the TLS syslog
// listener, or returns (nil, nil) when TLS is not configured. It mirrors the
// client-side pattern in internal/telemetry but is a server config: the keypair is
// the receiver's own certificate, and a client-CA turns on mandatory client-cert
// verification (the only real sender authentication syslog offers).
func buildSyslogServerTLS(listenAddr, certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if listenAddr == "" {
		// No TLS listener. A stray cert/key/CA without a listener is a misconfiguration
		// the user should see, not a silent no-op.
		if certFile != "" || keyFile != "" || clientCAFile != "" {
			return nil, fmt.Errorf(
				"logs.syslog: --logs.syslog.tls-cert-file/tls-key-file/tls-client-ca-file set but " +
					"--logs.syslog.listen-tls is empty (no TLS listener to apply them to)")
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf(
			"logs.syslog: --logs.syslog.listen-tls requires both --logs.syslog.tls-cert-file " +
				"and --logs.syslog.tls-key-file")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("logs.syslog: load TLS keypair: %w", err)
	}
	tc := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAFile != "" {
		ca, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("logs.syslog: read tls-client-ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf(
				"logs.syslog: tls-client-ca-file %q contains no valid certificates", clientCAFile)
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

// splitList parses a comma-separated list, dropping empties and whitespace.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseCIDRList parses a comma-separated CIDR allowlist. A bare address (no /len)
// is accepted and treated as a single-host prefix, because "10.0.0.254" is what a
// user reaches for first and silently ignoring it would be worse than accepting it.
func parseCIDRList(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("logs.syslog.allowed-peers: invalid CIDR %q: %w", part, err)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("logs.syslog.allowed-peers: invalid CIDR or address %q: %w", part, err)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}
