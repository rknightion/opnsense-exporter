package options

import (
	"fmt"
	"net/netip"
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
	).Envar("OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED").Default("false").Bool()

	// 5514, not 514: 514 is a privileged port and the container runs as a non-root
	// user (distroless nonroot), so it cannot bind it.
	logsSyslogListenUDP = kingpin.Flag(
		"logs.syslog.listen-udp",
		"UDP listen address for the syslog receiver. Empty disables the UDP listener. "+
			"Port 5514 (not 514) because 514 is privileged and the container runs non-root.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_UDP").Default(":5514").String()

	logsSyslogListenTCP = kingpin.Flag(
		"logs.syslog.listen-tcp",
		"TCP listen address for the syslog receiver. Empty disables the TCP listener. "+
			"Prefer TCP for firewall logs: UDP datagram loss is silent and unrecoverable.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TCP").Default(":5514").String()

	// Syslog is UNAUTHENTICATED: anything that can reach the port can inject arbitrary
	// log records into the user's observability stack. On a shared network, restrict
	// senders to the firewall.
	logsSyslogAllowedPeers = kingpin.Flag(
		"logs.syslog.allowed-peers",
		"Comma-separated CIDR allowlist of hosts permitted to send syslog (e.g. "+
			"10.0.0.254/32). Empty accepts any sender. Syslog is unauthenticated, so set this "+
			"on a shared network.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SYSLOG_ALLOWED_PEERS").Default("").String()

	logsSyslogMaxConns = kingpin.Flag(
		"logs.syslog.max-conns",
		"Maximum concurrent TCP connections to the syslog receiver. Bounds goroutine "+
			"growth on an unauthenticated ingress.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SYSLOG_MAX_CONNS").Default("64").Int()

	logsSyslogEnrich = kingpin.Flag(
		"logs.syslog.enrich",
		"Enrich received syslog records from the OPNsense API: firewall rule descriptions "+
			"(including auto-generated system rules), friendly interface names, DHCP hostnames, "+
			"MAC addresses, local/remote scope and well-known service names.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SYSLOG_ENRICH").Default("true").Bool()
)

// SyslogConfig is the resolved configuration for the syslog receiver.
type SyslogConfig struct {
	UDPAddr      string
	TCPAddr      string
	AllowedPeers []netip.Prefix
	MaxConns     int
	Enrich       bool
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
		UDPAddr:  strings.TrimSpace(*logsSyslogListenUDP),
		TCPAddr:  strings.TrimSpace(*logsSyslogListenTCP),
		MaxConns: *logsSyslogMaxConns,
		Enrich:   *logsSyslogEnrich,
	}
	if cfg.UDPAddr == "" && cfg.TCPAddr == "" {
		return nil, false, fmt.Errorf(
			"logs.syslog: at least one of --logs.syslog.listen-udp / --logs.syslog.listen-tcp " +
				"must be set when --logs.syslog.enabled is set (otherwise nothing can be received)")
	}
	if cfg.MaxConns < 1 {
		return nil, false, fmt.Errorf("logs.syslog.max-conns must be positive, got %d", cfg.MaxConns)
	}
	peers, err := parseCIDRList(*logsSyslogAllowedPeers)
	if err != nil {
		return nil, false, err
	}
	cfg.AllowedPeers = peers
	return cfg, true, nil
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
