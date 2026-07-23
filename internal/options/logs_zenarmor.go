package options

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

// zenarmorFamilies is the complete set of Zenarmor reporting families, spelled the
// way Zenarmor spells them on the wire (its index names). Validation is strict
// against this set: a typo in --logs.zenarmor.families would otherwise silently
// ship nothing for that family, which looks exactly like a quiet network.
var zenarmorFamilies = map[string]bool{
	"conn": true, "dns": true, "tls": true, "http": true, "alert": true, "sip": true,
}

var (
	logsZenarmorEnabled = kingpin.Flag(
		"logs.zenarmor.enabled",
		"Enable the Zenarmor receiver: poses as an Elasticsearch node so Zenarmor can stream its "+
			"reporting data (connections, DNS, TLS, HTTP, threat alerts) to the exporter, which ships "+
			"it enriched over OTLP. Off by default. Requires --logs.enabled. Configure the firewall "+
			"under Configuration/Zenarmor > Settings > Streaming Data > 'Stream Reporting Data to "+
			"External Elasticsearch' — NOT the initial wizard's 'Remote Elasticsearch Database', which "+
			"replaces local reporting irreversibly.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENABLED").Default("false").Bool()

	// 9200 is the Elasticsearch convention and what Zenarmor's port field defaults
	// to. Nothing needs it to be 9200 — the receiver is not an Elasticsearch — but
	// matching the convention is one less field for an operator to get wrong.
	logsZenarmorListenHTTP = kingpin.Flag(
		"logs.zenarmor.listen-http",
		"Listen address for the Zenarmor receiver. Point Zenarmor's streaming URI at it.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_LISTEN_HTTP").Default(":9200").String()

	// The ingress is unauthenticated unless auth-user is set: anything that can reach
	// the port can inject arbitrary records into the observability stack.
	logsZenarmorAllowedPeers = kingpin.Flag(
		"logs.zenarmor.allowed-peers",
		"Comma-separated CIDR allowlist of hosts permitted to stream (e.g. 10.0.0.254/32). Empty "+
			"accepts any sender. The receiver is unauthenticated unless --logs.zenarmor.auth-user is "+
			"set, so set this on a shared network.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_ALLOWED_PEERS").Default("").String()

	// Cutting families here is defence in depth. The better place is Zenarmor's own
	// `indexes` setting: data cut at source never crosses the wire at all, and
	// connections alone are ~61% of the volume.
	logsZenarmorFamilies = kingpin.Flag(
		"logs.zenarmor.families",
		"Comma-separated Zenarmor families to ship (conn, dns, tls, http, alert, sip). Empty ships "+
			"all of them. Prefer restricting this at the Zenarmor end instead — data cut at source "+
			"never crosses the wire. Zenarmor streams ~2.5-3.3M records/day (~4-6 GB/day of JSON), "+
			"of which conn is ~61%.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_FAMILIES").Default("").String()

	// Default ON. Zenarmor inspects the link the receiver listens on, so it reports
	// the _bulk connection delivering its own records — measured at ~15% of all
	// volume on a live box, and 76% of the web family (#278). That is an artefact of
	// measuring rather than traffic, and logs_zenarmor_bulk_requests_total already
	// describes the same connection properly, so the default is to drop it.
	logsZenarmorDropSelfTraffic = kingpin.Flag(
		"logs.zenarmor.drop-self-traffic",
		"Drop records describing the exporter's own Elasticsearch ingest connection — Zenarmor "+
			"inspects the link the receiver listens on, so it reports the very connection "+
			"delivering its records (roughly 15% of all volume, and most of the http family). "+
			"Matched on the streaming peer's address plus the receiver's listen port, never the "+
			"destination address, which a containerised exporter cannot know. Set false to keep "+
			"them; drops are counted as logs_rejected_total{reason=\"self_traffic\"}.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_DROP_SELF_TRAFFIC").Default("true").Bool()

	// Repeatable, and default off: no implicit blind spots. Unlike --logs.syslog.sample
	// this is LOSSY in a way no counter makes up for — see the ExcludeRules doc in the
	// zenarmor package, and docs/zenarmor-receiver.md. Kingpin splits a cumulative
	// flag's env value on NEWLINE, not comma, so a regex containing a comma (a{1,3})
	// survives the env form intact.
	logsZenarmorExclude = kingpin.Flag(
		"logs.zenarmor.exclude",
		"Drop Zenarmor records whose FIELD matches REGEX, as FIELD=~REGEX (e.g. "+
			"'server_name=~.*\\.grafana\\.net'). Repeatable; default off. The field name is "+
			"validated at startup against the receiver's attribute vocabulary — a typo is a "+
			"startup error, never a silent no-op. Derived counters are observed BEFORE the drop, "+
			"so opnsense_log_events_zenarmor_total stays complete; drops are counted as "+
			"logs_rejected_total{reason=\"excluded\"} and logs_zenarmor_excluded_total{rule}. "+
			"EXCLUSION IS LOSSY: the derived counters carry no server_name, query or device_name, "+
			"so an excluded record's forensic detail is gone for good. Prefer a query-time filter "+
			"unless volume genuinely forces this. Set via env as one rule per LINE.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_EXCLUDE").Strings()

	logsZenarmorEnrich = kingpin.Flag(
		"logs.zenarmor.enrich",
		"Enrich received Zenarmor records from the OPNsense API: friendly interface names, "+
			"local/remote scope and well-known service names. Zenarmor resolves hostnames, MACs and "+
			"device identity itself, so this adds only what it does not already know.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENRICH").Default("true").Bool()

	logsZenarmorAuthUser = kingpin.Flag(
		"logs.zenarmor.auth-user",
		"Require HTTP basic auth on the Zenarmor receiver, with this username. Set the same "+
			"credentials in Zenarmor's streaming settings. Empty disables auth.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_AUTH_USER").Default("").String()

	logsZenarmorAuthPassword = kingpin.Flag(
		"logs.zenarmor.auth-password",
		"Password for --logs.zenarmor.auth-user.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_AUTH_PASSWORD").Default("").String()

	logsZenarmorMaxConcurrentRequests = kingpin.Flag(
		"logs.zenarmor.max-concurrent-requests",
		"Maximum bulk requests processed concurrently by the Zenarmor receiver. The per-request body "+
			"limit bounds one request; without this, N simultaneous requests each buffer that full allowance. "+
			"Excess requests are refused with 503 before a body is read. 0 disables the limit.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_MAX_CONCURRENT_REQUESTS").Default("8").Int()

	logsZenarmorTLSCertFile = kingpin.Flag(
		"logs.zenarmor.tls-cert-file",
		"PEM server certificate for the Zenarmor receiver. Set with --logs.zenarmor.tls-key-file to "+
			"serve HTTPS, and use an https:// URI in Zenarmor's streaming settings.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_TLS_CERT_FILE").Default("").String()

	logsZenarmorTLSKeyFile = kingpin.Flag(
		"logs.zenarmor.tls-key-file",
		"PEM private key for --logs.zenarmor.tls-cert-file.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_TLS_KEY_FILE").Default("").String()

	logsZenarmorDebugCapture = kingpin.Flag(
		"logs.zenarmor.debug-capture",
		"Dump Zenarmor signals this receiver does not model (unhandled Elasticsearch endpoints, "+
			"unknown families, documents that would not parse) to --logs.debug-capture.dir for "+
			"inspection. Requires --logs.debug-capture.dir. While on, the unhandled-endpoint warning "+
			"is suppressed — the capture file carries the same signal.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_DEBUG_CAPTURE").Default("false").Bool()

	logsZenarmorTransport = kingpin.Flag(
		"logs.zenarmor.transport",
		"How Zenarmor delivers its reporting data: 'elasticsearch' (default) runs the "+
			"built-in Elasticsearch receiver on --logs.zenarmor.listen-http; 'syslog' ingests "+
			"it through the shared syslog receiver (requires --logs.syslog.enabled and a "+
			"business-tier Zenarmor licence). families/exclude/enrich/drop-self-traffic apply "+
			"to either transport.",
	).Envar("OPNSENSE_EXPORTER_LOGS_ZENARMOR_TRANSPORT").Default("elasticsearch").Enum("elasticsearch", "syslog")
)

// ZenarmorConfig is the resolved Zenarmor receiver configuration. It mirrors
// zenarmor.Config field for field; the two are deliberately separate types so the
// receiver package does not import options for its own config.
type ZenarmorConfig struct {
	Addr         string
	AllowedPeers []netip.Prefix
	Families     []string // empty = all
	// Excludes are the raw --logs.zenarmor.exclude rules, exactly as written. They are
	// parsed, validated and compiled by the zenarmor package rather than here: the
	// field name is checked against that package's attribute vocabulary, which lives
	// next to the parser that produces it, and options cannot import zenarmor (zenarmor
	// imports options).
	Excludes        []string
	Enrich          bool
	AuthUser        string
	AuthPassword    string
	TLSConfig       *tls.Config
	DropSelfTraffic bool
	// MaxConcurrentRequests bounds simultaneous bulk handlers. The per-request body
	// limit is per request, so aggregate in-flight memory is otherwise unbounded.
	// Zero disables the limit.
	MaxConcurrentRequests int
	// DebugCapture opts this receiver into the shared debug-capture sink
	// (--logs.debug-capture.dir). Validated against that dir being set.
	DebugCapture bool
	// Warnings holds non-fatal startup advisories discovered while resolving this
	// config (#317) — e.g. an enabled receiver with no admission control at all. This
	// package has no logger and never fails the build for these, so it does not log
	// them itself; the caller (main) owns logging each entry after LogsZenarmor
	// returns, so an operator actually sees the gap instead of it being silent.
	Warnings []string
}

// LogsZenarmorEnabled reports whether the receiver is switched on, without
// resolving or validating the rest of the configuration. main uses it to decide
// whether enrichment is wanted before the full config is built.
func LogsZenarmorEnabled() bool { return *logsZenarmorEnabled }

// LogsZenarmorEnrichWanted reports whether an enabled receiver also wants
// enrichment. Kept separate from LogsZenarmor so main can answer "does anything
// need the enrichment refresher?" without ordering constraints on config building.
func LogsZenarmorEnrichWanted() bool { return *logsZenarmorEnabled && *logsZenarmorEnrich }

// LogsZenarmorTransport reports the configured transport, lowercased. An unset
// value (the zero value before kingpin applies the flag default) reads as the
// default "elasticsearch", so the accessor is correct whether or not Parse ran.
func LogsZenarmorTransport() string {
	v := strings.ToLower(strings.TrimSpace(*logsZenarmorTransport))
	if v == "" {
		return "elasticsearch"
	}
	return v
}

// LogsZenarmor resolves the receiver configuration, reporting (nil, false, nil)
// when it is disabled. Validation refuses ambiguity rather than guessing: a
// misconfigured receiver that silently ships nothing is indistinguishable from a
// firewall with nothing to say.
func LogsZenarmor() (*ZenarmorConfig, bool, error) {
	if !*logsZenarmorEnabled {
		return nil, false, nil
	}

	if LogsZenarmorTransport() == "syslog" && !LogsSyslogEnabled() {
		return nil, false, fmt.Errorf(
			"logs.zenarmor.transport=syslog needs the syslog receiver: set --logs.syslog.enabled " +
				"(the shared syslog listener is what receives Zenarmor's syslog stream)")
	}

	cfg := &ZenarmorConfig{
		Addr:            strings.TrimSpace(*logsZenarmorListenHTTP),
		Enrich:          *logsZenarmorEnrich,
		AuthUser:        strings.TrimSpace(*logsZenarmorAuthUser),
		AuthPassword:    *logsZenarmorAuthPassword,
		DropSelfTraffic: *logsZenarmorDropSelfTraffic,
		Excludes:        *logsZenarmorExclude,
		DebugCapture:    *logsZenarmorDebugCapture,

		MaxConcurrentRequests: *logsZenarmorMaxConcurrentRequests,
	}

	if cfg.MaxConcurrentRequests < 0 {
		return nil, false, fmt.Errorf(
			"logs.zenarmor: --logs.zenarmor.max-concurrent-requests must not be negative, got %d",
			cfg.MaxConcurrentRequests)
	}

	if cfg.DebugCapture && !LogsDebugCaptureEnabled() {
		return nil, false, fmt.Errorf(
			"logs.zenarmor: --logs.zenarmor.debug-capture needs a capture directory: set " +
				"--logs.debug-capture.dir (otherwise capture is on but writes nowhere)")
	}

	transport := LogsZenarmorTransport()
	switch transport {
	case "elasticsearch", "syslog":
		// Known transports. --logs.zenarmor.transport is a kingpin .Enum(), so a
		// flag-parsed value can never reach here as anything else; this default
		// case only matters to a test (or any other direct-var caller) that sets
		// the package var without going through flag parsing.
	default:
		return nil, false, fmt.Errorf(
			"logs.zenarmor.transport: unknown transport %q (valid: elasticsearch, syslog)", transport)
	}

	if transport == "elasticsearch" {
		if cfg.Addr == "" {
			return nil, false, fmt.Errorf(
				"logs.zenarmor: --logs.zenarmor.listen-http must be set when --logs.zenarmor.enabled is " +
					"set (otherwise nothing can be received)")
		}
	}

	families := splitList(*logsZenarmorFamilies)
	for _, f := range families {
		if !zenarmorFamilies[strings.ToLower(f)] {
			return nil, false, fmt.Errorf(
				"logs.zenarmor.families: unknown family %q (valid: conn, dns, tls, http, alert, sip)", f)
		}
	}
	cfg.Families = families

	peers, err := parseCIDRList(*logsZenarmorAllowedPeers)
	if err != nil {
		return nil, false, err
	}
	cfg.AllowedPeers = peers

	// Either both auth-user and auth-password must be set, or neither. Either
	// half-configured case is a configuration the operator plainly did not mean: a
	// password with no username reads as "auth on" but basic auth never activates; a
	// username with no password reads as "auth on" too, but the receiver's
	// constant-time comparison of an empty configured password against an empty
	// client-supplied one succeeds, so a client needs only the (non-secret) username
	// to get in (#314) — a real auth bypass, not merely misleading. Reject both.
	if (cfg.AuthUser == "") != (cfg.AuthPassword == "") {
		return nil, false, fmt.Errorf(
			"logs.zenarmor: --logs.zenarmor.auth-user and --logs.zenarmor.auth-password must both be " +
				"set, or both left empty; one without the other reads as auth-on but leaves the " +
				"receiver open to anyone who knows (or guesses) the one value that is set")
	}

	if transport == "elasticsearch" {
		certFile := strings.TrimSpace(*logsZenarmorTLSCertFile)
		keyFile := strings.TrimSpace(*logsZenarmorTLSKeyFile)
		switch {
		case certFile == "" && keyFile == "":
			// Plain HTTP: fine on a LAN-local link, which is the common case.
		case certFile == "" || keyFile == "":
			return nil, false, fmt.Errorf(
				"logs.zenarmor: --logs.zenarmor.tls-cert-file and --logs.zenarmor.tls-key-file must be " +
					"set together")
		default:
			pair, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, false, fmt.Errorf("logs.zenarmor: load TLS keypair: %w", err)
			}
			cfg.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{pair},
				MinVersion:   tls.VersionTLS12,
			}
		}
	}

	// #317: an enabled receiver with neither a peer allowlist nor authentication
	// accepts records from any reachable sender, which then become metrics and
	// shipped logs. This is a deliberate, documented open mode (trusted management
	// networks) so it is not fatal — but nothing else tells the operator at startup
	// that they are running it, so warn.
	if len(cfg.AllowedPeers) == 0 && cfg.AuthUser == "" && cfg.AuthPassword == "" {
		cfg.Warnings = append(cfg.Warnings,
			"logs.zenarmor: the receiver is enabled with no peer allowlist and no authentication, "+
				"so any host that can reach the listener can inject records that become metrics and "+
				"shipped logs; recommend setting --logs.zenarmor.allowed-peers or "+
				"--logs.zenarmor.auth-user/--logs.zenarmor.auth-password")
	}

	return cfg, true, nil
}
