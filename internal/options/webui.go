package options

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

// Web UI operator-console flags. Always-on by default (WebUIEnabled); the
// per-page kill switches (config/devices) exist because those pages surface
// more than the bare metrics a scrape would (redacted config, MAC/hostname
// device inventory) and an operator may want them off even though nothing on
// them is ever a raw secret.
var (
	WebUIEnabled = kingpin.Flag(
		"web.ui-enabled",
		"Serve the operator console at / (else the minimal landing page).",
	).Envar("OPN2OTEL_WEB_UI_ENABLED").Default("true").Bool()
	WebUIRefreshInterval = kingpin.Flag(
		"web.ui-refresh-interval",
		"Live-poll interval for the console's dynamic pages.",
	).Envar("OPN2OTEL_WEB_UI_REFRESH_INTERVAL").Default("5s").Duration()
	WebUIDisableConfig = kingpin.Flag(
		"web.ui-disable-config",
		"Hide the /config page.",
	).Envar("OPN2OTEL_WEB_UI_DISABLE_CONFIG").Default("false").Bool()
	WebUIDisableDevices = kingpin.Flag(
		"web.ui-disable-devices",
		"Hide the /devices page (exposes MAC/hostname).",
	).Envar("OPN2OTEL_WEB_UI_DISABLE_DEVICES").Default("false").Bool()
)

// ConfigSection groups related ConfigItem rows under a title for the /config
// operator-console page (e.g. "Connection", "Collectors").
type ConfigSection struct {
	Title string
	Items []ConfigItem
}

// ConfigItem is one rendered row of the effective-configuration view. Secret
// is true for anything derived from a credential; buildEffectiveConfig only
// ever produces a redacted or "unset" placeholder for those rows — never a
// real secret value — so a template bug can't leak one.
type ConfigItem struct {
	Key, Value string
	// Display is an optional human-friendly label for Key. It is set for
	// collector switches (a de-camelCased form of the Go field name) so the
	// config page can show both the raw field name and a readable version;
	// empty for rows whose Key is already readable.
	Display string
	Secret  bool
}

// redacted is the placeholder rendered for a secret field that IS set.
// unset is rendered for any field (secret or not) with no value.
const (
	redacted = "••••"
	unset    = "—"
)

// configInputs is the pure input to buildEffectiveConfig. This is the
// load-bearing structural guarantee behind "secrets never rendered" (Global
// Constraints): every secret-backed field here is a presence BOOLEAN (the
// *Set fields), never the resolved secret string. gatherConfigInputs is the
// only place allowed to look at a real secret value, and it does so only to
// compute `!= ""` — the string itself never crosses into this struct.
type configInputs struct {
	host, metricsPath, listen, instance, maxScrape string
	insecure                                       bool
	apiKeySet, apiSecretSet                        bool

	otlpEndpoint                string
	otlpEnabled, otlpHeadersSet bool

	pyroServer                                    string
	pyroEnabled, pyroAuthUserSet, pyroAuthPassSet bool

	collectors []ConfigItem // one {Key: <switch name>, Value: "on"/"off"} per collector switch

	// Annotations (#518): the exporter's only outbound write, so a preflight that
	// silently omits it cannot confirm whether a start will write to Grafana.
	annotationsEnabled     bool
	annotationsURL         string
	annotationsTokenSet    bool
	annotationsLookback    string
	annotationsInterval    string
	annotationsMaxPerCycle int

	// Log shipping (#518). All three push receivers (syslog, Zenarmor, NetFlow
	// below) are UNAUTHENTICATED by default, so whether a peer allowlist is
	// actually in effect is the security-relevant fact this summary must not
	// withhold — hence allowlist rows carry a prefix COUNT, not just on/off.
	logsEnabled bool
	logsSink    string

	syslogEnabled        bool
	syslogListen         string // combined "udp <addr>, tcp <addr>, tls <addr>"
	syslogTLS            bool
	syslogAllowlistCount int
	syslogDebugCapture   bool

	zenarmorEnabled        bool
	zenarmorListen         string
	zenarmorTLS            bool
	zenarmorAllowlistCount int
	zenarmorDebugCapture   bool

	// logsDebugCaptureDir is the ONE shared capture directory both receivers'
	// debug-capture switches write into (logs_debug_capture.go) - shown once at
	// the Log shipping level rather than duplicated per receiver.
	logsDebugCaptureDir string

	// Flow (#518).
	flowEnabled   bool
	flowCorrelate bool
	flowLogMode   string

	netflowEnabled        bool
	netflowListen         string
	netflowAllowlistCount int
	netflowDebugCapture   string // "off" | "unidentified" | "all"

	// GeoIP (#520). The database paths and whether anything is loaded are the two
	// facts an operator preflighting geo enrichment needs: a typo'd path is
	// fail-open, so without this row it looks identical to "enabled and working".
	// The license key is a credential and crosses as a presence boolean only.
	geoipEnabled          bool
	geoipCountryPath      string
	geoipASNPath          string
	geoipMetricDims       bool
	geoipDownloadEnabled  bool
	geoipDownloadEditions string
	geoipLicenseKeySet    bool
}

// boolStr renders a bool as the on/off vocabulary used across the config view.
func boolStr(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// secretItem renders a secret-backed row from a presence boolean only.
func secretItem(key string, set bool) ConfigItem {
	v := unset
	if set {
		v = redacted
	}
	return ConfigItem{Key: key, Value: v, Secret: true}
}

// plainItem renders a non-secret row, substituting the unset placeholder for
// a blank value so an empty field never renders as a confusing bare gap.
func plainItem(key, value string) ConfigItem {
	if value == "" {
		value = unset
	}
	return ConfigItem{Key: key, Value: value}
}

// allowlistItem renders a peer-allowlist row from a prefix COUNT, never the
// prefixes themselves: an operator preflighting an unauthenticated receiver
// (#518) needs to know an allowlist is actually in effect and how big it is,
// not have the row grow unboundedly with a long list.
func allowlistItem(key string, count int) ConfigItem {
	if count == 0 {
		return plainItem(key, "open (no allowlist)")
	}
	unit := "prefix"
	if count != 1 {
		unit = "prefixes"
	}
	return plainItem(key, fmt.Sprintf("set (%d %s)", count, unit))
}

// buildEffectiveConfig is the pure builder: it never touches a kingpin flag,
// an env var, or a secret-file lookup directly — everything it needs arrives
// pre-resolved (and, for secrets, pre-reduced to a presence boolean) in in.
// This is what TestBuildEffectiveConfig_SecretsRedacted exercises directly,
// without ever calling Init()/kingpin.Parse().
func buildEffectiveConfig(in configInputs) []ConfigSection {
	return []ConfigSection{
		{
			Title: "Connection",
			Items: []ConfigItem{
				plainItem("Host", in.host),
				secretItem("API Key", in.apiKeySet),
				secretItem("API Secret", in.apiSecretSet),
				plainItem("Insecure TLS", boolStr(in.insecure)),
			},
		},
		{
			Title: "Exporter / Server",
			Items: []ConfigItem{
				plainItem("Metrics Path", in.metricsPath),
				plainItem("Listen", in.listen),
				plainItem("Instance", in.instance),
				plainItem("Max Poll Duration", in.maxScrape),
			},
		},
		{
			Title: "Collectors",
			Items: in.collectors,
		},
		{
			Title: "Telemetry (OTLP)",
			Items: []ConfigItem{
				plainItem("Endpoint", in.otlpEndpoint),
				plainItem("Enabled", boolStr(in.otlpEnabled)),
				secretItem("Headers", in.otlpHeadersSet),
			},
		},
		{
			Title: "Pyroscope",
			Items: []ConfigItem{
				plainItem("Server", in.pyroServer),
				plainItem("Enabled", boolStr(in.pyroEnabled)),
				secretItem("Auth User", in.pyroAuthUserSet),
				secretItem("Auth Password", in.pyroAuthPassSet),
			},
		},
		{
			// #518: this is the exporter's only outbound write, so a preflight
			// that does not mention it cannot confirm whether a start will write
			// to Grafana, or which Grafana.
			Title: "Annotations",
			Items: []ConfigItem{
				plainItem("Enabled", boolStr(in.annotationsEnabled)),
				plainItem("Grafana URL", in.annotationsURL),
				secretItem("Token", in.annotationsTokenSet),
				plainItem("Lookback", in.annotationsLookback),
				plainItem("Interval", in.annotationsInterval),
				plainItem("Max Per Cycle", strconv.Itoa(in.annotationsMaxPerCycle)),
			},
		},
		{
			// #518: syslog and Zenarmor are both push receivers that open a
			// listening socket UNAUTHENTICATED by default, so allowlist/TLS state
			// is security-relevant, not cosmetic - a typo'd allowlist flag must
			// not read as "not configured" here.
			Title: "Log shipping",
			Items: []ConfigItem{
				plainItem("Enabled", boolStr(in.logsEnabled)),
				plainItem("Sink", in.logsSink),

				plainItem("Syslog Enabled", boolStr(in.syslogEnabled)),
				plainItem("Syslog Listen", in.syslogListen),
				allowlistItem("Syslog Allowed Peers", in.syslogAllowlistCount),
				plainItem("Syslog TLS", boolStr(in.syslogTLS)),
				plainItem("Syslog Debug Capture", boolStr(in.syslogDebugCapture)),

				plainItem("Zenarmor Enabled", boolStr(in.zenarmorEnabled)),
				plainItem("Zenarmor Listen", in.zenarmorListen),
				allowlistItem("Zenarmor Allowed Peers", in.zenarmorAllowlistCount),
				plainItem("Zenarmor TLS", boolStr(in.zenarmorTLS)),
				plainItem("Zenarmor Debug Capture", boolStr(in.zenarmorDebugCapture)),

				plainItem("Debug Capture Dir", in.logsDebugCaptureDir),
			},
		},
		{
			// #518: the NetFlow receiver is the same "unauthenticated listening
			// socket" shape as the log receivers above, so it gets the same
			// allowlist-count treatment.
			Title: "Flow",
			Items: []ConfigItem{
				plainItem("Enabled", boolStr(in.flowEnabled)),
				plainItem("Correlate", boolStr(in.flowCorrelate)),
				plainItem("Log Mode", in.flowLogMode),

				plainItem("NetFlow Enabled", boolStr(in.netflowEnabled)),
				plainItem("NetFlow Listen", in.netflowListen),
				allowlistItem("NetFlow Allowed Peers", in.netflowAllowlistCount),
				plainItem("NetFlow Debug Capture", in.netflowDebugCapture),
			},
		},
		{
			// #520: GeoIP enrichment is fail-open by design, so a database path that
			// is wrong, unwritable or simply not downloaded yet produces exactly the
			// same silence as a correctly configured one that has nothing to say.
			// These rows are how an operator tells those apart before going looking
			// for missing attributes in Loki.
			Title: "GeoIP",
			Items: []ConfigItem{
				plainItem("Enabled", boolStr(in.geoipEnabled)),
				plainItem("Country Database", in.geoipCountryPath),
				plainItem("ASN Database", in.geoipASNPath),
				plainItem("Metric Country Label", boolStr(in.geoipMetricDims)),
				plainItem("Download Enabled", boolStr(in.geoipDownloadEnabled)),
				plainItem("Download Editions", in.geoipDownloadEditions),
				secretItem("MaxMind License Key", in.geoipLicenseKeySet),
			},
		},
	}
}

// EffectiveConfig resolves the exporter's real, live configuration (reading
// flags/env/secret files) and redacts it through buildEffectiveConfig for the
// /config operator-console page. It is the only exported entry point; the
// pure builder above is what tests exercise so they never need Init().
func EffectiveConfig() []ConfigSection {
	return buildEffectiveConfig(gatherConfigInputs())
}

// gatherConfigInputs reads the real, already-registered package-level flag
// vars/accessors and reduces every secret to a presence boolean before it
// crosses into configInputs. Errors resolving a *_FILE secret (e.g. an
// unreadable file) are treated as "not set" here — this is a best-effort
// status view, not the startup validation path (OPNSenseConfig.Validate /
// Pyroscope / OTLP already own failing hard on a bad secret file).
func gatherConfigInputs() configInputs {
	apiKey, _ := opsAPIKey()
	apiSecret, _ := opsAPISecret()

	pyroUser, _ := resolveSecretMulti(*pyroscopeAuthUser,
		"OPN2OTEL_PYROSCOPE_AUTH_USER_FILE", "PYROSCOPE_AUTH_USER_FILE")
	pyroPass, _ := resolveSecretMulti(*pyroscopeAuthPassword,
		"OPN2OTEL_PYROSCOPE_AUTH_PASSWORD_FILE", "PYROSCOPE_AUTH_PASSWORD_FILE")
	pyroAddr := strings.TrimSpace(*pyroscopeServerAddress)

	annToken, _ := resolveSecret("OPN2OTEL_ANNOTATIONS_TOKEN_FILE", *annotationsToken)

	return configInputs{
		host:         strings.TrimSpace(*opnsenseAPI),
		metricsPath:  *MetricsPath,
		listen:       strings.Join(*WebConfig.WebListenAddresses, ", "),
		instance:     *InstanceLabel,
		maxScrape:    MaxScrapeDuration.String(),
		insecure:     *opnsenseInsecure,
		apiKeySet:    apiKey != "",
		apiSecretSet: apiSecret != "",

		otlpEndpoint:   *otlpEndpoint,
		otlpEnabled:    *otlpEnabled,
		otlpHeadersSet: strings.TrimSpace(*otlpHeaders) != "",

		pyroServer:      pyroAddr,
		pyroEnabled:     pyroAddr != "",
		pyroAuthUserSet: strings.TrimSpace(pyroUser) != "",
		pyroAuthPassSet: strings.TrimSpace(pyroPass) != "",

		collectors: collectorConfigItems(),

		annotationsEnabled:     *annotationsEnabled,
		annotationsURL:         strings.TrimSpace(*annotationsGrafanaURL),
		annotationsTokenSet:    strings.TrimSpace(annToken) != "",
		annotationsLookback:    annotationsLookback.String(),
		annotationsInterval:    annotationsInterval.String(),
		annotationsMaxPerCycle: *annotationsMaxPerCycle,

		logsEnabled: *logsEnabled,
		logsSink:    *logsSink,

		syslogEnabled: *logsSyslogEnabled,
		syslogListen: syslogListenSummary(
			strings.TrimSpace(*logsSyslogListenUDP),
			strings.TrimSpace(*logsSyslogListenTCP),
			strings.TrimSpace(*logsSyslogListenTLS),
		),
		syslogTLS:            strings.TrimSpace(*logsSyslogListenTLS) != "",
		syslogAllowlistCount: len(splitList(*logsSyslogAllowedPeers)),
		syslogDebugCapture:   *logsSyslogDebugCapture,

		zenarmorEnabled:        *logsZenarmorEnabled,
		zenarmorListen:         strings.TrimSpace(*logsZenarmorListenHTTP),
		zenarmorTLS:            strings.TrimSpace(*logsZenarmorTLSCertFile) != "" && strings.TrimSpace(*logsZenarmorTLSKeyFile) != "",
		zenarmorAllowlistCount: len(splitList(*logsZenarmorAllowedPeers)),
		zenarmorDebugCapture:   *logsZenarmorDebugCapture,

		logsDebugCaptureDir: LogsDebugCaptureDir(),

		flowEnabled:   *flowEnabled,
		flowCorrelate: *flowCorrelate,
		flowLogMode:   *flowLogMode,

		netflowEnabled:        *flowNetflowEnabled,
		netflowListen:         strings.TrimSpace(*flowNetflowListen),
		netflowAllowlistCount: countNonEmpty(*flowNetflowPeers),
		netflowDebugCapture:   captureModeOrOff(*flowNetflowDebugCapture),

		// The RESOLVED paths, not the raw flags: an operator who configured only the
		// downloader has empty flags and non-empty effective paths, and the effective
		// ones are what the exporter actually opens. A key that fails to resolve is
		// reported as "not set" — this is a status view, not the startup validation
		// path, and GeoIP.Validate already owns failing hard on a bad secret file.
		geoipEnabled:          *geoipEnabled,
		geoipCountryPath:      geoipResolvedCountryPath(),
		geoipASNPath:          geoipResolvedASNPath(),
		geoipMetricDims:       *geoipMetricDims,
		geoipDownloadEnabled:  *geoipDownloadEnabled,
		geoipDownloadEditions: strings.TrimSpace(*geoipDownloadEditions),
		geoipLicenseKeySet:    geoipLicenseKeyPresent(),
	}
}

// geoipResolvedCountryPath / geoipResolvedASNPath / geoipLicenseKeyPresent read the
// same defaulting GeoIP() applies, so the summary shows what the exporter will
// actually open rather than the raw flag. They never surface the key itself.
func geoipResolvedCountryPath() string { return geoipResolvedPaths().CountryPath }
func geoipResolvedASNPath() string     { return geoipResolvedPaths().ASNPath }

func geoipResolvedPaths() GeoIPConfig {
	c := GeoIPConfig{
		CountryPath:      strings.TrimSpace(*geoipCountryDatabase),
		ASNPath:          strings.TrimSpace(*geoipASNDatabase),
		DownloadEnabled:  *geoipDownloadEnabled,
		DownloadEditions: splitEditions(*geoipDownloadEditions),
		DownloadDir:      strings.TrimSpace(*geoipDownloadDir),
	}
	c.applyDownloadDefaults()
	return c
}

func geoipLicenseKeyPresent() bool {
	key, err := geoipLicenseKey()
	return err == nil && key != ""
}

// syslogListenSummary renders the syslog receiver's up-to-three listeners
// (UDP/TCP/TLS) as one "udp <addr>, tcp <addr>, tls <addr>" row, omitting
// whichever transport is disabled (empty). At least one is non-empty whenever
// the receiver validated at startup (LogsSyslog rejects all-three-empty), but
// this reads the raw flags directly rather than that validated config, so it
// stays correct even from a not-yet-validated context.
func syslogListenSummary(udp, tcp, tls string) string {
	var parts []string
	if udp != "" {
		parts = append(parts, "udp "+udp)
	}
	if tcp != "" {
		parts = append(parts, "tcp "+tcp)
	}
	if tls != "" {
		parts = append(parts, "tls "+tls)
	}
	return strings.Join(parts, ", ")
}

// countNonEmpty counts the non-blank entries in a repeatable string flag
// (e.g. --flow.netflow.allowed-peers), mirroring how splitList counts a
// comma-separated one for the allowlist-count rows above.
func countNonEmpty(items []string) int {
	n := 0
	for _, s := range items {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}

// collectorConfigItems renders one ConfigItem per collector switch from the
// live CollectorsDisableSwitch (CollectorsSwitches()). Reflection is used
// deliberately: the switch struct already carries a resolved, human-labelled
// field per collector subsystem, and walking it generically means a new
// collector switch shows up on /config automatically the day it's added to
// CollectorsDisableSwitch, with no second place to update. (internal/collector
// cannot be imported here — CollectorFlags' own comment notes the resulting
// import cycle through opnsense/client.go — so this reads only from the
// options package's own CollectorsSwitches(), never collector.SubsystemDisplayNames.)
func collectorConfigItems() []ConfigItem {
	sw := CollectorsSwitches()
	// Prefer the post-resolution set when main has recorded one: with
	// --exporter.enable-all-available set, the raw flag values say "off" for every
	// collector the blanket switch turned on, so rendering them would understate the
	// running exporter on all three config surfaces.
	if resolvedSwitches != nil {
		sw = *resolvedSwitches
	}
	v := reflect.ValueOf(sw)
	t := v.Type()
	items := make([]ConfigItem, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		it := plainItem(name, boolStr(v.Field(i).Bool()))
		it.Display = prettifyFieldName(name)
		items = append(items, it)
	}
	return items
}

var (
	// lowerUpper splits a lower/digit → upper boundary: "trafficShaper" → "traffic Shaper".
	lowerUpper = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	// acronymWord splits a run of 2+ capitals followed by a capitalised word:
	// "NATCounts" → "NAT Counts", while a single leading capital ("QStats") is
	// left intact so short abbreviations aren't chopped.
	acronymWord = regexp.MustCompile(`([A-Z]{2,})([A-Z][a-z])`)
)

// prettifyFieldName turns a Go struct field name into a readable label by
// inserting spaces at camelCase boundaries. It deliberately keeps acronym runs
// together (ARP, IPsec, NAT) rather than consulting collector.SubsystemDisplayNames,
// which internal/options cannot import (import cycle via opnsense/client.go).
func prettifyFieldName(name string) string {
	s := lowerUpper.ReplaceAllString(name, "$1 $2")
	s = acronymWord.ReplaceAllString(s, "$1 $2")
	return s
}
