package options

import (
	"reflect"
	"regexp"
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
	).Envar("OPNSENSE_EXPORTER_WEB_UI_ENABLED").Default("true").Bool()
	WebUIRefreshInterval = kingpin.Flag(
		"web.ui-refresh-interval",
		"Live-poll interval for the console's dynamic pages.",
	).Envar("OPNSENSE_EXPORTER_WEB_UI_REFRESH_INTERVAL").Default("5s").Duration()
	WebUIDisableConfig = kingpin.Flag(
		"web.ui-disable-config",
		"Hide the /config page.",
	).Envar("OPNSENSE_EXPORTER_WEB_UI_DISABLE_CONFIG").Default("false").Bool()
	WebUIDisableDevices = kingpin.Flag(
		"web.ui-disable-devices",
		"Hide the /devices page (exposes MAC/hostname).",
	).Envar("OPNSENSE_EXPORTER_WEB_UI_DISABLE_DEVICES").Default("false").Bool()
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
				plainItem("Max Scrape Duration", in.maxScrape),
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
		"OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER_FILE", "PYROSCOPE_AUTH_USER_FILE")
	pyroPass, _ := resolveSecretMulti(*pyroscopeAuthPassword,
		"OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD_FILE", "PYROSCOPE_AUTH_PASSWORD_FILE")
	pyroAddr := strings.TrimSpace(*pyroscopeServerAddress)

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
	}
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
