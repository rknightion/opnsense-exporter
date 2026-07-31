package options

import (
	"fmt"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
)

// Editions shipped by default. Country + ASN, following the reference implementation
// in rknightion/tailscale2otel:
//
//   - Country is ~9 MB resident and answers the only question that may ever become a
//     metric label.
//   - ASN is ~12 MB and is the one thing Zenarmor cannot supply on ANY box — a live
//     check found no ASN database anywhere under /usr/local/zenarmor, and its asn
//     field was the string "0" on every record of the capture box.
//
// City is SUPPORTED but not default: it is roughly 60 MB resident, six times Country,
// and city belongs on logs only regardless. It is the right choice for an operator who
// wants locality without Zenarmor — which is most of them, since on a box with no
// Zenarmor our database is the ONLY city source. Set
// --geoip.download.editions=GeoLite2-City,GeoLite2-ASN (or point
// --geoip.country-database at a City file): the Country and City schemas are the same
// and one path accepts either.
const defaultGeoIPEditions = "GeoLite2-Country,GeoLite2-ASN"

var (
	geoipEnabled = kingpin.Flag(
		"geoip.enabled",
		"Enable local GeoIP enrichment from MaxMind-format .mmdb files on disk. Adds "+
			"country/continent/city/ASN attributes to flow LOGS for external addresses, so geo no "+
			"longer depends on whether Zenarmor happened to see the connection. Purely local: no "+
			"lookup ever touches the network. ON by default since #549, because the container image "+
			"now bundles DB-IP Lite Country + ASN databases (CC BY 4.0, https://db-ip.com) and there "+
			"is nothing left to source first. A build that is not the container image has no bundled "+
			"database and enriches nothing until one is configured - that is fail-open, not an error. "+
			"BEHAVIOUR CHANGE ON UPGRADE (#528): this ALSO now covers "+
			"filterlog, sshd/auth and Suricata log lines with country/continent/ASN/as_org (no "+
			"city/region there) - filterlog is the highest-volume log stream on the box, so an "+
			"existing --geoip.enabled deployment gains real per-line byte cost on upgrade with no "+
			"config change. Set --logs.syslog.geoip=false to opt those log lines back out while "+
			"keeping GeoIP on flow records. See docs/geoip.md.",
	).Envar("OPN2OTEL_GEOIP_ENABLED").Default("true").Bool()

	geoipCountryDatabase = kingpin.Flag(
		"geoip.country-database",
		"Path to a Country OR City database in MaxMind .mmdb format (DB-IP Country/City Lite, "+
			"GeoLite2-Country, GeoLite2-City, GeoIP2-City). A City database is a strict superset, so "+
			"one path accepts either and the city/region attributes are simply absent with a Country "+
			"file. Defaults to the DB-IP Country Lite database bundled in the container image "+
			"(CC BY 4.0, https://db-ip.com); point it at your own file to override, or set "+
			"--geoip.download.enabled and it defaults to the downloaded MaxMind copy instead. "+
			"A missing file is not an error - enrichment is fail-open and the attributes are just "+
			"absent, which is what a non-container build gets.",
	).Envar("OPN2OTEL_GEOIP_COUNTRY_DATABASE").Default(geoip.BundledCountryPath).String()

	geoipASNDatabase = kingpin.Flag(
		"geoip.asn-database",
		"Path to an ASN database in MaxMind .mmdb format (DB-IP ASN Lite, GeoLite2-ASN, GeoIP2-ISP). "+
			"This is the one enrichment no amount of Zenarmor coverage supplies: Zenarmor ships no ASN "+
			"database on any box. Defaults to the DB-IP ASN Lite database bundled in the container "+
			"image (CC BY 4.0, https://db-ip.com), or to the downloaded copy when "+
			"--geoip.download.enabled is set.",
	).Envar("OPN2OTEL_GEOIP_ASN_DATABASE").Default(geoip.BundledASNPath).String()

	geoipReloadInterval = kingpin.Flag(
		"geoip.reload-interval",
		"How often to re-stat the database paths and hot-swap a changed file. This is what makes the "+
			"operator-managed path work - a geoipupdate cron, a sidecar or a re-mounted volume can "+
			"rewrite the files under a running exporter. Separate from --geoip.download.interval, which "+
			"asks MaxMind whether a newer build exists. 0 disables reloading.",
	).Envar("OPN2OTEL_GEOIP_RELOAD_INTERVAL").Default("15m").Duration()

	geoipDownloadEnabled = kingpin.Flag(
		"geoip.download.enabled",
		"Download MaxMind databases directly, so no geoipupdate cron or sidecar is needed. Requires "+
			"--geoip.download.account-id and a license key. Conditional requests mean an unchanged "+
			"database costs a 304 and no download quota. Off by default: operator-managed files are "+
			"the supported baseline and this adds an outbound network dependency.",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_ENABLED").Default("false").Bool()

	geoipDownloadAccountID = kingpin.Flag(
		"geoip.download.account-id",
		"MaxMind account ID for the database download API (the Basic-auth username).",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_ACCOUNT_ID").Default("").String()

	geoipDownloadLicenseKey = kingpin.Flag(
		"geoip.download.license-key",
		"MaxMind license key. This flag/ENV or OPN2OTEL_GEOIP_DOWNLOAD_LICENSE_KEY_FILE may "+
			"be set; the file form is preferred for a container secret.",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_LICENSE_KEY").Default("").String()

	geoipDownloadEditions = kingpin.Flag(
		"geoip.download.editions",
		"Comma-separated MaxMind edition IDs to download. Default is Country + ASN (~9 MB and ~12 MB "+
			"resident). Swap GeoLite2-Country for GeoLite2-City (~60 MB resident) to get city and "+
			"region attributes without Zenarmor - the same --geoip.country-database path accepts "+
			"either edition.",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_EDITIONS").Default(defaultGeoIPEditions).String()

	geoipDownloadDir = kingpin.Flag(
		"geoip.download.dir",
		"Directory downloaded databases are installed into, as <dir>/<edition>.mmdb. Must be "+
			"writable and should be persistent - a volume that is lost on restart costs a full "+
			"download every start, against MaxMind's daily limit.",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_DIR").Default("/var/lib/opnsense2otel/geoip").String()

	geoipDownloadInterval = kingpin.Flag(
		"geoip.download.interval",
		"How often to ask MaxMind for a newer build. GeoLite2 rebuilds twice a week, so daily is "+
			"ample; an unchanged database answers 304 and costs no quota. The first download runs at "+
			"startup regardless, so a fresh container is not blind for a whole interval. 0 downloads "+
			"only at startup.",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_INTERVAL").Default("24h").Duration()

	geoipDownloadTimeout = kingpin.Flag(
		"geoip.download.timeout",
		"End-to-end timeout for one edition's download. A timeout leaves the installed database "+
			"untouched and is retried on the next interval.",
	).Envar("OPN2OTEL_GEOIP_DOWNLOAD_TIMEOUT").Default("5m").Duration()

	// The cardinality gate, and the reason it is a separate flag from
	// --geoip.enabled. Log attributes are free; a metric label is not.
	geoipMetricDims = kingpin.Flag(
		"flow.geoip.metric-dims",
		"Add a `country` label to the flow volume metrics. ON by default since #537, and "+
			"--flow.top-n/--flow.max-keys were raised 10x in the same change to hold it: country "+
			"multiplies the occupied key space by the number of countries the box actually talks to "+
			"(a few dozen in practice, not the ~250 the dimension can hold), and at the previous "+
			"1,000/2,500 bounds that would have folded real series into __other__ and cost detail on "+
			"the dimensions that already worked. Set it false to drop the label; the flow families "+
			"then carry the same dimensions they did before. It produces values only where GeoIP can "+
			"answer, so with --geoip.enabled off the label is present and empty. ASN and city NEVER "+
			"become labels at any setting. Geo on flow LOGS needs no flag - it is unconditional "+
			"whenever --geoip.enabled is set.",
	).Envar("OPN2OTEL_FLOW_GEOIP_METRIC_DIMS").Default("true").
		IsSetByUser(&geoipMetricDimsUserSet).Bool()

	// Whether the operator actually typed --flow.geoip.metric-dims (or set its env
	// var), as opposed to inheriting the default. Since #537 made the default true,
	// the two cases must be told apart: a DEFAULT true alongside --geoip.enabled=false
	// resolves quietly to false, because that is every stock deployment and refusing
	// to start would be absurd. An EXPLICIT true in the same situation still refuses,
	// which is the whole point of the check in Validate - the operator asked for a
	// country label and there is no country to put in it.
	geoipMetricDimsUserSet bool
)

// geoipLicenseKey resolves the MaxMind license key through the same secret precedence
// as every other credential: the *_FILE env var wins unless it is set-but-empty, in
// which case the flag/env value is used.
func geoipLicenseKey() (string, error) {
	return resolveSecret("OPN2OTEL_GEOIP_DOWNLOAD_LICENSE_KEY_FILE", *geoipDownloadLicenseKey)
}

// GeoIPConfig is the resolved GeoIP configuration.
type GeoIPConfig struct {
	Enabled bool
	// CountryPath / ASNPath are the resolved database paths, already defaulted from
	// the download directory where the operator gave no explicit path.
	CountryPath    string
	ASNPath        string
	ReloadInterval time.Duration

	DownloadEnabled  bool
	DownloadAccount  string
	DownloadKey      string
	DownloadEditions []string
	DownloadDir      string
	DownloadInterval time.Duration
	DownloadTimeout  time.Duration

	// MetricDims mirrors --flow.geoip.metric-dims: the country METRIC label only.
	MetricDims bool
}

// LicenseKeySet reports whether a license key resolved, without exposing it. The
// /config summary is built from presence booleans only.
func (c GeoIPConfig) LicenseKeySet() bool { return c.DownloadKey != "" }

// GeoIP returns the resolved GeoIP configuration, validated.
func GeoIP() (GeoIPConfig, error) {
	key, err := geoipLicenseKey()
	if err != nil {
		return GeoIPConfig{}, fmt.Errorf("geoip: reading the MaxMind license key: %w", err)
	}
	c := GeoIPConfig{
		Enabled:          *geoipEnabled,
		CountryPath:      strings.TrimSpace(*geoipCountryDatabase),
		ASNPath:          strings.TrimSpace(*geoipASNDatabase),
		ReloadInterval:   *geoipReloadInterval,
		DownloadEnabled:  *geoipDownloadEnabled,
		DownloadAccount:  strings.TrimSpace(*geoipDownloadAccountID),
		DownloadKey:      key,
		DownloadEditions: splitEditions(*geoipDownloadEditions),
		DownloadDir:      strings.TrimSpace(*geoipDownloadDir),
		DownloadInterval: *geoipDownloadInterval,
		DownloadTimeout:  *geoipDownloadTimeout,
		MetricDims:       *geoipMetricDims,
	}
	// Resolve the default-true against GeoIP being off BEFORE Validate sees it, so
	// the stock configuration (metric-dims defaulted on, no MaxMind database shipped)
	// starts cleanly with the label simply unpopulated, while an explicit request
	// still hits the error below.
	if !c.Enabled && !geoipMetricDimsUserSet {
		c.MetricDims = false
	}
	c.applyDownloadDefaults()
	if err := c.Validate(); err != nil {
		return GeoIPConfig{}, err
	}
	return c, nil
}

// applyDownloadDefaults points the unclaimed database paths at what the downloader
// will install, so an operator who configures only the downloader gets a working
// setup rather than a downloaded file nothing reads.
//
// "Unclaimed" is empty OR one of the bundled DB-IP paths (#549). Those paths are
// now the flag DEFAULTS, so an operator who supplies MaxMind credentials would
// otherwise keep reading the bundled DB-IP files forever and never see the
// database they configured. That is precedence rule 1 — MaxMind wins outright —
// and it is why this cannot simply test for empty any more. An EXPLICIT
// --geoip.country-database still wins over the downloader, unchanged.
//
// The edition-to-role mapping is by NAME, and City beats Country when both are
// listed: a City database answers every Country question too, so loading the Country
// file alongside it would spend ~9 MB to answer nothing extra.
func (c *GeoIPConfig) applyDownloadDefaults() {
	if !c.DownloadEnabled || c.DownloadDir == "" {
		return
	}
	unclaimed := func(path string) bool { return path == "" || geoip.IsBundledPath(path) }
	for _, ed := range c.DownloadEditions {
		lower := strings.ToLower(ed)
		switch {
		case strings.Contains(lower, "asn") || strings.Contains(lower, "isp"):
			if unclaimed(c.ASNPath) {
				c.ASNPath = geoip.DatabasePath(c.DownloadDir, ed)
			}
		case strings.Contains(lower, "city"):
			// City wins outright, overriding a Country default set on an earlier pass.
			if unclaimed(c.CountryPath) || isDefaultedTo(c.CountryPath, c.DownloadDir, "country") {
				c.CountryPath = geoip.DatabasePath(c.DownloadDir, ed)
			}
		case strings.Contains(lower, "country"):
			if unclaimed(c.CountryPath) {
				c.CountryPath = geoip.DatabasePath(c.DownloadDir, ed)
			}
		}
	}
}

// isDefaultedTo reports whether path is one applyDownloadDefaults itself produced for
// an edition of the given kind, so City may override a Country default without ever
// overriding an explicit operator path.
func isDefaultedTo(path, dir, kind string) bool {
	return strings.HasPrefix(path, dir) && strings.Contains(strings.ToLower(path), kind)
}

// splitEditions parses the comma-separated edition list, dropping empties.
func splitEditions(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// Validate rejects configurations that would silently do nothing — the same rule the
// flow and Zenarmor families follow. A flag that quietly no-ops looks exactly like a
// quiet network.
//
// It deliberately does NOT reject a missing database FILE. That is the fail-open
// contract: a download that has not landed yet, or a volume mounted a second later,
// must not be a startup failure.
func (c GeoIPConfig) Validate() error {
	if !c.Enabled {
		// Nothing downstream reads the rest, so an unused mis-set flag is not worth a
		// refusal to start. The exception is the metric label, which is a flow-family
		// setting an operator could reasonably believe took effect on its own.
		if c.MetricDims {
			return fmt.Errorf("flow: --flow.geoip.metric-dims requires --geoip.enabled; " +
				"there is no country to label with")
		}
		return nil
	}
	if c.ReloadInterval < 0 {
		return fmt.Errorf("geoip: --geoip.reload-interval must not be negative (got %s); 0 disables reloading",
			c.ReloadInterval)
	}
	if !c.DownloadEnabled {
		// Operator-managed is the default path, but it needs a path to manage.
		if c.CountryPath == "" && c.ASNPath == "" {
			return fmt.Errorf("geoip: --geoip.enabled needs --geoip.country-database and/or " +
				"--geoip.asn-database, or --geoip.download.enabled to fetch them")
		}
		return nil
	}
	if c.DownloadAccount == "" || c.DownloadKey == "" {
		return fmt.Errorf("geoip: --geoip.download.enabled requires --geoip.download.account-id and " +
			"--geoip.download.license-key (or OPN2OTEL_GEOIP_DOWNLOAD_LICENSE_KEY_FILE)")
	}
	if len(c.DownloadEditions) == 0 {
		return fmt.Errorf("geoip: --geoip.download.enabled requires at least one " +
			"--geoip.download.editions entry")
	}
	// Validated before a request is ever made, rather than sanitised afterwards into
	// something the operator did not ask for: the edition name is interpolated into
	// both a URL path and a filename.
	for _, ed := range c.DownloadEditions {
		if err := geoip.ValidateEdition(ed); err != nil {
			return fmt.Errorf("geoip: --geoip.download.editions: %w", err)
		}
	}
	if c.DownloadDir == "" {
		return fmt.Errorf("geoip: --geoip.download.enabled requires --geoip.download.dir")
	}
	if c.DownloadInterval < 0 {
		return fmt.Errorf("geoip: --geoip.download.interval must not be negative (got %s); "+
			"0 downloads only at startup", c.DownloadInterval)
	}
	if c.DownloadTimeout < 0 {
		return fmt.Errorf("geoip: --geoip.download.timeout must not be negative (got %s)", c.DownloadTimeout)
	}
	return nil
}
