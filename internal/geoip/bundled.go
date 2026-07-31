package geoip

import "strings"

// Bundled databases: the DB-IP Lite Country and ASN MMDBs the container image
// ships, so geo enrichment works on a stock deployment with no operator action
// (#549).
//
// # Why DB-IP and not GeoLite2
//
// GeoLite2 cannot be redistributed. Bundling it into a product you distribute
// needs MaxMind's paid, signed Commercial Redistribution License, and obliges you
// to hold every downstream user to a EULA restricting them to "Internal Restricted
// Business Purposes" — impossible for an Apache-2.0 public image. DB-IP Lite is
// plain CC BY 4.0: redistributable as long as DB-IP is credited. MaxMind stays the
// better data and stays fully supported; it is just operator-supplied.
//
// # Why these files are NOT in the repository
//
// They are ~17.8 MB uncompressed and republished monthly. Committing them would
// add that much binary to git history every refresh, permanently and irreversibly.
// The Dockerfile fetches them at image build time from DB-IP's anonymous
// download URLs and writes them to the paths below.
//
// The consequence is deliberate and must stay handled: a build that never ran the
// Dockerfile — `make`, `go build`, `go test`, a local `go run .` — has NOTHING at
// these paths. Since --geoip.enabled defaults on, that is the default
// configuration of every non-container build, so it must fail open: Open leaves an
// absent path unloaded and returns no error, enrichment is simply silent, and the
// exporter starts. TestOpenWithAbsentBundledDatabasesIsNotAnError pins it.
const (
	// BundledDir is where the image build installs the databases. It is outside
	// --geoip.download.dir on purpose: that directory is operator state (a
	// writable volume the MaxMind downloader owns), while this one is read-only
	// image content the exporter never writes.
	BundledDir = "/usr/share/opnsense2otel/geoip"

	// BundledCountryPath and BundledASNPath are the flag defaults for
	// --geoip.country-database / --geoip.asn-database. The filenames carry no
	// year-month: the content is refreshed by rebuilding the image, so a stable
	// path means nothing downstream has to learn a new one every month.
	BundledCountryPath = BundledDir + "/dbip-country-lite.mmdb"
	BundledASNPath     = BundledDir + "/dbip-asn-lite.mmdb"
)

// Attribution constants. CC BY 4.0's condition is credit to the source with a
// link, and it applies wherever the data or its results are shown — so this is
// one string, in one place, that the docs, the image's /licenses copy and the
// operator console all render. A credit typed separately into each surface is a
// credit that silently disappears from one of them.
const (
	BundledProvider    = "DB-IP"
	BundledProviderURL = "https://db-ip.com"
	BundledLicense     = "CC BY 4.0"
	BundledLicenseURL  = "https://creativecommons.org/licenses/by/4.0/"
)

// Attribution is the required credit for the bundled databases, as one line of
// plain text.
func Attribution() string {
	return "IP geolocation data by " + BundledProvider + " (" + BundledProviderURL +
		"), licensed under " + BundledLicense + " (" + BundledLicenseURL + ")."
}

// IsBundledPath reports whether path is one of the bundled databases rather than
// something the operator chose.
//
// It is what keeps the precedence order honest once the bundled files became the
// flag DEFAULTS: "the operator named no database" can no longer be spelled as an
// empty path, so anything that used to test for empty — notably the MaxMind
// download defaulting — has to treat a bundled path as equally unclaimed.
func IsBundledPath(path string) bool {
	switch strings.TrimSpace(path) {
	case BundledCountryPath, BundledASNPath:
		return true
	default:
		return false
	}
}
