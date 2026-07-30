package options

import (
	"strings"
	"testing"
	"time"
)

func TestGeoIPValidate(t *testing.T) {
	base := func() GeoIPConfig {
		return GeoIPConfig{
			Enabled:          true,
			CountryPath:      "/db/GeoLite2-Country.mmdb",
			ReloadInterval:   15 * time.Minute,
			DownloadEditions: splitEditions(defaultGeoIPEditions),
			DownloadDir:      "/var/lib/opnsense-exporter/geoip",
			DownloadInterval: 24 * time.Hour,
		}
	}

	cases := []struct {
		name    string
		mutate  func(*GeoIPConfig)
		wantErr string
	}{
		{name: "operator-managed country only", mutate: func(*GeoIPConfig) {}},
		{
			name:   "operator-managed asn only",
			mutate: func(c *GeoIPConfig) { c.CountryPath = ""; c.ASNPath = "/db/asn.mmdb" },
		},
		{
			name:    "enabled with no database and no downloader",
			mutate:  func(c *GeoIPConfig) { c.CountryPath = "" },
			wantErr: "needs --geoip.country-database",
		},
		{
			name:    "downloader without credentials",
			mutate:  func(c *GeoIPConfig) { c.DownloadEnabled = true },
			wantErr: "requires --geoip.download.account-id",
		},
		{
			name: "downloader with credentials",
			mutate: func(c *GeoIPConfig) {
				c.DownloadEnabled = true
				c.DownloadAccount, c.DownloadKey = "acct", "key"
			},
		},
		{
			name: "unsafe edition is refused before any request",
			mutate: func(c *GeoIPConfig) {
				c.DownloadEnabled = true
				c.DownloadAccount, c.DownloadKey = "acct", "key"
				c.DownloadEditions = []string{"../../etc/passwd"}
			},
			wantErr: "only letters, digits",
		},
		{
			name: "downloader with no editions",
			mutate: func(c *GeoIPConfig) {
				c.DownloadEnabled = true
				c.DownloadAccount, c.DownloadKey = "acct", "key"
				c.DownloadEditions = nil
			},
			wantErr: "at least one --geoip.download.editions",
		},
		{
			name:    "negative reload interval",
			mutate:  func(c *GeoIPConfig) { c.ReloadInterval = -time.Second },
			wantErr: "--geoip.reload-interval must not be negative",
		},
		// The metric label is a flow-family flag an operator could reasonably believe
		// took effect on its own, so it is the ONE setting that is an error rather
		// than a silent no-op when geo is off.
		//
		// Since #537 the flag DEFAULTS to true, so this case only survives for an
		// EXPLICIT request: GeoIPConfig() resolves a defaulted true down to false when
		// --geoip.enabled is off, before Validate ever runs. That resolution is what
		// keeps every stock deployment (default-on label, no MaxMind database shipped)
		// starting cleanly, and main_test.go's production-equivalent config covers it.
		// Validate itself must keep rejecting the explicit form, which is what this
		// case pins - reaching it with MetricDims still true means the operator asked.
		{
			name:    "metric dims explicitly set without geoip enabled",
			mutate:  func(c *GeoIPConfig) { c.Enabled = false; c.MetricDims = true },
			wantErr: "--flow.geoip.metric-dims requires --geoip.enabled",
		},
		{
			name:   "everything off is fine",
			mutate: func(c *GeoIPConfig) { *c = GeoIPConfig{} },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// A missing database FILE is deliberately NOT a validation error: fail-open means a
// download that has not landed, or a volume mounted a second later, must not be a
// startup failure.
func TestGeoIPValidateAcceptsAMissingDatabaseFile(t *testing.T) {
	c := GeoIPConfig{Enabled: true, CountryPath: "/definitely/not/here.mmdb"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a not-yet-present database", err)
	}
}

func TestGeoIPDownloadDefaultsPointAtWhatIsInstalled(t *testing.T) {
	c := GeoIPConfig{
		DownloadEnabled:  true,
		DownloadDir:      "/state/geoip",
		DownloadEditions: []string{"GeoLite2-Country", "GeoLite2-ASN"},
	}
	c.applyDownloadDefaults()
	if c.CountryPath != "/state/geoip/GeoLite2-Country.mmdb" {
		t.Errorf("CountryPath = %q", c.CountryPath)
	}
	if c.ASNPath != "/state/geoip/GeoLite2-ASN.mmdb" {
		t.Errorf("ASNPath = %q", c.ASNPath)
	}
}

// City is a strict superset of Country, so loading both would spend ~9 MB answering
// nothing extra. City wins the country slot when both are downloaded.
func TestGeoIPCityBeatsCountryForTheSameSlot(t *testing.T) {
	c := GeoIPConfig{
		DownloadEnabled:  true,
		DownloadDir:      "/state/geoip",
		DownloadEditions: []string{"GeoLite2-Country", "GeoLite2-City", "GeoLite2-ASN"},
	}
	c.applyDownloadDefaults()
	if c.CountryPath != "/state/geoip/GeoLite2-City.mmdb" {
		t.Errorf("CountryPath = %q, want the City database", c.CountryPath)
	}
}

// An explicit operator path is never overridden by a download default, whatever the
// edition list says.
func TestGeoIPExplicitPathsWin(t *testing.T) {
	c := GeoIPConfig{
		CountryPath:      "/mnt/mine/country.mmdb",
		ASNPath:          "/mnt/mine/asn.mmdb",
		DownloadEnabled:  true,
		DownloadDir:      "/state/geoip",
		DownloadEditions: []string{"GeoLite2-City", "GeoLite2-ASN"},
	}
	c.applyDownloadDefaults()
	if c.CountryPath != "/mnt/mine/country.mmdb" || c.ASNPath != "/mnt/mine/asn.mmdb" {
		t.Errorf("explicit paths were overridden: %+v", c)
	}
}

// With the downloader off, no path is invented: an operator-managed deployment that
// forgot the path must get the validation error, not a phantom default.
func TestGeoIPNoDefaultsWithoutTheDownloader(t *testing.T) {
	c := GeoIPConfig{DownloadDir: "/state/geoip", DownloadEditions: []string{"GeoLite2-ASN"}}
	c.applyDownloadDefaults()
	if c.CountryPath != "" || c.ASNPath != "" {
		t.Errorf("paths were defaulted with the downloader off: %+v", c)
	}
}

func TestSplitEditions(t *testing.T) {
	got := splitEditions(" GeoLite2-Country , ,GeoLite2-ASN ")
	if len(got) != 2 || got[0] != "GeoLite2-Country" || got[1] != "GeoLite2-ASN" {
		t.Errorf("splitEditions = %v", got)
	}
	if got := splitEditions("  "); got != nil {
		t.Errorf("splitEditions(blank) = %v, want nil", got)
	}
}

func TestGeoIPLicenseKeySet(t *testing.T) {
	if (GeoIPConfig{}).LicenseKeySet() {
		t.Error("an unset key reported as set")
	}
	if !(GeoIPConfig{DownloadKey: "k"}).LicenseKeySet() {
		t.Error("a set key reported as unset")
	}
}
