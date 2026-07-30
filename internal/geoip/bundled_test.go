package geoip

import (
	"path/filepath"
	"strings"
	"testing"
)

// The bundled paths are a contract with the Dockerfile: it writes the two DB-IP
// Lite files to exactly these paths, and the option defaults point at them. A
// change on either side alone silently ships an image whose databases nothing
// opens, which is indistinguishable from "geo has nothing to say".
func TestBundledPathsAreStable(t *testing.T) {
	if BundledCountryPath != "/usr/share/opnsense-exporter/geoip/dbip-country-lite.mmdb" {
		t.Errorf("BundledCountryPath = %q", BundledCountryPath)
	}
	if BundledASNPath != "/usr/share/opnsense-exporter/geoip/dbip-asn-lite.mmdb" {
		t.Errorf("BundledASNPath = %q", BundledASNPath)
	}
	if filepath.Dir(BundledCountryPath) != BundledDir || filepath.Dir(BundledASNPath) != BundledDir {
		t.Errorf("bundled files are not both under BundledDir %q", BundledDir)
	}
}

func TestIsBundledPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{BundledCountryPath, true},
		{BundledASNPath, true},
		{"  " + BundledASNPath + "  ", true},
		{"", false},
		{"/mnt/mine/country.mmdb", false},
		{BundledDir, false},
		{BundledDir + "/GeoLite2-Country.mmdb", false},
	}
	for _, tc := range cases {
		if got := IsBundledPath(tc.path); got != tc.want {
			t.Errorf("IsBundledPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// CC BY 4.0 requires crediting DB-IP with a link. The credit is a constant in
// this package rather than a string typed into each surface, so the docs, the
// container's /licenses copy and the console footer cannot drift apart.
func TestAttributionNamesTheProviderAndTheLicence(t *testing.T) {
	a := Attribution()
	for _, want := range []string{"DB-IP", "https://db-ip.com", "CC BY 4.0"} {
		if !strings.Contains(a, want) {
			t.Errorf("Attribution() = %q, missing %q", a, want)
		}
	}
	if BundledLicenseURL != "https://creativecommons.org/licenses/by/4.0/" {
		t.Errorf("BundledLicenseURL = %q", BundledLicenseURL)
	}
}

// A build that never ran the Dockerfile's fetch — `make`, `go build`, `go test` —
// has nothing at the bundled paths. With --geoip.enabled now defaulting ON, that
// is the DEFAULT configuration of every non-container build, so it must open
// cleanly and simply enrich nothing. An error here would be a startup failure on
// a plain `go run .`.
func TestOpenWithAbsentBundledDatabasesIsNotAnError(t *testing.T) {
	db, err := Open(Options{CountryPath: BundledCountryPath, ASNPath: BundledASNPath})
	if err != nil {
		t.Fatalf("Open() = %v, want nil for absent bundled databases", err)
	}
	if db == nil {
		t.Fatal("Open() returned a nil *DB")
	}
	if !db.Empty() {
		t.Error("Empty() = false with no bundled database present")
	}
}
