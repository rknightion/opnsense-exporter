package syslog

import (
	"net/netip"
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/geoip"
)

// fakeGeoLookup is a scripted geoip.Lookup for tests, so they never touch a real
// MaxMind database.
type fakeGeoLookup struct {
	results map[string]geoip.Result
}

func (f fakeGeoLookup) Lookup(addr netip.Addr) (geoip.Result, bool) {
	res, ok := f.results[addr.String()]
	return res, ok
}

func TestGeoAttrs_NilLookupIsANoOp(t *testing.T) {
	geoLookup = nil
	attrs := map[string]string{}
	geoAttrs(func(k, v string) { attrs[k] = v }, "src", "203.0.113.10")
	if len(attrs) != 0 {
		t.Errorf("attrs = %v, want empty (nil lookup must be a no-op)", attrs)
	}
}

func TestGeoAttrs_MissIsANoOp(t *testing.T) {
	geoLookup = fakeGeoLookup{results: map[string]geoip.Result{}}
	t.Cleanup(func() { geoLookup = nil })

	attrs := map[string]string{}
	geoAttrs(func(k, v string) { attrs[k] = v }, "src", "203.0.113.10")
	if len(attrs) != 0 {
		t.Errorf("attrs = %v, want empty (a miss must add nothing)", attrs)
	}
}

func TestGeoAttrs_EmptyOrInvalidIPIsANoOp(t *testing.T) {
	geoLookup = fakeGeoLookup{results: map[string]geoip.Result{
		"203.0.113.10": {CountryISO: "US"},
	}}
	t.Cleanup(func() { geoLookup = nil })

	for _, ip := range []string{"", "not-an-ip"} {
		attrs := map[string]string{}
		geoAttrs(func(k, v string) { attrs[k] = v }, "src", ip)
		if len(attrs) != 0 {
			t.Errorf("ip=%q: attrs = %v, want empty", ip, attrs)
		}
	}
}

func TestGeoAttrs_FullHit_ExactKeysAndValues(t *testing.T) {
	geoLookup = fakeGeoLookup{results: map[string]geoip.Result{
		"198.51.100.7": {
			CountryISO:    "GB",
			ContinentCode: "EU",
			// City/RegionISO deliberately populated to prove they are NEVER emitted
			// (#528 decision 4 excludes city/region from log attributes).
			City:      "London",
			RegionISO: "ENG",
			ASN:       15169,
			ASOrg:     "Google LLC",
		},
	}}
	t.Cleanup(func() { geoLookup = nil })

	attrs := map[string]string{}
	geoAttrs(func(k, v string) { attrs[k] = v }, "dst", "198.51.100.7")

	want := map[string]string{
		"dst.geo.country":        "GB",
		"dst.geo.country_source": "maxmind",
		"dst.geo.continent":      "EU",
		"dst.geo.asn":            "AS15169",
		"dst.geo.as_org":         "Google LLC",
	}
	if len(attrs) != len(want) {
		t.Fatalf("attrs = %v, want exactly %v", attrs, want)
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attrs[%q] = %q, want %q", k, attrs[k], v)
		}
	}
	for _, forbidden := range []string{"dst.geo.city", "dst.geo.region", "dst.geo.city_source"} {
		if _, ok := attrs[forbidden]; ok {
			t.Errorf("attrs contains %q; city/region must never be emitted on log records", forbidden)
		}
	}
}

// A record whose only fact is an ASN (a country database wasn't loaded, or the
// address is only in the ASN table) must not fabricate a country_source: that
// provenance attribute means "the country field is set", not "a lookup happened".
func TestGeoAttrs_ASNOnly_NoCountrySource(t *testing.T) {
	geoLookup = fakeGeoLookup{results: map[string]geoip.Result{
		"198.51.100.7": {ASN: 7018},
	}}
	t.Cleanup(func() { geoLookup = nil })

	attrs := map[string]string{}
	geoAttrs(func(k, v string) { attrs[k] = v }, "src", "198.51.100.7")

	want := map[string]string{"src.geo.asn": "AS7018"}
	if len(attrs) != len(want) || attrs["src.geo.asn"] != "AS7018" {
		t.Errorf("attrs = %v, want exactly %v", attrs, want)
	}
	if _, ok := attrs["src.geo.country_source"]; ok {
		t.Error("country_source present with no country; provenance must not be fabricated")
	}
}

func TestConfigureGeoIP_InstallsAndClears(t *testing.T) {
	t.Cleanup(func() { geoLookup = nil })

	lk := fakeGeoLookup{results: map[string]geoip.Result{"203.0.113.5": {CountryISO: "US"}}}
	ConfigureGeoIP(lk)

	attrs := map[string]string{}
	geoAttrs(func(k, v string) { attrs[k] = v }, "src", "203.0.113.5")
	if attrs["src.geo.country"] != "US" {
		t.Errorf("attrs = %v, want src.geo.country=US after ConfigureGeoIP", attrs)
	}

	ConfigureGeoIP(nil)
	attrs = map[string]string{}
	geoAttrs(func(k, v string) { attrs[k] = v }, "src", "203.0.113.5")
	if len(attrs) != 0 {
		t.Errorf("attrs = %v, want empty after ConfigureGeoIP(nil)", attrs)
	}
}
