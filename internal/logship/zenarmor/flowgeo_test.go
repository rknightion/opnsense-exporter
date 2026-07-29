package zenarmor

import (
	"testing"

	"github.com/rknightion/opnsense-exporter/internal/flow"
)

// A conn document carrying Zenarmor's own geo block. Anonymised like every other
// fixture in flowadapt_test.go: RFC 5737 documentation space, and the geo values are
// plausible rather than captured. The SHAPE is what matters — country_code2,
// city_name, region_name and the "0" asn are exactly what a live document carries.
const flowWithZenGeo = `{"transport_proto":"TCP","interface":"ixl0","vlanid":"0","direction":"out",` +
	`"is_local":0,"ip_src_saddr":"192.0.2.50","ip_src_port":49812,"ip_dst_saddr":"203.0.113.12",` +
	`"ip_dst_port":443,"is_blocked":0,"src_npackets":12,"src_nbytes":1804,"dst_npackets":18,` +
	`"dst_nbytes":23110,"start_time":1784656700000,"end_time":1784656707000,"app_proto":"HTTPS",` +
	`"dst_geoip":{"country_code2":"GB","country_code3":"GBR","country_name":"United Kingdom",` +
	`"city_name":"England","region_name":"England","continent_code":"EU","timezone":"Europe/London",` +
	`"asn":"0","latitude":51.5,"longitude":-0.1}}`

// Before #520 Zenarmor's geo reached only its own log record and never met ours, so
// the two databases could not be compared at all. This is the plumbing that changed.
func TestFlowFromDoc_CarriesZenarmorGeoOntoTheRecord(t *testing.T) {
	prev := flow.GeoEnrichment
	t.Cleanup(func() { flow.GeoEnrichment = prev })
	// No lookup of our own: this test is about the Zenarmor side reaching the record,
	// and with an empty database the resolved fields must fall back to Zenarmor's.
	flow.ConfigureGeoIP(nil, false)

	r := mustFlow(t, flowWithZenGeo)

	if r.Geo.Dst.ZenCountry != "GB" {
		t.Errorf("ZenCountry = %q, want GB", r.Geo.Dst.ZenCountry)
	}
	if r.Geo.Dst.ZenContinent != "EU" {
		t.Errorf("ZenContinent = %q, want EU", r.Geo.Dst.ZenContinent)
	}
	if r.Geo.Dst.ZenCity != "England" {
		t.Errorf("ZenCity = %q, want England", r.Geo.Dst.ZenCity)
	}
	if r.Geo.Dst.ZenRegion != "England" {
		t.Errorf("ZenRegion = %q, want England", r.Geo.Dst.ZenRegion)
	}
	// The local source has no geo block, and must not acquire one.
	if !r.Geo.Src.Empty() {
		t.Errorf("Src geo = %+v, want empty", r.Geo.Src)
	}
}

// Zenarmor's asn field is the string "0" on every record of the capture box, and "0"
// is its EMPTY value rather than AS0. It is deliberately never read: a live check
// found no ASN database anywhere under /usr/local/zenarmor, so Zenarmor structurally
// cannot supply one.
func TestFlowFromDoc_IgnoresZenarmorASN(t *testing.T) {
	prev := flow.GeoEnrichment
	t.Cleanup(func() { flow.GeoEnrichment = prev })
	flow.ConfigureGeoIP(nil, false)

	r := mustFlow(t, flowWithZenGeo)
	if r.Geo.Dst.ASN != 0 || r.Geo.Dst.ASOrg != "" {
		t.Errorf("an ASN was taken from Zenarmor: %+v", r.Geo.Dst)
	}
}

// A document with no geo block at all is the common case on most families, and must
// leave the record's geo untouched rather than producing empty-string attributes.
func TestFlowFromDoc_NoGeoBlockLeavesNothing(t *testing.T) {
	prev := flow.GeoEnrichment
	t.Cleanup(func() { flow.GeoEnrichment = prev })
	flow.ConfigureGeoIP(nil, false)

	r := mustFlow(t, flowLANToInternet)
	if !r.Geo.Src.Empty() || !r.Geo.Dst.Empty() {
		t.Errorf("geo appeared with no geoip block and no database: %+v", r.Geo)
	}
	for k := range r.LogAttributes() {
		if len(k) > 4 && (k[:4] == "src." || k[:4] == "dst.") && len(k) > 8 && k[4:8] == "geo." {
			t.Errorf("unexpected geo attribute %q", k)
		}
	}
}
