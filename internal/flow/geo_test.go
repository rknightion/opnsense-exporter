package flow

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
)

// fakeLookup is a table-driven geoip.Lookup, so the precedence rules can be tested
// without a database file.
type fakeLookup map[string]geoip.Result

func (f fakeLookup) Lookup(addr netip.Addr) (geoip.Result, bool) {
	if !geoip.Enrichable(addr) {
		return geoip.Result{}, false
	}
	r, ok := f[addr.String()]
	return r, ok
}

func newTestEnricher(t *testing.T, lk geoip.Lookup, metricDims bool) *GeoEnricher {
	t.Helper()
	e := NewGeoEnricher(lk, metricDims)
	return e
}

// The whole point of #520: a flow that Zenarmor never saw still gets geo.
func TestGeoEnrichWithoutZenarmor(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{
		"1.1.1.1": {CountryISO: "AU", ContinentCode: "OC", ASN: 13335, ASOrg: "Cloudflare"},
	}, false)

	r := Record{
		SrcAddr: netip.MustParseAddr("192.168.1.10"),
		DstAddr: netip.MustParseAddr("1.1.1.1"),
	}
	e.Enrich(&r)

	if r.Geo.Dst.Country != "AU" {
		t.Errorf("Dst.Country = %q, want AU", r.Geo.Dst.Country)
	}
	if r.Geo.Dst.Continent != "OC" {
		t.Errorf("Dst.Continent = %q, want OC", r.Geo.Dst.Continent)
	}
	if r.Geo.Dst.ASN != 13335 || r.Geo.Dst.ASOrg != "Cloudflare" {
		t.Errorf("Dst ASN = %d/%q, want 13335/Cloudflare", r.Geo.Dst.ASN, r.Geo.Dst.ASOrg)
	}
	if r.Geo.Dst.CountrySource != GeoSourceMaxMind {
		t.Errorf("Dst.CountrySource = %q, want %q", r.Geo.Dst.CountrySource, GeoSourceMaxMind)
	}
	// The private source must never be geolocated.
	if !r.Geo.Src.Empty() {
		t.Errorf("a private source address was geolocated: %+v", r.Geo.Src)
	}
}

// Country: ours wins, Zenarmor's is RETAINED alongside rather than discarded.
func TestGeoCountryOursWinsAndKeepsZenarmors(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{
		"203.0.113.9": {CountryISO: "US", ContinentCode: "NA"},
	}, false)

	r := Record{
		SrcAddr: netip.MustParseAddr("192.168.1.10"),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
	}
	r.Geo.Dst.ZenCountry = "GB"
	e.Enrich(&r)

	if r.Geo.Dst.Country != "US" {
		t.Errorf("Country = %q, want US (ours wins)", r.Geo.Dst.Country)
	}
	if r.Geo.Dst.ZenCountry != "GB" {
		t.Errorf("ZenCountry = %q, want GB retained alongside", r.Geo.Dst.ZenCountry)
	}
	if r.Geo.Dst.CountrySource != GeoSourceMaxMind {
		t.Errorf("CountrySource = %q, want maxmind", r.Geo.Dst.CountrySource)
	}
	if st := e.Stats(); st.CountryDisagreements != 1 || st.CountryAgreements != 0 {
		t.Errorf("disagreement not counted: %+v", st)
	}
}

func TestGeoCountryAgreementIsCountedToo(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{"203.0.113.9": {CountryISO: "US"}}, false)
	r := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	// Lowercase on the wire must not read as a disagreement.
	r.Geo.Dst.ZenCountry = "us"
	e.Enrich(&r)
	if st := e.Stats(); st.CountryAgreements != 1 || st.CountryDisagreements != 0 {
		t.Errorf("agreement not counted: %+v", st)
	}
	if r.Geo.Dst.ZenCountry != "US" {
		t.Errorf("ZenCountry = %q, want the normalized US", r.Geo.Dst.ZenCountry)
	}
}

// Without a database of our own, Zenarmor's country is still better than nothing —
// but the provenance attribute has to say so.
func TestGeoCountryFallsBackToZenarmor(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{}, false)
	r := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	r.Geo.Dst.ZenCountry = "DE"
	r.Geo.Dst.ZenContinent = "EU"
	e.Enrich(&r)

	if r.Geo.Dst.Country != "DE" || r.Geo.Dst.Continent != "EU" {
		t.Errorf("Zenarmor fallback not applied: %+v", r.Geo.Dst)
	}
	if r.Geo.Dst.CountrySource != GeoSourceZenarmor {
		t.Errorf("CountrySource = %q, want zenarmor", r.Geo.Dst.CountrySource)
	}
	// No comparison is possible with only one source, so neither counter moves.
	if st := e.Stats(); st.CountryAgreements != 0 || st.CountryDisagreements != 0 {
		t.Errorf("a one-sided record must not be counted as either: %+v", st)
	}
}

// City: Zenarmor when present (theirs is a commercial GeoIP2-City build), ours as
// fallback — which is the only source on the vast majority of boxes.
func TestGeoCityPrefersZenarmorAndFallsBackToOurs(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{
		"203.0.113.9":  {CountryISO: "GB", City: "Slough", RegionISO: "SLG"},
		"198.51.100.4": {CountryISO: "GB", City: "Reading", RegionISO: "RDG"},
	}, false)

	zen := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	zen.Geo.Dst.ZenCity = "London"
	zen.Geo.Dst.ZenRegion = "England"
	e.Enrich(&zen)
	if zen.Geo.Dst.City != "London" || zen.Geo.Dst.Region != "England" {
		t.Errorf("Zenarmor city/region did not win: %+v", zen.Geo.Dst)
	}
	if zen.Geo.Dst.CitySource != GeoSourceZenarmor {
		t.Errorf("CitySource = %q, want zenarmor", zen.Geo.Dst.CitySource)
	}

	ours := Record{DstAddr: netip.MustParseAddr("198.51.100.4")}
	e.Enrich(&ours)
	if ours.Geo.Dst.City != "Reading" || ours.Geo.Dst.Region != "RDG" {
		t.Errorf("our city/region fallback did not apply: %+v", ours.Geo.Dst)
	}
	if ours.Geo.Dst.CitySource != GeoSourceMaxMind {
		t.Errorf("CitySource = %q, want maxmind", ours.Geo.Dst.CitySource)
	}
}

// ASN is ours ONLY: Zenarmor ships no ASN database on any box, and its asn field is
// the string "0" on every record of the capture box.
func TestGeoASNIsOursOnly(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{}, false)
	r := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	r.Geo.Dst.ZenCountry = "DE"
	e.Enrich(&r)
	if r.Geo.Dst.ASN != 0 || r.Geo.Dst.ASOrg != "" {
		t.Errorf("an ASN appeared with no database of our own: %+v", r.Geo.Dst)
	}
}

// A nil enricher, and one with no databases, are both no-ops. Fail-open means the
// attributes are simply absent.
func TestGeoEnricherNilAndEmptyAreNoOps(t *testing.T) {
	var e *GeoEnricher
	r := Record{DstAddr: netip.MustParseAddr("1.1.1.1")}
	e.Enrich(&r)
	if !r.Geo.Dst.Empty() {
		t.Error("a nil enricher produced geo")
	}
	if st := e.Stats(); st != (GeoStats{}) {
		t.Errorf("nil enricher Stats = %+v, want zero", st)
	}

	e2 := NewGeoEnricher(nil, false)
	r2 := Record{DstAddr: netip.MustParseAddr("1.1.1.1")}
	e2.Enrich(&r2)
	if !r2.Geo.Dst.Empty() {
		t.Error("an enricher with no lookup produced geo")
	}
}

// Enrich must not throw away a Zenarmor value it cannot improve on.
func TestGeoEnrichPreservesZenarmorWhenWeKnowNothing(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{}, false)
	r := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	r.Geo.Dst.ZenCity = "London"
	e.Enrich(&r)
	if r.Geo.Dst.City != "London" || r.Geo.Dst.ZenCity != "London" {
		t.Errorf("Zenarmor city lost: %+v", r.Geo.Dst)
	}
}

func TestGeoEndpointEmpty(t *testing.T) {
	if !(GeoEndpoint{}).Empty() {
		t.Error("zero GeoEndpoint must be Empty")
	}
	if (GeoEndpoint{Country: "GB"}).Empty() {
		t.Error("a GeoEndpoint with a country is not Empty")
	}
	if (GeoEndpoint{ASN: 1}).Empty() {
		t.Error("a GeoEndpoint with an ASN is not Empty")
	}
}

// The country METRIC label is off unless the operator opts in, because it multiplies
// the flow series roughly 250-fold.
func TestGeoMetricLabelIsOptIn(t *testing.T) {
	lk := fakeLookup{"203.0.113.9": {CountryISO: "US"}}

	off := NewGeoEnricher(lk, false)
	r := Record{
		SrcAddr: netip.MustParseAddr("192.168.1.10"),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
		Enrich:  Enrichment{SrcScope: "local", DstScope: "remote"},
	}
	off.Enrich(&r)
	if got := off.MetricCountry(r); got != "" {
		t.Errorf("MetricCountry with the opt-in off = %q, want empty", got)
	}

	on := NewGeoEnricher(lk, true)
	r2 := r
	r2.Geo = GeoInfo{}
	on.Enrich(&r2)
	if got := on.MetricCountry(r2); got != "US" {
		t.Errorf("MetricCountry with the opt-in on = %q, want US", got)
	}
}

// The metric label names the REMOTE end, whichever end that is — a per-country
// breakdown of internal traffic would be meaningless.
func TestGeoMetricCountryPicksTheRemoteEnd(t *testing.T) {
	e := NewGeoEnricher(fakeLookup{
		"203.0.113.9":  {CountryISO: "US"},
		"198.51.100.4": {CountryISO: "JP"},
	}, true)

	inbound := Record{
		SrcAddr: netip.MustParseAddr("198.51.100.4"),
		DstAddr: netip.MustParseAddr("192.168.1.10"),
		Enrich:  Enrichment{SrcScope: "remote", DstScope: "local"},
	}
	e.Enrich(&inbound)
	if got := e.MetricCountry(inbound); got != "JP" {
		t.Errorf("inbound MetricCountry = %q, want JP", got)
	}

	internal := Record{
		SrcAddr: netip.MustParseAddr("192.168.1.10"),
		DstAddr: netip.MustParseAddr("192.168.1.20"),
		Enrich:  Enrichment{SrcScope: "local", DstScope: "local"},
	}
	e.Enrich(&internal)
	if got := e.MetricCountry(internal); got != "" {
		t.Errorf("internal MetricCountry = %q, want empty", got)
	}
}

// Enriched counts records that got at least one fact out of OUR database, which is
// the "is this feature doing anything" signal.
func TestGeoStatsCountsEnrichedRecords(t *testing.T) {
	e := NewGeoEnricher(fakeLookup{"203.0.113.9": {CountryISO: "US"}}, false)
	hit := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	e.Enrich(&hit)
	miss := Record{DstAddr: netip.MustParseAddr("198.51.100.7")}
	e.Enrich(&miss)
	if st := e.Stats(); st.Enriched != 1 {
		t.Errorf("Enriched = %d, want 1", st.Enriched)
	}
}

// The wiring seam, and the reason it is worth a test of its own: both receiver lanes
// reach the enricher through the package-level GeoEnrichment, so a lane that forgot to
// call it would ship records with no geo and nothing would fail.
func TestNetflowLaneEnrichesThroughTheProcessWideEnricher(t *testing.T) {
	prev := GeoEnrichment
	t.Cleanup(func() { GeoEnrichment = prev })
	ConfigureGeoIP(fakeLookup{"1.1.1.1": {CountryISO: "AU", ASN: 13335}}, false)

	r := Record{
		SrcAddr: netip.MustParseAddr("192.168.1.10"),
		DstAddr: netip.MustParseAddr("1.1.1.1"),
	}
	// nil snapshot: geo must survive a cold enrichment cache, since a flow log with
	// no country is exactly the asymmetry this feature closes.
	enrichRecord(&r, nil, nil, time.Time{})
	if r.Geo.Dst.Country != "AU" || r.Geo.Dst.ASN != 13335 {
		t.Errorf("the NetFlow lane did not apply geo: %+v", r.Geo.Dst)
	}
}

// The metric label must be empty whenever the process-wide enricher is unconfigured,
// so a build that never wires geo emits the flow family exactly as before.
func TestRollupKeyHasNoCountryWithoutAnEnricher(t *testing.T) {
	prev := GeoEnrichment
	t.Cleanup(func() { GeoEnrichment = prev })
	GeoEnrichment = nil

	k := keyFor(Record{
		DstAddr: netip.MustParseAddr("1.1.1.1"),
		Enrich:  Enrichment{DstScope: "remote"},
	})
	if k.Country != "" {
		t.Errorf("Country = %q with no enricher configured, want empty", k.Country)
	}
}

// The log attributes are the deliverable: geo has to be filterable in Loki, and the
// provenance attribute has to travel with it.
func TestGeoLogAttributes(t *testing.T) {
	r := Record{
		SrcAddr: netip.MustParseAddr("192.168.1.10"),
		DstAddr: netip.MustParseAddr("1.1.1.1"),
	}
	r.Geo.Dst = GeoEndpoint{
		Country: "AU", Continent: "OC", City: "Sydney", Region: "NSW",
		ASN: 13335, ASOrg: "Cloudflare",
		CountrySource: GeoSourceMaxMind, CitySource: GeoSourceMaxMind,
	}
	a := r.LogAttributes()

	for k, want := range map[string]string{
		"dst.geo.country":        "AU",
		"dst.geo.country_source": GeoSourceMaxMind,
		"dst.geo.continent":      "OC",
		"dst.geo.city":           "Sydney",
		"dst.geo.region":         "NSW",
		"dst.geo.city_source":    GeoSourceMaxMind,
		"dst.geo.asn":            "AS13335",
		"dst.geo.as_org":         "Cloudflare",
	} {
		if a[k] != want {
			t.Errorf("%s = %q, want %q", k, a[k], want)
		}
	}
	// An endpoint with no geo leaves no keys at all: an absent attribute is cheaper
	// than an empty one and reads correctly in Loki.
	for k := range a {
		if strings.HasPrefix(k, "src.geo.") {
			t.Errorf("unexpected src geo key %q on an unlocated endpoint", k)
		}
	}
}

// Zenarmor's country is retained on the wire only where it DISAGREES: re-emitting an
// identical value on every record is per-line cost for no information.
func TestGeoLogAttributesKeepZenarmorOnlyOnDisagreement(t *testing.T) {
	agree := Record{DstAddr: netip.MustParseAddr("1.1.1.1")}
	agree.Geo.Dst = GeoEndpoint{Country: "AU", ZenCountry: "AU", CountrySource: GeoSourceMaxMind}
	if _, ok := agree.LogAttributes()["dst.geo.zen_country"]; ok {
		t.Error("an agreeing Zenarmor country was emitted")
	}

	differ := Record{DstAddr: netip.MustParseAddr("1.1.1.1")}
	differ.Geo.Dst = GeoEndpoint{Country: "AU", ZenCountry: "NZ", CountrySource: GeoSourceMaxMind}
	if got := differ.LogAttributes()["dst.geo.zen_country"]; got != "NZ" {
		t.Errorf("dst.geo.zen_country = %q, want NZ", got)
	}
}

// A merged record must mean the same thing as a Zenarmor-only one, or the precedence
// table quietly has two readings.
func TestMergeGeoAppliesThePrecedenceTable(t *testing.T) {
	// The NetFlow side already carries OUR lookup.
	nf := GeoInfo{Dst: GeoEndpoint{
		Country: "US", Continent: "NA", City: "Ashburn", Region: "VA",
		ASN: 15169, ASOrg: "Google", CountrySource: GeoSourceMaxMind, CitySource: GeoSourceMaxMind,
	}}
	zen := GeoInfo{Dst: GeoEndpoint{
		ZenCountry: "GB", ZenContinent: "EU", ZenCity: "London", ZenRegion: "England",
	}}
	MergeGeo(&nf, zen)

	if nf.Dst.Country != "US" || nf.Dst.CountrySource != GeoSourceMaxMind {
		t.Errorf("country: ours must still win after a merge: %+v", nf.Dst)
	}
	if nf.Dst.ZenCountry != "GB" {
		t.Errorf("Zenarmor's country was discarded by the merge: %+v", nf.Dst)
	}
	if nf.Dst.City != "London" || nf.Dst.Region != "England" || nf.Dst.CitySource != GeoSourceZenarmor {
		t.Errorf("city: Zenarmor must win after a merge: %+v", nf.Dst)
	}
	// ASN is ours only and the merge must not touch it.
	if nf.Dst.ASN != 15169 {
		t.Errorf("ASN = %d, want 15169", nf.Dst.ASN)
	}
}

// With no database of our own, a merge is how a NetFlow-derived record gets any geo
// at all.
func TestMergeGeoFallsBackToZenarmorEntirely(t *testing.T) {
	nf := GeoInfo{}
	zen := GeoInfo{Dst: GeoEndpoint{ZenCountry: "DE", ZenContinent: "EU", ZenCity: "Berlin"}}
	MergeGeo(&nf, zen)
	if nf.Dst.Country != "DE" || nf.Dst.CountrySource != GeoSourceZenarmor {
		t.Errorf("country fallback not applied: %+v", nf.Dst)
	}
	if nf.Dst.Continent != "EU" {
		t.Errorf("continent fallback not applied: %+v", nf.Dst)
	}
	if nf.Dst.City != "Berlin" || nf.Dst.CitySource != GeoSourceZenarmor {
		t.Errorf("city fallback not applied: %+v", nf.Dst)
	}
}
