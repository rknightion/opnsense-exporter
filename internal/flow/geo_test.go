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

// City (#643): MaxMind wins when present - Zenarmor's city data on this deployment is
// anycast-wrong for remote destinations and subdivision-level for local ones, and the
// deployment runs GeoLite2-City specifically to get city/region without depending on
// Zenarmor. Zenarmor is the fallback only when MaxMind has none. Region follows City
// exactly since both come from the same record and the same CitySource.
func TestGeoCityMaxMindWinsAndFallsBackToZenarmor(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{
		"203.0.113.9":  {CountryISO: "GB", City: "Slough", RegionISO: "SLG"},
		"198.51.100.4": {CountryISO: "GB"}, // no city/region of our own for this one
	}, false)

	// MaxMind has a city: it must win even though Zenarmor also has one.
	ours := Record{DstAddr: netip.MustParseAddr("203.0.113.9")}
	ours.Geo.Dst.ZenCity = "London"
	ours.Geo.Dst.ZenRegion = "England"
	e.Enrich(&ours)
	if ours.Geo.Dst.City != "Slough" || ours.Geo.Dst.Region != "SLG" {
		t.Errorf("MaxMind city/region did not win: %+v", ours.Geo.Dst)
	}
	if ours.Geo.Dst.CitySource != GeoSourceMaxMind {
		t.Errorf("CitySource = %q, want maxmind", ours.Geo.Dst.CitySource)
	}
	// Zenarmor's raw values are still retained even though they lost the field.
	if ours.Geo.Dst.ZenCity != "London" || ours.Geo.Dst.ZenRegion != "England" {
		t.Errorf("Zenarmor raw city/region were discarded by losing: %+v", ours.Geo.Dst)
	}

	// MaxMind has nothing: Zenarmor is the fallback.
	fallback := Record{DstAddr: netip.MustParseAddr("198.51.100.4")}
	fallback.Geo.Dst.ZenCity = "Reading"
	fallback.Geo.Dst.ZenRegion = "RDG"
	e.Enrich(&fallback)
	if fallback.Geo.Dst.City != "Reading" || fallback.Geo.Dst.Region != "RDG" {
		t.Errorf("Zenarmor city/region fallback did not apply: %+v", fallback.Geo.Dst)
	}
	if fallback.Geo.Dst.CitySource != GeoSourceZenarmor {
		t.Errorf("CitySource = %q, want zenarmor", fallback.Geo.Dst.CitySource)
	}
}

// #639: an address in private/reserved space gets no RESOLVED geo from ANY source,
// even when Zenarmor supplied one for every field. The raw Zen* values must still be
// retained for audit (per the GeoEndpoint doc comment). Covers RFC1918 v4, RFC4193 ULA
// v6, loopback, link-local, and the v4-mapped form of RFC1918 - the exact set #639
// names.
func TestGeoPrivateAddressGetsNoResolvedGeoFromZenarmor(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"RFC1918 v4", "10.0.90.119"}, // the exact address from the #639 prod evidence
		{"RFC4193 ULA v6", "fd00::1"},
		{"loopback v4", "127.0.0.1"},
		{"loopback v6", "::1"},
		{"link-local v4", "169.254.1.1"},
		{"link-local v6", "fe80::1"},
		{"v4-mapped RFC1918", "::ffff:10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnricher(t, fakeLookup{}, false)
			r := Record{DstAddr: netip.MustParseAddr(tc.addr)}
			r.Geo.Dst.ZenCountry = "GB"
			r.Geo.Dst.ZenContinent = "EU"
			r.Geo.Dst.ZenCity = "England"
			r.Geo.Dst.ZenRegion = "England"
			e.Enrich(&r)

			if r.Geo.Dst.Country != "" || r.Geo.Dst.CountrySource != "" {
				t.Errorf("%s: Country/CountrySource = %q/%q, want empty (fabricated geo on a private address)",
					tc.addr, r.Geo.Dst.Country, r.Geo.Dst.CountrySource)
			}
			if r.Geo.Dst.Continent != "" {
				t.Errorf("%s: Continent = %q, want empty", tc.addr, r.Geo.Dst.Continent)
			}
			if r.Geo.Dst.City != "" || r.Geo.Dst.Region != "" || r.Geo.Dst.CitySource != "" {
				t.Errorf("%s: City/Region/CitySource = %q/%q/%q, want empty",
					tc.addr, r.Geo.Dst.City, r.Geo.Dst.Region, r.Geo.Dst.CitySource)
			}
			// The raw Zenarmor values must still be retained for audit.
			if r.Geo.Dst.ZenCountry != "GB" || r.Geo.Dst.ZenCity != "England" || r.Geo.Dst.ZenRegion != "England" {
				t.Errorf("%s: raw Zen* fields were discarded: %+v", tc.addr, r.Geo.Dst)
			}
		})
	}
}

// #639 regression guard: a PUBLIC address that is scoped "local" by the box's own
// topology (the AAISP routed IPv6 prefix, verified live and NOT a defect) must still
// get geo. Over-correcting by keying the guard on scope instead of the address itself
// would wrongly blind exactly this case.
func TestGeoPublicAddressScopedLocalStillGetsGeo(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{}, false)
	r := Record{
		DstAddr: netip.MustParseAddr("2001:db8:1f05::100e"),
		Enrich:  Enrichment{DstScope: "local"},
	}
	r.Geo.Dst.ZenCountry = "GB"
	r.Geo.Dst.ZenCity = "England"
	e.Enrich(&r)
	if r.Geo.Dst.Country != "GB" || r.Geo.Dst.CountrySource != GeoSourceZenarmor {
		t.Errorf("a public address scoped local lost its geo: %+v", r.Geo.Dst)
	}
	if r.Geo.Dst.City != "England" || r.Geo.Dst.CitySource != GeoSourceZenarmor {
		t.Errorf("a public address scoped local lost its city: %+v", r.Geo.Dst)
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
//
// The Zenarmor side is built via a real Enrich() pass, not hand-crafted with only raw
// Zen* fields: mergeGeoEndpoint now reads the zen side's RESOLVED fields (#639/#643),
// so a zen GeoInfo carrying only raw values would not exercise the real code path -
// see the mergeGeoEndpoint doc comment for why that distinction matters.
func TestMergeGeoAppliesThePrecedenceTable(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{
		"192.0.2.4": {CountryISO: "GB", ContinentCode: "EU"}, // no city/region of our own
	}, false)
	zenRec := Record{DstAddr: netip.MustParseAddr("192.0.2.4")}
	zenRec.Geo.Dst.ZenCountry = "GB"
	zenRec.Geo.Dst.ZenContinent = "EU"
	zenRec.Geo.Dst.ZenCity = "London"
	zenRec.Geo.Dst.ZenRegion = "England"
	e.Enrich(&zenRec) // simulates the Zenarmor lane's own Enrich() pass

	// The NetFlow side already carries OUR lookup, including a city of its own.
	nf := GeoInfo{Dst: GeoEndpoint{
		Country: "US", Continent: "NA", City: "Ashburn", Region: "VA",
		ASN: 15169, ASOrg: "Google", CountrySource: GeoSourceMaxMind, CitySource: GeoSourceMaxMind,
	}}
	MergeGeo(&nf, zenRec.Geo)

	if nf.Dst.Country != "US" || nf.Dst.CountrySource != GeoSourceMaxMind {
		t.Errorf("country: ours must still win after a merge: %+v", nf.Dst)
	}
	if nf.Dst.ZenCountry != "GB" {
		t.Errorf("Zenarmor's raw country was discarded by the merge: %+v", nf.Dst)
	}
	// City (#643): MaxMind already won on the NetFlow side, so the merge must NOT
	// overwrite it with Zenarmor's, even though Zenarmor has one too.
	if nf.Dst.City != "Ashburn" || nf.Dst.Region != "VA" || nf.Dst.CitySource != GeoSourceMaxMind {
		t.Errorf("city: MaxMind must still win after a merge: %+v", nf.Dst)
	}
	if nf.Dst.ZenCity != "London" || nf.Dst.ZenRegion != "England" {
		t.Errorf("Zenarmor's raw city/region were discarded by the merge: %+v", nf.Dst)
	}
	// ASN is ours only and the merge must not touch it.
	if nf.Dst.ASN != 15169 {
		t.Errorf("ASN = %d, want 15169", nf.Dst.ASN)
	}
}

// With no database of our own, a merge is how a NetFlow-derived record gets any geo
// at all - the country/continent/city fallback case of #643's precedence, exercised
// through MergeGeo rather than endpoint() directly.
func TestMergeGeoFallsBackToZenarmorEntirely(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{}, false)
	zenRec := Record{DstAddr: netip.MustParseAddr("198.51.100.4")}
	zenRec.Geo.Dst.ZenCountry = "DE"
	zenRec.Geo.Dst.ZenContinent = "EU"
	zenRec.Geo.Dst.ZenCity = "Berlin"
	e.Enrich(&zenRec)

	nf := GeoInfo{}
	MergeGeo(&nf, zenRec.Geo)
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

// #643 through MergeGeo: MaxMind must win the city field on a merged record too, with
// Zenarmor as the fallback only when the NetFlow side has no city of its own -
// otherwise the flip in endpoint() would be visible on a Zenarmor-only record but
// silently absent on opnsense_source="merged" ones, which is exactly what the #643
// evidence (72% of remote destinations) was measured on.
func TestMergeGeoAppliesTheCityPrecedenceTable(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{
		"198.51.100.4": {CountryISO: "US"}, // no city of our own for this address
	}, false)
	zenRec := Record{DstAddr: netip.MustParseAddr("198.51.100.4")}
	zenRec.Geo.Dst.ZenCountry = "US"
	zenRec.Geo.Dst.ZenCity = "Montreal"
	zenRec.Geo.Dst.ZenRegion = "Quebec"
	e.Enrich(&zenRec) // simulates the Zenarmor lane's own Enrich() pass

	// The NetFlow side ran its own Enrich() against the same address and also has no
	// city of its own, but did get the country.
	fallback := GeoInfo{Dst: GeoEndpoint{Country: "US", CountrySource: GeoSourceMaxMind}}
	MergeGeo(&fallback, zenRec.Geo)
	if fallback.Dst.City != "Montreal" || fallback.Dst.Region != "Quebec" || fallback.Dst.CitySource != GeoSourceZenarmor {
		t.Errorf("Zenarmor city fallback did not merge in: %+v", fallback.Dst)
	}

	// Now the case where MaxMind DOES have a city on the NetFlow side already: it
	// must not be overwritten by Zenarmor's anycast-wrong one, even on merge.
	winner := GeoInfo{Dst: GeoEndpoint{
		City: "Ashburn", Region: "VA", CitySource: GeoSourceMaxMind,
		Country: "US", CountrySource: GeoSourceMaxMind,
	}}
	MergeGeo(&winner, zenRec.Geo)
	if winner.Dst.City != "Ashburn" || winner.Dst.CitySource != GeoSourceMaxMind {
		t.Errorf("MaxMind city was overwritten by Zenarmor's on merge: %+v", winner.Dst)
	}
}

// #639 through MergeGeo: the private-address guard must hold for a merged record too,
// not just endpoint() directly - this is the shape the prod evidence (921k
// records/day, opnsense_source="merged") was actually measured on.
func TestMergeGeoAppliesThePrivateAddressGuard(t *testing.T) {
	e := newTestEnricher(t, fakeLookup{}, false)
	zenRec := Record{DstAddr: netip.MustParseAddr("10.0.90.119")}
	zenRec.Geo.Dst.ZenCountry = "GB"
	zenRec.Geo.Dst.ZenCity = "England"
	zenRec.Geo.Dst.ZenRegion = "England"
	e.Enrich(&zenRec) // simulates the Zenarmor lane's own Enrich() pass

	nf := GeoInfo{} // the NetFlow side never got a MaxMind hit for this address either
	MergeGeo(&nf, zenRec.Geo)

	if nf.Dst.Country != "" || nf.Dst.CountrySource != "" {
		t.Errorf("merged record fabricated a country on a private address: %+v", nf.Dst)
	}
	if nf.Dst.City != "" || nf.Dst.Region != "" || nf.Dst.CitySource != "" {
		t.Errorf("merged record fabricated a city on a private address: %+v", nf.Dst)
	}
	// Raw values still travel through the merge for audit.
	if nf.Dst.ZenCountry != "GB" || nf.Dst.ZenCity != "England" || nf.Dst.ZenRegion != "England" {
		t.Errorf("raw Zen* fields lost in the merge: %+v", nf.Dst)
	}
}
