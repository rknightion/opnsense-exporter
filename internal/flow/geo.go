package flow

import (
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
)

// Provenance values for GeoEndpoint.CountrySource / CitySource.
//
// These are REQUIRED on every enriched endpoint, not decorative. City's source
// legitimately varies by deployment — Zenarmor's commercial GeoIP2-City build where
// the plugin saw the flow, ours everywhere else — and a field that quietly means two
// different things depending on plugin state is exactly the class of defect #491
// spent a whole sweep finding. The attribute is what makes the variation explicit.
const (
	GeoSourceMaxMind  = "maxmind"
	GeoSourceZenarmor = "zenarmor"
)

// GeoEndpoint is one end of a flow's geolocation.
//
// Two groups of fields, and the split is the whole design:
//
//   - Country and Continent are BOUNDED (~250 and 7 values) and are the only ones
//     that may reach a metric label, and only behind --flow.geoip.metric-dims.
//   - City, Region, ASN and ASOrg are NOT usefully bounded and are LOG-ONLY.
//
// Zen* are Zenarmor's own values, kept verbatim. They are never discarded, because
// ours-wins on country is not free: Zenarmor's database is a commercial GeoIP2-City
// build (read off a live firewall: database_type "GeoIP2-City", 126 MB against
// CrowdSec's 63 MB stock GeoLite2), so overwriting its answer with a free GeoLite2
// lookup can replace a better attribution with a worse one. Keeping both is what lets
// that cost be measured rather than assumed.
type GeoEndpoint struct {
	// Country is the ISO 3166-1 alpha-2 code the dashboards read. Resolved
	// ours-wins-else-Zenarmor; CountrySource names which answered.
	Country   string
	Continent string
	// City is resolved Zenarmor-wins-else-ours; CitySource names which answered.
	City string
	// Region is the most specific subdivision, resolved with City and from the same
	// record, so CitySource covers it too. NOTE the format differs by source and the
	// provenance attribute is how a consumer tells them apart: MaxMind gives the ISO
	// 3166-2 code ("ENG"), Zenarmor gives a name ("England"). Neither is normalised
	// into the other, because inventing a mapping would be fabricating data.
	Region string
	// ASN and ASOrg are OURS ONLY. Zenarmor ships no ASN database on any box — its
	// asn field was the string "0" on every record of the capture box, and "0" is its
	// empty value rather than AS0 (see zenarmor/parse.go). This is the one thing no
	// amount of Zenarmor coverage would ever supply.
	ASN   uint
	ASOrg string

	// CountrySource / CitySource are the provenance attributes. Empty when the
	// corresponding field is empty.
	CountrySource string
	CitySource    string

	// Zenarmor's raw values, retained alongside the resolved ones.
	ZenCountry   string
	ZenContinent string
	ZenCity      string
	ZenRegion    string
}

// Empty reports whether this endpoint carries no geo fact at all.
func (g GeoEndpoint) Empty() bool { return g == GeoEndpoint{} }

// GeoInfo is both ends of a flow's geolocation.
type GeoInfo struct {
	Src GeoEndpoint
	Dst GeoEndpoint
}

// GeoStats is the enrichment's own health, published as self-metrics.
type GeoStats struct {
	// Enriched counts records that got at least one fact out of OUR database. It is
	// the "is this feature doing anything at all" signal, and it is what distinguishes
	// "no database loaded" from "a network whose traffic is all internal".
	Enriched uint64
	// CountryAgreements / CountryDisagreements count records where BOTH databases
	// answered on the same endpoint. The disagreement counter is the point: ours-wins
	// is a deliberate trade of accuracy for consistency, and without a denominator
	// beside it the cost of that trade is assumed rather than measured.
	CountryAgreements    uint64
	CountryDisagreements uint64
}

// GeoEnricher applies MaxMind lookups to a flow Record and resolves the per-field
// precedence between our database and Zenarmor's.
//
// A nil *GeoEnricher, and one built with a nil Lookup, are both complete no-ops: the
// geo attributes are simply absent. That is the fail-open contract — geo enrichment
// must never be able to stop a flow record being emitted.
type GeoEnricher struct {
	lk geoip.Lookup
	// metricDims gates the country METRIC label only. Log attributes are
	// unconditional; a label multiplies the flow series roughly 250-fold.
	metricDims bool

	enriched      atomic.Uint64
	agreements    atomic.Uint64
	disagreements atomic.Uint64
}

// NewGeoEnricher returns an enricher over lk. metricDims mirrors
// --flow.geoip.metric-dims.
func NewGeoEnricher(lk geoip.Lookup, metricDims bool) *GeoEnricher {
	return &GeoEnricher{lk: lk, metricDims: metricDims}
}

// GeoEnrichment is the process-wide enricher both receiver lanes reach.
//
// A singleton for the same reason as collector.Flow and flowlog.Sink: the Zenarmor
// adapter and the NetFlow processor each build their own records in packages that do
// not see main's wiring, and threading a lookup through both constructors would mean
// two more seams for the same value. Nil until ConfigureGeoIP runs, and a nil
// enricher is a no-op, so an un-wired build enriches nothing rather than panicking.
var GeoEnrichment *GeoEnricher

// ConfigureGeoIP installs the process-wide enricher. main calls it once, before any
// receiver is started.
func ConfigureGeoIP(lk geoip.Lookup, metricDims bool) {
	GeoEnrichment = NewGeoEnricher(lk, metricDims)
}

// Enrich fills r.Geo from the loaded databases, applying the per-field precedence.
//
// Zenarmor's values must already be on the record (the Zenarmor adapter puts them
// there); this never reads a Zenarmor document itself. Calling it twice is safe but
// pointless — the second pass resolves the same fields to the same values.
func (e *GeoEnricher) Enrich(r *Record) {
	if e == nil || e.lk == nil || r == nil {
		return
	}
	srcHit := e.endpoint(&r.Geo.Src, r.SrcAddr)
	dstHit := e.endpoint(&r.Geo.Dst, r.DstAddr)
	if srcHit || dstHit {
		e.enriched.Add(1)
	}
}

// endpoint resolves one end, reporting whether OUR database answered.
func (e *GeoEnricher) endpoint(g *GeoEndpoint, addr netip.Addr) bool {
	// Normalise Zenarmor's country before anything compares against it: the wire
	// value has been seen lowercase, and a case difference is not a disagreement.
	g.ZenCountry = strings.ToUpper(strings.TrimSpace(g.ZenCountry))
	g.ZenContinent = strings.ToUpper(strings.TrimSpace(g.ZenContinent))

	var res geoip.Result
	var hit bool
	if addr.IsValid() {
		res, hit = e.lk.Lookup(addr)
	}

	// Country and continent: OURS WINS. The dashboards read this field, so its
	// meaning must not vary by which receiver happened to see the flow. Zenarmor's
	// value stays in ZenCountry either way.
	switch {
	case res.CountryISO != "":
		g.Country, g.CountrySource = res.CountryISO, GeoSourceMaxMind
	case g.ZenCountry != "":
		g.Country, g.CountrySource = g.ZenCountry, GeoSourceZenarmor
	}
	switch {
	case res.ContinentCode != "":
		g.Continent = res.ContinentCode
	case g.ZenContinent != "":
		g.Continent = g.ZenContinent
	}

	// City and region: ZENARMOR WINS when present, ours as the fallback. Theirs is a
	// commercial GeoIP2-City build; ours is the only source on the vast majority of
	// boxes, which have no Zenarmor at all.
	switch {
	case g.ZenCity != "" || g.ZenRegion != "":
		g.City, g.Region, g.CitySource = g.ZenCity, g.ZenRegion, GeoSourceZenarmor
	case res.City != "" || res.RegionISO != "":
		g.City, g.Region, g.CitySource = res.City, res.RegionISO, GeoSourceMaxMind
	}

	// ASN: ours only.
	g.ASN, g.ASOrg = res.ASN, res.ASOrg

	// The disagreement counter, and its denominator. Only a record where BOTH
	// databases answered can be either.
	if res.CountryISO != "" && g.ZenCountry != "" {
		if res.CountryISO == g.ZenCountry {
			e.agreements.Add(1)
		} else {
			e.disagreements.Add(1)
		}
	}
	return hit
}

// MetricCountry returns the value for the flow rollup's country label: the country of
// the REMOTE end of the flow, or empty.
//
// Empty unless --flow.geoip.metric-dims is set. Empty is also the honest answer for
// internal traffic, where neither end is remote and a country breakdown would be
// meaningless — and Prometheus treats an empty label value as an absent one, so a
// deployment with the opt-in off sees the flow family exactly as it was before #520.
func (e *GeoEnricher) MetricCountry(r Record) string {
	if e == nil || !e.metricDims {
		return ""
	}
	const remote = "remote"
	switch {
	case r.Enrich.DstScope == remote:
		return r.Geo.Dst.Country
	case r.Enrich.SrcScope == remote:
		return r.Geo.Src.Country
	}
	// No scope at all means a cold enrichment snapshot rather than internal traffic
	// (Scope returns "" when the box's own topology is not yet known), so fall back to
	// whichever end we could geolocate. Both ends geolocatable means neither is local,
	// which on a firewall is transit rather than internal.
	if r.Enrich.SrcScope == "" && r.Enrich.DstScope == "" {
		if r.Geo.Dst.Country != "" {
			return r.Geo.Dst.Country
		}
		return r.Geo.Src.Country
	}
	return ""
}

// MergeGeo folds a Zenarmor-derived record's geo into a NetFlow-derived one, for the
// correlator's merged output.
//
// Without this a merged record would silently lose Zenarmor's city, because the
// merged record is built from the NetFlow sample and only the Zenarmor side ever
// carried Zen* values — the precedence table would then mean one thing on a
// Zenarmor-only record and another on a merged one, which is the exact defect the
// provenance attribute exists to prevent.
//
// It deliberately does NOT count an agreement or disagreement. The Zenarmor record
// met our database already, in its own lane, and counting the same comparison twice
// would inflate both sides of the ratio the counter exists to expose.
func MergeGeo(dst *GeoInfo, zen GeoInfo) {
	mergeGeoEndpoint(&dst.Src, zen.Src)
	mergeGeoEndpoint(&dst.Dst, zen.Dst)
}

func mergeGeoEndpoint(dst *GeoEndpoint, zen GeoEndpoint) {
	dst.ZenCountry, dst.ZenContinent = zen.ZenCountry, zen.ZenContinent
	dst.ZenCity, dst.ZenRegion = zen.ZenCity, zen.ZenRegion

	// Country: ours already won if our database answered, which CountrySource records.
	if dst.CountrySource != GeoSourceMaxMind && dst.ZenCountry != "" {
		dst.Country, dst.CountrySource = dst.ZenCountry, GeoSourceZenarmor
	}
	if dst.Continent == "" {
		dst.Continent = dst.ZenContinent
	}
	// City: Zenarmor wins outright.
	if dst.ZenCity != "" || dst.ZenRegion != "" {
		dst.City, dst.Region, dst.CitySource = dst.ZenCity, dst.ZenRegion, GeoSourceZenarmor
	}
}

// Stats returns the enrichment's own counters.
func (e *GeoEnricher) Stats() GeoStats {
	if e == nil {
		return GeoStats{}
	}
	return GeoStats{
		Enriched:             e.enriched.Load(),
		CountryAgreements:    e.agreements.Load(),
		CountryDisagreements: e.disagreements.Load(),
	}
}
