package flow

import (
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/rknightion/opnsense2otel/v5/internal/geoip"
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
// that cost be measured rather than assumed. "Never discarded" is about these RAW
// fields specifically (#639): a private/reserved address still keeps its Zen* values
// for audit even though the RESOLVED fields below (Country/Continent/City/Region) and
// their *Source provenance are suppressed for it.
type GeoEndpoint struct {
	// Country is the ISO 3166-1 alpha-2 code the dashboards read. Resolved
	// ours-wins-else-Zenarmor; CountrySource names which answered.
	Country   string
	Continent string
	// City is resolved ours-wins-else-Zenarmor (#643); CitySource names which
	// answered. This reverses the original zenarmor-wins call: on the deployment that
	// call was made against, Zenarmor's city data turned out to be anycast-wrong for
	// remote destinations (Cloudflare/anycast resolving to Montreal from a London
	// line) and subdivision-level for local ones ("England"), while the deployment
	// runs GeoLite2-City specifically to get city/region without depending on
	// Zenarmor at all.
	City string
	// Region is the most specific subdivision, resolved with City and from the same
	// record, so CitySource covers it too and follows the same #643 precedence.
	// Neither field is ever resolved for a private/reserved address (#639), whichever
	// source would have answered. NOTE the format differs by source and the
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
	// MergeAddressMismatches counts correlator merges where the Zenarmor record and
	// the NetFlow record could not be lined up in EITHER orientation, so no geo was
	// folded across (#647). It should sit at or near zero: the correlator paired the
	// two records by connection key, so their addresses agreeing is the premise of
	// the merge, not a hope. A climbing counter means that premise is false and the
	// merged records are missing Zenarmor's contribution entirely — which is worth
	// knowing, because the previous behaviour was to merge anyway and attach each
	// end's geo to the wrong address.
	MergeAddressMismatches uint64
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

	enriched        atomic.Uint64
	agreements      atomic.Uint64
	disagreements   atomic.Uint64
	mergeMismatches atomic.Uint64
}

// countMergeMismatch records one unpairable correlator merge (#647). It hangs off
// the process-wide enricher rather than being threaded through MergeGeo's signature
// because MergeGeo is deliberately package-level - the correlator builds merged
// records in a package that never sees main's wiring. Nil-safe: an un-wired build
// counts nothing rather than panicking, matching every other method here.
func (e *GeoEnricher) countMergeMismatch() {
	if e == nil {
		return
	}
	e.mergeMismatches.Add(1)
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

	// #639: an address in private/reserved space (RFC1918, RFC4193 ULA, loopback,
	// link-local, unspecified - and the v4-mapped form of any of those, since
	// IsGloballyRoutable unwraps them first) gets no RESOLVED geo from ANY source. Our
	// own database already enforces this on its own arm - Lookup returns Result{},
	// false for such an address, so res is always zero here and always was - which is
	// exactly why the bug was invisible on the MaxMind path and only live on
	// Zenarmor's: the switches below gate the Zenarmor fallback arms on it explicitly.
	// Deliberately keyed on the ADDRESS, never on topology scope: the AAISP routed
	// IPv6 prefix is publicly routable and legitimately geolocated GB even though it
	// is scoped "local" on this box's topology - keying the guard on scope instead
	// would wrongly blind that case.
	//
	// This does NOT touch the raw Zen* fields: they are retained regardless (see the
	// GeoEndpoint doc comment), so Zenarmor's answer for a private address stays
	// visible for audit - it just cannot reach Country/Continent/City/Region.
	private := !geoip.IsGloballyRoutable(addr)

	// Country and continent: OURS WINS. The dashboards read this field, so its
	// meaning must not vary by which receiver happened to see the flow. Zenarmor's
	// value stays in ZenCountry either way.
	switch {
	case res.CountryISO != "":
		g.Country, g.CountrySource = res.CountryISO, GeoSourceMaxMind
	case g.ZenCountry != "" && !private:
		g.Country, g.CountrySource = g.ZenCountry, GeoSourceZenarmor
	}
	switch {
	case res.ContinentCode != "":
		g.Continent = res.ContinentCode
	case g.ZenContinent != "" && !private:
		g.Continent = g.ZenContinent
	}

	// City and region (#643): OURS WINS when present, Zenarmor as the fallback. This
	// reverses the original zenarmor-wins call - see the GeoEndpoint.City doc comment
	// for why - and follows the same private-address guard as country/continent
	// above.
	switch {
	case res.City != "" || res.RegionISO != "":
		g.City, g.Region, g.CitySource = res.City, res.RegionISO, GeoSourceMaxMind
	case (g.ZenCity != "" || g.ZenRegion != "") && !private:
		g.City, g.Region, g.CitySource = g.ZenCity, g.ZenRegion, GeoSourceZenarmor
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
//
// # Endpoints are paired by ADDRESS, never by position (#647)
//
// It takes whole Records rather than bare GeoInfo because the addresses are the only
// thing that says which end is which. A Zenarmor conn document records a connection
// from the initiator's side (private -> public); the NetFlow fragment being merged
// may be the RETURN direction (public -> private). Pairing Src<-Src and Dst<-Dst
// positionally then attaches each end's geo to the opposite address.
//
// Measured live on the prod box 2026-08-04, record
// a Cloudflare anycast address :443 -> 10.0.50.4:34210, where two values could only
// have come from
// the other end:
//
//   - the PUBLIC Cloudflare src carried zen_country GB — GB is what Zenarmor
//     fabricates for the PRIVATE host
//   - the PRIVATE dst carried zen_country CA and city Toronto — Zenarmor's known
//     anycast-wrong answer for CLOUDFLARE (#643 recorded exactly this)
//
// Both ends were wrong; only the dst was visible, because a public src re-resolves
// itself through endpoint() and overwrites the bad merge, while a private dst has no
// lookup of its own and nothing overwrites what the merge put there. That is what
// made it look like a missing #639 guard when the guard was working correctly.
//
// Orientation is resolved ONCE for the record rather than per endpoint: a per-endpoint
// match would happily accept a half-alignment, and two records that agree about one
// address but not the other are not describing the same connection — merging half of
// one into the other is worse than merging none of it.
func MergeGeo(dst *Record, zen Record) {
	if dst == nil {
		return
	}
	switch {
	case sameEndpointAddr(zen.SrcAddr, dst.SrcAddr) && sameEndpointAddr(zen.DstAddr, dst.DstAddr):
		mergeGeoEndpoint(&dst.Geo.Src, zen.Geo.Src)
		mergeGeoEndpoint(&dst.Geo.Dst, zen.Geo.Dst)
	case sameEndpointAddr(zen.SrcAddr, dst.DstAddr) && sameEndpointAddr(zen.DstAddr, dst.SrcAddr):
		// Reversed: the Zenarmor document describes the same connection from the
		// other side. Fold each end onto the address it actually describes.
		mergeGeoEndpoint(&dst.Geo.Src, zen.Geo.Dst)
		mergeGeoEndpoint(&dst.Geo.Dst, zen.Geo.Src)
	default:
		// Neither orientation lines up, so the two records disagree about which
		// connection this is. Merge NOTHING and count it: silently falling back to a
		// positional merge here is precisely the bug this function was rewritten for,
		// and a mismatch that is invisible cannot be diagnosed.
		GeoEnrichment.countMergeMismatch()
	}
}

// sameEndpointAddr reports whether two records name the same host at an endpoint.
//
// Unmapped on both sides for the same reason IsGloballyRoutable does it: the two
// lanes need not agree on representation, and ::ffff:10.0.50.4 and 10.0.50.4 are one
// address wearing two costumes. Comparing them raw would report a mismatch on every
// merged record where the receivers happened to differ, which would quietly turn the
// merge off rather than fix it.
//
// An invalid address matches nothing, including another invalid one — "we do not
// know this end" is not evidence that two records describe the same host.
func sameEndpointAddr(a, b netip.Addr) bool {
	if !a.IsValid() || !b.IsValid() {
		return false
	}
	return a.Unmap() == b.Unmap()
}

// mergeGeoEndpoint folds one Zenarmor-side endpoint's geo into one NetFlow-side
// endpoint's geo.
//
// #639/#643 TRAP, fixed here: this reads zen's RESOLVED fields (zen.Country,
// zen.City, zen.CountrySource, zen.CitySource, zen.Continent) - NEVER the raw Zen*
// fields copied below. The Zenarmor-side record already ran through endpoint()
// against the exact same address dst was itself resolved against (the Zenarmor
// receiver calls Enrich() on its own record before it ever reaches the correlator),
// which is where #639's private-address guard and #643's MaxMind-wins-city
// precedence are enforced. So zen.Country/zen.City already carry both correctly.
// Re-deriving from the raw Zen* fields here - as an earlier version of this function
// did - silently bypasses both on every merged record: a private address gets a
// fabricated country again, and Zenarmor's anycast-wrong city wins over MaxMind's
// regardless of the switch in endpoint(). That is exactly the shape the #639 prod
// evidence was measured on: opnsense_source="merged" records, not endpoint()-only
// ones.
func mergeGeoEndpoint(dst *GeoEndpoint, zen GeoEndpoint) {
	// Raw Zenarmor values are retained unconditionally, regardless of address: the
	// private-address guard suppresses only the resolved fields below, never these.
	dst.ZenCountry, dst.ZenContinent = zen.ZenCountry, zen.ZenContinent
	dst.ZenCity, dst.ZenRegion = zen.ZenCity, zen.ZenRegion

	// Country: ours already won if our database answered, which CountrySource
	// records. zen.Country is empty when Zenarmor had nothing OR when #639's guard
	// suppressed it on the zen side's own Enrich() pass - either way there is nothing
	// safe to merge in.
	if dst.CountrySource != GeoSourceMaxMind && zen.Country != "" {
		dst.Country, dst.CountrySource = zen.Country, zen.CountrySource
	}
	if dst.Continent == "" {
		dst.Continent = zen.Continent
	}
	// City/region (#643): MaxMind wins here too - only fall back to Zenarmor's
	// already-guarded, already-resolved city when dst has none of its own from
	// MaxMind.
	if dst.CitySource != GeoSourceMaxMind && zen.City != "" {
		dst.City, dst.Region, dst.CitySource = zen.City, zen.Region, zen.CitySource
	}
}

// Stats returns the enrichment's own counters.
func (e *GeoEnricher) Stats() GeoStats {
	if e == nil {
		return GeoStats{}
	}
	return GeoStats{
		Enriched:               e.enriched.Load(),
		CountryAgreements:      e.agreements.Load(),
		CountryDisagreements:   e.disagreements.Load(),
		MergeAddressMismatches: e.mergeMismatches.Load(),
	}
}
