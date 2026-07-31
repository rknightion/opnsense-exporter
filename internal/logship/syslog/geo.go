package syslog

import (
	"net/netip"
	"strconv"

	"github.com/rknightion/opnsense2otel/v4/internal/geoip"
)

// geoSourceMaxMind is the provenance value stamped on every geo attribute this
// package emits. It intentionally matches flow.GeoSourceMaxMind's literal value
// ("maxmind") rather than importing it: the point of #528's shared provenance
// attribute is that one Loki query covering the flow and log streams reads a single
// vocabulary, and that is a property of the two constants agreeing, not of Go-level
// sharing between two otherwise-unrelated packages.
const geoSourceMaxMind = "maxmind"

// geoLookup is the process-wide GeoIP source for the log lanes that name a remote
// peer's own address: filterlog, sshd/auth and Suricata (#528 decision 1). It is nil
// until ConfigureGeoIP installs it, and a nil Lookup is a complete no-op — the geo
// attributes are simply absent — matching the fail-open contract every other GeoIP
// consumer in this repo follows (internal/geoip, flow.GeoEnricher).
//
// This does NOT open a second database. main's startGeoIP opens the MaxMind files
// exactly once and hands the SAME *geoip.DB to both this package and flow.GeoEnrichment.
var geoLookup geoip.Lookup

// ConfigureGeoIP installs the process-wide GeoIP source for these lanes. main calls
// it once, after resolving both --geoip.enabled and the per-lane opt-out
// (--logs.syslog.geoip): lk is nil when either is off, which is what makes both
// switches complete no-ops rather than needing a second code path here.
func ConfigureGeoIP(lk geoip.Lookup) {
	geoLookup = lk
}

// geoAttrs resolves ip's geolocation and adds it under side (e.g. "src"/"dst"),
// mirroring flow.LogAttributes' geoAttrs: identical keys and the same provenance
// attribute, so one Loki query covers both the flow and log streams (#528 decision
// 4). City and region are deliberately NEVER added here — they stay a flow/Zenarmor
// log-only field, not part of this seam.
//
// A miss, an empty/unparseable ip, or a nil geoLookup all leave attrs untouched:
// this must never be able to turn an unenrichable line into an error. Non-global
// addresses never reach the database at all — geoip.DB.Lookup applies
// geoip.Enrichable itself before consulting either database, exactly as flow's
// GeoEnricher relies on the same internal check rather than a second classifier.
func geoAttrs(set func(k, v string), side, ip string) {
	if geoLookup == nil || ip == "" {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	res, hit := geoLookup.Lookup(addr)
	if !hit {
		return
	}
	// country_source is emitted only alongside country, exactly like the flow lane:
	// it is the provenance of that field, not a claim that a lookup merely happened.
	if res.CountryISO != "" {
		set(side+".geo.country", res.CountryISO)
		set(side+".geo.country_source", geoSourceMaxMind)
	}
	if res.ContinentCode != "" {
		set(side+".geo.continent", res.ContinentCode)
	}
	if res.ASN != 0 {
		set(side+".geo.asn", "AS"+strconv.FormatUint(uint64(res.ASN), 10))
	}
	if res.ASOrg != "" {
		set(side+".geo.as_org", res.ASOrg)
	}
}
