package syslog

import (
	"testing"

	"github.com/rknightion/opnsense2otel/v5/internal/geoip"
)

// TestGeoByteCost measures the actual per-line byte cost the four #528 log
// attributes (country, continent, asn, as_org — no city/region) add to a
// filterlog record, per the issue's required acceptance item: "measure the real
// per-line byte cost against a captured filterlog stream before this defaults on"
// (mirroring #475, which measured Zenarmor's lat/lon at 145-149 B/line for exactly
// this reason and removed them).
//
// The measurement is key+value byte length summed over every geo.* attribute
// geoAttrs would add for one endpoint, which is the same accounting #475 used.
//
// MaxMind's own test fixtures (internal/geoip/testdata) are real mmdb files but
// carry only a handful of synthetic records with no representative variety of
// autonomous-system organization NAMES — the one thing that varies enough to move
// this number. So this test scores a representative SAMPLE of real-world AS org
// strings (ISPs, cloud and hosting providers that commonly appear as the source of
// inbound firewall-block traffic) rather than the two names the test fixtures
// happen to carry. Country/continent/ASN-number formatting is exact and taken
// straight from geoAttrs; only the org-name corpus is representative rather than
// captured, and that is exactly the number the issue asks to be measured before
// as_org ships.
func TestGeoByteCost(t *testing.T) {
	samples := []geoip.Result{
		{CountryISO: "US", ContinentCode: "NA", ASN: 15169, ASOrg: "Google LLC"},
		{CountryISO: "CN", ContinentCode: "AS", ASN: 4134, ASOrg: "Chinanet"},
		{CountryISO: "CN", ContinentCode: "AS", ASN: 4837, ASOrg: "CHINA UNICOM China169 Backbone"},
		{CountryISO: "RU", ContinentCode: "EU", ASN: 197695, ASOrg: "JSC iPipe"},
		{CountryISO: "NL", ContinentCode: "EU", ASN: 60781, ASOrg: "LeaseWeb Netherlands B.V."},
		{CountryISO: "US", ContinentCode: "NA", ASN: 14061, ASOrg: "DIGITALOCEAN-ASN"},
		{CountryISO: "SG", ContinentCode: "AS", ASN: 135377, ASOrg: "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED"},
		{CountryISO: "DE", ContinentCode: "EU", ASN: 24940, ASOrg: "Hetzner Online GmbH"},
		{CountryISO: "BR", ContinentCode: "SA", ASN: 28573, ASOrg: "CLARO S.A."},
		{CountryISO: "IN", ContinentCode: "AS", ASN: 55836, ASOrg: "Reliance Jio Infocomm Limited"},
	}

	var (
		totalBytes, totalASOrgBytes int
		maxBytes, maxASOrgBytes     int
	)
	for _, res := range samples {
		attrs := map[string]string{}
		geoLookup = fakeGeoLookup{results: map[string]geoip.Result{"203.0.113.1": res}}
		geoAttrs(func(k, v string) { attrs[k] = v }, "src", "203.0.113.1")
		geoLookup = nil

		n := attrBytes(attrs)
		asOrgN := len("src.geo.as_org") + len(res.ASOrg)
		totalBytes += n
		totalASOrgBytes += asOrgN
		if n > maxBytes {
			maxBytes = n
		}
		if asOrgN > maxASOrgBytes {
			maxASOrgBytes = asOrgN
		}
	}

	avgBytes := totalBytes / len(samples)
	avgASOrgBytes := totalASOrgBytes / len(samples)

	t.Logf("one endpoint: average %d B/line (as_org averages %d B, %.0f%% of the total)",
		avgBytes, avgASOrgBytes, 100*float64(avgASOrgBytes)/float64(avgBytes))
	t.Logf("one endpoint: worst case %d B/line (worst as_org %d B, %.0f%% of that line)",
		maxBytes, maxASOrgBytes, 100*float64(maxASOrgBytes)/float64(maxBytes))
	t.Logf("both endpoints (worst case, transit traffic): average %d B/line, worst case %d B/line",
		2*avgBytes, 2*maxBytes)

	// Sanity bounds, not a precision assertion — the sample is representative, not
	// captured, so only gross regressions should fail this test.
	if avgBytes <= 0 || maxBytes <= avgBytes {
		t.Fatalf("implausible measurement: avg=%d max=%d", avgBytes, maxBytes)
	}
}

// attrBytes sums key+value byte length over a geo attribute set, the same
// accounting #475 used to measure Zenarmor's removed lat/lon fields.
func attrBytes(attrs map[string]string) int {
	n := 0
	for k, v := range attrs {
		n += len(k) + len(v)
	}
	return n
}
