package zenarmor

import (
	"strings"
	"testing"
)

// orgDoc is a flow document whose organization is NON-EMPTY. Every captured fixture
// in fixtures_test.go carries `"organization":""`, which set() skips anyway — so a
// test written against those would pass whether or not the key is attributed, and
// prove nothing about #475.
const orgDoc = `{"transport_proto":"TCP","policyid":"7","organization":"m7kni",` +
	`"interface":"ixl0","vlanid":"0","conn_uuid":"9d2f0e11-0000-4000-8000-000000000001",` +
	`"direction":"out","ip_src_saddr":"10.0.0.5","ip_src_port":51000,` +
	`"ip_dst_saddr":"1.1.1.1","ip_dst_port":443,"is_blocked":0,"start_time":1784224295000,` +
	`"app_proto":"TLS","app_name":"Cloudflare","app_category":"Network"}`

// #475: `organization` and `policyid` were measured at exactly ONE distinct value each
// over a 600-line live sample of every Zenarmor family, and nothing reads them —
// no dashboard panel, no alert rule, no derived metric. They are pure per-line
// constants in structured metadata, which Grafana Cloud bills as ingested volume.
//
// The record must not get poorer for it: the body is the document verbatim, so both
// values are still there for anyone who needs them on a specific line.
func TestConstantZenarmorMetadataIsNotAttributed(t *testing.T) {
	rec, ok := buildRecord("flow", []byte(orgDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	for _, k := range []string{"organization", "policyid"} {
		if v, present := rec.Attributes[k]; present {
			t.Errorf("attribute %q = %q was shipped; it is a per-line constant (#475) and "+
				"the body already carries it", k, v)
		}
	}
	assertBodyIsVerbatim(t, rec, orgDoc)
	// Belt and braces: the body really is the place the values survive.
	for _, want := range []string{`"organization":"m7kni"`, `"policyid":"7"`} {
		if !strings.Contains(rec.Body, want) {
			t.Errorf("body lost %s; pruning the attribute must not lose the datum", want)
		}
	}
	// The fields around them are untouched — this prunes two keys, not the geo/app block.
	assertAttr(t, rec, "app_name", "Cloudflare")
	assertAttr(t, rec, attrInterfaceDev, "ixl0")
}

// #475: latitude/longitude are the single most expensive geo keys on the wire —
// ~18 significant figures each, four of them per line (src+dst), measured at
// 145-149 B/line on the flow family alone. Nothing consumes them: the dashboard's
// geo panel ranks `dst_geoip_country_name`, and derive.go reads no geo at all. The
// coarse geo it DOES use has to survive untouched.
func TestGeoCoordinatesAreNotAttributed(t *testing.T) {
	rec, ok := buildRecord("tls", []byte(tlsDoc), nil)
	if !ok {
		t.Fatal("buildRecord returned !ok")
	}
	for _, k := range []string{
		"src_geoip.latitude", "src_geoip.longitude",
		"dst_geoip.latitude", "dst_geoip.longitude",
	} {
		if v, present := rec.Attributes[k]; present {
			t.Errorf("attribute %q = %q was shipped; coordinates are duplicated precision (#475)", k, v)
		}
	}
	// What the dashboard actually ranks on.
	assertAttr(t, rec, "dst_geoip.country_name", "China")
	assertAttr(t, rec, "dst_geoip.country_code2", "CN")
	assertAttr(t, rec, "dst_geoip.city_name", "Guangdong")
	// The coordinates are not lost, they are just not re-extracted: the body is the
	// document verbatim and carries both the flat pair and Zenarmor's nested
	// location{lat,lon} copy.
	if !strings.Contains(rec.Body, `"latitude":23.13170051574707`) {
		t.Error("body lost the latitude; pruning the attribute must not lose the datum")
	}
}
