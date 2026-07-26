package zenarmor

import (
	"encoding/json"
	"net/netip"
	"testing"
)

// maxZenarmorFuzzDocument bounds one direct parser invocation. HTTP ingestion has
// a larger request-body ceiling, but a document is parsed independently and the
// focused fuzz harness must not turn an input mutation into an unbounded allocation.
const maxZenarmorFuzzDocument = 64 << 10

// parseDoc maps a fixed union of JSON fields to at most 57 attributes with a nil
// enrichment snapshot. Keep a little headroom while making accidental unbounded
// attribute growth visible to the fuzz target.
const maxZenarmorFuzzAttributes = 64

const syntheticZenarmorSeedMarker = "synthetic-fuzz-fixture"

var syntheticZenarmorSeeds = []struct {
	family string
	doc    string
}{
	{"flow", `{"_fuzz_fixture":"synthetic-fuzz-fixture","transport_proto":"UDP","interface":"fuzz0","ip_src_saddr":"192.0.2.1","ip_dst_saddr":"198.51.100.2","is_blocked":0,"app_name":"test-app","app_category":"test"}`},
	{"dns", `{"_fuzz_fixture":"synthetic-fuzz-fixture","transport_proto":"UDP","interface":"fuzz0","ip_src_saddr":"192.0.2.1","ip_dst_saddr":"198.51.100.2","is_blocked":0,"query":"example.invalid","qtype":"A","resp_code":0,"domain_categories":["test"]}`},
	{"tls", `{"_fuzz_fixture":"synthetic-fuzz-fixture","transport_proto":"TCP","interface":"fuzz0","ip_src_saddr":"192.0.2.1","ip_dst_saddr":"198.51.100.2","is_blocked":0,"server_name":"example.invalid","category":"test"}`},
	{"web", `{"_fuzz_fixture":"synthetic-fuzz-fixture","transport_proto":"TCP","interface":"fuzz0","ip_src_saddr":"192.0.2.1","ip_dst_saddr":"198.51.100.2","is_blocked":0,"method":"GET","host":"example.invalid","uri":"/fuzz","status_msg":"200"}`},
	{"ids", `{"_fuzz_fixture":"synthetic-fuzz-fixture","transport_proto":"UDP","interface":"fuzz0","ip_src_saddr":"192.0.2.1","ip_dst_saddr":"198.51.100.2","is_blocked":1,"alert_category":"test","alert_severity":"1","alertinfo":{"action":"reject","signature":["test"],"category":["test"],"sid":"1","severity":1}}`},
	{"voip", `{"_fuzz_fixture":"synthetic-fuzz-fixture","transport_proto":"UDP","interface":"fuzz0","ip_src_saddr":"192.0.2.1","ip_dst_saddr":"198.51.100.2","is_blocked":0,"sip_method":"INVITE","sip_uri":"sip:100@example.invalid","sip_status":"200"}`},
}

// TestFuzzParseDocumentSeedsAreSynthetic makes the corpus policy reviewable in
// code: each valid seed identifies itself as synthetic and uses only RFC 5737
// documentation addresses. The malformed seed below is an invented plain string.
func TestFuzzParseDocumentSeedsAreSynthetic(t *testing.T) {
	t.Helper()
	wantFamilies := map[string]bool{
		"flow": true, "dns": true, "tls": true, "web": true, "ids": true, "voip": true,
	}
	for _, seed := range syntheticZenarmorSeeds {
		var document map[string]any
		if err := json.Unmarshal([]byte(seed.doc), &document); err != nil {
			t.Fatalf("synthetic %s seed is invalid JSON: %v", seed.family, err)
		}
		if got, _ := document["_fuzz_fixture"].(string); got != syntheticZenarmorSeedMarker {
			t.Fatalf("%s seed marker = %q, want %q", seed.family, got, syntheticZenarmorSeedMarker)
		}
		for _, key := range []string{"ip_src_saddr", "ip_dst_saddr"} {
			address, err := netip.ParseAddr(document[key].(string))
			if err != nil || (!netip.MustParsePrefix("192.0.2.0/24").Contains(address) && !netip.MustParsePrefix("198.51.100.0/24").Contains(address)) {
				t.Fatalf("%s seed %s = %q, want a documentation address", seed.family, key, document[key])
			}
		}
		if !wantFamilies[seed.family] {
			t.Fatalf("unexpected synthetic seed family %q", seed.family)
		}
		delete(wantFamilies, seed.family)
	}
	if len(wantFamilies) != 0 {
		t.Fatalf("missing synthetic seed families: %v", wantFamilies)
	}
}

// FuzzParseDocument seeds every known document family with compact synthetic
// documents. parseDoc deliberately ships malformed JSON verbatim, so the invariant
// applies to both parsed and raw-fallback records.
func FuzzParseDocument(f *testing.F) {
	for _, seed := range syntheticZenarmorSeeds {
		f.Add(seed.family, []byte(seed.doc))
	}
	f.Add("flow", []byte("synthetic malformed fuzz fixture"))

	f.Fuzz(func(t *testing.T, family string, doc []byte) {
		if len(family) > 16 || len(doc) > maxZenarmorFuzzDocument {
			t.Skip()
		}

		record, _ := parseDoc(family, doc, nil)
		if record.Body != string(doc) {
			t.Fatal("record body is not a verbatim copy of the input document")
		}
		if len(record.Attributes) > maxZenarmorFuzzAttributes {
			t.Fatalf("record has %d attributes, limit is %d", len(record.Attributes), maxZenarmorFuzzAttributes)
		}
	})
}
