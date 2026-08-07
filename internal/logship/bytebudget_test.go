package logship

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// WHERE 2705 BYTES/RECORD CAME FROM (#663, analysis point 5).
//
// The live-box rejection read `'2777' lines totaling '7513325' bytes`, i.e. 2705 bytes
// per line as LOKI measured it, against syslog DNS lines of 100-150 bytes. A ~20x
// multiplier looked like either a runaway structured-metadata set or resource attributes
// being replicated per partition.
//
// IT IS NEITHER, and the premise about which records were in the batch was wrong. The
// dominant record family by BYTES on this box is not syslog at all — it is Zenarmor, and
// a Zenarmor record's Body is the raw NDJSON document VERBATIM (zenarmor/parse.go: "The
// raw line, not a re-encoding of the struct below ... the body is the lossless copy").
// A real captured conn document is ~1.5 kB before a single attribute is added, and ~40
// attributes are then derived from that same JSON and attached as structured metadata.
// zenarmorConnBody below is one of those captured documents, byte-for-byte.
//
// So the multiplier is a MIX effect: the syslog DNS lines that triggered the burst were
// riding in batches whose bytes were dominated by Zenarmor conn/dns records. There is no
// per-record metadata bug and no per-partition resource duplication to fix — resource
// attributes are carried once per ResourceLogs on the wire, not once per record.
//
// WHAT THIS TEST ACTUALLY MEASURES, so nothing here is asserted on faith: it drives the
// REAL otlpSink over a real HTTP socket and weighs the uncompressed protobuf request
// body the exporter produced. That is a measurement of our own encoder against a real
// captured payload. It is NOT a measurement of Loki's own accounting — we have no Loki
// here — so the relationship to the 2705 figure is stated as arithmetic over the same
// captured document, not claimed as an observation.
const zenarmorConnBody = `{"transport_proto":"UDP","policyid":"0","cloud_policyid":"2LD3owZ8cU",` +
	`"cloud_ruleid":"","cloud_networkid":"","interface":"ixl0","vlanid":"0",` +
	`"conn_uuid":"418a309b-1b40-42b0-b39e-03726055ff8c","direction":"out",` +
	`"src_hwaddr":"bc2411c1d512","src_username":"","ip_src_saddr":"10.0.0.114","ip_src_port":55309,` +
	`"src_hostname":"10.0.0.114","src_dir":"EGRESS","dst_hwaddr":"98b78521aff2","dst_username":"",` +
	`"ip_dst_saddr":"10.0.0.254","ip_dst_port":1900,"dst_hostname":"10.0.0.254","dst_dir":"INGRESS",` +
	`"is_blocked":0,"is_overlay":0,"organization":"","overlay_transport_type":"none","is_local":1,` +
	`"input":1,"output":1,"src_npackets":1,"src_nbytes":0,"src_pbytes":94,"dst_npackets":0,` +
	`"dst_nbytes":0,"dst_pbytes":0,"src_tcp_flags":"","dst_tcp_flags":"","start_time":1784224295000,` +
	`"end_time":1784224415000,"encryption":"Clear","app_id":34,"app_proto":"SSDP","app_name":"SSDP",` +
	`"app_category":"Network Management","tags":["Local Bound"],"security_tags":[],"web_actions":[],` +
	`"web_actions_description":[],"src_geoip":{"timezone":"","continent_code":"","city_name":"",` +
	`"country_name":"","country_code2":"","country_code3":"","dma_code":"0","region_name":"",` +
	`"region_code":"","postal_code":"","area":"0","metro":"0","asn":"0","latitude":0.0,` +
	`"longitude":0.0,"location":{"lat":0.0,"lon":0.0}},"dst_geoip":{"timezone":"",` +
	`"continent_code":"","city_name":"","country_name":"","country_code2":"","country_code3":"",` +
	`"dma_code":"0","region_name":"","region_code":"","postal_code":"","area":"0","metro":"0",` +
	`"asn":"0","latitude":0.0,"longitude":0.0,"location":{"lat":0.0,"lon":0.0}},` +
	`"device":{"id":"bc2411c1d512","name":"opnsense-devel","category":"other","vendor":"","os":"",` +
	`"osver":""},"remote_device":"","community_id":"1:tecORBpGbqEAiZw4rUmpJB5C6yM=",` +
	`"handshake_result":"None"}`

// zenarmorConnAttrs is the attribute set zenarmor/parse.go derives from the document
// above, transcribed here rather than imported: internal/logship/zenarmor imports this
// package, so the dependency cannot run the other way.
func zenarmorConnAttrs() map[string]string {
	return map[string]string{
		AttrSubsystem:      "conn",
		AttrAction:         ActionPass,
		AttrDeviceCategory: "other",
		AttrInterface:      "LAN",
		"transport_proto":  "UDP",
		"interface":        "ixl0",
		"vlanid":           "0",
		"direction":        "out",
		"conn_uuid":        "418a309b-1b40-42b0-b39e-03726055ff8c",
		"community_id":     "1:tecORBpGbqEAiZw4rUmpJB5C6yM=",
		"encryption":       "Clear",
		"ip_src_saddr":     "10.0.0.114",
		"ip_dst_saddr":     "10.0.0.254",
		"ip_src_port":      "55309",
		"ip_dst_port":      "1900",
		"src_hostname":     "10.0.0.114",
		"dst_hostname":     "10.0.0.254",
		"src_hwaddr":       "bc2411c1d512",
		"dst_hwaddr":       "98b78521aff2",
		"src_dir":          "EGRESS",
		"dst_dir":          "INGRESS",
		"app_proto":        "SSDP",
		"app_name":         "SSDP",
		"app_category":     "Network Management",
		"device.id":        "bc2411c1d512",
		"device.name":      "opnsense-devel",
		"device.category":  "other",
		"src_npackets":     "1",
		"src_pbytes":       "94",
		"handshake_result": "None",
		"tags":             "Local Bound",
		"is_local":         "1",
	}
}

// syslogDNSAttrs is the shape unbound's local-zone query log produces after the syslog
// envelope and endpoint enrichment: syslog/unbound.go's parseUnbound plus generic.go's
// genericRecord and addCommon.
func syslogDNSAttrs() map[string]string {
	return map[string]string{
		AttrSubsystem:      "dns",
		AttrInterface:      "LAN",
		"program":          "unbound",
		"host":             "OPNsense",
		"pid":              "46775",
		"facility":         "3",
		"severity":         "6",
		"dns.query_name":   "_ldap._tcp.dc._msdcs.example.com.",
		"dns.query_type":   "SRV",
		"dns.query_class":  "IN",
		"dns.local_zone":   "example.com.",
		"dns.local_action": "transparent",
		"src.ip":           "10.0.0.141",
		"src.port":         "51967",
		"src.hostname":     "workstation-07",
		"src.mac":          "bc2411c1d512",
		"src.scope":        "lan",
	}
}

const syslogDNSBody = `[46775:2] info: example.com. transparent 10.0.0.141@51967 ` +
	`_ldap._tcp.dc._msdcs.example.com. SRV IN`

// lokiBillableBytes is Loki's own ingestion-rate accounting, reproduced from its formula
// rather than measured: the entry line, plus each structured-metadata key and value.
// Resource attributes a tenant has NOT promoted to index labels land in structured
// metadata on every record, so they are counted once per record here; the two hoisted
// keys (opnsense.source / opnsense.subsystem) are counted either way, as a label or as
// metadata, so nothing depends on which the tenant chose.
func lokiBillableBytes(r Record, source string) int {
	n := len(r.Body)
	for k, v := range r.Attributes {
		n += len(k) + len(v)
	}
	// The resource, replicated per record by Loki's OTLP handler.
	for k, v := range map[string]string{
		"service.name":        "opnsense2otel",
		"service.version":     "v4.12.0",
		"service.instance.id": "opnsense.example.lan",
		attrSource:            source,
	} {
		n += len(k) + len(v)
	}
	// observed_timestamp (~37 B) and severity_number + severity_text (~33 B), both of
	// which Loki emits itself and neither of which is removable from this side — see the
	// notes on r.SetObservedTimestamp and r.SetSeverity in sink_otlp.go.
	return n + 37 + 33
}

// measureWireBytes ships batch through the REAL otlpSink over a real socket and returns
// the total uncompressed protobuf request bytes the exporter produced.
func measureWireBytes(t *testing.T, batch []Entry) int {
	t.Helper()
	var mu sync.Mutex
	total := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		// The exporter gzips AFTER the size check, so uncompressed is the number every
		// byte bound in this package is calibrated against.
		if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			zr, zerr := gzip.NewReader(bytes.NewReader(body))
			if zerr != nil {
				t.Errorf("gzip reader: %v", zerr)
			} else {
				if raw, rerr := io.ReadAll(zr); rerr == nil {
					body = raw
				}
				_ = zr.Close()
			}
		}
		mu.Lock()
		total += len(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := newSinkOverEndpoint(t, "http/protobuf", srv.URL)
	res := s.Emit(context.Background(), batch)
	if len(res.Acked) != len(batch) {
		t.Fatalf("measurement export was not acknowledged: acked=%d rejected=%d retry=%d err=%v",
			len(res.Acked), len(res.Rejected), len(res.Retry), res.Err)
	}
	mu.Lock()
	defer mu.Unlock()
	return total
}

// The measurement itself. It asserts only the ONE relationship the code depends on —
// that recordBytes stays within the 2x margin maxExportBytes documents itself as
// trusting — and logs the rest, because pinning an exact byte count would make this a
// snapshot test that breaks on any protobuf field addition.
func TestRecordBytesTracksTheRealWirePayload(t *testing.T) {
	cases := []struct {
		name   string
		source string
		rec    Record
	}{
		{"zenarmor conn (captured document)", "zenarmor", Record{
			Body: zenarmorConnBody, Attributes: zenarmorConnAttrs(), Severity: SeverityInfo,
		}},
		{"syslog unbound query", "syslog", Record{
			Body: syslogDNSBody, Attributes: syslogDNSAttrs(), Severity: SeverityInfo,
		}},
	}

	const n = 200
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batch := make([]Entry, n)
			for i := range batch {
				batch[i] = Entry{Source: tc.source, Record: tc.rec}
			}
			wire := measureWireBytes(t, batch)
			est := recordBytes(tc.rec)
			billable := lokiBillableBytes(tc.rec, tc.source)
			wirePer := float64(wire) / float64(n)

			t.Logf("%s: body=%dB attrs=%d | recordBytes estimate=%dB | measured OTLP wire=%.0fB/record | "+
				"Loki-billable (computed)=%dB/record",
				tc.name, len(tc.rec.Body), len(tc.rec.Attributes), est, wirePer, billable)

			// THE ASYMMETRIC CONTRACT, and the asymmetry is the point.
			//
			// UNDER-estimating is a correctness bug: --logs.max-export-bytes and
			// maxExportBytes both size a batch by summing recordBytes, so an estimate
			// below the real marshalled size means the request that actually goes out is
			// bigger than the budget the operator set — which for an ingest-rate budget
			// is exactly the failure #663 is about. Never allowed.
			//
			// OVER-estimating is safe and is what the numbers actually show. Measured
			// 2026-08-07 (the t.Logf above prints the current values): a Zenarmor conn
			// record estimates 4034 B against 2539 B on the wire (1.6x), and an
			// attribute-heavy syslog query record estimates 1356 B against 524 B (2.6x),
			// because recordAttrOverheadBytes = 48 charges Go map/string-header cost that
			// protobuf does not pay — 17 attributes are 816 B of the syslog estimate. That
			// is CORRECT for recordBytes' primary job, which is retained heap for the
			// queue's memory budget, and conservative for the wire: batches come out
			// smaller than the byte budget allows, never larger. The guard is therefore
			// 3x, sized to catch a genuine drift in the overhead constants rather than to
			// litigate an over-estimate that is deliberate.
			if float64(est) < wirePer {
				t.Fatalf("recordBytes UNDERESTIMATES: estimate=%dB vs measured %.0fB/record on the "+
					"wire — every batch would exceed its byte budget by the shortfall", est, wirePer)
			}
			if float64(est) > wirePer*3 {
				t.Fatalf("recordBytes overestimates by more than 3x: estimate=%dB vs measured %.0fB/record "+
					"— the byte bounds calibrated against it are then wrong by that factor", est, wirePer)
			}
		})
	}
}

// The premise check for #663's analysis point 5. The observed 2705 bytes/record cannot
// be produced by the syslog DNS lines the issue assumed, and IS produced by the Zenarmor
// documents that actually dominate the batch's bytes. If a future change ever made a
// syslog line able to reach that size, the explanation recorded above stops being true
// and this fails loudly rather than leaving a stale story in a comment.
func TestObservedByteMultiplierIsExplainedByZenarmorBodies(t *testing.T) {
	const observed = 2705

	syslogRec := Record{Body: syslogDNSBody, Attributes: syslogDNSAttrs()}
	zenRec := Record{Body: zenarmorConnBody, Attributes: zenarmorConnAttrs()}

	syslogBillable := lokiBillableBytes(syslogRec, "syslog")
	zenBillable := lokiBillableBytes(zenRec, "zenarmor")

	t.Logf("Loki-billable bytes/record: syslog unbound query = %d, zenarmor conn = %d, observed = %d",
		syslogBillable, zenBillable, observed)

	if syslogBillable > observed/2 {
		t.Fatalf("a syslog DNS record now bills at %dB, over half the observed %dB/record — the "+
			"recorded explanation (the batch's bytes were Zenarmor documents, not syslog lines) "+
			"no longer holds and needs re-deriving", syslogBillable, observed)
	}
	if zenBillable < observed/2 {
		t.Fatalf("a Zenarmor conn record now bills at only %dB against the observed %dB/record; it can "+
			"no longer account for the multiplier and the explanation needs re-deriving",
			zenBillable, observed)
	}
}
