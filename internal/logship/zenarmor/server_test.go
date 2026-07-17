package zenarmor

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// gatheredCounter reads one labelled counter off a registry by its EXPOSED name,
// without the (unvendored) prometheus/testutil package — the dto.Metric pattern from
// internal/logship/metrics_test.go:13, via Gather so the assertion is against the
// metric name a dashboard actually queries. A counter that was never incremented is
// absent from the gather, which reads as 0.
func gatheredCounter(t *testing.T, g prometheus.Gatherer, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(m *dto.Metric, want map[string]string) bool {
	got := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func rejectCount(t *testing.T, g prometheus.Gatherer, reason string) float64 {
	t.Helper()
	return gatheredCounter(t, g, "opnsense_exporter_logs_rejected_total",
		map[string]string{"source": sourceName, "reason": reason})
}

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

func gzipString(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func newTestServer(t *testing.T, m *metrics) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newServer(Config{}, func(string, []byte, netip.Addr) {}, m))
	t.Cleanup(srv.Close)
	return srv
}

// THE load-bearing test. ipdrstreamer links the official go-elasticsearch client,
// which runs a product check and hard-refuses any server that does not send this
// header ("the client noticed that the server is not Elasticsearch and we do not
// support this unknown product"). Without it we receive nothing, silently — so it is
// asserted on every endpoint including the ones we do not handle.
func TestEveryResponseCarriesProductHeader(t *testing.T) {
	srv := newTestServer(t, nil)

	paths := []string{
		"/",
		"/_cat/indices?format=json",
		"/_cat/aliases?format=json",
		"/_bulk",
		"/zenarmor_0000000000_abc_conn-260716",
		"/totally-unknown",
		"/_some/future/endpoint",
	}
	for _, p := range paths {
		resp, err := http.Get(srv.URL + p) //nolint:noctx // test client
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		got := resp.Header.Get("X-Elastic-Product")
		_ = resp.Body.Close()
		if got != "Elasticsearch" {
			t.Errorf("GET %s: X-Elastic-Product = %q, want %q", p, got, "Elasticsearch")
		}
	}
}

// The product header must survive the refusal paths too: a client that cannot even
// identify the server reports a confusing product error instead of the 401 it got.
func TestProductHeaderOnRefusedRequests(t *testing.T) {
	srv := httptest.NewServer(newServer(Config{AuthUser: "u", AuthPassword: "p"}, nil, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Elastic-Product"); got != "Elasticsearch" {
		t.Errorf("X-Elastic-Product = %q, want Elasticsearch", got)
	}
}

func TestRootReportsSupportedVersion(t *testing.T) {
	srv := newTestServer(t, nil)

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		Tagline string `json:"tagline"`
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// Zenarmor supports 8.9.x-8.17.1 only.
	if body.Version.Number != esVersion {
		t.Errorf("version = %q, want %q", body.Version.Number, esVersion)
	}
	if body.Tagline != "You Know, for Search" {
		t.Errorf("tagline = %q", body.Tagline)
	}
}

// _cat endpoints must return a JSON ARRAY. A real ES does; returning {} is what the
// throwaway capture stub did, and it made Zenarmor take a fallback path.
func TestCatEndpointsReturnArrays(t *testing.T) {
	srv := newTestServer(t, nil)

	for _, p := range []string{"/_cat/indices?format=json", "/_cat/aliases?format=json"} {
		resp, err := http.Get(srv.URL + p) //nolint:noctx // test client
		if err != nil {
			t.Fatal(err)
		}
		var arr []any
		err = json.NewDecoder(resp.Body).Decode(&arr)
		_ = resp.Body.Close()
		if err != nil {
			t.Errorf("GET %s: not a JSON array: %v", p, err)
		}
	}
}

func TestIndexRegistryLifecycle(t *testing.T) {
	srv := newTestServer(t, nil)
	const idx = "/zenarmor_0000000000_abc_conn-260716"

	head := func() int {
		t.Helper()
		resp, err := http.Head(srv.URL + idx) //nolint:noctx // test client
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if got := head(); got != http.StatusNotFound {
		t.Errorf("HEAD before create = %d, want 404", got)
	}

	req, _ := http.NewRequest(http.MethodPut, srv.URL+idx, strings.NewReader(`{"mappings":{}}`)) //nolint:noctx // test client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var put struct {
		Acknowledged       bool   `json:"acknowledged"`
		ShardsAcknowledged bool   `json:"shards_acknowledged"`
		Index              string `json:"index"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&put)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT = %d, want 200", resp.StatusCode)
	}
	if !put.Acknowledged || !put.ShardsAcknowledged {
		t.Errorf("PUT ack = %+v, want both true", put)
	}
	if want := strings.TrimPrefix(idx, "/"); put.Index != want {
		t.Errorf("PUT index = %q, want %q", put.Index, want)
	}

	if got := head(); got != http.StatusOK {
		t.Errorf("HEAD after create = %d, want 200", got)
	}

	// A delete must forget it again, so the exists probe stays honest rather than
	// promising an index we would no longer accept a mapping for.
	req, _ = http.NewRequest(http.MethodDelete, srv.URL+idx, nil) //nolint:noctx // test client
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DELETE = %d, want 200", resp.StatusCode)
	}
	if got := head(); got != http.StatusNotFound {
		t.Errorf("HEAD after delete = %d, want 404", got)
	}
}

func TestAliasesEndpointAcknowledges(t *testing.T) {
	srv := newTestServer(t, nil)

	resp, err := http.Post(srv.URL+"/_aliases", "application/json", //nolint:noctx // test client
		strings.NewReader(`{"actions":[{"add":{"index":"i","alias":"a"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Acknowledged bool `json:"acknowledged"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Acknowledged {
		t.Error("acknowledged = false, want true")
	}
}

// An unhandled endpoint must keep the stream flowing AND be counted, so a change in
// Zenarmor's client surface is a visible signal rather than a silent outage.
func TestUnhandledEndpointIsCountedNotFatal(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := newTestServer(t, newMetrics(reg, nil))

	resp, err := http.Get(srv.URL + "/_some/future/endpoint") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (must not break the stream)", resp.StatusCode)
	}
	if got := rejectCount(t, reg, "unhandled_endpoint"); got != 1 {
		t.Errorf("unhandled_endpoint count = %v, want 1", got)
	}
}

func TestBulkRoutesDocsToCallback(t *testing.T) {
	var gotIdx []string
	var gotDocs []string
	srv := httptest.NewServer(newServer(Config{}, func(i string, d []byte, _ netip.Addr) {
		gotIdx = append(gotIdx, i)
		gotDocs = append(gotDocs, string(d))
	}, nil))
	defer srv.Close()

	// Action line then source line, as Zenarmor writes them.
	body := `{"index":{"_index":"zenarmor_0000000000_abc_conn_write","_id":"1"}}
{"app_name":"BitTorrent","is_blocked":0}
{"index":{"_index":"zenarmor_0000000000_abc_dns_write","_id":"2"}}
{"query":"api.notion.com","resp_code":0}
`
	resp, err := http.Post(srv.URL+"/zenarmor_0000000000_abc_conn_write/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		Errors bool             `json:"errors"`
		Items  []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Errors {
		t.Error("errors = true, want false")
	}
	if len(out.Items) != 2 {
		t.Fatalf("items = %d, want 2 (one per action line)", len(out.Items))
	}
	// Each response item must be keyed by the SAME op its action line used and report
	// the created status, or the client treats the write as a failure.
	for i, it := range out.Items {
		op, ok := it["index"]
		if !ok {
			t.Fatalf("item %d = %v, want an \"index\" key matching the action line's op", i, it)
		}
		om, ok := op.(map[string]any)
		if !ok {
			t.Fatalf("item %d op payload = %T, want an object", i, op)
		}
		if status := om["status"]; status != float64(http.StatusCreated) {
			t.Errorf("item %d status = %v, want 201", i, status)
		}
	}
	if len(gotDocs) != 2 {
		t.Fatalf("callback got %d docs, want 2", len(gotDocs))
	}
	if !strings.Contains(gotDocs[0], "BitTorrent") {
		t.Errorf("doc 1 = %q, want the conn source line", gotDocs[0])
	}
	if gotIdx[1] != "zenarmor_0000000000_abc_dns_write" {
		t.Errorf("doc 2 index = %q; the action line's _index must win over the URL default", gotIdx[1])
	}
}

// A bulk write to the bare /_bulk path has no URL default, so each action line's own
// _index is the only source of truth.
func TestBulkBareEndpointUsesActionIndex(t *testing.T) {
	var gotIdx []string
	srv := httptest.NewServer(newServer(Config{}, func(i string, _ []byte, _ netip.Addr) {
		gotIdx = append(gotIdx, i)
	}, nil))
	defer srv.Close()

	body := `{"index":{"_index":"zenarmor_0000000000_abc_tls_write"}}
{"server_name":"example.com"}
`
	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(gotIdx) != 1 || gotIdx[0] != "zenarmor_0000000000_abc_tls_write" {
		t.Errorf("indices = %v, want [zenarmor_0000000000_abc_tls_write]", gotIdx)
	}
}

// A delete action carries no source line. Consuming one would swallow the NEXT action
// line and silently lose a document.
func TestBulkDeleteActionHasNoSourceLine(t *testing.T) {
	var gotDocs []string
	srv := httptest.NewServer(newServer(Config{}, func(_ string, d []byte, _ netip.Addr) {
		gotDocs = append(gotDocs, string(d))
	}, nil))
	defer srv.Close()

	body := `{"delete":{"_index":"zenarmor_0000000000_abc_conn_write","_id":"9"}}
{"index":{"_index":"zenarmor_0000000000_abc_conn_write","_id":"10"}}
{"app_name":"SSDP"}
`
	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	_ = resp.Body.Close()

	if len(out.Items) != 2 {
		t.Errorf("items = %d, want 2", len(out.Items))
	}
	if len(gotDocs) != 1 {
		t.Fatalf("callback got %d docs, want 1 (the delete has no source line)", len(gotDocs))
	}
	if !strings.Contains(gotDocs[0], "SSDP") {
		t.Errorf("doc = %q; the delete swallowed the following action line", gotDocs[0])
	}
}

func TestBulkCountsRequestsAndBytes(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := httptest.NewServer(newServer(Config{}, func(string, []byte, netip.Addr) {}, newMetrics(reg, nil)))
	defer srv.Close()

	body := `{"index":{"_index":"zenarmor_0000000000_abc_conn_write"}}
{"app_name":"SSDP"}
`
	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if got := gatheredCounter(t, reg, "opnsense_exporter_logs_zenarmor_bulk_requests_total", nil); got != 1 {
		t.Errorf("bulk requests = %v, want 1", got)
	}
	if got := gatheredCounter(t, reg, "opnsense_exporter_logs_zenarmor_bulk_bytes_total", nil); got != float64(len(body)) {
		t.Errorf("bulk bytes = %v, want %d", got, len(body))
	}
}

// An empty bulk must encode items as [] rather than null: the client decodes that
// field as an array.
func TestBulkEmptyBodyEncodesEmptyItemsArray(t *testing.T) {
	srv := newTestServer(t, nil)

	resp, err := http.Post(srv.URL+"/_bulk", "application/x-ndjson", strings.NewReader("")) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if got := string(raw["items"]); got != "[]" {
		t.Errorf("items = %s, want []", got)
	}
}

func TestPeerAllowlistRefusesAndCounts(t *testing.T) {
	reg := prometheus.NewRegistry()
	// httptest dials from loopback, so an allowlist of a foreign prefix refuses it.
	srv := httptest.NewServer(newServer(Config{AllowedPeers: mustPrefixes(t, "192.0.2.0/24")}, nil, newMetrics(reg, nil)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := rejectCount(t, reg, "peer"); got != 1 {
		t.Errorf("peer reject count = %v, want 1", got)
	}
}

func TestPeerAllowlistAdmitsLoopback(t *testing.T) {
	srv := httptest.NewServer(newServer(Config{
		AllowedPeers: mustPrefixes(t, "127.0.0.0/8", "::1/128"),
	}, nil, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/") //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestBasicAuth(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv := httptest.NewServer(newServer(Config{AuthUser: "zen", AuthPassword: "s3cret"}, nil, newMetrics(reg, nil)))
	defer srv.Close()

	cases := []struct {
		name, user, pass string
		want             int
	}{
		{"correct", "zen", "s3cret", http.StatusOK},
		{"wrong password", "zen", "nope", http.StatusUnauthorized},
		{"wrong user", "other", "s3cret", http.StatusUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil) //nolint:noctx // test client
			req.SetBasicAuth(c.user, c.pass)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, c.want)
			}
		})
	}

	if got := rejectCount(t, reg, "auth"); got != 2 {
		t.Errorf("auth reject count = %v, want 2", got)
	}
}

func TestGzippedBulkBodyIsDecompressed(t *testing.T) {
	var gotDocs []string
	srv := httptest.NewServer(newServer(Config{}, func(_ string, d []byte, _ netip.Addr) {
		gotDocs = append(gotDocs, string(d))
	}, nil))
	defer srv.Close()

	body := `{"index":{"_index":"zenarmor_0000000000_abc_conn_write"}}
{"app_name":"SSDP"}
`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/_bulk", strings.NewReader(gzipString(t, body))) //nolint:noctx // test client
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if len(gotDocs) != 1 || !strings.Contains(gotDocs[0], "SSDP") {
		t.Fatalf("docs = %v, want the decompressed source line", gotDocs)
	}
}

// A body that claims gzip but is not must be refused, never parsed as plain NDJSON:
// doing so would manufacture garbage records out of a transport fault.
func TestBrokenGzipIsRejectedNotParsed(t *testing.T) {
	reg := prometheus.NewRegistry()
	called := 0
	srv := httptest.NewServer(newServer(Config{}, func(string, []byte, netip.Addr) { called++ }, newMetrics(reg, nil)))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/_bulk", strings.NewReader("this is not gzip")) //nolint:noctx // test client
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if called != 0 {
		t.Errorf("callback ran %d times on an unreadable body, want 0", called)
	}
	if got := rejectCount(t, reg, "body"); got != 1 {
		t.Errorf("body reject count = %v, want 1", got)
	}
}

// A nil *metrics must no-op rather than panic on every counted path.
func TestNilMetricsHandleIsSafe(t *testing.T) {
	var m *metrics
	m.reject("peer")
	m.parseError("document")
	m.observeBulk(10)
}

func TestBulkDefaultIndex(t *testing.T) {
	cases := map[string]string{
		"/zenarmor_0000000000_abc_conn_write/_bulk": "zenarmor_0000000000_abc_conn_write",
		"/_bulk": "",
		"/zenarmor_0000000000_abc_conn_write/_doc/_bulk": "zenarmor_0000000000_abc_conn_write",
	}
	for in, want := range cases {
		if got := bulkDefaultIndex(in); got != want {
			t.Errorf("bulkDefaultIndex(%q) = %q, want %q", in, got, want)
		}
	}
}
