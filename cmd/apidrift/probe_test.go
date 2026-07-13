package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

func testSchema(endpoint, path string) opnsense.EndpointSchema {
	return opnsense.EndpointSchema{
		Endpoint:          endpoint,
		Method:            "GET",
		Path:              path,
		TopLevelKind:      opnsense.KindObject,
		KnownTopLevelKeys: []string{"rows", "total"},
		Fields: []opnsense.SchemaField{
			{Path: "rows", Kind: opnsense.KindArray},
			{Path: "rows[]", Kind: opnsense.KindObject},
			{Path: "rows[].name", Kind: opnsense.KindString},
			{Path: "total", Kind: opnsense.KindNumber},
		},
	}
}

func newTestProber(t *testing.T, handler http.Handler) *prober {
	t.Helper()
	p, _ := newTestProberLogged(t, handler)
	return p
}

// newTestProberLogged also hands back the prober's retry-note sink. retryPause
// stays zero so the tests don't sit through the production 2s pause.
func newTestProberLogged(t *testing.T, handler http.Handler) (*prober, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	notes := &bytes.Buffer{}
	return &prober{
		client:  srv.Client(),
		baseURL: srv.URL,
		key:     "k",
		secret:  "s",
		notes:   notes,
		pause:   func(time.Duration) {}, // no real 2s wait in tests
	}, notes
}

// hijackAndCorrupt answers with a truncated chunked body and slams the
// connection shut — the client sees a transport-level failure ("malformed
// chunked encoding"), not an HTTP status. It stands in for any mid-body
// transport fault (dropped connection, a timed-out traffic sample), which is
// what the single retry exists to absorb. The specific firmwareInfo truncation
// that prompted this (issue #235) is fixed at the source by ForceAttemptHTTP2
// in main.go, not by the retry — see fetchRaw's doc comment.
func hijackAndCorrupt(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("test server response writer is not a Hijacker")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n{\"total\":1")
	_ = buf.Flush()
	_ = conn.Close()
}

// A transport-level failure is retried exactly once, and a probe that only
// succeeds on that retry says so — box-side flakiness must stay observable.
func TestProbeOneRetriesOnceOnTransportError(t *testing.T) {
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/test/flaky", func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			hijackAndCorrupt(w)
			return
		}
		w.Write([]byte(`{"total":1,"rows":[{"name":"a"}]}`))
	})
	p, notes := newTestProberLogged(t, mux)

	res := p.probeOne(testSchema("flaky", "api/test/flaky"), opnsense.SchemaExemption{})
	if res.ProbeErr != "" || !res.Res.Clean() {
		t.Fatalf("flaky endpoint should succeed on retry, got %+v", res)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("request count = %d, want exactly 2 (one failure + one retry)", got)
	}
	if !res.Retried {
		t.Errorf("probeResult.Retried = false, want true so the report can surface the flake")
	}
	if !bytes.Contains(notes.Bytes(), []byte("flaky")) || !bytes.Contains(notes.Bytes(), []byte("retry")) {
		t.Errorf("retry note missing from stderr sink, got %q", notes.String())
	}
}

// A persistent transport failure stops after the single retry — no third try.
func TestProbeOneTransportErrorGivesUpAfterOneRetry(t *testing.T) {
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/test/dead", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		hijackAndCorrupt(w)
	})
	p := newTestProber(t, mux)

	res := p.probeOne(testSchema("dead", "api/test/dead"), opnsense.SchemaExemption{})
	if res.ProbeErr == "" {
		t.Fatalf("persistent transport failure should report a probe error, got %+v", res)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("request count = %d, want exactly 2 (attempt + one retry)", got)
	}
}

// 404 is a first-class Absent signal, not a transport failure: probe it once.
func TestProbeOne404IsNotRetried(t *testing.T) {
	var hits int32
	p := newTestProber(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.NotFound(w, r)
	}))

	res := p.probeOne(testSchema("gone", "api/test/gone"), opnsense.SchemaExemption{})
	if !res.Absent || res.Retried {
		t.Errorf("404 should be Absent and unretried, got %+v", res)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("request count = %d, want exactly 1 (404 must not be retried)", got)
	}
}

// A 200 carrying unparseable JSON is a schema matter, not a transport fault —
// re-asking the box would not change the answer, so it must not be retried.
func TestProbeOneBadJSONIsNotRetried(t *testing.T) {
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/test/junk", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`not json at all`))
	})
	p := newTestProber(t, mux)

	res := p.probeOne(testSchema("junk", "api/test/junk"), opnsense.SchemaExemption{})
	if res.ProbeErr == "" {
		t.Fatalf("unparseable body should report a probe error, got %+v", res)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("request count = %d, want exactly 1 (bad JSON must not be retried)", got)
	}
}

func TestProbeOneCleanAndDrift(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/test/clean", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":1,"rows":[{"name":"a"}]}`))
	})
	mux.HandleFunc("/api/test/retyped", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":"1","rows":[{"name":"a"}]}`))
	})
	mux.HandleFunc("/api/test/renamed", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":1,"rows":[{"label":"a"}]}`))
	})
	p := newTestProber(t, mux)

	clean := p.probeOne(testSchema("clean", "api/test/clean"), opnsense.SchemaExemption{})
	if !clean.Res.Clean() || clean.ProbeErr != "" {
		t.Errorf("clean endpoint reported drift: %+v", clean)
	}

	retyped := p.probeOne(testSchema("retyped", "api/test/retyped"), opnsense.SchemaExemption{})
	if len(retyped.Res.Mismatches) != 1 || retyped.Res.Mismatches[0].Path != "total" {
		t.Errorf("retyped endpoint mismatches = %+v", retyped.Res.Mismatches)
	}

	renamed := p.probeOne(testSchema("renamed", "api/test/renamed"), opnsense.SchemaExemption{})
	if len(renamed.Res.Missing) != 1 || renamed.Res.Missing[0] != "rows[].name" {
		t.Errorf("renamed endpoint missing = %+v", renamed.Res.Missing)
	}
}

func TestProbeOne404IsAbsent(t *testing.T) {
	p := newTestProber(t, http.NotFoundHandler())
	res := p.probeOne(testSchema("gone", "api/test/gone"), opnsense.SchemaExemption{})
	if !res.Absent || res.ProbeErr != "" {
		t.Errorf("404 should be Absent with no probe error, got %+v", res)
	}
}

// A POST endpoint must be probed with the client's own body and content type.
func TestProbeOnePostUsesCaptureRequest(t *testing.T) {
	var gotBody, gotCT, gotMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/interface/search_arp", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotCT, gotMethod = string(b), r.Header.Get("Content-Type"), r.Method
		w.Write([]byte(`{"total":0,"rows":[]}`))
	})
	p := newTestProber(t, mux)

	s := testSchema("arp", "api/diagnostics/interface/search_arp")
	s.Method = "POST"
	if res := p.probeOne(s, opnsense.SchemaExemption{}); res.ProbeErr != "" {
		t.Fatalf("probe error: %s", res.ProbeErr)
	}
	if gotMethod != "POST" || gotCT != "application/json" {
		t.Errorf("arp probed as %s %s, want POST application/json", gotMethod, gotCT)
	}
	want, _ := opnsense.CaptureRequestFor("arp")
	if gotBody != want.Body {
		t.Errorf("arp body = %s, want %s", gotBody, want.Body)
	}
}

// smartInfo resolves its device from a live smartList call first.
func TestProbeOneParameterizedSmartInfo(t *testing.T) {
	var infoBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"devices":["da0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		infoBody = string(b)
		w.Write([]byte(`{"output":{"model_name":"x"}}`))
	})
	p := newTestProber(t, mux)

	s := opnsense.EndpointSchema{
		Endpoint:     "smartInfo",
		Method:       "POST",
		Path:         "api/smart/service/info",
		TopLevelKind: opnsense.KindObject,
		Fields:       []opnsense.SchemaField{{Path: "output", Kind: opnsense.KindObject}},
	}
	res := p.probeOne(s, opnsense.SchemaExemption{})
	if res.ProbeErr != "" || res.SkippedParam {
		t.Fatalf("smartInfo probe failed: %+v", res)
	}
	if infoBody != "device=da0&type=a&json=1" {
		t.Errorf("smartInfo body = %q", infoBody)
	}
}

// No devices → parameterized probe is skipped, not failed.
func TestProbeOneParameterizedSkip(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"devices":[]}`))
	})
	p := newTestProber(t, mux)
	s := opnsense.EndpointSchema{Endpoint: "smartInfo", Method: "POST", Path: "api/smart/service/info", TopLevelKind: opnsense.KindObject}
	res := p.probeOne(s, opnsense.SchemaExemption{})
	if !res.SkippedParam || res.ProbeErr != "" {
		t.Errorf("expected SkippedParam, got %+v", res)
	}
}

// captivePortalVouchers has two positional path segments (provider, group),
// each resolved from a prior live GET — unlike smartInfo/ipsecPhase2, which
// resolve one POST-body parameter.
func TestProbeOneParameterizedCaptivePortalVouchers(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/captiveportal/voucher/list_providers", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`["TestVoucherServer"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups/TestVoucherServer", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`["TestGroup1"]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_vouchers/TestVoucherServer/TestGroup1", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`[{"validity":3600,"expirytime":0,"state":"unused"}]`))
	})
	p := newTestProber(t, mux)

	s := opnsense.EndpointSchema{
		Endpoint:     "captivePortalVouchers",
		Method:       "GET",
		Path:         "api/captiveportal/voucher/list_vouchers",
		TopLevelKind: opnsense.KindArray,
	}
	res := p.probeOne(s, opnsense.SchemaExemption{})
	if res.ProbeErr != "" || res.SkippedParam {
		t.Fatalf("captivePortalVouchers probe failed: %+v", res)
	}
	if gotPath != "/api/captiveportal/voucher/list_vouchers/TestVoucherServer/TestGroup1" {
		t.Errorf("captivePortalVouchers requested path = %q", gotPath)
	}
	if res.Path != "api/captiveportal/voucher/list_vouchers/TestVoucherServer/TestGroup1" {
		t.Errorf("probeResult.Path = %q, want the resolved concrete path", res.Path)
	}
}

// No voucher provider configured -> both dependent endpoints are skipped, not
// failed, and the bare route is never requested (it would 404).
func TestProbeOneParameterizedCaptivePortalVouchersSkip(t *testing.T) {
	var bareHit bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/captiveportal/voucher/list_providers", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/captiveportal/voucher/list_voucher_groups", func(w http.ResponseWriter, r *http.Request) {
		bareHit = true
		http.NotFound(w, r)
	})
	p := newTestProber(t, mux)

	groups := opnsense.EndpointSchema{Endpoint: "captivePortalVoucherGroups", Method: "GET", Path: "api/captiveportal/voucher/list_voucher_groups", TopLevelKind: opnsense.KindArray}
	res := p.probeOne(groups, opnsense.SchemaExemption{})
	if !res.SkippedParam || res.ProbeErr != "" {
		t.Errorf("expected SkippedParam for captivePortalVoucherGroups, got %+v", res)
	}

	vouchers := opnsense.EndpointSchema{Endpoint: "captivePortalVouchers", Method: "GET", Path: "api/captiveportal/voucher/list_vouchers", TopLevelKind: opnsense.KindArray}
	res2 := p.probeOne(vouchers, opnsense.SchemaExemption{})
	if !res2.SkippedParam || res2.ProbeErr != "" {
		t.Errorf("expected SkippedParam for captivePortalVouchers, got %+v", res2)
	}
	if bareHit {
		t.Error("the bare (parameter-less) route must never be requested — it 404s at the routing layer")
	}
}

func TestProbeOneExemptionSuppressesMissing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/test/renamed", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":1,"rows":[{"label":"a"}]}`))
	})
	p := newTestProber(t, mux)
	res := p.probeOne(testSchema("renamed", "api/test/renamed"), opnsense.SchemaExemption{MissingOK: []string{"rows[].name"}})
	if len(res.Res.Missing) != 0 {
		t.Errorf("exempted path still reported missing: %+v", res.Res.Missing)
	}
}
