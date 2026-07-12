package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &prober{
		client:  srv.Client(),
		baseURL: srv.URL,
		key:     "k",
		secret:  "s",
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
