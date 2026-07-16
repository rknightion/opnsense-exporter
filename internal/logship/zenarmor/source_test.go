package zenarmor

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// The pipeline waits on Run (unbounded) during shutdown. A Run that ignores ctx hangs
// the exporter forever on SIGTERM.
func TestRunReturnsOnContextCancel(t *testing.T) {
	s := &zenarmorSource{srv: &http.Server{Handler: http.NewServeMux()}, ln: mustListen(t)} //nolint:gosec // no ReadHeaderTimeout needed in-test
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, func(logship.Record) {}) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on a clean cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on ctx cancel — the exporter would never exit on SIGTERM")
	}
}

// Bind eagerly in the factory: a port already in use is a configuration error the
// operator must see at startup, not a receiver that is silently dead forever.
func TestFactoryBindsEagerly(t *testing.T) {
	busy := mustListen(t)
	_, err := newSource(logship.Deps{}, Config{Addr: busy.Addr().String()})
	if err == nil {
		t.Fatal("expected an error binding an in-use port")
	}
	if !strings.Contains(err.Error(), "zenarmor") {
		t.Errorf("error %q should name the source so the operator knows what failed", err)
	}
}

// A source built from a zero Deps must not panic: nil Cache, nil MetricSink and nil
// Registerer all have to be tolerated.
func TestNewSourceToleratesZeroDeps(t *testing.T) {
	s, err := newSource(logship.Deps{}, Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	if s.cache == nil {
		t.Error("cache must fall back to a cold cache, not stay nil")
	}
	if s.sink == nil {
		t.Error("sink must fall back to a NopMetricSink, not stay nil")
	}
	if s.Name() != sourceName {
		t.Errorf("Name() = %q, want %q", s.Name(), sourceName)
	}
}

// The end-to-end path: a bulk write arrives over HTTP and comes out as a Record.
func TestSourceEmitsRecordsFromBulk(t *testing.T) {
	s, err := newSource(logship.Deps{Registerer: prometheus.NewRegistry()}, Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	addr := s.ln.Addr().String()

	recs := make(chan logship.Record, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, func(r logship.Record) { recs <- r }) }()

	body := "{\"index\":{\"_index\":\"zenarmor_0000000000_abc_conn_write\"}}\n" + connDoc + "\n"
	resp, err := http.Post("http://"+addr+"/_bulk", "application/x-ndjson", strings.NewReader(body)) //nolint:noctx // test client
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	select {
	case rec := <-recs:
		if rec.Attributes[logship.AttrSubsystem] != "flow" {
			t.Errorf("subsystem = %q, want flow", rec.Attributes[logship.AttrSubsystem])
		}
		if rec.Body != connDoc {
			t.Error("body was not the verbatim document")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no record emitted")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on ctx cancel")
	}
}

// A document addressed to an index that is not one of Zenarmor's families is counted
// and dropped rather than shipped under an empty subsystem.
func TestSourceRejectsUnknownFamily(t *testing.T) {
	reg := prometheus.NewRegistry()
	s, err := newSource(logship.Deps{Registerer: reg}, Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	emitted := 0
	s.emit = func(logship.Record) { emitted++ }
	s.handleDoc("some_other_system_index", []byte(`{"a":1}`))

	if emitted != 0 {
		t.Errorf("emitted %d records for an unknown index, want 0", emitted)
	}
	if got := rejectCount(t, reg, "unknown_family"); got != 1 {
		t.Errorf("unknown_family count = %v, want 1", got)
	}
}

// An unparseable document is counted AND still shipped.
func TestSourceCountsParseErrorButStillEmits(t *testing.T) {
	reg := prometheus.NewRegistry()
	s, err := newSource(logship.Deps{Registerer: reg}, Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	var got []logship.Record
	s.emit = func(r logship.Record) { got = append(got, r) }
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(`not json`))

	if len(got) != 1 {
		t.Fatalf("emitted %d records, want 1 — a parse error must never drop the record", len(got))
	}
	if got[0].Body != "not json" {
		t.Errorf("body = %q, want the raw bytes", got[0].Body)
	}
	n := gatheredCounter(t, reg, "opnsense_exporter_logs_parse_errors_total",
		map[string]string{"source": sourceName, "stage": "document"})
	if n != 1 {
		t.Errorf("document parse-error count = %v, want 1", n)
	}
}

// A document arriving before Run has set emit is dropped, not a panic.
func TestSourceHandleDocBeforeRunDoesNotPanic(t *testing.T) {
	s, err := newSource(logship.Deps{}, Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(connDoc))
}

func TestSourceFamilyFilter(t *testing.T) {
	reg := prometheus.NewRegistry()
	s, err := newSource(logship.Deps{Registerer: reg}, Config{Addr: "127.0.0.1:0", Families: []string{"dns"}})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	var got []string
	s.emit = func(r logship.Record) { got = append(got, r.Attributes[logship.AttrSubsystem]) }
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(connDoc))
	s.handleDoc("zenarmor_0000000000_abc_dns_write", []byte(dnsDoc))

	if len(got) != 1 || got[0] != "dns" {
		t.Errorf("shipped %v, want only [dns]", got)
	}
	if n := rejectCount(t, reg, "filtered"); n != 1 {
		t.Errorf("filtered count = %v, want 1", n)
	}
}

// The family filter's vocabulary is Zenarmor's index token (conn, http), but our own
// family names (flow, web) are the obvious thing to reach for. Both must work: a
// silent "ships nothing" is the worst possible failure for this flag.
func TestFamilyAllowSetAcceptsBothSpellings(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want map[string]bool
	}{
		{"nil means all", nil, nil},
		{"empty means all", []string{}, nil},
		{"blank entries mean all", []string{"", "  "}, nil},
		{"index tokens", []string{"conn", "http"}, map[string]bool{"flow": true, "web": true}},
		{"family names", []string{"flow", "web"}, map[string]bool{"flow": true, "web": true}},
		{"mixed", []string{"conn", "web"}, map[string]bool{"flow": true, "web": true}},
		{"case and space tolerant", []string{" Conn ", "DNS"}, map[string]bool{"flow": true, "dns": true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := familyAllowSet(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("familyAllowSet(%v) = %v, want %v", c.in, got, c.want)
			}
			for k := range c.want {
				if !got[k] {
					t.Errorf("familyAllowSet(%v) missing %q", c.in, k)
				}
			}
		})
	}
}

// Enrich=false must skip the snapshot entirely rather than pass a cold one.
func TestSourceEnrichDisabled(t *testing.T) {
	s, err := newSource(logship.Deps{}, Config{Addr: "127.0.0.1:0", Enrich: false})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	var got logship.Record
	s.emit = func(r logship.Record) { got = r }
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(connDoc))

	if v, ok := got.Attributes["src.scope"]; ok {
		t.Errorf("src.scope = %q was set with enrichment disabled", v)
	}
}

// The registered factory must report itself disabled until the options seam lands,
// so it binds nothing at startup.
func TestFactorySeamIsInertUntilWired(t *testing.T) {
	cfg, enabled, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if enabled {
		t.Error("loadConfig reports enabled; the options seam is not wired yet (task 8)")
	}
	if cfg.Addr != "" {
		t.Errorf("cfg = %+v, want the zero Config", cfg)
	}
}
