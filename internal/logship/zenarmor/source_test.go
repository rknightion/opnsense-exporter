package zenarmor

import (
	"context"
	"net"
	"net/http"
	"net/netip"
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

// ReadHeaderTimeout stops a slow-header client, but stops applying once headers land.
// The body read and idle keep-alives must be bounded too (#289), or a peer that sends
// valid headers can trickle the body forever and pin a goroutine. Assert the server is
// wired with all three bounds so this defence cannot silently regress.
func TestServerConfiguresBodyAndIdleTimeouts(t *testing.T) {
	s, err := newSource(logship.Deps{}, Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("newSource: %v", err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })

	if s.srv.ReadHeaderTimeout != readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", s.srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if s.srv.ReadTimeout != readTimeout {
		t.Errorf("ReadTimeout = %v, want %v (bounds the whole body read, not just headers)", s.srv.ReadTimeout, readTimeout)
	}
	if s.srv.IdleTimeout != idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v (bounds kept-alive connections)", s.srv.IdleTimeout, idleTimeout)
	}
}

// End-to-end proof the body-read bound actually fires: a client that completes its
// headers, promises a body, then never sends it must be disconnected — not left to pin
// a goroutine indefinitely. Uses a deliberately short ReadTimeout (production uses the
// far larger readTimeout) so the mechanism is proven in a fraction of a second. Only
// ReadTimeout is set, so a pass proves ReadTimeout — not ReadHeaderTimeout — closes it.
func TestSlowBodyClientIsDisconnected(t *testing.T) {
	ln := mustListen(t)
	srv := &http.Server{ //nolint:gosec // ReadTimeout below is the bound under test; ReadHeaderTimeout intentionally omitted
		Handler:     newServer(Config{}, func(string, []byte, netip.Addr) {}, nil, discardLogger()),
		ReadTimeout: 300 * time.Millisecond,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Full headers promising a body we never send.
	if _, err := conn.Write([]byte("POST /_bulk HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n")); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	// Give the client a bound generously larger than the server's ReadTimeout. If the
	// server bounds the stalled body it closes the connection (a read returns bytes,
	// EOF, or a reset) well within it; if it does NOT, this read blocks until the client
	// deadline and reports a timeout — which is the regression.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("server did not bound a stalled request body — the connection was still open after 5s")
		}
		// EOF / connection reset: the server closed it. That is the pass.
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
	s.handleDoc("some_other_system_index", []byte(`{"a":1}`), netip.Addr{})

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
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(`not json`), netip.Addr{})

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
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(connDoc), netip.Addr{})
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
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(connDoc), netip.Addr{})
	s.handleDoc("zenarmor_0000000000_abc_dns_write", []byte(dnsDoc), netip.Addr{})

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
	s.handleDoc("zenarmor_0000000000_abc_conn_write", []byte(connDoc), netip.Addr{})

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
