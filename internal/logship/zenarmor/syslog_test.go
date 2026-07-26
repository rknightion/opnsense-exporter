package zenarmor

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
	"github.com/rknightion/opnsense-exporter/internal/logship/syslog"
)

func TestParseSyslogPayload(t *testing.T) {
	// Real dns line body (envelope already stripped by the syslog receiver).
	msg := `daemon=zenarmor, index=dns, data={"start_time":1784368102000,"query":"gsp-ssl.ls.apple.com","is_blocked":0}`
	fam, data, ok := parseSyslogPayload(msg)
	if !ok || fam != "dns" {
		t.Fatalf("dns: got fam=%q ok=%v, want dns/true", fam, ok)
	}
	if data != `{"start_time":1784368102000,"query":"gsp-ssl.ls.apple.com","is_blocked":0}` {
		t.Fatalf("dns: data mismatch: %q", data)
	}

	// alert line — data JSON contains commas and nested braces; must not be split.
	alert := `daemon=zenarmor, index=alert, data={"alertinfo":{"category":["A"],"sid":"x"},"is_blocked":1}`
	fam, data, ok = parseSyslogPayload(alert)
	if !ok || fam != "alert" {
		t.Fatalf("alert: got fam=%q ok=%v, want alert/true", fam, ok)
	}
	if data != `{"alertinfo":{"category":["A"],"sid":"x"},"is_blocked":1}` {
		t.Fatalf("alert: data mismatch: %q", data)
	}

	// Not a Zenarmor body.
	if _, _, ok := parseSyslogPayload("some other program output"); ok {
		t.Fatal("non-zenarmor body: want ok=false")
	}
}

func TestSyslogProcessor_ProcessRealAlert(t *testing.T) {
	proc := &docProcessor{
		cfg:   Config{Enrich: false},
		cache: enrich.NewCache(),
		sink:  logship.NopMetricSink{},
		m:     newMetrics(prometheus.NewRegistry(), nil),
	}
	sp := &syslogProcessor{proc: proc}
	if !sp.Handles("zenarmor") || sp.Handles("sshd") {
		t.Fatal("Handles() wrong")
	}
	env := syslog.Envelope{
		Program: "zenarmor",
		Message: `daemon=zenarmor, index=alert, data={"is_blocked":1,` +
			`"alertinfo":{"category":["Application Category"],"signature":["Network Management"],` +
			`"severity":0,"sid":"appcategories.abc","action":"reject"}}`,
	}
	var got logship.Record
	n := 0
	handled := sp.Process(env, netip.Addr{}, nil, func(r logship.Record) { got = r; n++ })
	if !handled || n != 1 {
		t.Fatalf("handled=%v emitted=%d, want true/1", handled, n)
	}
	if got.Attributes["alertinfo.category"] != "Application Category" {
		t.Errorf("category = %q", got.Attributes["alertinfo.category"])
	}
	if got.Attributes["alertinfo.sid"] != "appcategories.abc" {
		t.Errorf("sid = %q", got.Attributes["alertinfo.sid"])
	}
	// Task S: a Zenarmor record delivered through the shared syslog receiver must
	// carry the override so the pipeline ships it as source="zenarmor", not "syslog".
	if got.Source != "zenarmor" {
		t.Errorf("Source = %q, want zenarmor", got.Source)
	}
}

// TestSyslogProcessor_SelfTrafficMatchesAnyBoundPort covers #299: with more than one
// syslog listener bound (say UDP and TCP), Zenarmor may stream its reporting data to a
// NON-first port. Self-traffic detection must match the record's dst port against ANY
// bound port, not just ports[0] — otherwise the box->exporter self-record silently
// ships instead of being dropped.
func TestSyslogProcessor_SelfTrafficMatchesAnyBoundPort(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink := &captureSink{}
	proc := &docProcessor{
		cfg:   Config{DropSelfTraffic: true},
		cache: enrich.NewCache(),
		sink:  sink,
		m:     newMetrics(reg, nil),
	}
	sp := &syslogProcessor{proc: proc}

	peer := netip.MustParseAddr("10.0.0.254") // the firewall, streaming to us
	// Two listeners bound (UDP 5514, TCP 6514); Zenarmor streams to the SECOND one.
	ports := []int{5514, 6514}
	env := syslog.Envelope{
		Program: "zenarmor",
		Message: "daemon=zenarmor, index=conn, data=" + selfDoc("10.0.0.254", "10.0.0.5", 6514),
	}
	n := 0
	handled := sp.Process(env, peer, ports, func(logship.Record) { n++ })
	if !handled {
		t.Fatal("handled=false, want true")
	}
	if n != 0 {
		t.Errorf("emitted %d records, want 0 — self-traffic to a non-first bound port must still be dropped", n)
	}
	if got := rejectCount(t, reg, "self_traffic"); got != 1 {
		t.Errorf("self_traffic reject = %v, want 1", got)
	}
}

func TestSyslogProcessor_EmittedSource(t *testing.T) {
	sp := &syslogProcessor{}
	if got := sp.EmittedSource(); got != "zenarmor" {
		t.Errorf("EmittedSource() = %q, want zenarmor", got)
	}
}

// TestFactory_SyslogTransport_RegistersRealProcessor covers the init() factory's
// transport=="syslog" branch in source.go: build a docProcessor via newDocProcessor
// (exactly as the factory does), wrap it in a syslogProcessor, and register it with
// the REAL syslog registry — not a fake ProgramProcessor — then confirm a second
// registration from the same branch (the pipeline rebuilt: a test constructing it
// twice, or a future in-process reload) replaces the first cleanly instead of
// panicking. Before #401 the registry panicked on any second registration; that
// guard existed to catch two factories racing to claim the same slot, but it also
// made an ordinary rebuild fatal. The registry is now rebuild-safe, so this test
// asserts the OPPOSITE of what it used to: no panic, and the second registration
// wins.
//
// Driving the actual anonymous closure passed to logship.RegisterPushSource is not
// possible from here: registeredPushFactories (internal/logship/push.go) is
// unexported, the closure itself is never bound to a name, and the transport switch
// it reads (options.LogsZenarmorTransport) is backed by an unexported kingpin flag
// var that this package cannot flip (options imports nothing from zenarmor, so there
// is no seam to drive it through). This test instead exercises the two calls the
// branch actually makes — newDocProcessor + syslog.RegisterProgramProcessor — against
// the production registry, which is the observable effect the branch exists to
// produce. The branch's `return nil, nil` (no PushSource) is a literal return
// statement beside those two calls and is verified by inspection, not by this test.
func TestFactory_SyslogTransport_RegistersRealProcessor(t *testing.T) {
	t.Cleanup(syslog.ResetProgramProcessor)

	reg := prometheus.NewRegistry()
	proc := newDocProcessor(logship.Deps{Registerer: reg}, Config{
		Enrich:   false,
		Families: []string{"dns"},
	})
	sp := &syslogProcessor{proc: proc}

	syslog.RegisterProgramProcessor(sp)
	if !sp.Handles("zenarmor") {
		t.Fatal("registered processor does not handle its own program name")
	}

	// A rebuild (e.g. the pipeline constructed a second time in this process) must
	// replace the first registration cleanly, never panic (#401).
	proc2 := newDocProcessor(logship.Deps{Registerer: reg}, Config{
		Enrich:   false,
		Families: []string{"alert"},
	})
	sp2 := &syslogProcessor{proc: proc2}
	syslog.RegisterProgramProcessor(sp2)
	if !sp2.Handles("zenarmor") {
		t.Fatal("second registered processor does not handle its own program name")
	}
	if sp2.Handles("some-future-plugin") {
		t.Fatal("unknown program claimed by the Zenarmor processor; generic fallback would be bypassed")
	}
	fallback := syslog.BuildRecord(syslog.Envelope{
		Program: "some-future-plugin",
		Message: "opaque plugin payload",
	}, nil, nil)
	if fallback.Body != "opaque plugin payload" {
		t.Errorf("unknown-program fallback body = %q, want raw payload preserved", fallback.Body)
	}

	// A rebuild shares the registry-owned collectors, but no processor state. In
	// particular, the later runtime config must not mutate the processor it replaced.
	if proc == proc2 || proc.m == proc2.m || proc.m.recv == proc2.m.recv || proc.cache == proc2.cache {
		t.Fatal("rebuild shared processor-local state; only registered collectors may be shared")
	}
	if !proc.families["dns"] || proc.families["ids"] {
		t.Errorf("first processor family state changed after rebuild: %v", proc.families)
	}
	if !proc2.families["ids"] || proc2.families["dns"] {
		t.Errorf("second processor family state = %v, want only ids", proc2.families)
	}
	if proc.m.bulkReqs != proc2.m.bulkReqs ||
		proc.m.bulkBytes != proc2.m.bulkBytes ||
		proc.m.excluded != proc2.m.excluded {
		t.Fatal("rebuild did not reuse the registry-owned Zenarmor collectors")
	}

	proc.m.observeBulk(10)
	proc2.m.observeBulk(20)
	if got := gatheredCounter(t, reg, "opnsense_exporter_logs_zenarmor_bulk_requests_total", nil); got != 2 {
		t.Errorf("shared bulk request count = %v, want 2", got)
	}
	if got := gatheredCounter(t, reg, "opnsense_exporter_logs_zenarmor_bulk_bytes_total", nil); got != 30 {
		t.Errorf("shared bulk byte count = %v, want 30", got)
	}
}
