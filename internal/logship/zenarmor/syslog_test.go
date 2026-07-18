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
// the REAL syslog registry — not a fake ProgramProcessor — then confirm the registry's
// dup guard is what stands between this branch and a double registration.
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
	proc := newDocProcessor(logship.Deps{Registerer: prometheus.NewRegistry()}, Config{Enrich: false})
	sp := &syslogProcessor{proc: proc}

	syslog.RegisterProgramProcessor(sp)
	if !sp.Handles("zenarmor") {
		t.Fatal("registered processor does not handle its own program name")
	}

	// The dup guard is what would catch this branch running twice (e.g. two
	// RegisterPushSource factories both resolving transport=syslog): confirm a
	// second registration panics rather than silently replacing the first.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("second RegisterProgramProcessor call did not panic (dup guard broken)")
		}
	}()
	syslog.RegisterProgramProcessor(&syslogProcessor{proc: proc})
}
