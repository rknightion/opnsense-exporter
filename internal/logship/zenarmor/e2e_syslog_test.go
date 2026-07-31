package zenarmor

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v4/internal/logship/syslog"
)

// TestEndToEnd_SyslogTransport_RealCaptureShapes is the Task 9 end-to-end smoke test.
// It drives the REAL production seams top to bottom for --logs.zenarmor.transport=syslog:
//
//	syslog.ParseEnvelope (actual RFC3164 wire-format decode, exercised on synthetic
//	wire framing — PRI/timestamp/host/tag are constructed here, since fabricating a
//	raw UDP datagram byte-for-byte from a real capture is not needed to prove the
//	decode) -> syslogProcessor.Process (the real production dispatch code registered
//	via syslog.RegisterProgramProcessor in this package's init()) -> docProcessor.process
//	-> parseDoc (the real family-specific decoder).
//
// This is everything the actual UDP listener (syslog.source.handle) does with a line
// EXCEPT the socket read and s.proc.Handles/dispatch gate, which is covered separately
// by TestSource_DelegatesToProgramProcessor in the syslog package (there is no
// exported way to construct a real syslog.source from outside the package, since
// newSource/source are unexported — see Task 9 brief).
//
// The message bodies are the byte-verbatim conn/dns/tls/http fixtures already
// committed in fixtures_test.go (captured from a live Zenarmor 2026-07-16) plus the
// constructed-but-shape-verified alertDoc fixture — no fresh real capture data is
// introduced here, only a synthetic syslog envelope wrapped around already-committed
// fixtures.
func TestEndToEnd_SyslogTransport_RealCaptureShapes(t *testing.T) {
	proc := &docProcessor{
		cfg:   Config{Enrich: false},
		cache: enrich.NewCache(),
		sink:  logship.NopMetricSink{},
		m:     newMetrics(prometheus.NewRegistry(), nil),
	}
	sp := &syslogProcessor{proc: proc}

	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	peer := netip.MustParseAddr("10.0.0.114")
	ports := []int{5514}

	line := func(index, data string) []byte {
		return []byte("<134>Jul 18 12:00:00 opnsense-devel zenarmor[54321]: daemon=zenarmor, index=" +
			index + ", data=" + data)
	}

	cases := []struct {
		name       string
		index      string
		data       string
		wantFamily string
	}{
		{"conn->flow", "conn", connDoc, "flow"},
		{"dns", "dns", dnsDoc, "dns"},
		{"tls", "tls", tlsDoc, "tls"},
		{"http->web", "http", httpDoc, "web"},
		{"alert->ids", "alert", alertDoc, "ids"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := syslog.ParseEnvelope(line(tc.index, tc.data), now)
			if err != nil {
				t.Fatalf("ParseEnvelope: %v", err)
			}
			if env.Program != "zenarmor" {
				t.Fatalf("Program = %q, want zenarmor", env.Program)
			}
			if !sp.Handles(env.Program) {
				t.Fatal("Handles(zenarmor) = false")
			}

			var got logship.Record
			n := 0
			handled := sp.Process(env, peer, ports, func(r logship.Record) { got = r; n++ })
			if !handled || n != 1 {
				t.Fatalf("handled=%v emitted=%d, want true/1", handled, n)
			}

			if got.Source != sourceName {
				t.Errorf("Source = %q, want %q", got.Source, sourceName)
			}
			if fam := got.Attributes[logship.AttrSubsystem]; fam != tc.wantFamily {
				t.Errorf("subsystem = %q, want %q", fam, tc.wantFamily)
			}
		})
	}

	// is_blocked=0 (conn/flow fixture): the record carries the "pass" disposition, not
	// "block" -- confirms the is_blocked=1/0 discrimination survives the syslog path,
	// not just the ES path already covered by parse_test.go.
	t.Run("is_blocked=0 carries pass", func(t *testing.T) {
		env, err := syslog.ParseEnvelope(line("conn", connDoc), now)
		if err != nil {
			t.Fatalf("ParseEnvelope: %v", err)
		}
		var got logship.Record
		sp.Process(env, peer, ports, func(r logship.Record) { got = r })
		if got.Attributes[logship.AttrAction] != logship.ActionPass {
			t.Errorf("action = %q, want %q", got.Attributes[logship.AttrAction], logship.ActionPass)
		}
	})

	// is_blocked=1 (alertDoc): the record carries the "block" disposition, and (the
	// Task 1 fix) alertinfo.* decodes instead of failing the whole document.
	t.Run("is_blocked=1 carries block and alertinfo", func(t *testing.T) {
		env, err := syslog.ParseEnvelope(line("alert", alertDoc), now)
		if err != nil {
			t.Fatalf("ParseEnvelope: %v", err)
		}
		var got logship.Record
		sp.Process(env, peer, ports, func(r logship.Record) { got = r })

		if got.Attributes[logship.AttrAction] != logship.ActionBlock {
			t.Errorf("action = %q, want %q", got.Attributes[logship.AttrAction], logship.ActionBlock)
		}
		wantAttrs := map[string]string{
			"alertinfo.category":  "Attempted Administrator Privilege Gain",
			"alertinfo.signature": "ET EXPLOIT Possible CVE-2021-44228",
			"alertinfo.sid":       "2034647",
			"alertinfo.severity":  "1",
			"alertinfo.action":    "reject",
		}
		for k, want := range wantAttrs {
			if got.Attributes[k] != want {
				t.Errorf("Attributes[%q] = %q, want %q", k, got.Attributes[k], want)
			}
		}
	})
}
