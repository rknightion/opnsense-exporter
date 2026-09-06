package syslog

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

type unparsedMetricSink struct {
	subsystems []string
}

func (s *unparsedMetricSink) Unparsed(subsystem string) {
	s.subsystems = append(s.subsystems, subsystem)
}

func unparsedTestSource(t *testing.T, observer *unparsedMetricSink) *source {
	t.Helper()
	return &source{
		cache:  enrich.NewCache(),
		m:      logship.NewReceiverMetrics(prometheus.NewRegistry(), sourceName, logship.ReceiverVocab{Reasons: RejectReasons, Stages: ParseStages}),
		filter: NewFilter(nil, nil, 0, false),
		sink:   logship.NopMetricSink{},
		// The production source routes this through ReceiverMetrics. Tests exercise
		// the same helper with a recorder because the new root method is owned by
		// the integration lane.
		unparsed: observer.Unparsed,
	}
}

func syslogTestLine(program, message string) []byte {
	return []byte(fmt.Sprintf(
		"<134>1 2026-07-14T19:50:01Z opnsense %s 42 - - %s",
		program, message,
	))
}

// A parser that was selected but rejected its body is parser-coverage erosion,
// whereas a program with no parser is expected catch-all traffic. The metric must
// count only the former and must receive subsystemFor's bounded value, never the
// raw program name.
func TestSourceCountsOnlyParserDispatchedUnparsedMessages(t *testing.T) {
	sink := &unparsedMetricSink{}
	s := unparsedTestSource(t, sink)
	s.emit = func(logship.Record) {}

	cases := []struct {
		program   string
		message   string
		subsystem string
	}{
		{"filterlog", "not,enough,fields", "firewall"},
		{"openvpn_server40", "not an OpenVPN lifecycle line", "vpn"},
		// opnsense is intentionally a catch-all program whose subsystemFor value is
		// empty; the empty label is still a bounded, code-defined result and must not
		// turn into the unbounded program name.
		{"opnsense", "not an AcmeClient line", ""},
	}
	for _, tc := range cases {
		t.Run(tc.program, func(t *testing.T) {
			if _, ok := parserFor(tc.program); !ok {
				t.Fatalf("parserFor(%q) = false, want a dispatch for this test", tc.program)
			}
			s.handle(syslogTestLine(tc.program, tc.message), netip.MustParseAddr("192.0.2.1"))
		})
	}

	// A genuinely unknown program is generic traffic, not an erosion of a parser
	// contract, so it must not add a fourth observation.
	s.handle(syslogTestLine("mystery-plugin", "unknown program"), netip.MustParseAddr("192.0.2.1"))

	want := []string{"firewall", "vpn", ""}
	if len(sink.subsystems) != len(want) {
		t.Fatalf("unparsed observations = %v, want %v", sink.subsystems, want)
	}
	for i := range want {
		if sink.subsystems[i] != want[i] {
			t.Errorf("observation %d subsystem = %q, want %q", i, sink.subsystems[i], want[i])
		}
	}
}

// Keep the test seam's nil enrichment cache explicit: parser-coverage counting
// must not depend on API enrichment being available.
func TestSourceUnparsedMetricDoesNotNeedEnrichmentSnapshot(t *testing.T) {
	sink := &unparsedMetricSink{}
	s := &source{
		cache:    enrich.NewCache(),
		m:        logship.NewReceiverMetrics(prometheus.NewRegistry(), sourceName, logship.ReceiverVocab{Reasons: RejectReasons, Stages: ParseStages}),
		filter:   NewFilter(nil, nil, 0, false),
		sink:     logship.NopMetricSink{},
		unparsed: sink.Unparsed,
	}
	s.emit = func(logship.Record) {}

	s.handle(syslogTestLine("filterlog", "not,enough,fields"), netip.MustParseAddr("192.0.2.1"))
	if len(sink.subsystems) != 1 || sink.subsystems[0] != "firewall" {
		t.Fatalf("unparsed observations = %v, want [firewall]", sink.subsystems)
	}
}
