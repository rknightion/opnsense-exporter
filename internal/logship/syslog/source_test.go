package syslog

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

type parseErrorSample struct {
	labels map[string]string
	value  float64
}

func sourceParseErrorSamples(t *testing.T, reg *prometheus.Registry) []parseErrorSample {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "opnsense_exporter_logs_parse_errors_total" {
			continue
		}
		samples := make([]parseErrorSample, 0, len(family.GetMetric()))
		for _, metric := range family.GetMetric() {
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			samples = append(samples, parseErrorSample{
				labels: labels,
				value:  metric.GetCounter().GetValue(),
			})
		}
		return samples
	}
	t.Fatal("logs_parse_errors_total was not registered")
	return nil
}

func envelopeFailureOutcomeError(line []byte, emitted []logship.Record, samples []parseErrorSample) error {
	if len(emitted) != 1 {
		return fmt.Errorf("emitted %d records, want 1", len(emitted))
	}
	if emitted[0].Body != string(line) {
		return fmt.Errorf("record body = %q, want original raw line %q", emitted[0].Body, line)
	}
	if len(samples) != 1 {
		return fmt.Errorf("parse-error samples = %d, want exactly 1", len(samples))
	}
	if want := map[string]string{"source": sourceName, "stage": "envelope"}; !sameLabels(samples[0].labels, want) {
		return fmt.Errorf("parse-error labels = %v, want bounded vocabulary %v", samples[0].labels, want)
	}
	if samples[0].value != 1 {
		return fmt.Errorf("parse-error count = %v, want 1", samples[0].value)
	}
	return nil
}

func sameLabels(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			return false
		}
	}
	return true
}

// #397: an RFC5424 envelope with unclosed structured data must remain an
// unparsed record. It must not silently turn into an empty parsed message: the
// shipped body remains the original bytes and the bounded envelope counter rises
// once.
func TestSourceUnclosedStructuredDataShipsRawBodyAndCountsEnvelopeParseError(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := newSource(&options.SyslogConfig{}, logship.Deps{Registerer: reg})
	var emitted []logship.Record
	s.emit = func(record logship.Record) { emitted = append(emitted, record) }

	line := []byte(`<134>1 2026-07-26T12:34:56Z firewall filterlog 123 ID47 [example@32473 key="value" still-unclosed payload`)
	s.handle(line, netip.MustParseAddr("192.0.2.1"))

	samples := sourceParseErrorSamples(t, reg)
	if err := envelopeFailureOutcomeError(line, emitted, samples); err != nil {
		t.Fatal(err)
	}

	// The production fix is already present, so prove this characterization is not
	// tautological without changing production: either regression (truncation or a
	// missing count) makes the same observable-outcome check fail.
	truncated := append([]logship.Record(nil), emitted...)
	truncated[0].Body = string(line[:len(line)-1])
	if err := envelopeFailureOutcomeError(line, truncated, samples); err == nil {
		t.Fatal("outcome check accepted a truncated raw body")
	}
	missingCount := append([]parseErrorSample(nil), samples...)
	missingCount[0].value = 0
	if err := envelopeFailureOutcomeError(line, emitted, missingCount); err == nil {
		t.Fatal("outcome check accepted a missing envelope parse-error increment")
	}
}
