package syslog

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/capture"
)

func TestCapturedAPIFailureRedactsBeforeShippingAndCapture(t *testing.T) {
	const secret = "synthetic-private-key-material"
	for _, tc := range []struct {
		name, program, message string
		malformed              bool
	}{
		{"supported", "api", "uri /api/dnsmasq/settings/searchHost authentication failed for api key " + secret, false},
		{"multiline", "api", "uri /api/dnsmasq/settings/searchHost authentication failed for api key " + secret + "\nsecond-secret-line", false},
		{"unknown-shape", "api", "new error: authentication failed for api key " + secret, false},
		{"malformed-envelope", "api", "uri /api/example authentication failed for api key " + secret, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cap, err := capture.New(capture.Config{Dir: dir, MaxBytes: 8 << 20}, prometheus.NewRegistry(), nil)
			if err != nil {
				t.Fatal(err)
			}
			s := newCaptureSource(t, cap)
			var records []logship.Record
			s.emit = func(r logship.Record) { records = append(records, r) }
			raw := syslogTestLine(tc.program, tc.message)
			if tc.malformed {
				raw = []byte("<bad> api " + tc.message)
			}
			s.handle(raw, netip.MustParseAddr("192.0.2.1"))
			if err := cap.Close(); err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 {
				t.Fatalf("shipped=%d", len(records))
			}
			captures := readSyslogCaptures(t, dir)
			wantCaptures := 0
			if tc.name == "unknown-shape" || tc.malformed {
				wantCaptures = 1
			}
			if len(captures) != wantCaptures {
				t.Fatalf("captures=%d, want %d", len(captures), wantCaptures)
			}
			for sink, value := range map[string]any{"shipped": records, "capture": captures} {
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), secret) || strings.Contains(string(data), "second-secret-line") {
					t.Fatalf("credential reached %s", sink)
				}
				if (sink == "shipped" || wantCaptures > 0) && !strings.Contains(string(data), "[REDACTED]") {
					t.Fatalf("redaction marker absent from %s", sink)
				}
			}
			if tc.name == "supported" {
				assertAttrs(t, records[0], map[string]string{"syslog.event": "api_authentication_failed", "url.path": "/api/dnsmasq/settings/searchHost"})
			}
		})
	}
}
