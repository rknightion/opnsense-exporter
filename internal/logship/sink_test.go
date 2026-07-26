package logship

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

func TestStdoutSink_OneJSONLinePerEntry(t *testing.T) {
	var buf bytes.Buffer
	s := newStdoutSinkTo(&buf)
	ts := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	batch := []Entry{
		{Source: "firewall", Record: Record{Timestamp: ts, Body: "block", Severity: SeverityWarn, Attributes: map[string]string{"src": "10.0.0.1"}}},
		{Source: "ids", Record: Record{Body: "alert"}},
	}
	res := s.Emit(context.Background(), batch)
	if len(res.Acked) != len(batch) || res.Err != nil {
		t.Fatalf("emit: %+v", res)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d: %q", len(lines), buf.String())
	}
	var first stdoutLine
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 not valid JSON: %v", err)
	}
	if first.Source != "firewall" || first.Body != "block" || first.Severity != "warn" || first.Attributes["src"] != "10.0.0.1" {
		t.Fatalf("unexpected line 0: %+v", first)
	}
}

func TestBuildSink_OTLPRequiresEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	cfg := &options.LogsConfig{Sink: "otlp", PollInterval: 5 * time.Second, BufferSize: 1, BatchMax: 1}
	transport := &options.OTLPConfig{Protocol: "http/protobuf"} // no endpoint
	_, err := buildSink(cfg, transport, "v", "inst", nil)
	if err == nil {
		t.Fatal("expected an actionable error when no OTLP endpoint is resolvable")
	}
	if !strings.Contains(err.Error(), "--otlp.endpoint") {
		t.Fatalf("error should name the missing flag, got: %v", err)
	}
}

func TestBuildSink_OTLPNilTransport(t *testing.T) {
	cfg := &options.LogsConfig{Sink: "otlp", PollInterval: 5 * time.Second, BufferSize: 1, BatchMax: 1}
	_, err := buildSink(cfg, nil, "v", "inst", nil)
	if err == nil || !strings.Contains(err.Error(), "--otlp.") {
		t.Fatalf("expected actionable nil-transport error, got: %v", err)
	}
}

func TestBuildSink_Stdout(t *testing.T) {
	cfg := &options.LogsConfig{Sink: "stdout", PollInterval: 5 * time.Second, BufferSize: 1, BatchMax: 1}
	sink, err := buildSink(cfg, nil, "v", "inst", nil)
	if err != nil {
		t.Fatalf("stdout sink build: %v", err)
	}
	if _, ok := sink.(*stdoutSink); !ok {
		t.Fatalf("expected *stdoutSink, got %T", sink)
	}
}

func TestLogsEndpointURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://otlp-gateway-x.grafana.net/otlp", "https://otlp-gateway-x.grafana.net/otlp/v1/logs"},
		{"https://collector:4318", "https://collector:4318"}, // empty path -> SDK default
		{"https://collector:4318/v1/logs", "https://collector:4318/v1/logs"},
		{"https://collector:4318/otlp/", "https://collector:4318/otlp/v1/logs"},
	}
	for _, c := range cases {
		got, err := logsEndpointURL(c.in)
		if err != nil {
			t.Fatalf("logsEndpointURL(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("logsEndpointURL(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
