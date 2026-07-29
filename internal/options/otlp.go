package options

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

var (
	otlpEnabled = kingpin.Flag(
		"otlp.enabled",
		"Enable pushing metrics to an OTLP endpoint (in addition to the /metrics pull endpoint). "+
			"Off by default.",
	).Envar("OPNSENSE_EXPORTER_OTLP_ENABLED").Default("false").Bool()
	otlpEndpoint = kingpin.Flag(
		"otlp.endpoint",
		"OTLP endpoint URL. When empty, the standard OTEL_EXPORTER_OTLP_ENDPOINT env var is used.",
	).Envar("OPNSENSE_EXPORTER_OTLP_ENDPOINT").Default("").String()
	otlpProtocol = kingpin.Flag(
		"otlp.protocol",
		"OTLP transport protocol: grpc or http/protobuf. Defaults to http/protobuf; an empty value is rejected.",
	).Envar("OPNSENSE_EXPORTER_OTLP_PROTOCOL").Default("http/protobuf").String()
	otlpInsecure = kingpin.Flag(
		"otlp.insecure",
		"Disable TLS for the OTLP connection (plaintext).",
	).Envar("OPNSENSE_EXPORTER_OTLP_INSECURE").Default("false").Bool()
	otlpHeaders = kingpin.Flag(
		"otlp.headers",
		"OTLP headers as comma-separated key=value pairs (e.g. X-Scope-OrgID=1,Authorization=Bearer x). "+
			"When set, replaces OTEL_EXPORTER_OTLP_HEADERS entirely; when empty, that env var is used.",
	).Envar("OPNSENSE_EXPORTER_OTLP_HEADERS").Default("").String()
	otlpExportInterval = kingpin.Flag(
		"otlp.export-interval",
		"Interval between OTLP metric exports (independent of Prometheus scrapes).",
	).Envar("OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL").Default("60s").Duration()
	otlpFastExportInterval = kingpin.Flag(
		"otlp.fast-export-interval",
		"Optional second OTLP export lane for fast-tier collectors only (#390). Zero (the default) keeps the single-stream behaviour exactly. When set, fast-tier collectors (gateways, interfaces, protocol, pf_stats, activity, netflow, carp — or whatever --collector.poll-interval-override makes fast) export at this interval while everything else stays on --otlp.export-interval. Must be shorter than --otlp.export-interval. Fast-tier series are a small fraction of the total, so 15s here costs far less than setting --otlp.export-interval=15s for everything.",
	).Envar("OPNSENSE_EXPORTER_OTLP_FAST_EXPORT_INTERVAL").Default("0s").Duration()
	otlpTLSCAFile = kingpin.Flag(
		"otlp.tls-ca-file",
		"Path to a CA certificate file used to verify the OTLP server.",
	).Envar("OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE").Default("").String()
	otlpTLSCertFile = kingpin.Flag(
		"otlp.tls-cert-file",
		"Path to a client certificate file for OTLP mutual TLS (requires --otlp.tls-key-file).",
	).Envar("OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE").Default("").String()
	otlpTLSKeyFile = kingpin.Flag(
		"otlp.tls-key-file",
		"Path to a client key file for OTLP mutual TLS (requires --otlp.tls-cert-file).",
	).Envar("OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE").Default("").String()
	otlpServiceName = kingpin.Flag(
		"otlp.service-name",
		"service.name resource attribute for exported metrics.",
	).Envar("OPNSENSE_EXPORTER_OTLP_SERVICE_NAME").Default("opnsense-exporter").String()
	otlpGCInstanceID = kingpin.Flag(
		"otlp.grafana-cloud-instance-id",
		"Grafana Cloud OTLP instance ID. With --otlp.grafana-cloud-token, synthesizes basic-auth. "+
			"This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE may be set.",
	).Envar("OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID").Default("").String()
	otlpGCToken = kingpin.Flag(
		"otlp.grafana-cloud-token",
		"Grafana Cloud Access Policy token. "+
			"This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE may be set.",
	).Envar("OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN").Default("").String()
	otlpGCEndpoint = kingpin.Flag(
		"otlp.grafana-cloud-endpoint",
		"Grafana Cloud OTLP gateway base URL (required when using the Grafana Cloud shortcut).",
	).Envar("OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT").Default("").String()
)

// OTLPConfig holds the resolved configuration for OTLP metrics export.
//
// Temporality is intentionally not configurable: metrics are sourced from the
// Prometheus registry via a bridge producer, so they arrive already aggregated as
// cumulative (Prometheus' model) and are exported as-is. That is exactly the
// temporality Grafana Cloud / Prometheus OTLP ingest require, and an exporter-side
// temporality selector cannot re-aggregate producer-supplied metrics anyway.
type OTLPConfig struct {
	Endpoint       string
	Protocol       string // "grpc" | "http/protobuf" (empty is rejected: no OTEL_* env fallthrough exists)
	Insecure       bool
	Headers        map[string]string
	ExportInterval time.Duration
	// FastExportInterval, when > 0, enables the optional second export lane
	// carrying only fast-tier collectors (#390). Zero means one lane, exactly as
	// before.
	FastExportInterval time.Duration
	TLSCAFile          string
	TLSCertFile        string
	TLSKeyFile         string
	ServiceName        string
}

// Validate checks an enabled OTLP configuration for internal consistency.
func (c *OTLPConfig) Validate() error {
	// The OTel Go SDK selects protocol by which exporter package is imported, not from
	// OTEL_EXPORTER_OTLP_PROTOCOL (which it never reads), so an empty value has no
	// fallthrough — reject it as a config error rather than silently defaulting.
	switch c.Protocol {
	case "grpc", "http/protobuf":
	default:
		return fmt.Errorf("otlp protocol must be grpc or http/protobuf, got %q", c.Protocol)
	}
	if c.ExportInterval <= 0 {
		return fmt.Errorf("otlp export-interval must be positive, got %s", c.ExportInterval)
	}
	// A fast lane no faster than the base lane buys nothing and doubles the export
	// calls, so reject it rather than silently accepting a pointless split.
	if c.FastExportInterval < 0 {
		return fmt.Errorf("otlp fast-export-interval must not be negative, got %s", c.FastExportInterval)
	}
	if c.FastExportInterval > 0 && c.FastExportInterval >= c.ExportInterval {
		return fmt.Errorf(
			"otlp fast-export-interval (%s) must be shorter than otlp export-interval (%s); a fast lane that is not faster only doubles export calls",
			c.FastExportInterval, c.ExportInterval)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("otlp mutual TLS requires both --otlp.tls-cert-file and --otlp.tls-key-file")
	}
	hasTLSMaterial := c.TLSCAFile != "" || c.TLSCertFile != "" || c.TLSKeyFile != ""
	// --otlp.insecure means plaintext, which is mutually exclusive with TLS
	// material. The http exporter rejects this at construction (a non-fatal start
	// failure that would silently disable export); the grpc exporter silently
	// ignores insecure. Reject it up front so it is a fatal, obvious config error.
	if c.Insecure && hasTLSMaterial {
		return fmt.Errorf("otlp --otlp.insecure cannot be combined with --otlp.tls-ca-file/--otlp.tls-cert-file/--otlp.tls-key-file")
	}
	// For http/protobuf the SDK derives insecurity from the endpoint URL scheme in
	// WithEndpointURL (non-https ⇒ insecure), independent of --otlp.insecure, then
	// rejects TLS material at construction with errInsecureEndpointWithTLS — another
	// silent, non-fatal export failure. Catch it here. grpc is unaffected: its oconf
	// prioritizes TLS credentials over scheme-derived insecurity.
	if c.Protocol == "http/protobuf" && hasTLSMaterial && c.Endpoint != "" {
		if u, err := url.Parse(c.Endpoint); err == nil && u.Scheme != "" && u.Scheme != "https" {
			return fmt.Errorf("otlp http/protobuf endpoint %q uses a non-https scheme (treated as insecure by the SDK) but TLS files are set; use an https:// endpoint or drop the TLS files", c.Endpoint)
		}
	}
	return nil
}

// otlpRawInputs is the set of raw flag/env values (with secrets already resolved)
// that assembleOTLP turns into an OTLPConfig. Splitting it out keeps the precedence
// and Grafana Cloud shortcut logic pure and unit-testable, independent of the
// package-global kingpin flags.
type otlpRawInputs struct {
	enabled      bool
	endpoint     string
	protocol     string
	insecure     bool
	headers      string
	interval     time.Duration
	fastInterval time.Duration
	tlsCAFile    string
	tlsCertFile  string
	tlsKeyFile   string
	serviceName  string
	gcInstanceID string
	gcToken      string
	gcEndpoint   string
}

// parseHeaders parses "k=v,k2=v2" into a map. Whitespace around keys, values and
// separators is trimmed. Only the first '=' is treated as the separator so header
// values may themselves contain '='. Empty segments (from leading/trailing/repeated
// commas) are skipped. A segment missing '=' or with an empty key is a fatal error,
// as is a non-empty input that yields zero pairs: silently dropping these would let a
// malformed --otlp.headers fall back to OTEL_EXPORTER_OTLP_HEADERS, inverting the
// documented "when set, replaces it entirely" contract (#92).
//
// Error messages deliberately never interpolate the raw segment or its value (#308):
// main.go logs this error verbatim at startup, and a header value is very often a
// bearer token or similar secret, so a typo (e.g. ':' instead of '=') must not print
// the secret to stderr/log sinks. Errors instead cite the segment's 1-based position
// in the comma-separated list; where a key was successfully extracted it is named too
// (a key name is not a secret — only the value, and the pre-'=' text when no '=' was
// found at all, are treated as sensitive).
func parseHeaders(s string) (map[string]string, error) {
	out := map[string]string{}
	pos := 0
	for pair := range strings.SplitSeq(s, ",") {
		pos++
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("otlp header at position %d is missing '='; expected key=value", pos)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, fmt.Errorf("otlp header at position %d has an empty key", pos)
		}
		out[k] = strings.TrimSpace(v)
	}
	if strings.TrimSpace(s) != "" && len(out) == 0 {
		return nil, fmt.Errorf("otlp headers parsed to zero valid key=value pairs")
	}
	return out, nil
}

// assembleOTLP applies precedence and the Grafana Cloud shortcut to raw inputs,
// returning the resolved config and whether OTLP export is enabled. Precedence
// (highest first): explicit flags/OPNSENSE_EXPORTER_OTLP_* env, then the Grafana
// Cloud shortcut, then standard OTEL_* env consulted later by the SDK when a field
// is left empty.
func assembleOTLP(in otlpRawInputs) (*OTLPConfig, bool, error) {
	if !in.enabled {
		return nil, false, nil
	}

	headers, err := parseHeaders(in.headers)
	if err != nil {
		return nil, false, err
	}

	// Grafana Cloud shortcut: both id and token required; synthesize basic-auth and
	// (when no explicit endpoint is set) the endpoint. Explicit values always win.
	gcID := strings.TrimSpace(in.gcInstanceID)
	gcToken := strings.TrimSpace(in.gcToken)
	endpoint := strings.TrimSpace(in.endpoint)
	switch {
	case gcID != "" && gcToken == "":
		return nil, false, fmt.Errorf("otlp grafana-cloud-instance-id set without grafana-cloud-token")
	case gcToken != "" && gcID == "":
		return nil, false, fmt.Errorf("otlp grafana-cloud-token set without grafana-cloud-instance-id")
	case gcID != "" && gcToken != "":
		gcEndpoint := strings.TrimSpace(in.gcEndpoint)
		if endpoint == "" {
			endpoint = gcEndpoint
		}
		if endpoint == "" {
			return nil, false, fmt.Errorf("otlp grafana-cloud credentials set but no endpoint (set --otlp.grafana-cloud-endpoint or --otlp.endpoint)")
		}
		if _, ok := headers["Authorization"]; !ok {
			auth := base64.StdEncoding.EncodeToString([]byte(gcID + ":" + gcToken))
			headers["Authorization"] = "Basic " + auth
		}
	}

	if len(headers) == 0 {
		headers = nil
	}

	cfg := &OTLPConfig{
		Endpoint:           endpoint,
		Protocol:           strings.TrimSpace(in.protocol),
		Insecure:           in.insecure,
		Headers:            headers,
		ExportInterval:     in.interval,
		FastExportInterval: in.fastInterval,
		TLSCAFile:          strings.TrimSpace(in.tlsCAFile),
		TLSCertFile:        strings.TrimSpace(in.tlsCertFile),
		TLSKeyFile:         strings.TrimSpace(in.tlsKeyFile),
		ServiceName:        strings.TrimSpace(in.serviceName),
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return cfg, true, nil
}

// OTLP assembles the OTLP export configuration from flags/env. The returned bool
// reports whether OTLP metrics export is enabled (true only when --otlp.enabled is
// set). Grafana Cloud instance ID and token support *_FILE secret variants,
// mirroring the OPS_API_*_FILE precedence used elsewhere.
func OTLP() (*OTLPConfig, bool, error) {
	if !*otlpEnabled {
		return nil, false, nil
	}
	return resolveOTLPTransport()
}

// OTLPTransport resolves the OTLP transport configuration (endpoint, protocol,
// TLS, headers, Grafana Cloud shortcut, service name) from the --otlp.* flags
// WITHOUT the --otlp.enabled gate. It exists so the log-shipping OTLP sink can
// reuse the exact same transport family: metrics stay gated by --otlp.enabled,
// logs by --logs.enabled, and both share one transport config. It returns an
// actionable error when the configuration is inconsistent (e.g. a Grafana Cloud
// id without a token, or a missing endpoint) so a logs-only caller can report
// exactly which --otlp.* flag is missing.
func OTLPTransport() (*OTLPConfig, error) {
	cfg, _, err := resolveOTLPTransport()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// resolveOTLPTransport resolves secrets and assembles the transport with the
// enabled flag forced true (so the transport is always built regardless of
// --otlp.enabled). The returned bool is always true on success; it exists so
// OTLP() can return it directly.
func resolveOTLPTransport() (*OTLPConfig, bool, error) {
	gcID, err := resolveSecret("OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE", *otlpGCInstanceID)
	if err != nil {
		return nil, false, err
	}
	gcToken, err := resolveSecret("OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE", *otlpGCToken)
	if err != nil {
		return nil, false, err
	}

	return assembleOTLP(otlpRawInputs{
		enabled:      true,
		endpoint:     *otlpEndpoint,
		protocol:     *otlpProtocol,
		insecure:     *otlpInsecure,
		headers:      *otlpHeaders,
		interval:     *otlpExportInterval,
		fastInterval: *otlpFastExportInterval,
		tlsCAFile:    *otlpTLSCAFile,
		tlsCertFile:  *otlpTLSCertFile,
		tlsKeyFile:   *otlpTLSKeyFile,
		serviceName:  *otlpServiceName,
		gcInstanceID: gcID,
		gcToken:      gcToken,
		gcEndpoint:   *otlpGCEndpoint,
	})
}

// OTLPSignalLogs and OTLPSignalMetrics name the OTLP signals whose exporters this
// binary builds. They form the signal-specific half of the compression environment
// variable names below.
const (
	OTLPSignalLogs    = "LOGS"
	OTLPSignalMetrics = "METRICS"
)

// OTLPGzipDefault reports whether the caller should ASK for gzip on this signal.
//
// It answers false whenever the operator has stated a preference through the
// environment, so `OTEL_EXPORTER_OTLP_COMPRESSION=none` genuinely disables compression
// rather than being silently overridden.
//
// The keys are listed signal-specific first, matching the SDK's own order and the spec's
// rule that "Each configuration option MUST be overridable by a signal specific option".
// Be aware that the order is DOCUMENTARY here, not load-bearing: this returns a bool, and
// any recognised value in either key produces false, so the loop is an OR and reversing
// it would change nothing. Actual precedence is enforced downstream by the SDK, which is
// the component that reads the value. Order only starts to matter if this ever returns
// WHICH key supplied the preference rather than merely whether one did.
//
// WHY THE CALLER MUST NOT JUST PASS WithCompression UNCONDITIONALLY: in the OTel Go
// SDK's config resolution, a passed option BEATS the environment — getenv() returns early
// when the setting is already Set, commented "Passed, valid, options have precedence".
// So an unconditional WithCompression would make the documented env override a no-op.
// Asking this function first, and staying silent when it says false, is what keeps the
// override working.
//
// DEFAULTING TO GZIP IS DELIBERATE AND SPEC-SANCTIONED. The OTLP exporter spec lists the
// default as "No value" (no compression) but explicitly delegates the choice: "If no
// compression value is explicitly specified, SIGs can default to the value they deem most
// useful among the supported options"
// (https://opentelemetry.io/docs/specs/otel/protocol/exporter/). Both signals here ship
// highly compressible payloads — log lines, and Prometheus-bridged metric families whose
// name and label strings repeat on every export — so gzip is the largest egress lever on
// either path and costs a little CPU on a box that is otherwise idle between scrapes.
//
// An unrecognised value falls through to the next key and finally to the gzip default,
// mirroring the SDK's own loop, which skips values that fail conversion — the difference
// being that our terminal fallback is gzip rather than none.
func OTLPGzipDefault(signal string) bool {
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_" + signal + "_COMPRESSION",
		"OTEL_EXPORTER_OTLP_COMPRESSION",
	} {
		switch os.Getenv(k) {
		case "none", "gzip":
			return false
		}
	}
	return true
}
