// Command apidrift is the live half of the OPNsense API drift detection
// (issue #195). It probes every manifest endpoint on a (development-channel)
// OPNsense box with the same requests the exporter sends, validates the
// response STRUCTURE against schemas derived from the exporter's own response
// structs (see opnsense/schema.go), and emits a markdown drift report plus
// GitHub Actions step outputs.
//
// Severity model: a type mismatch on a consumed path is breaking (exit 1,
// `drift=true`); missing paths, unexpected top-level keys, vanished endpoints
// (404) and probe errors are warnings (exit 0, `warnings=true`). Raw captures
// stay in a runner-local scratch dir; the report carries key paths and JSON
// type names only — never response values.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

func main() {
	baseURL := flag.String("base-url", os.Getenv("OPNSENSE_CAPTURE_BASE_URL"), "OPNsense base URL, e.g. https://192.168.1.1 (env OPNSENSE_CAPTURE_BASE_URL)")
	apiKey := flag.String("api-key", os.Getenv("OPNSENSE_EXPORTER_OPS_API_KEY"), "OPNsense API key (env OPNSENSE_EXPORTER_OPS_API_KEY)")
	apiSecret := flag.String("api-secret", os.Getenv("OPNSENSE_EXPORTER_OPS_API_SECRET"), "OPNsense API secret (env OPNSENSE_EXPORTER_OPS_API_SECRET)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (for self-signed OPNsense certs)")
	out := flag.String("out", "", "write the markdown report to this file as well as stdout")
	captures := flag.String("captures", "", "runner-local scratch dir for raw captures (never commit or upload)")
	exemptionsPath := flag.String("exemptions", "opnsense/testdata/schemas/exemptions.json", "committed known-optional-paths file")
	flag.Parse()

	resolvedKey, err := options.ResolveOPSAPIKey(*apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving API key: %v\n", err)
		os.Exit(2)
	}
	resolvedSecret, err := options.ResolveOPSAPISecret(*apiSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving API secret: %v\n", err)
		os.Exit(2)
	}
	if *baseURL == "" || resolvedKey == "" || resolvedSecret == "" {
		fmt.Fprintln(os.Stderr, "error: --base-url, --api-key and --api-secret (or their env vars) are required")
		flag.Usage()
		os.Exit(2)
	}

	schemas, err := opnsense.AllEndpointSchemas()
	if err != nil {
		fmt.Fprintf(os.Stderr, "deriving endpoint schemas: %v\n", err)
		os.Exit(2)
	}
	exemptions, err := loadExemptions(*exemptionsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading exemptions: %v\n", err)
		os.Exit(2)
	}

	p := &prober{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure}, //nolint:gosec // opt-in for self-signed boxes
			},
		},
		baseURL:  *baseURL,
		key:      resolvedKey,
		secret:   resolvedSecret,
		captures: *captures,
	}

	// Pre-flight: one cheap probe before the full sweep. When the box is
	// unreachable (tailnet ACL, box down), failing fast beats 107 endpoints
	// each burning the client timeout twice.
	if _, _, err := p.fetchRaw("GET", "api/core/system/status", "", ""); err != nil {
		fmt.Fprintf(os.Stderr, "pre-flight probe failed — box unreachable from here: %v\n", err)
		os.Exit(2)
	}

	results := p.probeAll(schemas, exemptions)

	// A box-wide outage is a probe problem, not API drift — fail loudly so the
	// workflow step errors instead of filing a misleading drift issue.
	var errored int
	for _, r := range results {
		if r.ProbeErr != "" {
			errored++
		}
	}
	if len(results) > 0 && errored > len(results)/2 {
		fmt.Fprintf(os.Stderr, "%d/%d endpoints failed to probe — box unreachable or credentials bad\n", errored, len(results))
		os.Exit(2)
	}

	report := renderReport(results, stringKeyed(opnsense.SchemaExemptions()))
	fmt.Print(report)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(2)
		}
	}

	drift, warnings := aggregate(results)
	if ghOut := os.Getenv("GITHUB_OUTPUT"); ghOut != "" {
		f, err := os.OpenFile(ghOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "drift=%t\nwarnings=%t\n", drift, warnings)
			f.Close()
		}
	}
	if drift {
		os.Exit(1)
	}
}

// stringKeyed converts the exemption map for the report renderer.
func stringKeyed(in map[opnsense.EndpointName]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}
