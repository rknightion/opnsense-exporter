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
	"slices"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

func main() {
	baseURL := flag.String("base-url", os.Getenv("OPNSENSE_CAPTURE_BASE_URL"), "OPNsense base URL, e.g. https://192.168.1.1 (env OPNSENSE_CAPTURE_BASE_URL)")
	apiKey := flag.String("api-key", os.Getenv("OPN2OTEL_OPS_API_KEY"), "OPNsense API key (env OPN2OTEL_OPS_API_KEY)")
	apiSecret := flag.String("api-secret", os.Getenv("OPN2OTEL_OPS_API_SECRET"), "OPNsense API secret (env OPN2OTEL_OPS_API_SECRET)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (for self-signed OPNsense certs)")
	out := flag.String("out", "", "write the markdown report to this file as well as stdout")
	captures := flag.String("captures", "", "runner-local scratch dir for raw captures (never commit or upload)")
	exemptionsPath := flag.String("exemptions", "opnsense/testdata/schemas/exemptions.json", "committed known-optional-paths file")
	gen := flag.String("generation", os.Getenv("OPNSENSE_CANARY_GENERATION"), "OPNsense generation label for the report heading, e.g. \"release 26.7.1_1\" (env OPNSENSE_CANARY_GENERATION)")
	profile := flag.String("profile", os.Getenv("OPNSENSE_CANARY_PROFILE"), fmt.Sprintf("probe profile selecting profile-scoped ledger entries, one of %v (env OPNSENSE_CANARY_PROFILE)", opnsense.KnownProbeProfiles()))
	flag.Parse()
	generation = *gen
	// Set BEFORE the validation below only in the sense that it is assigned
	// here; nothing reads it until the report is rendered, and an unknown value
	// exits non-zero two lines down rather than reaching the coverage ledger.
	canaryProfile = *profile

	// Reject an unknown profile rather than falling back to the base ledger.
	// A silent fallback would still produce a plausible-looking report, just
	// with the target's exemptions quietly inactive, and nothing in the output
	// would say so.
	if *profile != "" && !slices.Contains(opnsense.KnownProbeProfiles(), *profile) {
		fmt.Fprintf(os.Stderr, "error: unknown --profile %q, want one of %v\n", *profile, opnsense.KnownProbeProfiles())
		os.Exit(2)
	}

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
	// Flatten once, here, so every consumer below keeps seeing a plain
	// exemption and only this line knows profiles exist (#490).
	for name, ex := range exemptions {
		exemptions[name] = ex.ForProfile(*profile)
	}

	p := &prober{
		client: &http.Client{
			Timeout: 30 * time.Second,
			// Never follow a redirect, matching opnsense/client.go (#306/#307).
			// This tool also SetBasicAuth's the API key+secret before every Do,
			// and Go's stdlib strips Authorization on a redirect only when the
			// target's HOSTNAME differs — not its scheme, not its port — so an
			// https->http bounce on the same host would hand the credentials
			// over in cleartext.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure}, //nolint:gosec // opt-in for self-signed boxes
				// Load-bearing, and easy to lose: setting TLSClientConfig on a
				// custom Transport SILENTLY disables Go's HTTP/2 auto-negotiation
				// unless ForceAttemptHTTP2 is also set. Without it this tool speaks
				// HTTP/1.1, and lighttpd 1.4.84 (OPNsense 26.7) with
				// server.stream-response-body=2 deterministically truncates large
				// chunked responses — firmwareInfo (~380 KB) dies at a fixed byte
				// offset every time ("malformed chunked encoding"). Over HTTP/2 it
				// serves cleanly. The production client (opnsense/client.go) already
				// sets this; the dev tools must match it or they misreport drift.
				ForceAttemptHTTP2: true,
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
