// Command apicapture fetches the response-contract endpoints from a live OPNsense
// box and writes the raw JSON responses to a capture directory, so the response
// contract test (opnsense.TestResponseContracts) can validate the current box's
// payload shapes. Point it at a beta/RC box to catch a new OPNsense release's
// payload-shape drift before it ships — the class of change the endpoint-manifest
// canary (cmd/apicontract) cannot see.
//
// Usage:
//
//	apicapture --base-url https://192.168.1.1 --insecure [--out opnsense/testdata/captures]
//
// Credentials come from --api-key/--api-secret, the OPN2OTEL_OPS_API_KEY /
// OPN2OTEL_OPS_API_SECRET environment variables, or the file-based
// OPS_API_KEY_FILE / OPS_API_SECRET_FILE secrets (resolved identically to the
// exporter, via internal/options). Captures land in a gitignored scratch dir by
// default; review one (it may contain host/network data) and promote it into a
// curated fixture to make it a permanent CI gate.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

func main() {
	baseURL := flag.String("base-url", os.Getenv("OPNSENSE_CAPTURE_BASE_URL"), "OPNsense base URL, e.g. https://192.168.1.1 (env OPNSENSE_CAPTURE_BASE_URL)")
	apiKey := flag.String("api-key", os.Getenv("OPN2OTEL_OPS_API_KEY"), "OPNsense API key (env OPN2OTEL_OPS_API_KEY)")
	apiSecret := flag.String("api-secret", os.Getenv("OPN2OTEL_OPS_API_SECRET"), "OPNsense API secret (env OPN2OTEL_OPS_API_SECRET)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (for self-signed OPNsense certs)")
	outDir := flag.String("out", "opnsense/testdata/captures", "directory to write captured responses into")
	flag.Parse()

	// Resolve credentials the same way the exporter does: OPS_API_KEY_FILE /
	// OPS_API_SECRET_FILE (file-based secrets) take precedence over the flag/plaintext
	// env value, so `make capture` has full parity with `make local-run` (#157).
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
		fmt.Fprintln(os.Stderr, "error: --base-url, --api-key and --api-secret (or their env vars, incl. OPS_API_KEY_FILE/OPS_API_SECRET_FILE) are required")
		flag.Usage()
		os.Exit(2)
	}

	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		// Never follow a redirect, matching opnsense/client.go (#306/#307). This
		// tool also SetBasicAuth's the API key+secret before every Do, and Go's
		// stdlib strips Authorization on a redirect only when the target's
		// HOSTNAME differs — not its scheme, not its port — so an https->http
		// bounce on the same host would hand the credentials over in cleartext.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure}, //nolint:gosec // opt-in for self-signed boxes
			// Load-bearing, and easy to lose: setting TLSClientConfig on a custom
			// Transport SILENTLY disables Go's HTTP/2 auto-negotiation unless
			// ForceAttemptHTTP2 is also set. Without it this tool speaks HTTP/1.1,
			// and lighttpd 1.4.84 (OPNsense 26.7) with server.stream-response-body=2
			// deterministically truncates large chunked responses — firmwareInfo
			// (~380 KB) dies at a fixed byte offset every time ("malformed chunked
			// encoding"). Over HTTP/2 it serves cleanly. The production client
			// (opnsense/client.go) already sets this; the dev tools must match it or
			// they capture truncated contracts.
			ForceAttemptHTTP2: true,
		},
	}

	results, err := captureContracts(httpClient, *baseURL, resolvedKey, resolvedSecret, *outDir,
		opnsense.ResponseContracts(), opnsense.ContractManifest())
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture failed: %v\n", err)
		os.Exit(1)
	}

	var failed int
	for _, r := range results {
		switch {
		case r.Err != nil:
			failed++
			fmt.Printf("FAIL  %-16s %s: %v\n", r.Endpoint, r.Path, r.Err)
		default:
			fmt.Printf("ok    %-16s -> %s (HTTP %d)\n", r.Endpoint, r.File, r.Status)
		}
	}
	fmt.Printf("\ncaptured %d/%d response-contract endpoints into %s\n", len(results)-failed, len(results), *outDir)
	if failed > 0 {
		os.Exit(1)
	}
}
