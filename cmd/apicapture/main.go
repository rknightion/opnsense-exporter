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
// Credentials come from --api-key/--api-secret or the OPNSENSE_EXPORTER_OPS_API_KEY
// and OPNSENSE_EXPORTER_OPS_API_SECRET environment variables. Captures land in a
// gitignored scratch dir by default; review one (it may contain host/network data)
// and promote it into a curated fixture to make it a permanent CI gate.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

func main() {
	baseURL := flag.String("base-url", os.Getenv("OPNSENSE_CAPTURE_BASE_URL"), "OPNsense base URL, e.g. https://192.168.1.1 (env OPNSENSE_CAPTURE_BASE_URL)")
	apiKey := flag.String("api-key", os.Getenv("OPNSENSE_EXPORTER_OPS_API_KEY"), "OPNsense API key (env OPNSENSE_EXPORTER_OPS_API_KEY)")
	apiSecret := flag.String("api-secret", os.Getenv("OPNSENSE_EXPORTER_OPS_API_SECRET"), "OPNsense API secret (env OPNSENSE_EXPORTER_OPS_API_SECRET)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (for self-signed OPNsense certs)")
	outDir := flag.String("out", "opnsense/testdata/captures", "directory to write captured responses into")
	flag.Parse()

	if *baseURL == "" || *apiKey == "" || *apiSecret == "" {
		fmt.Fprintln(os.Stderr, "error: --base-url, --api-key and --api-secret (or their env vars) are required")
		flag.Usage()
		os.Exit(2)
	}

	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure}, //nolint:gosec // opt-in for self-signed boxes
		},
	}

	results, err := captureContracts(httpClient, *baseURL, *apiKey, *apiSecret, *outDir,
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
