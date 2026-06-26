package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// captureResult records the outcome of capturing one endpoint's response.
type captureResult struct {
	Endpoint opnsense.EndpointName
	Path     opnsense.EndpointPath
	Status   int
	File     string
	Err      error
}

// captureContracts fetches each response-contract endpoint from a live OPNsense
// box and writes the raw JSON body to <outDir>/<endpoint>.json, so the response
// contract test (TestResponseContracts) can validate the current box's payloads.
// Only GET endpoints are captured — every current response contract is GET, and
// POST endpoints need request bodies/params this simple capturer does not build.
func captureContracts(httpClient *http.Client, baseURL, key, secret, outDir string,
	contracts []opnsense.ResponseContract,
	manifest map[opnsense.EndpointName]opnsense.EndpointContract) ([]captureResult, error) {

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create out dir: %w", err)
	}

	results := make([]captureResult, 0, len(contracts))
	for _, c := range contracts {
		res := captureResult{Endpoint: c.Endpoint}
		ec, ok := manifest[c.Endpoint]
		if !ok {
			res.Err = fmt.Errorf("endpoint %q is not in the client manifest", c.Endpoint)
			results = append(results, res)
			continue
		}
		res.Path = ec.Path
		if ec.Method != "GET" {
			res.Err = fmt.Errorf("skipped: capture supports GET only (manifest method is %s)", ec.Method)
			results = append(results, res)
			continue
		}

		body, status, err := fetchRaw(httpClient, baseURL, string(ec.Path), key, secret)
		res.Status = status
		if err != nil {
			res.Err = err
			results = append(results, res)
			continue
		}

		file := filepath.Join(outDir, string(c.Endpoint)+".json")
		if err := os.WriteFile(file, body, 0o644); err != nil {
			res.Err = fmt.Errorf("write %s: %w", file, err)
			results = append(results, res)
			continue
		}
		res.File = file
		results = append(results, res)
	}
	return results, nil
}

// fetchRaw GETs a single endpoint with basic auth and returns the raw body. It
// requests identity encoding so the stored fixture is plain JSON (no gzip).
func fetchRaw(httpClient *http.Client, baseURL, path, key, secret string) ([]byte, int, error) {
	url := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(key, secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}
