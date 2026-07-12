package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// loadExemptions reads the committed exemptions file. A missing file is an
// empty exemption set, not an error.
func loadExemptions(path string) (map[string]opnsense.SchemaExemption, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]opnsense.SchemaExemption{}, nil
		}
		return nil, err
	}
	out := map[string]opnsense.SchemaExemption{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

// probeResult is the outcome of validating one endpoint against the live box.
type probeResult struct {
	Endpoint     string
	Path         string
	Status       int
	Res          opnsense.ValidationResult
	Absent       bool   // 404 — plugin uninstalled / route gone
	ProbeErr     string // transport error, unexpected status, or non-JSON body
	SkippedParam bool   // parameterized endpoint with no live parameter to use
}

// prober fetches raw endpoint responses from one box.
type prober struct {
	client   *http.Client
	baseURL  string
	key      string
	secret   string
	captures string
}

// probeAll validates every schema against the live box, in schema order.
func (p *prober) probeAll(schemas []opnsense.EndpointSchema, exemptions map[string]opnsense.SchemaExemption) []probeResult {
	results := make([]probeResult, 0, len(schemas))
	for _, s := range schemas {
		results = append(results, p.probeOne(s, exemptions[s.Endpoint]))
	}
	return results
}

// probeOne fetches one endpoint with the client's own request shape and
// validates the response structure.
func (p *prober) probeOne(s opnsense.EndpointSchema, ex opnsense.SchemaExemption) probeResult {
	res := probeResult{Endpoint: s.Endpoint, Path: s.Path}

	method := "GET"
	contentType, body := "", ""
	if req, ok := opnsense.CaptureRequestFor(opnsense.EndpointName(s.Endpoint)); ok {
		method, contentType, body = "POST", req.ContentType, req.Body
		if req.Parameterized {
			param, err := p.resolveParam(s.Endpoint)
			if err != nil {
				res.ProbeErr = fmt.Sprintf("resolving request parameter: %v", err)
				return res
			}
			if param == "" {
				res.SkippedParam = true
				return res
			}
			if contentType == "application/json" {
				b, _ := json.Marshal(param)
				body = fmt.Sprintf(body, strings.Trim(string(b), `"`))
			} else {
				body = fmt.Sprintf(body, url.QueryEscape(param))
			}
		}
	}

	raw, status, err := p.fetchRaw(method, s.Path, contentType, body)
	res.Status = status
	if status == http.StatusNotFound {
		res.Absent = true
		return res
	}
	if err != nil {
		res.ProbeErr = err.Error()
		return res
	}

	if p.captures != "" {
		// Runner-local scratch only — captures hold live values and are never
		// committed or uploaded.
		_ = os.MkdirAll(p.captures, 0o755)
		_ = os.WriteFile(filepath.Join(p.captures, s.Endpoint+".json"), raw, 0o644)
	}

	vr, err := opnsense.ValidateResponseSchema(s, raw, ex)
	if err != nil {
		res.ProbeErr = err.Error()
		return res
	}
	res.Res = vr
	return res
}

// resolveParam produces the live request parameter for the two parameterized
// endpoints: a SMART device name, or an IPsec phase-1 connection id. An empty
// string with nil error means "nothing to probe with" (valid box state).
func (p *prober) resolveParam(endpoint string) (string, error) {
	switch endpoint {
	case "smartInfo":
		raw, _, err := p.probeSource("smartList")
		if err != nil {
			return "", err
		}
		var list struct {
			Devices []string `json:"devices"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			return "", fmt.Errorf("decode smartList: %w", err)
		}
		if len(list.Devices) == 0 {
			return "", nil
		}
		return list.Devices[0], nil
	case "ipsecPhase2":
		raw, _, err := p.probeSource("ipsecPhase1")
		if err != nil {
			return "", err
		}
		var search struct {
			Rows []struct {
				IkeId string `json:"ikeid"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(raw, &search); err != nil {
			return "", fmt.Errorf("decode ipsecPhase1: %w", err)
		}
		if len(search.Rows) == 0 {
			return "", nil
		}
		return search.Rows[0].IkeId, nil
	default:
		return "", fmt.Errorf("no parameter resolver for endpoint %q", endpoint)
	}
}

// probeSource fetches a helper endpoint raw, using its own manifest path and
// capture request.
func (p *prober) probeSource(endpoint string) ([]byte, int, error) {
	ec, ok := opnsense.ContractManifest()[opnsense.EndpointName(endpoint)]
	if !ok {
		return nil, 0, fmt.Errorf("endpoint %q not in manifest", endpoint)
	}
	method, contentType, body := "GET", "", ""
	if req, ok := opnsense.CaptureRequestFor(opnsense.EndpointName(endpoint)); ok {
		method, contentType, body = "POST", req.ContentType, req.Body
	}
	return p.fetchRaw(method, string(ec.Path), contentType, body)
}

// fetchRaw performs one authenticated request and returns the raw body. It
// retries once on transport errors. Non-2xx statuses are returned as errors
// (the caller special-cases 404 before looking at err).
func (p *prober) fetchRaw(method, path, contentType, body string) ([]byte, int, error) {
	target := strings.TrimRight(p.baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(method, target, strings.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.SetBasicAuth(p.key, p.secret)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "identity")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return raw, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return raw, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}
