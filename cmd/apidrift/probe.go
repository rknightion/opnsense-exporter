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
	"time"

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

// retryPause is how long fetchRaw waits before its single transport-error
// retry. Deliberately conservative: 107 endpoints share the timeout budget, so
// one short pause — no exponential backoff, no third attempt.
const retryPause = 2 * time.Second

// probeResult is the outcome of validating one endpoint against the live box.
type probeResult struct {
	Endpoint     string
	Path         string
	Status       int
	Res          opnsense.ValidationResult
	Absent       bool   // 404 — plugin uninstalled / route gone
	ProbeErr     string // transport error, unexpected status, or non-JSON body
	SkippedParam bool   // parameterized endpoint with no live parameter to use
	Retried      bool   // a transport-level failure was retried for this probe
}

// prober fetches raw endpoint responses from one box.
type prober struct {
	client   *http.Client
	baseURL  string
	key      string
	secret   string
	captures string

	// notes sinks retry chatter (defaults to os.Stderr). Box-side flakiness
	// absorbed by the retry must stay visible rather than vanish silently.
	notes io.Writer
	// pause defers to time.Sleep when nil; tests inject a no-op.
	pause func(time.Duration)
	// retries counts transport-error retries attempted, across all endpoints.
	retries int
}

// note writes one observability line about a retry.
func (p *prober) note(format string, args ...any) {
	w := p.notes
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// sleep pauses between the failed attempt and its retry.
func (p *prober) sleep(d time.Duration) {
	if p.pause != nil {
		p.pause(d)
		return
	}
	time.Sleep(d)
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
// The result is a NAMED return so the deferred retry-stamp below is written
// into the value the caller actually receives, not a dead local copy.
func (p *prober) probeOne(s opnsense.EndpointSchema, ex opnsense.SchemaExemption) (res probeResult) {
	res = probeResult{Endpoint: s.Endpoint, Path: s.Path}
	retriesBefore := p.retries
	defer func() { res.Retried = p.retries > retriesBefore }()

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

// fetchRaw performs one authenticated request and returns the raw body.
//
// Retry policy: exactly ONE retry, after a short fixed pause, and only for a
// transport-level failure — the roundtrip itself errored (connection reset,
// client timeout / context deadline, truncated body), so no HTTP status was
// ever obtained.
//
// This is a safety net, NOT the fix for the firmwareInfo truncation: that was
// lighttpd 1.4.84 mangling large HTTP/1.1 chunked responses, and it is fixed
// properly by ForceAttemptHTTP2 on the Transport in main.go — retrying it over
// HTTP/1.1 would have failed identically every time. What the retry still buys
// us is the genuinely transient case: the traffic sampler (interfaces) samples
// server-side before responding and occasionally overruns the client timeout,
// plus any box where HTTP/2 is unavailable and we fall back to 1.1.
//
// Anything that produced a real HTTP status is NOT retried: a 404 stays a
// first-class "Absent" signal, and any other non-2xx is returned as-is. A 200
// with an unparseable body is a schema matter and never reaches this retry.
func (p *prober) fetchRaw(method, path, contentType, body string) ([]byte, int, error) {
	target := strings.TrimRight(p.baseURL, "/") + "/" + strings.TrimLeft(path, "/")
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			p.retries++
			p.note("apidrift: transport error on %s %s: %v — retrying once in %s", method, path, lastErr, retryPause)
			p.sleep(retryPause)
		}

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
		if attempt > 0 {
			p.note("apidrift: %s %s succeeded on retry (intermittent box-side transport failure)", method, path)
		}
		return raw, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}
