package opnsense

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// MaxRetries is the maximum number of retries
// when a request to the OPNsense API fails
const MaxRetries = 3

// maxResponseBodyBytes caps how much of an API response body the client reads
// (after any gzip decompression), so a compromised or misbehaving OPNsense box
// cannot exhaust the exporter's memory with an oversized or maliciously
// compressed response.
const maxResponseBodyBytes = 64 << 20 // 64 MiB

// maxErrorBodyBytes caps how much of a non-2xx response body is propagated
// into APICallError messages (and from there into logs).
const maxErrorBodyBytes = 4 << 10 // 4 KiB

// EndpointName is the custom type for name of an endpoint definition
type EndpointName string

// EndpointPath is the custom type for url path of an endpoint definition
type EndpointPath string

// Client is an OPNsense API client
type Client struct {
	httpClient       *http.Client
	gatewayLossRegex *regexp.Regexp
	gatewayRTTRegex  *regexp.Regexp
	log              *slog.Logger
	headers          map[string]string
	endpoints        map[EndpointName]EndpointPath
	baseURL          string
	key              string
	secret           string
	sslInsecure      bool
}

// NewClient creates a new OPNsense API Client
func NewClient(cfg options.OPNSenseConfig, userAgentVersion string, log *slog.Logger) (Client, error) {
	sslPool, err := x509.SystemCertPool()
	if err != nil {
		return Client{}, errors.Join(fmt.Errorf("failed to load system cert pool"), err)
	}

	gatewayLossRegex, err := regexp.Compile(`\d+\.\d+ %`)
	if err != nil {
		return Client{}, errors.Join(fmt.Errorf("failed to build regex for gatewayLoss calculation"), err)
	}

	gatewayRTTRegex, err := regexp.Compile(`\d+\.\d+ ms`)
	if err != nil {
		return Client{}, errors.Join(fmt.Errorf("failed to build regex for gatewayRTT calculation"), err)
	}
	client := Client{
		log:              log,
		baseURL:          fmt.Sprintf("%s://%s", cfg.Protocol, cfg.Host),
		key:              cfg.APIKey,
		secret:           cfg.APISecret,
		gatewayLossRegex: gatewayLossRegex,
		gatewayRTTRegex:  gatewayRTTRegex,
		endpoints: map[EndpointName]EndpointPath{
			"services":                "api/core/service/search",
			"interfaces":              "api/diagnostics/traffic/interface",
			"protocolStatistics":      "api/diagnostics/interface/get_protocol_statistics",
			"pfStatisticsByInterface": "api/diagnostics/firewall/pf_statistics/interfaces",
			"arp":                     "api/diagnostics/interface/search_arp",
			"dhcpv4":                  "api/dhcpv4/leases/searchLease",
			"openVPNInstances":        "api/openvpn/instances/search",
			"openVPNSessions":         "api/openvpn/service/search_sessions",
			"gatewaysStatus":          "api/routing/settings/searchGateway",
			"unboundDNSStatus":        "api/unbound/diagnostics/stats",
			"cronJobs":                "api/cron/settings/searchJobs",
			"wireguardClients":        "api/wireguard/service/show",
			"ipsecPhase1":             "api/ipsec/sessions/search_phase1",
			"ipsecPhase2":             "api/ipsec/sessions/search_phase2",
			"healthCheck":             "api/core/system/status",
			"firmware":                "api/core/firmware/status",
			"dnsmasqLeases":           "api/dnsmasq/leases/search",
			"systemResources":         "api/diagnostics/system/systemResources",
			"systemTime":              "api/diagnostics/system/systemTime",
			"systemDisk":              "api/diagnostics/system/systemDisk",
			"systemSwap":              "api/diagnostics/system/systemSwap",
			"systemTemperature":       "api/diagnostics/system/systemTemperature",
			"pfStates":                "api/diagnostics/firewall/pf_states/1",
			"firewallRuleStats":       "api/firewall/filter_util/rule_stats",
			"firewallRules":           "api/firewall/filter/search_rule",
			"systemMbuf":              "api/diagnostics/system/systemMbuf",
			"ntpStatus":               "api/ntpd/service/status",
			"certificates":            "api/trust/cert/search",
			"unboundBlockList":        "api/unbound/overview/isBlockListEnabled",
			"carpStatus":              "api/diagnostics/interface/get_vip_status",
			"systemActivity":          "api/diagnostics/activity/get_activity",
			"keaLeases4":              "api/kea/leases4/search",
			"keaLeases6":              "api/kea/leases6/search",
			"unboundServiceStatus":    "api/unbound/service/status",
			"dnsmasqServiceStatus":    "api/dnsmasq/service/status",
			"ipsecServiceStatus":      "api/ipsec/service/status",
			"wireguardServiceStatus":  "api/wireguard/service/status",
			"netisrStatistics":        "api/diagnostics/interface/get_netisr_statistics",
			"socketStatistics":        "api/diagnostics/interface/get_socket_statistics",
			"routingTable":            "api/diagnostics/interface/get_routes",
			"netflowIsEnabled":        "api/diagnostics/netflow/isEnabled",
			"netflowStatus":           "api/diagnostics/netflow/status",
			"netflowCacheStats":       "api/diagnostics/netflow/cacheStats",
			"pfStatsInfo":             "api/diagnostics/firewall/pf_statistics/info",
			"pfStatsMemory":           "api/diagnostics/firewall/pf_statistics/memory",
			"pfStatsTimeouts":         "api/diagnostics/firewall/pf_statistics/timeouts",
			"cpuType":                 "api/diagnostics/cpu_usage/getCPUType",
			"systemInformation":       "api/diagnostics/system/system_information",
			"memoryStatistics":        "api/diagnostics/interface/get_memory_statistics",
			"ndpTable":                "api/diagnostics/interface/get_ndp",
			"firewallStats":           "api/diagnostics/firewall/stats",
			"pfsyncNodes":             "api/diagnostics/interface/get_pfsync_nodes",
			"acmeCertificates":        "api/acmeclient/certificates/search",
			"smartList":               "api/smart/service/list",
			"smartInfo":               "api/smart/service/info",
			"dyndnsAccounts":          "api/dyndns/accounts/searchItem",
			"dyndnsServiceStatus":     "api/dyndns/service/status",
		},
		headers: map[string]string{
			"Accept":          "application/json",
			"User-Agent":      fmt.Sprintf("prometheus-opnsense-exporter/%s", userAgentVersion),
			"Accept-Encoding": "gzip, deflate, br",
		},
		sslInsecure: cfg.Insecure,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.Insecure,
					RootCAs:            sslPool,
				},
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   3 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
				MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
			},
		},
	}

	return client, nil
}

// Endpoints returns a map of all the endpoints
// that are called by the client.
func (c *Client) Endpoints() map[EndpointName]EndpointPath {
	return c.endpoints
}

// do sends a request to the OPNsense API.
// The response is unmarshalled into responseStruct.
// For POST requests, Content-Type is set to application/json;charset=utf-8.
func (c *Client) do(method string, path EndpointPath, body io.Reader, responseStruct any) *APICallError {
	return c.doWithContentType(method, path, body, "application/json;charset=utf-8", responseStruct)
}

// doForm sends a form-encoded POST request to the OPNsense API.
// form values are URL-encoded in the request body.
func (c *Client) doForm(path EndpointPath, form url.Values, responseStruct any) *APICallError {
	return c.doWithContentType("POST", path, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", responseStruct)
}

// doWithContentType sends a request to the OPNsense API with the specified
// Content-Type header (only set for POST). The response is unmarshalled into
// responseStruct. This is the underlying implementation used by do and doForm.
func (c *Client) doWithContentType(method string, path EndpointPath, body io.Reader, contentType string, responseStruct any) *APICallError {
	reqURL := fmt.Sprintf("%s/%s", c.baseURL, string(path))

	// Buffer the request body so every retry attempt sends it from the start;
	// the transport consumes a request's body even when the attempt fails.
	var bodyBytes []byte
	if body != nil {
		b, err := io.ReadAll(body)
		if err != nil {
			return &APICallError{
				Endpoint:   string(path),
				Message:    fmt.Sprintf("failed to read request body: %s", err.Error()),
				StatusCode: 0,
			}
		}
		bodyBytes = b
	}

	c.log.Debug("fetching data", "component", "opnsense-client", "url", reqURL, "method", method)

	// Retry the request up to MaxRetries times
	for range MaxRetries {
		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequest(method, reqURL, reqBody)
		if err != nil {
			return &APICallError{
				Endpoint:   string(path),
				Message:    err.Error(),
				StatusCode: 0,
			}
		}

		req.SetBasicAuth(c.key, c.secret)

		for k, v := range c.headers {
			req.Header.Add(k, v)
		}

		if method == "POST" {
			req.Header.Add("Content-Type", contentType)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.log.Error("failed to send request; retrying",
				"component", "opnsense-client",
				"err", err.Error())
			time.Sleep(25 * time.Millisecond)
			continue
		}

		return c.readResponse(path, resp, responseStruct)
	}
	return &APICallError{
		Endpoint:   string(path),
		Message:    fmt.Sprintf("max retries of %d times reached", MaxRetries),
		StatusCode: 0,
	}
}

// readResponse decompresses, size-limits and unmarshals an API response into
// responseStruct, closing the response body. Non-2xx responses and unmarshal
// failures carry a bounded slice of the body in the returned error, which is
// where response payloads are surfaced for debugging; successful responses are
// never logged.
func (c *Client) readResponse(path EndpointPath, resp *http.Response, responseStruct any) *APICallError {
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return &APICallError{
				Endpoint:   string(path),
				Message:    fmt.Sprintf("failed to decompress gzip response body: %s", err.Error()),
				StatusCode: resp.StatusCode,
			}
		}
		defer gz.Close()
		reader = gz
	}

	respBody, err := io.ReadAll(io.LimitReader(reader, maxResponseBodyBytes+1))
	if err != nil {
		return &APICallError{
			Endpoint:   string(path),
			Message:    fmt.Sprintf("failed to read response body: %s", err.Error()),
			StatusCode: resp.StatusCode,
		}
	}
	if len(respBody) > maxResponseBodyBytes {
		return &APICallError{
			Endpoint:   string(path),
			Message:    fmt.Sprintf("response body exceeds %d byte limit", maxResponseBodyBytes),
			StatusCode: resp.StatusCode,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APICallError{
			Endpoint:   string(path),
			Message:    string(truncateBody(respBody)),
			StatusCode: resp.StatusCode,
		}
	}

	if err := json.Unmarshal(respBody, &responseStruct); err != nil {
		return &APICallError{
			Endpoint:   string(path),
			Message:    fmt.Sprintf("failed to unmarshal response body: %s; body: %s", err.Error(), truncateBody(respBody)),
			StatusCode: resp.StatusCode,
		}
	}

	return nil
}

// sensitiveJSONField matches JSON key/value pairs whose key contains a
// credential-like word (password, secret, token, api key, private key),
// including OPNsense's "%"-prefixed field variants, so the value (string,
// number or null) can be redacted before the body reaches an error message.
var sensitiveJSONField = regexp.MustCompile(`(?i)("(?:%+)?[^"]*(?:password|passwd|secret|token|api_?key|private_?key)[^"]*"\s*:\s*)("(?:[^"\\]|\\.)*"|[0-9eE+.\-]+|null)`)

// redactSensitiveFields replaces the values of credential-like JSON fields
// with "[REDACTED]". Non-JSON bodies pass through unchanged.
func redactSensitiveFields(b []byte) []byte {
	return sensitiveJSONField.ReplaceAll(b, []byte(`${1}"[REDACTED]"`))
}

// truncateBody redacts credential-like field values from a response body
// destined for an error message, then bounds its length.
func truncateBody(b []byte) []byte {
	b = redactSensitiveFields(b)
	if len(b) <= maxErrorBodyBytes {
		return b
	}
	return append(b[:maxErrorBodyBytes:maxErrorBodyBytes], "... (truncated)"...)
}
