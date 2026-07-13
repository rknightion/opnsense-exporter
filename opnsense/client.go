package opnsense

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
)

// MaxRetries is the default maximum number of attempts for a failed request to the
// OPNsense API, used when OPNSenseConfig.MaxRetries is not set (#140).
const MaxRetries = 3

// defaultClientTimeout is the default per-request HTTP timeout, used when
// OPNSenseConfig.Timeout is not set (#140).
const defaultClientTimeout = 15 * time.Second

// baseRetryDelay is the first backoff interval; subsequent retries grow it
// exponentially (100ms, 200ms, 400ms, ...) with jitter, instead of a fixed 25ms, so a
// down or flapping firewall isn't hammered with back-to-back doomed dials (#127).
const baseRetryDelay = 100 * time.Millisecond

// retryBackoff returns the base backoff before retry attempt n (1-indexed): exponential
// growth from baseRetryDelay. Jitter is applied at the call site; this stays a pure,
// deterministic function so the growth is unit-testable.
func retryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return baseRetryDelay << (attempt - 1)
}

// runConcurrentFetches runs each independent sub-fetch concurrently and returns their
// errors in the same order. Used by the multi-endpoint Fetch* functions whose sub-calls
// write to disjoint fields of a shared result struct, so overall wall time is bounded by
// the slowest single call instead of the sum of all of them (#129). Each fn must only
// touch its own disjoint field(s); errs[i] is written by a single goroutine so the slice
// is race-free.
func runConcurrentFetches(fns ...func() *APICallError) []*APICallError {
	errs := make([]*APICallError, len(fns))
	var wg sync.WaitGroup
	wg.Add(len(fns))
	for i, fn := range fns {
		go func(i int, fn func() *APICallError) {
			defer wg.Done()
			errs[i] = fn()
		}(i, fn)
	}
	wg.Wait()
	return errs
}

// retryableStatus reports whether an idempotent GET receiving this status code should
// be retried: transient gateway/proxy errors that a brief service restart produces.
func retryableStatus(method string, code int) bool {
	if method != "GET" {
		return false
	}
	return code == http.StatusBadGateway || code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

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

// defaultEndpoints returns the canonical endpoint name→path table used by the
// live client and by the API-contract tooling (cmd/apicontract). Keep this the
// single source of truth for endpoint paths.
func defaultEndpoints() map[EndpointName]EndpointPath {
	return map[EndpointName]EndpointPath{
		"services":                   "api/core/service/search",
		"interfaces":                 "api/diagnostics/traffic/interface",
		"protocolStatistics":         "api/diagnostics/interface/get_protocol_statistics",
		"pfStatisticsByInterface":    "api/diagnostics/firewall/pf_statistics/interfaces",
		"arp":                        "api/diagnostics/interface/search_arp",
		"dhcpv4":                     "api/dhcpv4/leases/searchLease",
		"openVPNInstances":           "api/openvpn/instances/search",
		"openVPNSessions":            "api/openvpn/service/search_sessions",
		"gatewaysStatus":             "api/routing/settings/searchGateway",
		"unboundDNSStatus":           "api/unbound/diagnostics/stats",
		"cronJobs":                   "api/cron/settings/searchJobs",
		"wireguardClients":           "api/wireguard/service/show",
		"ipsecPhase1":                "api/ipsec/sessions/search_phase1",
		"ipsecPhase2":                "api/ipsec/sessions/search_phase2",
		"healthCheck":                "api/core/system/status",
		"firmware":                   "api/core/firmware/status",
		"firmwareInfo":               "api/core/firmware/info",
		"dnsmasqLeases":              "api/dnsmasq/leases/search",
		"systemResources":            "api/diagnostics/system/systemResources",
		"systemTime":                 "api/diagnostics/system/systemTime",
		"systemDisk":                 "api/diagnostics/system/systemDisk",
		"systemSwap":                 "api/diagnostics/system/systemSwap",
		"systemTemperature":          "api/diagnostics/system/systemTemperature",
		"pfStates":                   "api/diagnostics/firewall/pf_states/1",
		"firewallRuleStats":          "api/firewall/filter_util/rule_stats",
		"firewallRules":              "api/firewall/filter/search_rule",
		"systemMbuf":                 "api/diagnostics/system/systemMbuf",
		"ntpStatus":                  "api/ntpd/service/status",
		"certificates":               "api/trust/cert/search",
		"unboundBlocklistPolicies":   "api/unbound/overview/get_policies",
		"carpStatus":                 "api/diagnostics/interface/get_vip_status",
		"systemActivity":             "api/diagnostics/activity/get_activity",
		"keaLeases4":                 "api/kea/leases4/search",
		"keaLeases6":                 "api/kea/leases6/search",
		"unboundServiceStatus":       "api/unbound/service/status",
		"dnsmasqServiceStatus":       "api/dnsmasq/service/status",
		"ipsecServiceStatus":         "api/ipsec/service/status",
		"wireguardServiceStatus":     "api/wireguard/service/status",
		"netisrStatistics":           "api/diagnostics/interface/get_netisr_statistics",
		"socketStatistics":           "api/diagnostics/interface/get_socket_statistics",
		"routingTable":               "api/diagnostics/interface/get_routes",
		"netflowIsEnabled":           "api/diagnostics/netflow/isEnabled",
		"netflowStatus":              "api/diagnostics/netflow/status",
		"netflowCacheStats":          "api/diagnostics/netflow/cacheStats",
		"pfStatsInfo":                "api/diagnostics/firewall/pf_statistics/info",
		"pfStatsMemory":              "api/diagnostics/firewall/pf_statistics/memory",
		"pfStatsTimeouts":            "api/diagnostics/firewall/pf_statistics/timeouts",
		"cpuType":                    "api/diagnostics/cpu_usage/getCPUType",
		"systemInformation":          "api/diagnostics/system/system_information",
		"memoryStatistics":           "api/diagnostics/interface/get_memory_statistics",
		"ndpTable":                   "api/diagnostics/interface/get_ndp",
		"firewallStats":              "api/diagnostics/firewall/stats",
		"pfsyncNodes":                "api/diagnostics/interface/get_pfsync_nodes",
		"acmeCertificates":           "api/acmeclient/certificates/search",
		"smartList":                  "api/smart/service/list",
		"smartInfo":                  "api/smart/service/info",
		"dyndnsAccounts":             "api/dyndns/accounts/searchItem",
		"dyndnsServiceStatus":        "api/dyndns/service/status",
		"interfacesOverview":         "api/interfaces/overview/interfaces_info",
		"unboundInfra":               "api/unbound/diagnostics/dumpinfra",
		"syslogStats":                "api/syslog/service/stats",
		"syslogServiceStatus":        "api/syslog/service/status",
		"qfeedsStats":                "api/qfeeds/settings/stats",
		"tailscaleStatus":            "api/tailscale/status/status",
		"tailscaleServiceStatus":     "api/tailscale/service/status",
		"aliasTableSize":             "api/firewall/alias/get_table_size",
		"keaSubnets4":                "api/kea/dhcpv4/searchSubnet",
		"keaSubnets6":                "api/kea/dhcpv6/searchSubnet",
		"keaServiceStatus":           "api/kea/service/status",
		"keaPdPools6":                "api/kea/dhcpv6/searchPdPool",
		"dnsmasqRanges":              "api/dnsmasq/settings/searchRange",
		"caCertificates":             "api/trust/ca/search",
		"haproxyCounters":            "api/haproxy/statistics/counters",
		"haproxyInfo":                "api/haproxy/statistics/info",
		"haproxyServiceStatus":       "api/haproxy/service/status",
		"nginxVts":                   "api/nginx/service/vts",
		"nginxServiceStatus":         "api/nginx/service/status",
		"quaggaBgpSummary":           "api/quagga/diagnostics/bgpsummary",
		"quaggaOspfOverview":         "api/quagga/diagnostics/ospfoverview",
		"quaggaOspfNeighbors":        "api/quagga/diagnostics/searchOspfneighbor",
		"quaggaBfdNeighbors":         "api/quagga/diagnostics/bfdneighbors",
		"quaggaBfdCounters":          "api/quagga/diagnostics/bfdcounters",
		"quaggaServiceStatus":        "api/quagga/service/status",
		"monitStatus":                "api/monit/status/get/xml",
		"monitServiceStatus":         "api/monit/service/status",
		"crowdsecAlerts":             "api/crowdsec/alerts/search",
		"crowdsecDecisions":          "api/crowdsec/decisions/search",
		"crowdsecBouncers":           "api/crowdsec/bouncers/search",
		"crowdsecMachines":           "api/crowdsec/machines/search",
		"crowdsecServiceStatus":      "api/crowdsec/service/status",
		"nutUpsStatus":               "api/nut/diagnostics/upsstatus",
		"nutServiceStatus":           "api/nut/service/status",
		"apcupsdUpsStatus":           "api/apcupsd/service/getUpsStatus",
		"apcupsdServiceStatus":       "api/apcupsd/service/status",
		"captivePortalSessions":      "api/captiveportal/session/search",
		"captivePortalZones":         "api/captiveportal/session/zones",
		"captivePortalServiceStatus": "api/captiveportal/service/status",
		"trafficShaperStatistics":    "api/trafficshaper/service/statistics",
		"ipsecPools":                 "api/ipsec/leases/pools",
		"hasyncVersion":              "api/core/hasync_status/version",
		"hasyncServices":             "api/core/hasync_status/services",
		"chronyTracking":             "api/chrony/service/chronytracking",
		"chronySources":              "api/chrony/service/chronysources",
		"chronySourceStats":          "api/chrony/service/chronysourcestats",
		"chronyServiceStatus":        "api/chrony/service/status",
		"dhcpv6Leases":               "api/dhcpv6/leases/searchLease",
		"dhcpv6Prefixes":             "api/dhcpv6/leases/searchPrefix",
		"bpfStatistics":              "api/diagnostics/interface/get_bpf_statistics",
		"unboundQueryStatsEnabled":   "api/unbound/overview/is_enabled",
		"unboundQueryStatsTotals":    "api/unbound/overview/totals/1",
		"unboundLocalZones":          "api/unbound/diagnostics/listlocalzones",
		"unboundLocalData":           "api/unbound/diagnostics/listlocaldata",
		"unboundInsecureDomains":     "api/unbound/diagnostics/listinsecure",
		"backupHistory":              "api/core/backup/backups/this",
		"snapshotsSearch":            "api/core/snapshots/search",
		"snapshotsIsSupported":       "api/core/snapshots/is_supported",
	}
}

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
	maxRetries       int
	// reqCtx, when set via WithContext, bounds every request issued by this
	// client (scrape deadline / cancellation). Storing a context in a struct is
	// deliberate here: the clone is request-scoped, mirroring the
	// http.Request.WithContext pattern. nil means context.Background().
	reqCtx context.Context
	// observer, when set, is notified once per API call passing through the request
	// choke point (doWithContentType). It lets the collector layer record per-endpoint
	// request-count/duration self-metrics without coupling this package to Prometheus.
	// nil means no instrumentation.
	observer RequestObserver
	// cache, when set, serves successful GET responses for endpoints given a TTL via
	// SetEndpointCacheTTL. It is a pointer so the per-scrape WithContext clone shares
	// one cache with its parent; a value field would hand every scrape an empty cache.
	// nil (and a cache with no TTLs) means every request goes to the box.
	cache *responseCache
	// cacheObserver, when set, is notified of every cache hit/miss on an endpoint that
	// has a TTL, so the collector layer can record cache self-metrics. nil means no
	// instrumentation.
	cacheObserver CacheObserver
}

// RequestObserver is notified after every API request that passes through the client's
// request choke point, with the endpoint path, the HTTP status code (0 when no response
// was received, e.g. a network error or context cancellation), and the elapsed wall
// time for the whole call (including retries). Implemented by the collector layer to
// record self-metrics; kept as an interface here so opnsense/ stays Prometheus-free.
type RequestObserver interface {
	ObserveAPIRequest(endpoint string, statusCode int, duration time.Duration)
}

// SetRequestObserver installs o as the per-request observer for this client (and any
// request-scoped clone made afterwards via WithContext, since the clone is shallow).
func (c *Client) SetRequestObserver(o RequestObserver) {
	c.observer = o
}

// CacheObserver is notified when the response cache is used: a hit (kind "body" for
// a replayed payload, "absent" for a replayed 404) or a miss.
//
// A miss is a call that POPULATED the cache — a cold cache or an expired TTL — not
// merely a call that found nothing. The distinction matters: a plugin-gated endpoint
// whose plugin IS installed answers 200 on every scrape, and that payload is never
// cacheable (only its 404 would be), so it is not a miss. Counting it as one would
// make every healthy plugin look like a permanent cache miss and drag the hit rate
// toward zero while the cache was working perfectly.
//
// Implemented by the collector layer to record cache self-metrics; kept as an
// interface here so opnsense/ stays Prometheus-free, mirroring RequestObserver.
type CacheObserver interface {
	ObserveCacheHit(endpoint, kind string)
	ObserveCacheMiss(endpoint string)
}

// Cache hit kinds reported to a CacheObserver. A replayed body and a replayed 404
// are counted separately because they mean different things: one saved a fetch of
// slow-moving data, the other means the plugin is not installed on this firewall.
const (
	CacheHitBody   = "body"
	CacheHitAbsent = "absent"
)

// SetCacheObserver installs o as the response-cache observer for this client (and any
// request-scoped clone made afterwards via WithContext, since the clone is shallow).
func (c *Client) SetCacheObserver(o CacheObserver) {
	c.cacheObserver = o
}

// NewClient creates a new OPNsense API Client
func NewClient(cfg options.OPNSenseConfig, userAgentVersion string, log *slog.Logger) (Client, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = MaxRetries
	}

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
		endpoints:        defaultEndpoints(),
		headers: map[string]string{
			"Accept":     "application/json",
			"User-Agent": fmt.Sprintf("prometheus-opnsense-exporter/%s", userAgentVersion),
			// Only advertise encodings readResponse can actually decode. The client
			// decompresses gzip (see readResponse); deflate/br are not handled, so
			// advertising them would risk an undecodable body.
			"Accept-Encoding": "gzip",
		},
		sslInsecure: cfg.Insecure,
		maxRetries:  maxRetries,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion:         tls.VersionTLS12,
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

	// Surface an insecure-TLS config at runtime, not just in docs/security.md: an
	// operator who sets --opnsense.insecure (e.g. copied from a sample manifest) and
	// forgets gets no other signal that cert verification is off (#159). Mirrors
	// node_exporter/blackbox_exporter behaviour.
	if cfg.Insecure {
		log.Warn("TLS certificate verification disabled (opnsense.insecure); API credentials and data are exposed to MITM risk",
			"component", "opnsense-client")
	}

	return client, nil
}

// Endpoints returns a map of all the endpoints
// that are called by the client.
func (c *Client) Endpoints() map[EndpointName]EndpointPath {
	return c.endpoints
}

// WithContext returns a shallow copy of the client whose requests are bound to
// ctx (deadline and cancellation). The clone shares the underlying http.Client,
// endpoint table and credentials; only the request context differs.
func (c *Client) WithContext(ctx context.Context) *Client {
	clone := *c
	clone.reqCtx = ctx
	return &clone
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
func (c *Client) doWithContentType(method string, path EndpointPath, body io.Reader, contentType string, responseStruct any) (apiErr *APICallError) {
	reqURL := fmt.Sprintf("%s/%s", c.baseURL, string(path))

	// Serve slow-moving endpoints from the response cache (opt-in per endpoint via
	// SetEndpointCacheTTL; no TTL configured = no caching, which is the default for
	// every endpoint). GET only: a POST is an action on the box, not an idempotent
	// read. This precedes the observer below deliberately — a cache hit issues no
	// request, so it must not be counted as one.
	if cached, ok := c.cache.get(path); ok {
		// A cached 404 is replayed for ANY method, POST included: a 404 is a property
		// of the route ("Endpoint not found" — the plugin is not installed), not of the
		// request body, so it holds whatever was posted. It is returned as the same
		// error a live 404 produces, so callers that read it as "feature absent" behave
		// exactly as they do uncached.
		if cached.statusCode == http.StatusNotFound {
			c.log.Debug("serving cached 404", "component", "opnsense-client", "url", reqURL)
			if c.cacheObserver != nil {
				c.cacheObserver.ObserveCacheHit(string(path), CacheHitAbsent)
			}
			return &APICallError{
				Endpoint:   string(path),
				Message:    string(cached.body),
				StatusCode: cached.statusCode,
			}
		}
		// A cached BODY is only ever replayed for a GET. A POST's response depends on
		// what was posted (smartInfo is POSTed once per device), so replaying one body
		// for a different request would return another device's data. Such an entry is
		// never stored — this is belt and braces.
		if method == "GET" {
			c.log.Debug("serving cached response", "component", "opnsense-client", "url", reqURL)
			if c.cacheObserver != nil {
				c.cacheObserver.ObserveCacheHit(string(path), CacheHitBody)
			}
			return unmarshalBody(path, cached.body, cached.statusCode, responseStruct)
		}
	}

	// Record one self-metric observation per logical API call (not per retry): total
	// wall time and the final HTTP status code. statusCode is a stack-local (the client
	// clone is shared across concurrent sub-collector goroutines, so per-call state must
	// not live on the struct); it is set on the response path below, and a returned
	// APICallError's StatusCode (if non-zero) takes precedence in the deferred emit (#126).
	var statusCode int
	if c.observer != nil {
		start := time.Now()
		defer func() {
			code := statusCode
			if apiErr != nil && apiErr.StatusCode != 0 {
				code = apiErr.StatusCode
			}
			c.observer.ObserveAPIRequest(string(path), code, time.Since(start))
		}()
	}

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

	ctx := c.reqCtx
	if ctx == nil {
		ctx = context.Background()
	}

	// Retry the request up to MaxRetries times. lastErr records the real underlying
	// cause (transport error text or retryable HTTP status) so an exhausted-retries
	// failure surfaces WHY (DNS / refused / timeout / 503) instead of a generic string.
	lastErr := "unknown error"
	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		if attempt > 1 {
			// Jittered exponential backoff (full jitter over [base/2, base]), honouring
			// context cancellation so a cancelled scrape doesn't sleep pointlessly.
			base := retryBackoff(attempt - 1)
			delay := base/2 + time.Duration(rand.Int64N(int64(base/2)+1))
			select {
			case <-ctx.Done():
				return &APICallError{
					Endpoint:   string(path),
					Message:    fmt.Sprintf("request aborted: %s", ctx.Err()),
					StatusCode: 0,
				}
			case <-time.After(delay):
			}
		}

		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
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
			if ctx.Err() != nil {
				return &APICallError{
					Endpoint:   string(path),
					Message:    fmt.Sprintf("request aborted: %s", ctx.Err()),
					StatusCode: 0,
				}
			}
			lastErr = err.Error()
			// Warn (not Error): a single unreachable firewall would otherwise emit an
			// Error line per endpoint per attempt (a log storm); opnsense_up=0 is the
			// real signal. The exhausted-retries APICallError below carries the cause.
			c.log.Warn("failed to send request; will retry",
				"component", "opnsense-client",
				"attempt", attempt,
				"err", err.Error())
			continue
		}

		// Retry idempotent GETs on transient gateway errors (e.g. a brief lighttpd/
		// configd restart during a firmware check), which previously failed outright.
		if retryableStatus(method, resp.StatusCode) && attempt < c.maxRetries {
			lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
			c.log.Warn("retryable server error; will retry",
				"component", "opnsense-client",
				"attempt", attempt,
				"code", resp.StatusCode)
			continue
		}

		statusCode = resp.StatusCode
		return c.readResponse(method, path, resp, responseStruct)
	}
	return &APICallError{
		Endpoint:   string(path),
		Message:    fmt.Sprintf("max retries of %d times reached: %s", c.maxRetries, lastErr),
		StatusCode: 0,
	}
}

// readResponse decompresses, size-limits and unmarshals an API response into
// responseStruct, closing the response body. Non-2xx responses and unmarshal
// failures carry a bounded slice of the body in the returned error, which is
// where response payloads are surfaced for debugging; successful responses are
// never logged.
//
// A successful GET body is handed to the response cache, which keeps it only if
// the endpoint has a TTL. Failures are deliberately never cached: a scrape that
// errored must retry on the next one, not serve the error for hours.
func (c *Client) readResponse(method string, path EndpointPath, resp *http.Response, responseStruct any) *APICallError {
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
		errBody := truncateBody(respBody)
		// A 404 from a plugin-gated endpoint means the plugin is not installed. Cache it
		// regardless of method (only if the endpoint has an absent TTL): route absence is
		// body-independent, so the POST-body-collision problem that rules out positive
		// POST caching does not apply. put() ignores every other status, so a 5xx or an
		// auth failure still re-requests — and reports whether it stored, which is what
		// makes this call a cache miss (a fetch that filled the cache).
		if c.cache.put(path, resp.StatusCode, errBody) && c.cacheObserver != nil {
			c.cacheObserver.ObserveCacheMiss(string(path))
		}
		return &APICallError{
			Endpoint:   string(path),
			Message:    string(errBody),
			StatusCode: resp.StatusCode,
		}
	}

	if err := unmarshalBody(path, respBody, resp.StatusCode, responseStruct); err != nil {
		return err
	}

	if method == "GET" {
		if c.cache.put(path, resp.StatusCode, respBody) && c.cacheObserver != nil {
			c.cacheObserver.ObserveCacheMiss(string(path))
		}
	}

	return nil
}

// unmarshalBody decodes an already-read, already-validated 2xx body into
// responseStruct. Shared by the live-response path and the cache-hit path in
// doWithContentType so a cached body is decoded exactly as a fresh one is,
// giving each caller its own copy of the data.
func unmarshalBody(path EndpointPath, body []byte, statusCode int, responseStruct any) *APICallError {
	if err := json.Unmarshal(body, &responseStruct); err != nil {
		return &APICallError{
			Endpoint:   string(path),
			Message:    fmt.Sprintf("failed to unmarshal response body: %s; body: %s", err.Error(), truncateBody(body)),
			StatusCode: statusCode,
		}
	}
	return nil
}

// sensitiveJSONField matches JSON key/value pairs whose key contains a
// credential-like word (password, secret, token, api key, private key),
// including OPNsense's "%"-prefixed field variants, so the value (string,
// number or null) can be redacted before the body reaches an error message.
var sensitiveJSONField = regexp.MustCompile(`(?i)("(?:%+)?[^"]*(?:password|passwd|secret|token|api_?key|private_?key|prv)[^"]*"\s*:\s*)("(?:[^"\\]|\\.)*"|[0-9eE+.\-]+|null)`)

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
