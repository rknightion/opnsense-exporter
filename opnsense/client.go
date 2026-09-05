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
	"html"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/fetchshare"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
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
		"gatewayGroups":              "api/routing/group_settings/search",
		"firewallMigrationRules":     "api/firewall/migration/countRules",
		"firewallMigrationOutbound":  "api/firewall/migration/countOutbound",
		"unboundDNSStatus":           "api/unbound/diagnostics/stats",
		"cronJobs":                   "api/cron/settings/searchJobs",
		"wireguardClients":           "api/wireguard/service/show",
		"ipsecPhase1":                "api/ipsec/sessions/search_phase1",
		"ipsecPhase2":                "api/ipsec/sessions/search_phase2",
		"ipsecSad":                   "api/ipsec/sad/search",
		"ipsecSpd":                   "api/ipsec/spd/search",
		"ipsecLegacyStatus":          "api/ipsec/legacy_subsystem/status",
		"healthCheck":                "api/core/system/status",
		"firmware":                   "api/core/firmware/status",
		"firmwareInfo":               "api/core/firmware/info",
		"dnsmasqLeases":              "api/dnsmasq/leases/search",
		"systemResources":            "api/diagnostics/system/systemResources",
		"systemTime":                 "api/diagnostics/system/systemTime",
		"systemDisk":                 "api/diagnostics/system/systemDisk",
		"systemSwap":                 "api/diagnostics/system/systemSwap",
		"systemTemperature":          "api/diagnostics/system/systemTemperature",
		"firewallStates":             "api/diagnostics/firewall/query_states",
		"pfTop":                      "api/diagnostics/firewall/query_pf_top",
		"pfStates":                   "api/diagnostics/firewall/pf_states/1",
		"firewallRuleStats":          "api/firewall/filter_util/rule_stats",
		"firewallRules":              "api/firewall/filter/search_rule",
		"firewallRuleIDs":            "api/diagnostics/firewall/list_rule_ids",
		"systemMbuf":                 "api/diagnostics/system/systemMbuf",
		"systemMemory":               "api/diagnostics/system/memory",
		"ntpStatus":                  "api/ntpd/service/status",
		"certificates":               "api/trust/cert/search",
		"unboundBlocklistPolicies":   "api/unbound/overview/get_policies",
		"carpStatus":                 "api/diagnostics/interface/get_vip_status",
		"systemActivity":             "api/diagnostics/activity/get_activity",
		"keaLeases4":                 "api/kea/leases4/search",
		"keaLeases6":                 "api/kea/leases6/search",
		"keaReservations4":           "api/kea/dhcpv4/searchReservation",
		"keaReservations6":           "api/kea/dhcpv6/searchReservation",
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
		"netflowGetConfig":           "api/diagnostics/netflow/getconfig",
		"pfStatsInfo":                "api/diagnostics/firewall/pf_statistics/info",
		"pfStatsMemory":              "api/diagnostics/firewall/pf_statistics/memory",
		"pfStatsTimeouts":            "api/diagnostics/firewall/pf_statistics/timeouts",
		"cpuType":                    "api/diagnostics/cpu_usage/getCPUType",
		"cpuUsageStream":             "api/diagnostics/cpu_usage/stream",
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
		"trafficTop":                 "api/diagnostics/traffic/top",
		"interfaceConfig":            "api/diagnostics/interface/get_interface_config",
		"interfaceStatistics":        "api/diagnostics/interface/get_interface_statistics",
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
		"quaggaBgpRoute4":            "api/quagga/diagnostics/searchBgproute4",
		"quaggaBgpRoute6":            "api/quagga/diagnostics/searchBgproute6",
		"quaggaBfdSummary":           "api/quagga/diagnostics/bfdsummary",
		"quaggaServiceStatus":        "api/quagga/service/status",
		"monitStatus":                "api/monit/status/get/xml",
		"monitServiceStatus":         "api/monit/service/status",
		"crowdsecAlerts":             "api/crowdsec/alerts/search",
		"crowdsecDecisions":          "api/crowdsec/decisions/search",
		"crowdsecBouncers":           "api/crowdsec/bouncers/search",
		"crowdsecMachines":           "api/crowdsec/machines/search",
		"crowdsecServiceStatus":      "api/crowdsec/service/status",
		"crowdsecCollections":        "api/crowdsec/collections/search",
		"crowdsecScenarios":          "api/crowdsec/scenarios/search",
		"crowdsecParsers":            "api/crowdsec/parsers/search",
		"crowdsecPostoverflows":      "api/crowdsec/postoverflows/search",
		"crowdsecAppsecConfigs":      "api/crowdsec/appsecconfigs/search",
		"crowdsecAppsecRules":        "api/crowdsec/appsecrules/search",
		"crowdsecVersion":            "api/crowdsec/version/get",
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
		// Deliberately use current is_enabled; upstream's deprecated isBlockListEnabled sibling must not be restored.
		"unboundQueryStatsEnabled": "api/unbound/overview/is_enabled",
		// The trailing segment is the {max} row limit the backend binds straight to its
		// SQL LIMIT (stats.py handle_top), so it is a hard ceiling on how many
		// top/top_blocked domains can ever reach the exporter. It was 1 while #209's
		// cardinality rejection stood; #587 reopened that under bounded inventory, and
		// the value is now UnboundTopDomainsMax so the URL and the collector's key cap
		// cannot drift apart. TestUnboundQueryStatsTotalsMaxMatchesLeaderboardCap pins it.
		"unboundQueryStatsTotals":       "api/unbound/overview/totals/512",
		"unboundLocalZones":             "api/unbound/diagnostics/listlocalzones",
		"unboundLocalData":              "api/unbound/diagnostics/listlocaldata",
		"unboundInsecureDomains":        "api/unbound/diagnostics/listinsecure",
		"unboundSearchQueries":          "api/unbound/overview/search_queries",
		"backupHistory":                 "api/core/backup/backups/this",
		"backupDiff":                    "api/core/backup/diff",
		"snapshotsSearch":               "api/core/snapshots/search",
		"snapshotsIsSupported":          "api/core/snapshots/is_supported",
		"clamavVersion":                 "api/clamav/service/version",
		"idsStatus":                     "api/ids/service/status",
		"idsAlertLogs":                  "api/ids/service/get_alert_logs",
		"idsQueryAlerts":                "api/ids/service/query_alerts",
		"idsSettings":                   "api/ids/settings/get",
		"idsRulesets":                   "api/ids/settings/list_rulesets",
		"idsSearchInstalledRules":       "api/ids/settings/searchInstalledRules",
		"lldpdNeighbors":                "api/lldpd/service/neighbor",
		"dmidecodeInfo":                 "api/dmidecode/service/get",
		"dechwPowerStatus":              "api/dechw/info/power_status",
		"vnstatInterfaceList":           "api/vnstat/service/interface_list",
		"vnstatGetJsonData":             "api/vnstat/service/get_json_data",
		"netbirdStatus":                 "api/netbird/status/status",
		"netbirdServiceStatus":          "api/netbird/service/status",
		"beatsServiceStatus":            "api/beats/service/status",
		"collectdServiceStatus":         "api/collectd/service/status",
		"muninNodeServiceStatus":        "api/muninnode/service/status",
		"netSnmpServiceStatus":          "api/netsnmp/service/status",
		"netdataServiceStatus":          "api/netdata/service/status",
		"nodeExporterServiceStatus":     "api/nodeexporter/service/status",
		"nrpeServiceStatus":             "api/nrpe/service/status",
		"puppetAgentServiceStatus":      "api/puppetagent/service/status",
		"qemuGuestAgentServiceStatus":   "api/qemuguestagent/service/status",
		"telegrafServiceStatus":         "api/telegraf/service/status",
		"wazuhAgentServiceStatus":       "api/wazuh_agent/service/status",
		"zabbixAgentServiceStatus":      "api/zabbixagent/service/status",
		"zabbixProxyServiceStatus":      "api/zabbixproxy/service/status",
		"zerotierNetworks":              "api/zerotier/network/search",
		"zerotierNetworkInfo":           "api/zerotier/network/info",
		"torCircuits":                   "api/tor/service/circuits",
		"torStreams":                    "api/tor/service/streams",
		"torHiddenServices":             "api/tor/service/get_hidden_services",
		"authUsers":                     "api/auth/user/search",
		"authAPIKeys":                   "api/auth/user/search_api_key",
		"authGroups":                    "api/auth/group/search",
		"hostdiscoverySearch":           "api/hostdiscovery/service/search",
		"captivePortalVoucherProviders": "api/captiveportal/voucher/list_providers",
		"captivePortalVoucherGroups":    "api/captiveportal/voucher/list_voucher_groups",
		"captivePortalVouchers":         "api/captiveportal/voucher/list_vouchers",
		"relaydStatusSum":               "api/relayd/status/sum",
		"haproxyTables":                 "api/haproxy/statistics/tables",
		"ntpGPS":                        "api/ntpd/service/gps",
		"siproxdRegistrations":          "api/siproxd/service/showregistrations",
		"nginxBans":                     "api/nginx/bans/searchban",
		"firewallGeoIP":                 "api/firewall/alias/get_geo_i_p",
		"natSourceNATRules":             "api/firewall/source_nat/search_rule",
		"natDNATRules":                  "api/firewall/d_nat/search_rule",
		"natOneToOneRules":              "api/firewall/one_to_one/search_rule",
		"natNPTRules":                   "api/firewall/npt/search_rule",
		"quaggaBgpNeighbors":            "api/quagga/diagnostics/bgpneighbors",
		"quaggaOspfInterface":           "api/quagga/diagnostics/ospfinterface",
		"quaggaOspfDatabase":            "api/quagga/diagnostics/ospfdatabase",
		"quaggaOspfRoute":               "api/quagga/diagnostics/search_ospfroute",
		"quaggaOspfv3Overview":          "api/quagga/diagnostics/ospfv3overview",
		"quaggaOspfv3Interface":         "api/quagga/diagnostics/ospfv3interface",
		"quaggaOspfv3Route":             "api/quagga/diagnostics/search_ospfv3route",
		"quaggaOspfv3Database":          "api/quagga/diagnostics/search_ospfv3database",
		"quaggaGeneralRoute4":           "api/quagga/diagnostics/search_generalroute4",
		"quaggaGeneralRoute6":           "api/quagga/diagnostics/search_generalroute6",
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
	// results, when set, receives the decoded result of the handful of Fetch* methods
	// that more than one consumer in this process wants (#571) — the syslog enrichment
	// refresher was independently re-fetching twelve endpoints the metrics collectors
	// had just decoded. It is NOT a cache: nothing in this package ever reads from it,
	// and no Fetch* is ever served from it. Publication is a pure side effect, and the
	// only reader is a consumer that explicitly asks fetchshare for a result of a
	// stated maximum age. See the package comment on internal/fetchshare for why the
	// distinction is load-bearing rather than pedantic.
	//
	// A pointer, for the same reason as cache: the per-scrape WithContext clone must
	// share one seam with its parent. nil means nothing is published.
	results *fetchshare.Store
	// sem bounds the number of upstream API requests in flight across the whole
	// exporter. A default scrape fans ~61 collectors out as goroutines and several of
	// them nest further sub-fetches (runConcurrentFetches), so without a cap a single
	// scrape can burst dozens of simultaneous PHP/configd calls at a low-power firewall.
	// It is a channel so the shallow WithContext clone shares ONE budget with its parent
	// and siblings (a value field would hand every scrape its own). nil means unbounded,
	// preserving the previous behaviour for directly-constructed clients (e.g. tests).
	//
	// A slot is held only for a single request's round-trip (Do + body read) and always
	// released before any retry backoff, so no goroutine ever holds a slot while blocking
	// to acquire another — nested fan-out therefore cannot deadlock against the cap.
	sem chan struct{}
}

// RequestObserver is notified after every API request that passes through the client's
// request choke point, with the endpoint path, the HTTP status code (0 when no response
// was received, e.g. a network error or context cancellation), and the elapsed wall
// time for the whole call (including retries). Implemented by the collector layer to
// record self-metrics; kept as an interface here so opnsense/ stays Prometheus-free.
type RequestObserver interface {
	ObserveAPIRequest(endpoint string, statusCode int, duration time.Duration)
}

// RequestResultObserver is the optional richer request-observer seam. It preserves
// RequestObserver compatibility while exposing logical failures that still carry a
// successful HTTP status, such as a malformed JSON body returned with 200 OK.
type RequestResultObserver interface {
	ObserveAPIRequestResult(endpoint string, statusCode int, duration time.Duration, apiErr *APICallError)
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
	// A configured cap builds the shared budget; <=0 leaves it unbounded (the option
	// layer already rejects <1, so this only guards a directly-built config).
	var sem chan struct{}
	if cfg.MaxConcurrentRequests > 0 {
		sem = make(chan struct{}, cfg.MaxConcurrentRequests)
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
			"User-Agent": fmt.Sprintf("prometheus-opnsense2otel/%s", userAgentVersion),
			// Only advertise encodings readResponse can actually decode. The client
			// decompresses gzip (see readResponse); deflate/br are not handled, so
			// advertising them would risk an undecodable body.
			"Accept-Encoding": "gzip",
		},
		sslInsecure: cfg.Insecure,
		maxRetries:  maxRetries,
		sem:         sem,
		httpClient: &http.Client{
			Timeout: timeout,
			// Never follow a redirect (#306/#307). Every request carries the API
			// key+secret in an Authorization header (SetBasicAuth, below in
			// doWithContentType), and Go's stdlib only strips that header when the
			// redirect target's HOSTNAME differs — shouldCopyHeaderOnRedirect
			// compares hostname ONLY, not scheme and not port. So a 302 from
			// https://fw/api/... to http://fw/api/... (or to another port on the
			// same host) forwards the credentials in cleartext: an SSL-strip.
			// The OPNsense /api/* REST surface never redirects, so nothing
			// legitimate is lost; ErrUseLastResponse hands the 3xx back to
			// readResponse, which turns any non-2xx into a loud APICallError.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
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

// WithoutCache returns a shallow copy of the client with its response cache
// detached: every request the clone makes bypasses both the positive (body)
// and negative (404) TTLs and always reaches the box. The original client's
// cache is untouched — cache is a pointer field and this clone gets a nil one,
// so put()/get() on the clone are the documented nil-safe no-ops (cache.go).
//
// Built for the feature-availability prober (#517 decision D): a plugin-gated
// endpoint's 404 may be cached for up to --exporter.cache-ttl's absent-TTL
// counterpart, and a probe that hit that cache would keep reporting a plugin
// installed mid-run as absent for as long as the TTL. Not intended for
// anything else — every other caller wants the cache.
func (c *Client) WithoutCache() *Client {
	clone := *c
	clone.cache = nil
	return &clone
}

// acquireSlot blocks until an upstream-concurrency slot is free or ctx is cancelled,
// returning a release func that hands the slot back. When no limit is configured
// (sem == nil) it is a no-op, so an unbounded client keeps its previous behaviour.
// Waiting on ctx (not just the channel) is what lets a cancelled/expired scrape stop
// queueing behind a saturated budget instead of stalling to the deadline.
func (c *Client) acquireSlot(ctx context.Context) (func(), error) {
	if c.sem == nil {
		return func() {}, nil
	}
	select {
	case c.sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-c.sem }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
			duration := time.Since(start)
			if observer, ok := c.observer.(RequestResultObserver); ok {
				observer.ObserveAPIRequestResult(string(path), code, duration, apiErr)
				return
			}
			c.observer.ObserveAPIRequest(string(path), code, duration)
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

		// Acquire an upstream-concurrency slot for the actual round-trip (Do + body read),
		// releasing it before any backoff sleep so a retry waiting to fire frees capacity
		// for other collectors. A cancelled/expired scrape stops queueing here.
		release, aerr := c.acquireSlot(ctx)
		if aerr != nil {
			return &APICallError{
				Endpoint:   string(path),
				Message:    fmt.Sprintf("request aborted: %s", aerr),
				StatusCode: 0,
			}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			release()
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
			release()
			c.log.Warn("retryable server error; will retry",
				"component", "opnsense-client",
				"attempt", attempt,
				"code", resp.StatusCode)
			continue
		}

		statusCode = resp.StatusCode
		result := c.readResponse(method, path, resp, responseStruct)
		release()
		return result
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
	// A *[]byte target opts out of JSON decoding entirely. A handful of OPNsense
	// endpoints (crowdsec's version/get, which passes cscli's raw multi-line
	// text straight through) do not return JSON at all, so json.Unmarshal would
	// always fail on them. The caller gets the exact bytes the box sent back and
	// owns its own tolerant parsing; this is shared by both the live-response
	// path and the cache-hit path since both call unmarshalBody.
	if raw, ok := responseStruct.(*[]byte); ok {
		*raw = append([]byte(nil), body...)
		return nil
	}
	if err := json.Unmarshal(body, &responseStruct); err != nil {
		// A type error means the body WAS valid JSON that disagreed with the
		// struct on some field. encoding/json defers those and carries on, so
		// responseStruct already holds everything it understood — flag it so a
		// caller can keep that data rather than discard the payload wholesale
		// (#615). Syntax errors get no flag: nothing decoded.
		var typeErr *json.UnmarshalTypeError
		return &APICallError{
			Endpoint:      string(path),
			Message:       fmt.Sprintf("failed to unmarshal response body: %s; body: %s", err.Error(), truncateBody(body)),
			StatusCode:    statusCode,
			PartialDecode: errors.As(err, &typeErr),
		}
	}
	return nil
}

// sensitiveURLQueryName recognizes credential-bearing query parameter names.
// Redacting by JSON field name alone is not enough: the firewall GeoIP config
// returns a field literally named "url" whose value embeds a live credential.
const sensitiveURLQueryNamePattern = `license_?key|api_?key|apikey|auth_?token|access_?token|key|secret|token|password|passwd|auth`

var sensitiveURLQueryName = regexp.MustCompile(`(?i)^(?:` + sensitiveURLQueryNamePattern + `)$`)

// urlUserinfo matches the "user:password@" credential form of an absolute or
// scheme-relative URL, which no key-name rule would ever catch either. Only
// the password half is replaced; the scheme, username and host survive so the
// body still says what it was talking to.
const urlAuthorityPrefixPattern = `(?:[a-z][a-z0-9+.\-]*:)?(?:/|\\/){2}`

var urlUserinfo = regexp.MustCompile(`(?i)(` + urlAuthorityPrefixPattern + `[^/:@\s"']*:)[^/@\s"']+@`)

// quotedURLUserinfo is used only after a complete quoted token has been
// isolated. Quote and whitespace bytes are data there, not token boundaries,
// so they cannot be allowed to split a password around an HTML reference.
var quotedURLUserinfo = regexp.MustCompile(`(?i)(` + urlAuthorityPrefixPattern + `[^/:@]*:)[^/@]+@`)

// truncatedURLUserinfoSuffix is the fail-closed form used only after an error
// body has been cut to its diagnostic limit. The trailing @ may be beyond that
// boundary, so a scheme://authority-prefix:value at EOF must be treated as
// possible userinfo rather than allowed to expose a password prefix.
var truncatedURLUserinfoSuffix = regexp.MustCompile(`(?i)(` + urlAuthorityPrefixPattern + `[^/:@\s"']*:)[^/@\s"']*$`)

// truncatedQuotedURLUserinfoSuffix runs only inside an already isolated,
// incomplete quoted token. Whitespace and quote bytes can therefore be part
// of entity-decoded password data rather than trustworthy token boundaries.
var truncatedQuotedURLUserinfoSuffix = regexp.MustCompile(`(?i)` + urlAuthorityPrefixPattern + `[^/:@]*:[^/@]+$`)

func redactTruncatedURLUserinfo(b []byte) []byte {
	match := truncatedURLUserinfoSuffix.FindSubmatchIndex(b)
	if match == nil {
		return b
	}
	const marker = "[REDACTED]"
	prefixEnd := match[3]
	// Keep the diagnostic body within its fixed budget without cutting the
	// redaction marker itself when the observed password prefix is shorter.
	if limit := maxErrorBodyBytes - len(marker); prefixEnd > limit {
		prefixEnd = limit
	}
	out := make([]byte, 0, prefixEnd+len(marker))
	out = append(out, b[:prefixEnd]...)
	return append(out, marker...)
}

func redactTruncatedHTMLQuotedURLUserinfo(value string) string {
	const marker = "[REDACTED]"
	b := []byte(value)
	for i := 0; i < len(value); i++ {
		if value[i] != '=' || !htmlURLAttributeEquals(value, i) {
			continue
		}
		start := i + 1
		for start < len(value) && htmlSpace(value[start]) {
			start++
		}
		if start >= len(value) || value[start] != '"' && value[start] != '\'' {
			continue
		}
		_, complete := htmlQuotedStringEnd(b, start, value[start])
		if complete {
			// A malformed attribute may close on the quote that opens a
			// later attribute. Keep scanning inside this candidate so the
			// later URL boundary is still considered.
			continue
		}
		decoded := html.UnescapeString(value[start+1:])
		if redactSensitiveURLValue(decoded) != decoded || truncatedQuotedURLUserinfoSuffix.MatchString(decoded) {
			return value[:start+1] + marker
		}
		break
	}
	for start := 0; start < len(value); {
		quote := value[start]
		if quote != '"' && quote != '\'' {
			start++
			continue
		}
		end, complete := quotedStringEnd(b, start, quote)
		if complete {
			start = end
			continue
		}
		raw := value[start+1:]
		decoded := html.UnescapeString(raw)
		if truncatedQuotedURLUserinfoSuffix.MatchString(decoded) {
			return value[:start+1] + marker
		}
		break
	}
	return value
}

func jsonStringEnd(b []byte, start int) (int, bool) {
	return quotedStringEnd(b, start, '"')
}

func quotedStringEnd(b []byte, start int, quote byte) (int, bool) {
	if start >= len(b) || b[start] != quote {
		return start, false
	}
	for i := start + 1; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case quote:
			return i + 1, true
		}
	}
	return len(b), false
}

// htmlQuotedStringEnd finds an HTML attribute's closing quote. Unlike JSON,
// HTML does not give backslash any escape semantics: a quote after a
// backslash still ends the attribute. Keeping this separate prevents one
// benign attribute from swallowing the opener of a later credential-bearing
// URL attribute during diagnostic redaction.
func htmlQuotedStringEnd(b []byte, start int, quote byte) (int, bool) {
	if start >= len(b) || b[start] != quote {
		return start, false
	}
	for i := start + 1; i < len(b); i++ {
		if b[i] == quote {
			return i + 1, true
		}
	}
	return len(b), false
}

func jsonSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func htmlSpace(c byte) bool {
	return jsonSpace(c) || c == '\f'
}

// jsonLikeValueEnd finds the end of the value after a closed JSON key. The
// response itself may be malformed, so incomplete strings and composites run
// through the end of the body. That is the fail-closed behaviour required for
// error text: once a sensitive key is known, no part of its value may survive.
func jsonLikeValueEnd(b []byte, start int) (int, bool) {
	if start >= len(b) {
		return start, false
	}
	switch b[start] {
	case '"':
		end, complete := jsonStringEnd(b, start)
		if !complete {
			return len(b), true
		}
		return jsonLikeClosedValueEnd(b, end), true
	case '\'':
		end, complete := quotedStringEnd(b, start, '\'')
		if !complete {
			return len(b), true
		}
		return jsonLikeClosedValueEnd(b, end), true
	case '{', '[':
		stack := []byte{'}'}
		if b[start] == '[' {
			stack[0] = ']'
		}
		for i := start + 1; i < len(b); {
			switch b[i] {
			case '"', '\'':
				end, complete := quotedStringEnd(b, i, b[i])
				if !complete {
					return len(b), true
				}
				i = end
				continue
			case '{':
				stack = append(stack, '}')
			case '[':
				stack = append(stack, ']')
			case '}', ']':
				if b[i] != stack[len(stack)-1] {
					return len(b), true
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					return jsonLikeClosedValueEnd(b, i+1), true
				}
			}
			i++
		}
		return len(b), true
	default:
		if b[start] == ',' || b[start] == '}' || b[start] == ']' || jsonSpace(b[start]) {
			return start, false
		}
		end := start
		for end < len(b) && b[end] != ',' && b[end] != '}' && b[end] != ']' {
			end++
		}
		return end, true
	}
}

func jsonLikeClosedValueEnd(b []byte, end int) int {
	boundary := end
	for boundary < len(b) && jsonSpace(b[boundary]) {
		boundary++
	}
	if boundary == len(b) || b[boundary] == ',' || b[boundary] == '}' || b[boundary] == ']' {
		return end
	}
	// A known-sensitive closed value followed by non-structural bytes is
	// malformed. Consume that suffix through the next object delimiter so no
	// credential fragment can survive after the first apparent closing token.
	for boundary < len(b) {
		switch b[boundary] {
		case '"', '\'':
			quotedEnd, complete := quotedStringEnd(b, boundary, b[boundary])
			if !complete {
				return len(b)
			}
			boundary = quotedEnd
			continue
		case ',', '}', ']':
			return boundary
		}
		boundary++
	}
	return boundary
}

// redactSensitiveJSONFields replaces the values of sensitive JSON fields with
// "[REDACTED]". It deliberately uses SensitiveConfigKey, so malformed API
// response bodies cannot drift from the vocabulary used for shipped config.
func redactSensitiveJSONFields(b []byte) []byte {
	const marker = `"[REDACTED]"`
	out := make([]byte, 0, len(b))
	cursor := 0
	for i := 0; i < len(b); {
		if b[i] != '"' {
			i++
			continue
		}
		keyEnd, complete := jsonStringEnd(b, i)
		if !complete {
			break
		}
		colon := keyEnd
		for colon < len(b) && jsonSpace(b[colon]) {
			colon++
		}
		if colon >= len(b) || b[colon] != ':' {
			// Malformed error bodies may contain a stray quote before a real
			// field opener. Reconsider overlapping quote starts rather than
			// letting that stray token hide a later sensitive key.
			i++
			continue
		}
		var key string
		keyErr := json.Unmarshal(b[i:keyEnd], &key)
		// An invalidly escaped field name has no authoritative decoded value
		// to classify through SensitiveConfigKey. Error diagnostics fail closed
		// by redacting its value rather than letting malformed escape bytes hide
		// a credential name (for example pass\qword).
		if keyErr == nil && !SensitiveConfigKey(key) {
			i = keyEnd
			continue
		}
		valueStart := colon + 1
		for valueStart < len(b) && jsonSpace(b[valueStart]) {
			valueStart++
		}
		valueEnd, present := jsonLikeValueEnd(b, valueStart)
		if !present {
			i = keyEnd
			continue
		}
		out = append(out, b[cursor:valueStart]...)
		out = append(out, marker...)
		cursor = valueEnd
		i = valueEnd
	}
	return append(out, b[cursor:]...)
}

func jsonLikeKeyBeforeDelimiter(b []byte, delimiter int) (string, bool, bool) {
	end := delimiter
	for end > 0 && jsonSpace(b[end-1]) {
		end--
	}
	start := end
	for start > 0 {
		c := b[start-1]
		if asciiAlphaNumeric(c) || c == '_' || c == '-' || c == '.' || c == '%' ||
			c == '\'' || c == '"' || c == '\\' {
			start--
			continue
		}
		break
	}
	boundary := start
	for boundary > 0 && jsonSpace(b[boundary-1]) {
		boundary--
	}
	if boundary == 0 || b[boundary-1] != '{' && b[boundary-1] != ',' {
		return "", false, false
	}
	if end-start >= 2 && b[start] == '"' && b[end-1] == '"' {
		var key string
		if json.Unmarshal(b[start:end], &key) == nil {
			return key, false, true
		}
	}

	var key strings.Builder
	key.Grow(end - start)
	for i := start; i < end; i++ {
		c := b[i]
		if c == '\'' || c == '"' {
			continue
		}
		if c != '\\' {
			key.WriteByte(c)
			continue
		}
		if i+5 >= end || b[i+1] != 'u' {
			return key.String(), true, true
		}
		decoded, err := strconv.ParseUint(string(b[i+2:i+6]), 16, 16)
		if err != nil {
			return key.String(), true, true
		}
		i += 5
		if decoded != '\'' && decoded != '"' && decoded != '\\' {
			key.WriteRune(rune(decoded))
		}
	}
	if key.Len() == 0 {
		return "", false, false
	}
	return key.String(), false, true
}

// redactSensitiveJSONLikeFields covers bounded object-key syntax from
// malformed diagnostic bodies: single-quoted keys, unquoted keys, and quote
// artifacts inside a key. A candidate must follow an object boundary, which
// keeps URL colons and ordinary prose out of this fail-closed field pass.
func redactSensitiveJSONLikeFields(b []byte) []byte {
	const marker = `"[REDACTED]"`
	out := make([]byte, 0, len(b))
	cursor := 0
	for at := 0; at < len(b); at++ {
		if (b[at] == '"' || b[at] == '\'') && jsonLikeStringOpener(b, at) {
			end, complete := quotedStringEnd(b, at, b[at])
			if complete && jsonLikeQuotedTokenCanSkip(b, at, end) {
				at = end - 1
				continue
			}
		}
		delimiterEnd := at + 1
		if b[at] != ':' {
			if at+6 > len(b) || b[at] != '\\' || b[at+1] != 'u' {
				continue
			}
			decoded, err := strconv.ParseUint(string(b[at+2:at+6]), 16, 16)
			if err != nil || decoded != ':' {
				continue
			}
			delimiterEnd = at + 6
		}
		key, malformed, ok := jsonLikeKeyBeforeDelimiter(b, at)
		if !ok || !malformed && !SensitiveConfigKey(key) {
			continue
		}
		valueStart := delimiterEnd
		for valueStart < len(b) && jsonSpace(b[valueStart]) {
			valueStart++
		}
		valueEnd, present := jsonLikeValueEnd(b, valueStart)
		if !present || valueStart < cursor {
			continue
		}
		out = append(out, b[cursor:valueStart]...)
		out = append(out, marker...)
		cursor = valueEnd
		at = valueEnd - 1
	}
	return append(out, b[cursor:]...)
}

func jsonLikeQuotedTokenCanSkip(b []byte, start, end int) bool {
	if jsonLikeTokenEndsAtSensitiveDelimiter(b, start, end) {
		// The apparent closing quote may also open the malformed sensitive
		// value. Do not skip the enclosing token or its inner key delimiter.
		return false
	}
	previous := start
	for previous > 0 && jsonSpace(b[previous-1]) {
		previous--
	}
	next := end
	for next < len(b) && jsonSpace(b[next]) {
		next++
	}
	if previous == 0 {
		return next == len(b)
	}
	if next == len(b) {
		return b[previous-1] == ':' || b[previous-1] == '[' || b[previous-1] == ','
	}
	switch b[previous-1] {
	case '{':
		return b[next] == ':'
	case ':', '[':
		return b[next] == ',' || b[next] == '}' || b[next] == ']'
	case ',':
		return b[next] == ':' || b[next] == ',' || b[next] == '}' || b[next] == ']'
	}
	return false
}

func jsonLikeTokenEndsAtSensitiveDelimiter(b []byte, start, end int) bool {
	contentEnd := end - 1
	for contentEnd > start+1 && jsonSpace(b[contentEnd-1]) {
		contentEnd--
	}
	if contentEnd <= start+1 {
		return false
	}
	delimiter := contentEnd - 1
	if b[delimiter] != ':' {
		if contentEnd-start <= 6 || b[contentEnd-6] != '\\' || b[contentEnd-5] != 'u' {
			return false
		}
		decoded, err := strconv.ParseUint(string(b[contentEnd-4:contentEnd]), 16, 16)
		if err != nil || decoded != ':' {
			return false
		}
		delimiter = contentEnd - 6
	}
	key, malformed, ok := jsonLikeKeyBeforeDelimiter(b, delimiter)
	return ok && (malformed || SensitiveConfigKey(key))
}

func jsonLikeStringOpener(b []byte, at int) bool {
	previous := at
	for previous > 0 && jsonSpace(b[previous-1]) {
		previous--
	}
	if previous == 0 {
		return true
	}
	switch b[previous-1] {
	case '{', '[', ',', ':':
		return true
	default:
		return false
	}
}

func redactSensitiveURLValue(value string) string {
	value = redactSensitiveRawQueryComponents(value, false)
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		changed := false
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				parsed.User = url.UserPassword(parsed.User.Username(), "[REDACTED]")
				changed = true
			}
		}
		if changed {
			value = parsed.String()
		}
	}
	return quotedURLUserinfo.ReplaceAllString(value, `${1}[REDACTED]@`)
}

// redactSensitiveRawQueryComponents scans query-shaped text without parsing
// the whole URL. Each key is decoded independently from its value, so a bad
// percent escape in one credential value cannot make the parser discard that
// same component. It also covers relative URLs and plain-text diagnostics.
// Decoded JSON strings run to URL delimiters because spaces and backslashes are
// value bytes there; the whole-body pass additionally stops at text boundaries.
func redactSensitiveRawQueryComponents(value string, textBoundaries bool) string {
	const marker = "[REDACTED]"
	var out strings.Builder
	cursor := 0
	for i := 0; i < len(value); i++ {
		keyStart, separator := querySeparatorEnd(value, i)
		if !separator {
			continue
		}
		keyEnd := keyStart
		for keyEnd < len(value) && value[keyEnd] != '=' && !queryKeyDelimiter(value[keyEnd]) {
			keyEnd++
		}
		if keyEnd >= len(value) || value[keyEnd] != '=' {
			continue
		}
		key, err := url.QueryUnescape(value[keyStart:keyEnd])
		if err != nil || !sensitiveURLQueryName.MatchString(key) {
			continue
		}
		valueStart := keyEnd + 1
		valueEnd := valueStart
		for valueEnd < len(value) && !queryValueDelimiter(value[valueEnd], textBoundaries) {
			valueEnd++
		}
		out.WriteString(value[cursor:valueStart])
		out.WriteString(marker)
		cursor = valueEnd
		i = valueEnd - 1
	}
	if cursor == 0 {
		return value
	}
	out.WriteString(value[cursor:])
	return out.String()
}

func querySeparatorEnd(value string, start int) (int, bool) {
	if value[start] == '?' {
		return start + 1, true
	}
	if value[start] != '&' {
		return start, false
	}
	// HTML error pages normally entity-escape ampersands inside href values.
	// Treat named and numeric references to '&' as separators for detection
	// while preserving the original diagnostic representation in the output.
	if end := start + len("&amp;"); end <= len(value) && strings.EqualFold(value[start:end], "&amp;") {
		return end, true
	}
	if end := start + len("&amp"); end < len(value) && strings.EqualFold(value[start:end], "&amp") &&
		!asciiAlphaNumeric(value[end]) && value[end] != '=' {
		return end, true
	}
	if end, ok := numericAmpersandReferenceEnd(value, start); ok {
		return end, true
	}
	return start + 1, true
}

func numericAmpersandReferenceEnd(value string, start int) (int, bool) {
	if start+3 >= len(value) || value[start:start+2] != "&#" {
		return start, false
	}
	base := byte(10)
	pos := start + 2
	if value[pos] == 'x' || value[pos] == 'X' {
		base = 16
		pos++
	}
	digitStart := pos
	number := 0
	for pos < len(value) {
		var digit int
		switch c := value[pos]; {
		case c >= '0' && c <= '9':
			digit = int(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			digit = int(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			digit = int(c-'A') + 10
		default:
			goto parsed
		}
		number = number*int(base) + digit
		if number > '&' {
			number = '&' + 1
		}
		pos++
	}

parsed:
	if pos == digitStart || number != '&' {
		return start, false
	}
	if pos < len(value) && value[pos] == ';' {
		pos++
	}
	return pos, true
}

func questionMarkReferenceEnd(value string, start int) (int, bool) {
	if value[start] == '?' {
		return start + 1, true
	}
	if value[start] != '&' {
		return start, false
	}
	if end := start + len("&quest;"); end <= len(value) && strings.EqualFold(value[start:end], "&quest;") {
		return end, true
	}
	if end := start + len("&quest"); end < len(value) && strings.EqualFold(value[start:end], "&quest") &&
		!asciiAlphaNumeric(value[end]) && value[end] != '=' {
		return end, true
	}
	if start+3 >= len(value) || value[start:start+2] != "&#" {
		return start, false
	}
	base := byte(10)
	pos := start + 2
	if value[pos] == 'x' || value[pos] == 'X' {
		base = 16
		pos++
	}
	digitStart := pos
	number := 0
	for pos < len(value) {
		var digit int
		switch c := value[pos]; {
		case c >= '0' && c <= '9':
			digit = int(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			digit = int(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			digit = int(c-'A') + 10
		default:
			goto parsed
		}
		number = number*int(base) + digit
		if number > '?' {
			number = '?' + 1
		}
		pos++
	}

parsed:
	if pos == digitStart || number != '?' {
		return start, false
	}
	if pos < len(value) && value[pos] == ';' {
		pos++
	}
	return pos, true
}

func asciiAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func queryKeyDelimiter(c byte) bool {
	return c == '&' || c == '#' || c == '"' || c == '\'' || c == '\\' || jsonSpace(c)
}

func queryValueDelimiter(c byte, textBoundaries bool) bool {
	if c == '&' || c == '#' {
		return true
	}
	return textBoundaries && (c == '"' || c == '\'' || c == '\\' || jsonSpace(c))
}

// redactSensitiveHTMLQueryRegions handles the mapping problem introduced by
// HTML character references. When decoding a query-shaped region exposes a
// sensitive parameter, redact the whole original query rather than trying to
// map decoded byte offsets back onto source bytes. This is intentionally
// conservative diagnostic text: it prevents an encoded quote or ampersand in
// the value from leaving a credential suffix behind.
func redactSensitiveHTMLQueryRegions(value string) string {
	const marker = "[REDACTED]"
	var out strings.Builder
	cursor := 0
	for start := 0; start < len(value); start++ {
		queryEnd, ok := questionMarkReferenceEnd(value, start)
		if !ok {
			continue
		}
		end := queryEnd
		for end < len(value) && value[end] != '"' && value[end] != '\'' &&
			value[end] != '\\' && !jsonSpace(value[end]) {
			end++
		}
		raw := value[start:end]
		decoded := html.UnescapeString(raw)
		if decoded == raw || redactSensitiveRawQueryComponents(decoded, false) == decoded {
			continue
		}
		out.WriteString(value[cursor:queryEnd])
		out.WriteString(marker)
		cursor = end
		start = end - 1
	}
	if cursor == 0 {
		return value
	}
	out.WriteString(value[cursor:])
	return out.String()
}

// redactSensitiveHTMLQuotedURLs inspects complete quoted URL attributes before
// whole-body entity normalization. Starting at the attribute's equals boundary
// avoids pairing an unrelated quote in HTML text with the attribute opener.
// If decoding exposes URL credentials, replace the whole token content:
// preserving byte offsets is less important than keeping every password byte
// out of the diagnostic.
func redactSensitiveHTMLQuotedURLs(value string) string {
	var out strings.Builder
	cursor := 0
	for i := 0; i < len(value); i++ {
		if value[i] != '=' || !htmlURLAttributeEquals(value, i) {
			continue
		}
		start := i + 1
		for start < len(value) && htmlSpace(value[start]) {
			start++
		}
		if start >= len(value) || value[start] != '"' && value[start] != '\'' {
			continue
		}
		end, complete := htmlQuotedStringEnd([]byte(value), start, value[start])
		if !complete {
			break
		}
		raw := value[start+1 : end-1]
		decoded := html.UnescapeString(raw)
		redacted := redactSensitiveURLValue(decoded)
		if redacted != decoded {
			out.WriteString(value[cursor : start+1])
			out.WriteString(html.EscapeString(redacted))
			cursor = end - 1
			i = end - 2
		}
		// Do not skip the candidate wholesale. In malformed HTML its closing
		// quote can also open a later URL attribute, and that later equals
		// boundary must remain visible to this pass.
	}
	if cursor == 0 {
		return value
	}
	out.WriteString(value[cursor:])
	return out.String()
}

// redactSensitiveSingleQuotedURLs handles standalone diagnostic URLs enclosed
// in single quotes. JSON string scanning intentionally owns double quotes;
// this pass closes the equivalent boundary for prose and malformed HTML after
// entity normalization.
func redactSensitiveSingleQuotedURLs(value string) string {
	var out strings.Builder
	cursor := 0
	for i := 0; i < len(value); i++ {
		if value[i] != '\'' {
			continue
		}
		end, complete := quotedStringEnd([]byte(value), i, '\'')
		rawEnd := end
		if complete {
			rawEnd--
		}
		raw := value[i+1 : rawEnd]
		redacted := redactSensitiveURLValue(raw)
		if !complete && truncatedQuotedURLUserinfoSuffix.MatchString(redacted) {
			redacted = "[REDACTED]"
		}
		if redacted == raw {
			if !complete {
				break
			}
			continue
		}
		out.WriteString(value[cursor : i+1])
		out.WriteString(redacted)
		if complete {
			cursor = end - 1
			i = end - 2
		} else {
			cursor = end
			break
		}
	}
	if cursor == 0 {
		return value
	}
	out.WriteString(value[cursor:])
	return out.String()
}

// redactSensitiveHTMLUnquotedURLs protects URL-valued attributes before HTML
// normalization. Character references are decoded after the tokenizer has
// already delimited an unquoted attribute, so an encoded space or quote is
// data inside a password even though the normalized byte would otherwise look
// like a boundary to the whole-body scanners.
func redactSensitiveHTMLUnquotedURLs(value string) string {
	const marker = "[REDACTED]"
	var out strings.Builder
	cursor := 0
	for i := 0; i < len(value); i++ {
		if value[i] != '=' || !htmlURLAttributeEquals(value, i) {
			continue
		}
		start := i + 1
		for start < len(value) && htmlSpace(value[start]) {
			start++
		}
		if start >= len(value) || value[start] == '"' || value[start] == '\'' {
			continue
		}
		end := start
		for end < len(value) && value[end] != '>' && !htmlSpace(value[end]) {
			end++
		}
		raw := value[start:end]
		decoded := html.UnescapeString(raw)
		redacted := redactSensitiveURLValue(decoded)
		redacted = quotedURLUserinfo.ReplaceAllString(redacted, `${1}[REDACTED]@`)
		if redacted == decoded {
			continue
		}
		out.WriteString(value[cursor:start])
		out.WriteString(marker)
		cursor = end
		i = end - 1
	}
	if cursor == 0 {
		return value
	}
	out.WriteString(value[cursor:])
	return out.String()
}

func htmlURLAttributeEquals(value string, equals int) bool {
	nameEnd := equals
	for nameEnd > 0 && htmlSpace(value[nameEnd-1]) {
		nameEnd--
	}
	for _, name := range []string{"href", "src", "action", "formaction", "poster"} {
		start := nameEnd - len(name)
		if start < 0 || !strings.EqualFold(value[start:nameEnd], name) {
			continue
		}
		if start == 0 || value[start-1] == '<' || htmlSpace(value[start-1]) {
			return true
		}
	}
	return false
}

// looselyDecodeJSONStringToken produces a detection-only view when a malformed
// string token cannot be decoded by encoding/json. It recognizes every JSON
// escape that can conceal URL syntax; invalid or incomplete escapes are reduced
// conservatively. Callers replace the whole malformed token on a match, so no
// byte from an uncertain credential value is copied back out.
func looselyDecodeJSONStringToken(token []byte, complete bool) string {
	end := len(token)
	if complete && end > 1 && token[end-1] == '"' {
		end--
	}
	var decoded strings.Builder
	decoded.Grow(end)
	for i := 1; i < end; i++ {
		if token[i] != '\\' {
			decoded.WriteByte(token[i])
			continue
		}
		if i+1 >= end {
			break
		}
		i++
		switch token[i] {
		case '"', '\\', '/':
			decoded.WriteByte(token[i])
		case 'b', 'f', 'n', 'r', 't':
			decoded.WriteByte(' ')
		case 'u':
			if i+4 < end {
				value, err := strconv.ParseUint(string(token[i+1:i+5]), 16, 16)
				if err == nil {
					decoded.WriteRune(rune(value))
					i += 4
					continue
				}
			}
			decoded.WriteByte('u')
		default:
			decoded.WriteByte(token[i])
		}
	}
	return decoded.String()
}

// redactSensitiveURLsInJSONStrings decodes each JSON string token, or builds a
// conservative detection view when malformed escapes prevent decoding, before
// applying the URL and nested object-field scrubbers. Looking only at the wire
// encoding is not enough: JSON may escape punctuation or credential bytes.
func redactSensitiveURLsInJSONStrings(b []byte, bodyTruncated bool) []byte {
	out := make([]byte, 0, len(b))
	cursor := 0
	for i := 0; i < len(b); {
		if b[i] != '"' {
			i++
			continue
		}
		end, complete := jsonStringEnd(b, i)
		token := b[i:end]
		replaced := false
		if !complete {
			// A truncated JSON string can still be decoded when its content and
			// escapes are complete. Add only the missing quote for inspection;
			// remove it again if a redacted token is written back.
			token = append(append([]byte(nil), token...), '"')
		}
		var value string
		if err := json.Unmarshal(token, &value); err == nil {
			decoded := html.UnescapeString(value)
			redacted := redactSensitiveURLValue(decoded)
			if strings.Contains(decoded, "{") {
				redacted = string(redactSensitiveJSONLikeFields(redactSensitiveJSONFields([]byte(redacted))))
			}
			if !complete && bodyTruncated {
				// The body limit may cut an otherwise valid userinfo URL before its
				// trailing @. Classify the decoded prefix at EOF so JSON-escaped
				// separators cannot conceal the password bytes that did arrive.
				redacted = truncatedURLUserinfoSuffix.ReplaceAllString(redacted, `${1}[REDACTED]`)
			}
			if redacted != decoded {
				encoded, err := json.Marshal(redacted)
				if err == nil {
					if !complete {
						encoded = encoded[:len(encoded)-1]
					}
					out = append(out, b[cursor:i]...)
					if complete {
						// Leave the source closing quote in place. Malformed
						// input can reuse it as the next string opener.
						out = append(out, encoded[:len(encoded)-1]...)
						cursor = end - 1
					} else {
						out = append(out, encoded...)
						cursor = end
					}
					replaced = true
				}
			}
		} else {
			// token always has a closing quote here: either the wire supplied it
			// or the incomplete-token path appended one for detection.
			shadow := looselyDecodeJSONStringToken(token, true)
			decoded := html.UnescapeString(shadow)
			redacted := redactSensitiveURLValue(decoded)
			if strings.Contains(decoded, "{") {
				redacted = string(redactSensitiveJSONLikeFields(redactSensitiveJSONFields([]byte(redacted))))
			}
			if !complete && bodyTruncated {
				// A cut inside an encoded escape (for example the @ in userinfo)
				// makes the temporary JSON token undecodable. Apply the same EOF
				// userinfo rule to the tolerant detection view as to decoded tokens.
				redacted = truncatedURLUserinfoSuffix.ReplaceAllString(redacted, `${1}[REDACTED]`)
			}
			if redacted != decoded {
				replacement := []byte(`"[REDACTED]"`)
				if !complete {
					replacement = replacement[:len(replacement)-1]
				}
				out = append(out, b[cursor:i]...)
				if complete {
					out = append(out, replacement[:len(replacement)-1]...)
					cursor = end - 1
				} else {
					out = append(out, replacement...)
					cursor = end
				}
				replaced = true
			}
		}
		if !complete {
			break
		}
		if replaced {
			// Reconsider the closing quote as a possible overlapping opener.
			i = end - 1
		} else {
			// A malformed body may contain a stray quote before the real
			// URL-string opener. Reconsider overlapping quote starts until a
			// candidate is actually rewritten.
			i++
		}
	}
	return append(out, b[cursor:]...)
}

// redactSensitiveFields replaces the values of sensitive JSON fields, then
// makes a second pass over the whole body to scrub
// credentials embedded in URL VALUES (query parameters and userinfo), which
// the key-name rule cannot see. Non-JSON bodies pass through unchanged apart
// from that second pass, which is deliberate — an HTML error page can carry
// the same URL.
func redactSensitiveFields(b []byte, truncated bool) []byte {
	b = redactSensitiveJSONFields(b)
	b = redactSensitiveJSONLikeFields(b)
	b = []byte(redactSensitiveHTMLUnquotedURLs(string(b)))
	b = []byte(redactSensitiveHTMLQuotedURLs(string(b)))
	if truncated {
		b = []byte(redactTruncatedHTMLQuotedURLUserinfo(string(b)))
	}
	b = []byte(redactSensitiveHTMLQueryRegions(string(b)))
	// Error bodies can be HTML as well as JSON. Normalize character
	// references before classification so encoded punctuation inside a query
	// key cannot hide its credential name from the same scanner a browser sees.
	// Sensitive JSON values are protected first so normalization cannot inject
	// a quote that makes the value appear to end early; scan fields again after
	// normalization to catch an encoded sensitive key.
	b = []byte(html.UnescapeString(string(b)))
	if truncated {
		b = []byte(redactTruncatedHTMLQuotedURLUserinfo(string(b)))
	}
	b = redactSensitiveJSONFields(b)
	b = redactSensitiveJSONLikeFields(b)
	b = redactSensitiveURLsInJSONStrings(b, truncated)
	b = []byte(redactSensitiveSingleQuotedURLs(string(b)))
	b = []byte(redactSensitiveRawQueryComponents(string(b), true))
	b = urlUserinfo.ReplaceAll(b, []byte(`${1}[REDACTED]@`))
	return b
}

// truncateBody redacts credential-like field values from a response body
// destined for an error message, then bounds its length.
func truncateBody(b []byte) []byte {
	truncated := len(b) > maxErrorBodyBytes
	if truncated {
		// Redaction only needs to inspect bytes that can reach the diagnostic.
		// Cutting first also bounds its working memory; the scanners treat any
		// sensitive value cut at this boundary as truncated and redact to EOF.
		b = b[:maxErrorBodyBytes]
	}
	b = redactSensitiveFields(b, truncated)
	if truncated {
		b = redactTruncatedURLUserinfo(b)
	}
	if len(b) > maxErrorBodyBytes {
		b = b[:maxErrorBodyBytes]
		b = redactTruncatedURLUserinfo(b)
		truncated = true
	}
	if truncated {
		return append(b[:len(b):len(b)], "... (truncated)"...)
	}
	return b
}
