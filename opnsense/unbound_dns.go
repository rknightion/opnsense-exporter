package opnsense

import (
	"bytes"
	"encoding/json"
)

type unboundDNSStatusResponse struct {
	Status string `json:"status"`
	Data   struct {
		Total struct {
			Num struct {
				Queries               string `json:"queries"`
				QueriesIPRatelimited  string `json:"queries_ip_ratelimited"`
				QueriesCookieValid    string `json:"queries_cookie_valid"`
				QueriesCookieClient   string `json:"queries_cookie_client"`
				QueriesCookieInvalid  string `json:"queries_cookie_invalid"`
				Cachehits             string `json:"cachehits"`
				Cachemiss             string `json:"cachemiss"`
				Prefetch              string `json:"prefetch"`
				QueriesTimedOut       string `json:"queries_timed_out"`
				Expired               string `json:"expired"`
				Recursivereplies      string `json:"recursivereplies"`
				QueriesDiscardTimeout string `json:"queries_discard_timeout"`
				QueriesWaitLimit      string `json:"queries_wait_limit"`
				DNSErrorReports       string `json:"dns_error_reports"`
				Dnscrypt              struct {
					Crypted   string `json:"crypted"`
					Cert      string `json:"cert"`
					Cleartext string `json:"cleartext"`
					Malformed string `json:"malformed"`
				} `json:"dnscrypt"`
			} `json:"num"`
			Query struct {
				QueueTimeUs struct {
					Max string `json:"max"`
				} `json:"queue_time_us"`
			} `json:"query"`
			Requestlist struct {
				Avg         string `json:"avg"`
				Max         string `json:"max"`
				Overwritten string `json:"overwritten"`
				Exceeded    string `json:"exceeded"`
				Current     struct {
					All  string `json:"all"`
					User string `json:"user"`
				} `json:"current"`
			} `json:"requestlist"`
			Recursion struct {
				Time struct {
					Avg    string `json:"avg"`
					Median string `json:"median"`
				} `json:"time"`
			} `json:"recursion"`
			Tcpusage string `json:"tcpusage"`
		} `json:"total"`
		Time struct {
			Now     string `json:"now"`
			Up      string `json:"up"`
			Elapsed string `json:"elapsed"`
		} `json:"time"`
		// The sections below (mem, num, unwanted, msg, rrset, infra, key,
		// dnscrypt_*) are unbound's EXTENDED statistics. They are served only when
		// the resolver runs with `extended-statistics: yes` — on by default on
		// OPNsense 26.1, OFF by default on 26.7, where the keys are simply absent
		// from the payload. They are therefore POINTERS: nil means "the box did not
		// report this section", which is distinguishable from "reported as zero".
		// Mapping them unconditionally would decode absent sections to zeros and
		// publish ~40 phantom zero series (see UnboundDNSOverview.ExtendedPresent).
		// This is presence-gating, not removal — an admin re-enabling
		// extended-statistics brings every section straight back.
		Mem *struct {
			Cache struct {
				Rrset                string `json:"rrset"`
				Message              string `json:"message"`
				DnscryptSharedSecret string `json:"dnscrypt_shared_secret"`
				DnscryptNonce        string `json:"dnscrypt_nonce"`
			} `json:"cache"`
			Mod struct {
				Iterator  string `json:"iterator"`
				Validator string `json:"validator"`
				Respip    string `json:"respip"`
				Dynlibmod string `json:"dynlibmod"`
			} `json:"mod"`
			Streamwait string `json:"streamwait"`
			HTTP       struct {
				QueryBuffer    string `json:"query_buffer"`
				ResponseBuffer string `json:"response_buffer"`
			} `json:"http"`
		} `json:"mem"`
		Num *struct {
			Query struct {
				// data.num.query.type is dynamic: unbound-control emits a
				// num.query.type.<T> key only for RR types actually queried, not a fixed
				// schema. Decode as a map so every observed type is captured — a fixed
				// struct silently dropped any type outside its named fields (#138).
				// Cardinality is naturally bounded by the DNS RR-type space.
				Type  map[string]string `json:"type"`
				Class struct {
					In string `json:"IN"`
				} `json:"class"`
				Opcode struct {
					Query string `json:"QUERY"`
				} `json:"opcode"`
				TCP    string `json:"tcp"`
				Tcpout string `json:"tcpout"`
				Udpout string `json:"udpout"`
				TLS    struct {
					Value  string `json:"__value__"`
					Resume string `json:"resume"`
				} `json:"tls"`
				Ipv6  string `json:"ipv6"`
				HTTPS string `json:"https"`
				Flags struct {
					Qr string `json:"QR"`
					Aa string `json:"AA"`
					Tc string `json:"TC"`
					Rd string `json:"RD"`
					Ra string `json:"RA"`
					Z  string `json:"Z"`
					Ad string `json:"AD"`
					Cd string `json:"CD"`
				} `json:"flags"`
				Edns struct {
					Present string `json:"present"`
					Do      string `json:"DO"`
				} `json:"edns"`
				Ratelimited string `json:"ratelimited"`
				Aggressive  struct {
					Noerror  string `json:"NOERROR"`
					Nxdomain string `json:"NXDOMAIN"`
				} `json:"aggressive"`
				Dnscrypt struct {
					SharedSecret struct {
						Cachemiss string `json:"cachemiss"`
					} `json:"shared_secret"`
					Replay string `json:"replay"`
				} `json:"dnscrypt"`
				Authzone struct {
					Up   string `json:"up"`
					Down string `json:"down"`
				} `json:"authzone"`
			} `json:"query"`
			Answer struct {
				Rcode struct {
					Noerror  string `json:"NOERROR"`
					Formerr  string `json:"FORMERR"`
					Servfail string `json:"SERVFAIL"`
					Nxdomain string `json:"NXDOMAIN"`
					Notimpl  string `json:"NOTIMPL"`
					Refused  string `json:"REFUSED"`
					Nodata   string `json:"nodata"`
				} `json:"rcode"`
				Secure string `json:"secure"`
				Bogus  string `json:"bogus"`
			} `json:"answer"`
			Rrset struct {
				Bogus string `json:"bogus"`
			} `json:"rrset"`
		} `json:"num"`
		Unwanted *struct {
			Queries string `json:"queries"`
			Replies string `json:"replies"`
		} `json:"unwanted"`
		Msg *struct {
			Cache struct {
				Count         string `json:"count"`
				MaxCollisions string `json:"max_collisions"`
			} `json:"cache"`
		} `json:"msg"`
		Rrset *struct {
			Cache struct {
				Count         string `json:"count"`
				MaxCollisions string `json:"max_collisions"`
			} `json:"cache"`
		} `json:"rrset"`
		Infra *struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"infra"`
		Key *struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"key"`
		DnscryptSharedSecret *struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"dnscrypt_shared_secret"`
		DnscryptNonce *struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"dnscrypt_nonce"`
	} `json:"data"`
}

type UnboundDNSOverview struct {
	// Present is false when unbound-control could not be reached: OPNsense's
	// statsAction() returns HTTP 200 {"status":"failed"} with no data key when
	// Unbound is stopped/restarting or disabled (e.g. dnsmasq-only boxes). The
	// collector gates all stats series on this so it never emits ~60 zero-valued
	// counters that read as real zero-traffic and corrupt rate() (#90).
	Present bool

	// ExtendedPresent is false when the box serves only unbound's BASE statistics:
	// OPNsense 26.7 ships the resolver with `extended-statistics: no` (26.1 had it
	// on), so data.num / data.mem / data.msg / data.rrset / data.infra / data.key /
	// data.unwanted are simply absent from the stats payload. The collector gates
	// every extended-sourced series on this so those absent stats are never emitted
	// as zeros — ~40 zero-valued counters/gauges that read as real zero-traffic and
	// corrupt rate() (same failure class as Present, #90). Presence-gating, not
	// removal: re-enabling extended-statistics brings all of them back.
	ExtendedPresent bool

	UptimeSeconds float64

	// Query totals (from data.total.num)
	QueriesTotal         int64
	CacheHits            int64
	CacheMiss            int64
	Prefetch             int64
	QueriesTimedOut      int64
	ExpiredTotal         int64
	RecursiveReplies     int64
	QueriesIPRateLimited int64

	// Query types (from data.num.query.type) - map label->count
	QueryTypesByType map[string]int64

	// Query protocols
	QueryTCP    int64
	QueryTCPOut int64
	QueryUDPOut int64
	QueryTLS    int64
	QueryIPv6   int64
	QueryHTTPS  int64

	// Answer rcodes - map label->count
	AnswerRcodesByRcode map[string]int64

	// DNSSEC
	AnswerSecureTotal int64
	AnswerBogusTotal  int64
	RrsetBogusTotal   int64

	// Cache entry counts
	CacheRrsetCount   int64
	CacheMessageCount int64
	CacheInfraCount   int64
	CacheKeyCount     int64

	// Memory in bytes
	MemCacheRrset   int64
	MemCacheMessage int64
	MemModIterator  int64
	MemModValidator int64
	MemModRespip    int64
	MemStreamwait   int64

	// Request list
	RequestListAvg         float64
	RequestListMax         int64
	RequestListOverwritten int64
	RequestListExceeded    int64
	RequestListCurrentAll  int64
	RequestListCurrentUser int64

	// Recursion time
	RecursionTimeAvg    float64
	RecursionTimeMedian float64

	// TCP usage
	TCPUsage float64

	// Query flags - map label->count
	FlagsByFlag map[string]int64

	// EDNS
	EdnsPresent int64
	EdnsDO      int64

	// Unwanted
	UnwantedQueries int64
	UnwantedReplies int64
}

func (c *Client) FetchUnboundOverview() (UnboundDNSOverview, *APICallError) {
	var (
		response unboundDNSStatusResponse
		data     UnboundDNSOverview
	)

	url, ok := c.endpoints["unboundDNSStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "unboundDNSStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	if err := c.do("GET", url, nil, &response); err != nil {
		return data, err
	}

	// statsAction() returns HTTP 200 {"status":"failed"} (no data key) when
	// unbound-control is unreachable — Unbound stopped/restarting, or disabled on
	// a dnsmasq-only box. Treat anything other than "ok" as "no stats this scrape"
	// (Present stays false) so the collector skips the whole stats set instead of
	// emitting zeros (#90).
	if response.Status != "ok" {
		return data, nil
	}
	data.Present = true

	// Uptime — use tolerant helper so empty/invalid values (e.g. during restart) return 0
	data.UptimeSeconds = safeParseFloat(response.Data.Time.Up)

	// Query totals
	data.QueriesTotal = safeAtoi(response.Data.Total.Num.Queries)
	data.CacheHits = safeAtoi(response.Data.Total.Num.Cachehits)
	data.CacheMiss = safeAtoi(response.Data.Total.Num.Cachemiss)
	data.Prefetch = safeAtoi(response.Data.Total.Num.Prefetch)
	data.QueriesTimedOut = safeAtoi(response.Data.Total.Num.QueriesTimedOut)
	data.ExpiredTotal = safeAtoi(response.Data.Total.Num.Expired)
	data.RecursiveReplies = safeAtoi(response.Data.Total.Num.Recursivereplies)
	data.QueriesIPRateLimited = safeAtoi(response.Data.Total.Num.QueriesIPRatelimited)

	// Extended statistics (data.num / data.mem / …) are absent on a box running
	// with `extended-statistics: no` — the 26.7 default. Flag their presence so the
	// collector can skip the series they feed instead of publishing them as zeros,
	// and nil-guard every section below so an absent one leaves its fields at zero.
	data.ExtendedPresent = response.Data.Num != nil || response.Data.Mem != nil

	if num := response.Data.Num; num != nil {
		// Query types — capture every RR type the API reported (dynamic key set), so
		// nothing is silently dropped for want of a named struct field (#138).
		data.QueryTypesByType = make(map[string]int64, len(num.Query.Type))
		for rrType, count := range num.Query.Type {
			data.QueryTypesByType[rrType] = safeAtoi(count)
		}

		// Query protocols
		data.QueryTCP = safeAtoi(num.Query.TCP)
		data.QueryTCPOut = safeAtoi(num.Query.Tcpout)
		data.QueryUDPOut = safeAtoi(num.Query.Udpout)
		data.QueryTLS = safeAtoi(num.Query.TLS.Value)
		data.QueryIPv6 = safeAtoi(num.Query.Ipv6)
		data.QueryHTTPS = safeAtoi(num.Query.HTTPS)

		// Answer rcodes
		data.AnswerRcodesByRcode = map[string]int64{
			"NOERROR":  safeAtoi(num.Answer.Rcode.Noerror),
			"FORMERR":  safeAtoi(num.Answer.Rcode.Formerr),
			"SERVFAIL": safeAtoi(num.Answer.Rcode.Servfail),
			"NXDOMAIN": safeAtoi(num.Answer.Rcode.Nxdomain),
			"NOTIMPL":  safeAtoi(num.Answer.Rcode.Notimpl),
			"REFUSED":  safeAtoi(num.Answer.Rcode.Refused),
			"nodata":   safeAtoi(num.Answer.Rcode.Nodata),
		}

		// DNSSEC
		data.AnswerSecureTotal = safeAtoi(num.Answer.Secure)
		data.AnswerBogusTotal = safeAtoi(num.Answer.Bogus)
		data.RrsetBogusTotal = safeAtoi(num.Rrset.Bogus)

		// Query flags
		data.FlagsByFlag = map[string]int64{
			"QR": safeAtoi(num.Query.Flags.Qr),
			"AA": safeAtoi(num.Query.Flags.Aa),
			"TC": safeAtoi(num.Query.Flags.Tc),
			"RD": safeAtoi(num.Query.Flags.Rd),
			"RA": safeAtoi(num.Query.Flags.Ra),
			"Z":  safeAtoi(num.Query.Flags.Z),
			"AD": safeAtoi(num.Query.Flags.Ad),
			"CD": safeAtoi(num.Query.Flags.Cd),
		}

		// EDNS
		data.EdnsPresent = safeAtoi(num.Query.Edns.Present)
		data.EdnsDO = safeAtoi(num.Query.Edns.Do)
	}

	// Cache entry counts
	if rrset := response.Data.Rrset; rrset != nil {
		data.CacheRrsetCount = safeAtoi(rrset.Cache.Count)
	}
	if msg := response.Data.Msg; msg != nil {
		data.CacheMessageCount = safeAtoi(msg.Cache.Count)
	}
	if infra := response.Data.Infra; infra != nil {
		data.CacheInfraCount = safeAtoi(infra.Cache.Count)
	}
	if key := response.Data.Key; key != nil {
		data.CacheKeyCount = safeAtoi(key.Cache.Count)
	}

	// Memory in bytes
	if mem := response.Data.Mem; mem != nil {
		data.MemCacheRrset = safeAtoi(mem.Cache.Rrset)
		data.MemCacheMessage = safeAtoi(mem.Cache.Message)
		data.MemModIterator = safeAtoi(mem.Mod.Iterator)
		data.MemModValidator = safeAtoi(mem.Mod.Validator)
		data.MemModRespip = safeAtoi(mem.Mod.Respip)
		data.MemStreamwait = safeAtoi(mem.Streamwait)
	}

	// Unwanted
	if unwanted := response.Data.Unwanted; unwanted != nil {
		data.UnwantedQueries = safeAtoi(unwanted.Queries)
		data.UnwantedReplies = safeAtoi(unwanted.Replies)
	}

	// Request list
	data.RequestListAvg = safeParseFloat(response.Data.Total.Requestlist.Avg)
	data.RequestListMax = safeAtoi(response.Data.Total.Requestlist.Max)
	data.RequestListOverwritten = safeAtoi(response.Data.Total.Requestlist.Overwritten)
	data.RequestListExceeded = safeAtoi(response.Data.Total.Requestlist.Exceeded)
	data.RequestListCurrentAll = safeAtoi(response.Data.Total.Requestlist.Current.All)
	data.RequestListCurrentUser = safeAtoi(response.Data.Total.Requestlist.Current.User)

	// Recursion time
	data.RecursionTimeAvg = safeParseFloat(response.Data.Total.Recursion.Time.Avg)
	data.RecursionTimeMedian = safeParseFloat(response.Data.Total.Recursion.Time.Median)

	// TCP usage
	data.TCPUsage = safeParseFloat(response.Data.Total.Tcpusage)

	return data, nil
}

// unboundInfraResponse is the JSON returned by api/unbound/diagnostics/dumpinfra.
// Numeric values arrive as strings; only the fields we export are modelled.
type unboundInfraResponse struct {
	Status string `json:"status"`
	Data   []struct {
		IP   string `json:"ip"`
		Host string `json:"host"`
		RTT  string `json:"rtt"`
		RTO  string `json:"rto"`
	} `json:"data"`
}

// UnboundInfraHost is one entry of Unbound's infra cache (one upstream
// server IP / zone pair) with its smoothed RTT and retransmission timeout.
type UnboundInfraHost struct {
	IP              string
	Host            string
	RTTMilliseconds float64
	RTOMilliseconds float64
}

// UnboundInfra holds the parsed dumpinfra output. The number of entries
// scales with the resolver's infra cache (infra-cache-numhosts, default
// 10000 on recursive resolvers), which is why the corresponding collector
// metrics are opt-in.
type UnboundInfra struct {
	Hosts []UnboundInfraHost
}

// FetchUnboundInfra calls api/unbound/diagnostics/dumpinfra and returns
// per-upstream RTT/RTO data from Unbound's infra cache.
func (c *Client) FetchUnboundInfra() (UnboundInfra, *APICallError) {
	var resp unboundInfraResponse
	var data UnboundInfra

	url, ok := c.endpoints["unboundInfra"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "unboundInfra",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, h := range resp.Data {
		data.Hosts = append(data.Hosts, UnboundInfraHost{
			IP:              h.IP,
			Host:            h.Host,
			RTTMilliseconds: safeParseFloat(h.RTT),
			RTOMilliseconds: safeParseFloat(h.RTO),
		})
	}

	return data, nil
}

// unboundPolicyEntry is one dnsbl policy from the get_policies response,
// keyed by policy UUID. Only the enabled flag is needed here; the model's
// BooleanField serializes it as the string "1"/"0" (via getNodeContent()'s
// getValue(), not a native JSON boolean), so this uses flexBool rather than
// a plain bool.
type unboundPolicyEntry struct {
	Enabled flexBool `json:"enabled"`
}

// unboundPoliciesResponse is the api/unbound/overview/get_policies payload: a
// PHP associative array keyed by policy UUID. Like subsystemMap
// (health_check.go), an empty PHP array serializes as JSON "[]" rather than
// "{}" — verified against a live OPNsense 26.7-devel box with no dnsbl
// policies configured — so this type tolerates that shape as "no policies".
type unboundPoliciesResponse map[string]unboundPolicyEntry

// UnmarshalJSON implements json.Unmarshaler.
func (m *unboundPoliciesResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] == '[' || string(trimmed) == "null" {
		*m = nil
		return nil
	}
	var raw map[string]unboundPolicyEntry
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*m = raw
	return nil
}

// FetchUnboundBlockListStatus reports whether any Unbound DNS blocklist
// (dnsbl) policy is enabled. It calls api/unbound/overview/get_policies —
// the replacement for the deprecated isBlockListEnabled endpoint, which OPNsense
// core removes in 26.7 (#210) — and derives the same "any policy enabled"
// result the old endpoint computed server-side
// (array_filter($nodes, fn($v) => $v['enabled'])). get_policies is a core
// (non-plugin-gated) endpoint present across the whole 26.1/26.7 support
// window, so no legacy fallback is needed.
func (c *Client) FetchUnboundBlockListStatus() (bool, *APICallError) {
	var resp unboundPoliciesResponse

	url, ok := c.endpoints["unboundBlocklistPolicies"]
	if !ok {
		return false, &APICallError{
			Endpoint:   "unboundBlocklistPolicies",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return false, err
	}

	for _, policy := range resp {
		if policy.Enabled.Bool() {
			return true, nil
		}
	}

	return false, nil
}

// unboundIsEnabledResponse is the api/unbound/overview/is_enabled payload:
// whether Unbound's query-stats logging (general.stats) is on. Serialized as
// the string "1"/"0" (verified against a live OPNsense 26.7-devel box), so
// this uses flexBool rather than a plain bool.
type unboundIsEnabledResponse struct {
	Enabled flexBool `json:"enabled"`
}

// unboundOverviewTotalsResponse is the api/unbound/overview/totals/{max}
// payload — a flat object, not the {"status":"ok","data":...} envelope used
// by the diagnostics/* endpoints. total, blocklist_size and start_time arrive
// as JSON numbers on the validated box; flexInt tolerates a string
// representation too, matching the tolerant-reader convention used
// everywhere else numeric fields cross OPNsense API generations.
//
// top/top_blocked are intentionally NOT modelled: they are per-domain query
// counts keyed by domain name, which is unbounded cardinality (#209) — never
// turn them into metrics or struct fields, and see
// testdata/schemas/exemptions.json for the matching knownExtraTopKeys entry.
type unboundOverviewTotalsResponse struct {
	Total         flexInt `json:"total"`
	BlocklistSize flexInt `json:"blocklist_size"`
	Passed        flexInt `json:"passed"`
	Resolved      struct {
		Total flexInt `json:"total"`
	} `json:"resolved"`
	Blocked struct {
		Total flexInt `json:"total"`
	} `json:"blocked"`
	Local struct {
		Total flexInt `json:"total"`
	} `json:"local"`
	StartTime flexInt `json:"start_time"`
}

// UnboundQueryStats holds the DNSBL query-stats totals reported by Unbound's
// overview/totals backend, plus the loaded blocklist size. This is a
// DIFFERENT data source from unbound-control's stats (UnboundDNSOverview
// above): dnsbl blocking happens in OPNsense's own python dnsbl module, so
// these are the only numbers that show blocked-vs-passed-vs-local-vs-resolved
// outcomes and the loaded blocklist size.
//
// CRITICAL — every count here is a GAUGE, never a counter. logger.py
// truncates the underlying query table to a rolling 7-day window (hourly
// DELETE) and a `qstats reset` truncates it entirely, so these totals can and
// do decrease — a counter would read that as a phantom reset (#227).
//
// The backend is expensive: configd spawns python+pandas+DuckDB per call
// (~1s), so callers should only fetch this when explicitly opted in
// (--exporter.enable-unbound-qstats) and should treat Enabled=false as a
// signal to skip the call entirely rather than pay for it — see
// FetchUnboundQueryStats.
type UnboundQueryStats struct {
	// Enabled reports whether Unbound's query-stats logging (general.stats) is
	// on, from the cheap api/unbound/overview/is_enabled config read.
	Enabled bool

	// TotalsPresent is true only when the expensive totals call was actually
	// made and succeeded (i.e. Enabled was true). When false, every field below
	// is zero and must NOT be published as a metric — the #90 lesson: a zero
	// derived from a call we chose not to make reads as real zero-traffic and
	// corrupts rate()/analysis downstream, even though these series are gauges.
	TotalsPresent bool

	// QueriesTotal7d is the overall query count over the rolling window (the
	// payload's top-level "total").
	QueriesTotal7d int64

	// BlocklistSize is the number of entries in the currently loaded DNSBL
	// blocklist (0 when no blocklist is loaded).
	BlocklistSize int64

	// Outcome breakdown over the rolling window.
	PassedTotal7d   int64
	ResolvedTotal7d int64
	BlockedTotal7d  int64
	LocalTotal7d    int64

	// StartTimeSeconds is the unix timestamp the rolling-window data starts
	// from. A jump forward (other than the expected daily roll-off) signals the
	// underlying qstats database was reset.
	StartTimeSeconds int64
}

// FetchUnboundQueryStats reports Unbound DNSBL query-stats totals and the
// loaded blocklist size (#209). It first makes the cheap is_enabled config
// read; only when query-stats logging is on does it pay for the expensive
// totals call (configd + python + pandas + DuckDB, ~1s). This mirrors what
// OPNsense's own UI does and avoids spending the expensive call merely to
// discover stats are off — verified against a live OPNsense 26.7-devel box:
// the totals endpoint itself does NOT self-gate on is_enabled (it still
// returns the full historical rolling-window payload from existing DuckDB
// rows when general.stats is off), so the caller must check is_enabled first.
func (c *Client) FetchUnboundQueryStats() (UnboundQueryStats, *APICallError) {
	var data UnboundQueryStats

	enabledURL, ok := c.endpoints["unboundQueryStatsEnabled"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "unboundQueryStatsEnabled",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	var enabledResp unboundIsEnabledResponse
	if err := c.do("GET", enabledURL, nil, &enabledResp); err != nil {
		return data, err
	}
	data.Enabled = enabledResp.Enabled.Bool()
	if !data.Enabled {
		return data, nil
	}

	totalsURL, ok := c.endpoints["unboundQueryStatsTotals"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "unboundQueryStatsTotals",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	var totals unboundOverviewTotalsResponse
	if err := c.do("GET", totalsURL, nil, &totals); err != nil {
		return data, err
	}

	data.TotalsPresent = true
	data.QueriesTotal7d = int64(totals.Total.Int())
	data.BlocklistSize = int64(totals.BlocklistSize.Int())
	data.PassedTotal7d = int64(totals.Passed.Int())
	data.ResolvedTotal7d = int64(totals.Resolved.Total.Int())
	data.BlockedTotal7d = int64(totals.Blocked.Total.Int())
	data.LocalTotal7d = int64(totals.Local.Total.Int())
	data.StartTimeSeconds = int64(totals.StartTime.Int())

	return data, nil
}

// unboundLocalZonesResponse is the api/unbound/diagnostics/listlocalzones
// payload: the standard {"status":"ok","data":[...]} diagnostics envelope
// wrapping unbound-control's `list_local_zones` output.
type unboundLocalZonesResponse struct {
	Status string `json:"status"`
	Data   []struct {
		Zone string `json:"zone"`
		Type string `json:"type"`
	} `json:"data"`
}

// unboundLocalDataResponse is the api/unbound/diagnostics/listlocaldata
// payload wrapping unbound-control's `list_local_data` output. Only the
// record count is exported; per-record name/value are unbounded cardinality.
type unboundLocalDataResponse struct {
	Status string `json:"status"`
	Data   []struct {
		Name   string `json:"name"`
		TTL    string `json:"ttl"`
		Type   string `json:"type"`
		RRType string `json:"rrtype"`
		Value  string `json:"value"`
	} `json:"data"`
}

// unboundInsecureDomainsResponse is the api/unbound/diagnostics/listinsecure
// payload wrapping unbound-control's `list_insecure` output: a plain list of
// domain names. Verified against a live OPNsense 26.7-devel box with no
// insecure domains configured: the degenerate shape is {"data":[""]} — one
// empty-string entry, not a truly empty array — so a naive len(Data) would
// overcount "0 insecure domains configured" as 1.
type unboundInsecureDomainsResponse struct {
	Status string   `json:"status"`
	Data   []string `json:"data"`
}

// UnboundLocalData holds counts derived from Unbound's local-zone, local-data
// and insecure-domain diagnostics — the #209 "rider" data. Unlike
// UnboundQueryStats these are cheap unbound-control commands, not the
// DuckDB-backed qstats backend, and are wholly slow-moving configuration
// (ideal --exporter.cache-ttl response-cache candidates). They are still
// gated behind the same --exporter.enable-unbound-qstats flag as the qstats
// metrics because, like qstats, they cost an extra API call per scrape.
type UnboundLocalData struct {
	// ZonesByType counts configured local zones grouped by zone type (e.g.
	// "static", "transparent", "redirect" — a small, fixed enum, not the zone
	// names themselves, so cardinality stays bounded).
	ZonesByType map[string]int64

	// LocalDataRecords is the total number of local-data resource records
	// configured, aggregated (per-record name/value are unbounded cardinality
	// and are never exported, per the issue's no-per-domain-labels constraint).
	LocalDataRecords int64

	// InsecureDomains is the number of domains configured as DNSSEC-insecure.
	// The degenerate single-empty-string shape (see
	// unboundInsecureDomainsResponse) is treated as zero.
	InsecureDomains int64
}

// FetchUnboundLocalData calls Unbound's listlocalzones/listlocaldata/listinsecure
// diagnostics endpoints and returns aggregated counts (#209 rider data). The
// three sub-fetches are independent GETs writing disjoint fields, so they run
// concurrently (#129); a failure on one does not block the others — partial
// data is returned along with the first error encountered, matching the
// tolerant-partial-failure convention used by FetchPFStatistics.
func (c *Client) FetchUnboundLocalData() (UnboundLocalData, *APICallError) {
	data := UnboundLocalData{ZonesByType: make(map[string]int64)}

	fetchZones := func() *APICallError {
		url, ok := c.endpoints["unboundLocalZones"]
		if !ok {
			return &APICallError{Endpoint: "unboundLocalZones", Message: "endpoint not found in client endpoints"}
		}
		var resp unboundLocalZonesResponse
		if err := c.do("GET", url, nil, &resp); err != nil {
			return err
		}
		for _, z := range resp.Data {
			data.ZonesByType[z.Type]++
		}
		return nil
	}

	fetchLocalData := func() *APICallError {
		url, ok := c.endpoints["unboundLocalData"]
		if !ok {
			return &APICallError{Endpoint: "unboundLocalData", Message: "endpoint not found in client endpoints"}
		}
		var resp unboundLocalDataResponse
		if err := c.do("GET", url, nil, &resp); err != nil {
			return err
		}
		data.LocalDataRecords = int64(len(resp.Data))
		return nil
	}

	fetchInsecure := func() *APICallError {
		url, ok := c.endpoints["unboundInsecureDomains"]
		if !ok {
			return &APICallError{Endpoint: "unboundInsecureDomains", Message: "endpoint not found in client endpoints"}
		}
		var resp unboundInsecureDomainsResponse
		if err := c.do("GET", url, nil, &resp); err != nil {
			return err
		}
		var count int64
		for _, d := range resp.Data {
			if d != "" {
				count++
			}
		}
		data.InsecureDomains = count
		return nil
	}

	errs := runConcurrentFetches(fetchZones, fetchLocalData, fetchInsecure)
	for _, err := range errs {
		if err != nil {
			return data, err
		}
	}

	return data, nil
}
