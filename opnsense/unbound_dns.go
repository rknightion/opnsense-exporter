package opnsense

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
		Mem struct {
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
		Num struct {
			Query struct {
				Type struct {
					A      string `json:"A"`
					Soa    string `json:"SOA"`
					Ptr    string `json:"PTR"`
					Mx     string `json:"MX"`
					Txt    string `json:"TXT"`
					Aaaa   string `json:"AAAA"`
					Srv    string `json:"SRV"`
					Svcb   string `json:"SVCB"`
					HTTPS  string `json:"HTTPS"`
					NS     string `json:"NS"`
					CNAME  string `json:"CNAME"`
					NAPTR  string `json:"NAPTR"`
					DNSKEY string `json:"DNSKEY"`
					ANY    string `json:"ANY"`
					LOC    string `json:"LOC"`
					HINFO  string `json:"HINFO"`
				} `json:"type"`
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
		Unwanted struct {
			Queries string `json:"queries"`
			Replies string `json:"replies"`
		} `json:"unwanted"`
		Msg struct {
			Cache struct {
				Count         string `json:"count"`
				MaxCollisions string `json:"max_collisions"`
			} `json:"cache"`
		} `json:"msg"`
		Rrset struct {
			Cache struct {
				Count         string `json:"count"`
				MaxCollisions string `json:"max_collisions"`
			} `json:"cache"`
		} `json:"rrset"`
		Infra struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"infra"`
		Key struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"key"`
		DnscryptSharedSecret struct {
			Cache struct {
				Count string `json:"count"`
			} `json:"cache"`
		} `json:"dnscrypt_shared_secret"`
		DnscryptNonce struct {
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

	// Query types
	data.QueryTypesByType = map[string]int64{
		"A":      safeAtoi(response.Data.Num.Query.Type.A),
		"AAAA":   safeAtoi(response.Data.Num.Query.Type.Aaaa),
		"SOA":    safeAtoi(response.Data.Num.Query.Type.Soa),
		"PTR":    safeAtoi(response.Data.Num.Query.Type.Ptr),
		"MX":     safeAtoi(response.Data.Num.Query.Type.Mx),
		"TXT":    safeAtoi(response.Data.Num.Query.Type.Txt),
		"SRV":    safeAtoi(response.Data.Num.Query.Type.Srv),
		"SVCB":   safeAtoi(response.Data.Num.Query.Type.Svcb),
		"HTTPS":  safeAtoi(response.Data.Num.Query.Type.HTTPS),
		"NS":     safeAtoi(response.Data.Num.Query.Type.NS),
		"CNAME":  safeAtoi(response.Data.Num.Query.Type.CNAME),
		"NAPTR":  safeAtoi(response.Data.Num.Query.Type.NAPTR),
		"DNSKEY": safeAtoi(response.Data.Num.Query.Type.DNSKEY),
		"ANY":    safeAtoi(response.Data.Num.Query.Type.ANY),
	}

	// Query protocols
	data.QueryTCP = safeAtoi(response.Data.Num.Query.TCP)
	data.QueryTCPOut = safeAtoi(response.Data.Num.Query.Tcpout)
	data.QueryUDPOut = safeAtoi(response.Data.Num.Query.Udpout)
	data.QueryTLS = safeAtoi(response.Data.Num.Query.TLS.Value)
	data.QueryIPv6 = safeAtoi(response.Data.Num.Query.Ipv6)
	data.QueryHTTPS = safeAtoi(response.Data.Num.Query.HTTPS)

	// Answer rcodes
	data.AnswerRcodesByRcode = map[string]int64{
		"NOERROR":  safeAtoi(response.Data.Num.Answer.Rcode.Noerror),
		"FORMERR":  safeAtoi(response.Data.Num.Answer.Rcode.Formerr),
		"SERVFAIL": safeAtoi(response.Data.Num.Answer.Rcode.Servfail),
		"NXDOMAIN": safeAtoi(response.Data.Num.Answer.Rcode.Nxdomain),
		"NOTIMPL":  safeAtoi(response.Data.Num.Answer.Rcode.Notimpl),
		"REFUSED":  safeAtoi(response.Data.Num.Answer.Rcode.Refused),
		"nodata":   safeAtoi(response.Data.Num.Answer.Rcode.Nodata),
	}

	// DNSSEC
	data.AnswerSecureTotal = safeAtoi(response.Data.Num.Answer.Secure)
	data.AnswerBogusTotal = safeAtoi(response.Data.Num.Answer.Bogus)
	data.RrsetBogusTotal = safeAtoi(response.Data.Num.Rrset.Bogus)

	// Cache entry counts
	data.CacheRrsetCount = safeAtoi(response.Data.Rrset.Cache.Count)
	data.CacheMessageCount = safeAtoi(response.Data.Msg.Cache.Count)
	data.CacheInfraCount = safeAtoi(response.Data.Infra.Cache.Count)
	data.CacheKeyCount = safeAtoi(response.Data.Key.Cache.Count)

	// Memory in bytes
	data.MemCacheRrset = safeAtoi(response.Data.Mem.Cache.Rrset)
	data.MemCacheMessage = safeAtoi(response.Data.Mem.Cache.Message)
	data.MemModIterator = safeAtoi(response.Data.Mem.Mod.Iterator)
	data.MemModValidator = safeAtoi(response.Data.Mem.Mod.Validator)
	data.MemModRespip = safeAtoi(response.Data.Mem.Mod.Respip)
	data.MemStreamwait = safeAtoi(response.Data.Mem.Streamwait)

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

	// Query flags
	data.FlagsByFlag = map[string]int64{
		"QR": safeAtoi(response.Data.Num.Query.Flags.Qr),
		"AA": safeAtoi(response.Data.Num.Query.Flags.Aa),
		"TC": safeAtoi(response.Data.Num.Query.Flags.Tc),
		"RD": safeAtoi(response.Data.Num.Query.Flags.Rd),
		"RA": safeAtoi(response.Data.Num.Query.Flags.Ra),
		"Z":  safeAtoi(response.Data.Num.Query.Flags.Z),
		"AD": safeAtoi(response.Data.Num.Query.Flags.Ad),
		"CD": safeAtoi(response.Data.Num.Query.Flags.Cd),
	}

	// EDNS
	data.EdnsPresent = safeAtoi(response.Data.Num.Query.Edns.Present)
	data.EdnsDO = safeAtoi(response.Data.Num.Query.Edns.Do)

	// Unwanted
	data.UnwantedQueries = safeAtoi(response.Data.Unwanted.Queries)
	data.UnwantedReplies = safeAtoi(response.Data.Unwanted.Replies)

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

type unboundBlockListResponse struct {
	Enabled bool `json:"enabled"`
}

// FetchUnboundBlockListStatus checks if the Unbound DNS blocklist is enabled
func (c *Client) FetchUnboundBlockListStatus() (bool, *APICallError) {
	var resp unboundBlockListResponse

	url, ok := c.endpoints["unboundBlockList"]
	if !ok {
		return false, &APICallError{
			Endpoint:   "unboundBlockList",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return false, err
	}

	return resp.Enabled, nil
}
