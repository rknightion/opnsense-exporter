package opnsense

import (
	"bytes"
	"encoding/json"
	"sort"
)

// unboundHistogramBucket is one bucket of unbound's reply-time histogram, in the
// shape OPNsense's wrapper.py reshapes it into. unbound-control emits the
// histogram as 40 flat keys
//
//	histogram.<from_sec>.<from_usec>.to.<to_sec>.<to_usec>=<count>
//
// and wrapper.py special-cases that prefix into an ARRAY of {from,to,value}
// objects instead of folding it into the dotted-key tree the rest of the payload
// uses (src/opnsense/scripts/unbound/wrapper.py, the args.stats branch). from and
// to are python tuples, so they arrive as two-element JSON arrays of [seconds,
// microseconds]; value is that bucket's own count, as a string.
//
// THE COUNTS ARE NOT CUMULATIVE ON THE WIRE — each bucket holds only its own
// observations, which is the opposite of what a Prometheus _bucket series means.
// buildUnboundRecursionHistogram is what accumulates them.
type unboundHistogramBucket struct {
	From  []flexInt `json:"from"`
	To    []flexInt `json:"to"`
	Value flexInt   `json:"value"`
}

// UnboundRecursionHistogram is unbound's reply-time histogram in the exact shape
// prometheus.MustNewConstHistogram consumes: Buckets maps each finite upper bound
// (in seconds) to the CUMULATIVE count at or below it, and Count is the implicit
// +Inf bucket. unbound's top bucket ends at 2^19 seconds, so nothing can land past
// the last finite bound and Count always equals the top cumulative bucket.
//
// Present is false when the box did not report data.histogram at all — the OPNsense
// 26.7 default, `extended-statistics: no`. That is BOX STATE, not drift, and the
// metric simply does not exist there. Synthesising 40 empty buckets instead would
// be strictly worse than no metric: it publishes a sub-microsecond p99 for a
// resolver nobody is actually measuring.
//
// SUM IS RECONSTRUCTED, AND THAT IS SOUND RATHER THAN A GUESS. unbound never prints
// its accumulated wait total; it prints the MEAN,
// total.recursion.time.avg = mesh->replies_sum_wait / mesh->replies_sent
// (daemon/remote.c print_stats, via timeval_divide). Multiplying that mean back by
// the histogram's own count inverts exactly that division, so this is algebra on
// two numbers describing one population, not an estimate — mesh_send_reply
// increments replies_sent, adds the duration into replies_sum_wait and inserts it
// into the histogram in three consecutive statements (services/mesh.c), and the
// histogram insert is NOT gated on stat_extended, only its printing is. The single
// loss is unbound printing the mean at microsecond resolution, which caps the error
// at half a microsecond per observation.
//
// Emitting Sum as 0 instead was rejected: rate(_sum)/rate(_count) would then read a
// flat zero-second average latency, a lie with no tell. Dropping the histogram for
// want of a sum was rejected too — histogram_quantile() never reads _sum.
type UnboundRecursionHistogram struct {
	Present bool
	Count   uint64
	Sum     float64
	Buckets map[float64]uint64
}

// buildUnboundRecursionHistogram turns unbound's per-bucket counts into cumulative
// ones and reconstructs the sum from the mean. avgSeconds is
// data.total.recursion.time.avg.
func buildUnboundRecursionHistogram(raw []unboundHistogramBucket, avgSeconds float64) UnboundRecursionHistogram {
	type bound struct {
		ge, le float64
		count  uint64
	}
	bounds := make([]bound, 0, len(raw))
	for _, b := range raw {
		le, ok := unboundHistogramUpperBound(b.To)
		if !ok {
			return UnboundRecursionHistogram{}
		}
		ge, ok := unboundHistogramUpperBound(b.From)
		if !ok {
			return UnboundRecursionHistogram{}
		}
		n := b.Value.Int()
		if n < 0 {
			n = 0
		}
		bounds = append(bounds, bound{ge: ge, le: le, count: uint64(n)})
	}
	if len(bounds) == 0 {
		return UnboundRecursionHistogram{}
	}

	// Accumulate in upper-bound order, never wire order. unbound prints ascending
	// today, so folding in wire order passes against every real payload and would
	// go wrong SILENTLY the day upstream reorders: the resulting _bucket series
	// still parses, still has monotonicity Prometheus never checks, and still
	// answers histogram_quantile() — with garbage.
	sort.Slice(bounds, func(i, j int) bool { return bounds[i].le < bounds[j].le })

	// The buckets must TILE — each one's lower bound is the previous one's upper
	// bound, which is what makes a running sum over them the count "at or below
	// this le" that a Prometheus _bucket series means. That is why `from` is read
	// at all: it is redundant on a well-formed payload and is exactly the thing
	// that stops being redundant if upstream ever reshapes the histogram (a
	// coarser bucket set, or a set that no longer starts at zero). A gap or an
	// overlap makes every cumulative count and therefore every quantile wrong, and
	// nothing downstream could tell — so refuse the whole histogram instead. No
	// metric is a visible absence; a plausible wrong p99 is not.
	if bounds[0].ge != 0 {
		return UnboundRecursionHistogram{}
	}
	for i := 1; i < len(bounds); i++ {
		if bounds[i].ge != bounds[i-1].le {
			return UnboundRecursionHistogram{}
		}
	}

	out := UnboundRecursionHistogram{Present: true, Buckets: make(map[float64]uint64, len(bounds))}
	var cum uint64
	for _, b := range bounds {
		cum += b.count
		out.Buckets[b.le] = cum
	}
	out.Count = cum
	out.Sum = avgSeconds * float64(cum)
	return out
}

// unboundHistogramUpperBound converts a [seconds, microseconds] pair into seconds.
// A pair that is not exactly two elements is refused rather than guessed at: the
// alternative is a bucket silently landing at the wrong `le`, which moves every
// quantile above it.
func unboundHistogramUpperBound(pair []flexInt) (float64, bool) {
	if len(pair) != 2 {
		return 0, false
	}
	return float64(pair[0].Int()) + float64(pair[1].Int())/1e6, true
}

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
				QueriesReplyaddrLimit string `json:"queries_replyaddr_limit"`
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
					All     string `json:"all"`
					User    string `json:"user"`
					Replies string `json:"replies"`
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
			// Valops is unbound's num.valops: RRSIG verification operations attempted,
			// counted regardless of outcome (#581). print_ext writes it unconditionally
			// (unbound daemon/remote.c, immediately after num.rrset.bogus) and
			// stat_inhibit_zero never suppresses it, so its presence tracks
			// `extended-statistics` exactly like the rest of data.num and it needs no
			// presence gate of its own.
			Valops string `json:"valops"`
		} `json:"num"`
		// Histogram is unbound's reply-time histogram, served under the same
		// `extended-statistics: yes` switch as the sections around it: remote.c reaches
		// print_hist only from inside `if(daemon->cfg->stat_extended)`. It needs no
		// pointer to be presence-gated - a nil slice already tells "the box did not
		// report this" apart from "reported as empty".
		Histogram []unboundHistogramBucket `json:"histogram"`
		Unwanted  *struct {
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

	// Query drop/limit counters and error reporting (from data.total.num, #237).
	// These live in unbound's BASE statistics (unlike everything gated on
	// ExtendedPresent), so they populate even with extended-statistics: no — the
	// 26.7 default — and are read unconditionally like their siblings above.
	QueriesDiscardTimeout int64
	QueriesWaitLimit      int64
	QueriesReplyAddrLimit int64
	DNSErrorReports       int64

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

	// ValidationOperations is data.num.valops: RRSIG verifications attempted,
	// counted whether they passed or failed (#581). It is the DENOMINATOR the
	// existing secure/bogus counters lack — a validator doing a lot of work and
	// producing few secure answers is a different problem from one doing none.
	// Extended-statistics sourced, so it rides ExtendedPresent.
	ValidationOperations int64

	// RecursionHistogram is data.histogram: how long recursive lookups took,
	// bucketed (#581). Same extended-statistics gate as the fields above, but it
	// carries its own Present flag rather than borrowing ExtendedPresent — the
	// section is separate on the wire, and gating a histogram on a sibling
	// section's presence is how a fabricated all-zero histogram gets published.
	RecursionHistogram UnboundRecursionHistogram

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
	// RequestListCurrentReplies (#237): base statistic, read unconditionally like
	// RequestListCurrentAll/User above.
	RequestListCurrentReplies int64

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
	data.QueriesDiscardTimeout = safeAtoi(response.Data.Total.Num.QueriesDiscardTimeout)
	data.QueriesWaitLimit = safeAtoi(response.Data.Total.Num.QueriesWaitLimit)
	data.QueriesReplyAddrLimit = safeAtoi(response.Data.Total.Num.QueriesReplyaddrLimit)
	data.DNSErrorReports = safeAtoi(response.Data.Total.Num.DNSErrorReports)

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
		data.ValidationOperations = safeAtoi(num.Valops)

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
	data.RequestListCurrentReplies = safeAtoi(response.Data.Total.Requestlist.Current.Replies)

	// Recursion time
	data.RecursionTimeAvg = safeParseFloat(response.Data.Total.Recursion.Time.Avg)
	data.RecursionTimeMedian = safeParseFloat(response.Data.Total.Recursion.Time.Median)

	// TCP usage
	data.TCPUsage = safeParseFloat(response.Data.Total.Tcpusage)

	// Reply-time histogram. Built last because its reconstructed sum needs the
	// recursion mean parsed just above. A nil/empty data.histogram leaves the
	// zero value, whose Present is false — the box-state path.
	data.RecursionHistogram = buildUnboundRecursionHistogram(
		response.Data.Histogram, data.RecursionTimeAvg)
	if len(response.Data.Histogram) > 0 && !data.RecursionHistogram.Present {
		// Distinguish "the box sent no histogram" (silent, expected, the 26.7
		// default) from "the box sent one we refused to read as a histogram"
		// (loud: it means the payload's shape changed under us).
		c.log.Warn("unbound reply-time histogram buckets do not tile; skipping the histogram",
			"buckets", len(response.Data.Histogram))
	}

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

		// Host-health state (#581). unbound-control dump_infra prints one line per
		// host from a single fixed format string ending
		//
		//	... ednsknown %d edns %d delay %d lame dnssec %d rec %d A %d other %d
		//
		// (unbound daemon/remote.c, dump_infra_host), and wrapper.py pairs each
		// "<key> <value>" into a JSON key.
		//
		// THERE IS DELIBERATELY NO `lame` FIELD HERE AND ADDING ONE WOULD BE A BUG.
		// `lame` in that format string is a bare LITERAL WORD introducing the four
		// lameness values that follow it; it has no operand. wrapper.py special-cases
		// exactly that token (`if key == 'lame': record['lame'] = True`), so every
		// host in every payload carries "lame": true — a healthy forwarder included.
		// A metric fed from it would pin every upstream at 1 forever and read as a
		// total resolution outage. The real state is the four flags below;
		// TestFetchUnboundInfra_LameKeyIsALiteralNotAFlag holds this line.
		DNSSEC flexInt `json:"dnssec"`
		Rec    flexInt `json:"rec"`
		TypeA  flexInt `json:"A"`
		Other  flexInt `json:"other"`

		// EDNS is unbound's cached edns_version for this host and is NOT a boolean.
		// The infra cache initialises it to 0 ("EDNS0 assumed") and only
		// infra_edns_update ever writes -1, unbound's marker for "EDNS queries or
		// replies are dropped in transit to this server" (services/cache/infra.h).
		// A negative value is therefore always a determined probe result and never
		// "not yet probed", which is what makes reading it as a boolean safe without
		// also modelling the ednsknown companion.
		EDNS flexInt `json:"edns"`
	} `json:"data"`
}

// UnboundInfraHost is one entry of Unbound's infra cache (one upstream
// server IP / zone pair) with its smoothed RTT and retransmission timeout.
type UnboundInfraHost struct {
	IP              string
	Host            string
	RTTMilliseconds float64
	RTOMilliseconds float64

	// Health state (#581). These are what makes "resolution is intermittently
	// failing but every RTT looks fine" diagnosable: unbound stops asking a server
	// it has marked lame, so the timing series for that upstream stays healthy
	// precisely because it is no longer being used.
	//
	// The three lameness flags are separate because unbound tracks them separately
	// and they mean different things: a server can serve A records fine and be lame
	// for everything else. DNSSECLame is the fourth and distinct — the server answers
	// the zone but will not serve DNSSEC data for it.
	RecursionLame bool // not authoritative, but sets RA: answers by recursing itself
	TypeALame     bool // not authoritative for A records
	OtherLame     bool // not authoritative for other query types
	DNSSECLame    bool // serves the zone but not its DNSSEC data

	// EDNSBroken is true when unbound has determined EDNS is dropped in transit to
	// this server (edns_version < 0). Distinct from lameness: the server is
	// answering, but every EDNS-bearing exchange with it is being eaten, which
	// silently disables DNSSEC and forces fallbacks.
	EDNSBroken bool
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
			RecursionLame:   h.Rec.Int() != 0,
			TypeALame:       h.TypeA.Int() != 0,
			OtherLame:       h.Other.Int() != 0,
			DNSSECLame:      h.DNSSEC.Int() != 0,
			EDNSBroken:      h.EDNS.Int() < 0,
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
// top/top_blocked ARE modelled as of #587, reversing #209's rejection. That
// rejection ("per-domain query counts keyed by domain name, which is unbounded
// cardinality") was correct for its time and is superseded rather than refuted:
// the bounded-inventory primitive (#474 — hard key cap, last-seen retirement, a
// counted refusal total) did not exist then, and the same primitive now carries an
// equally open, equally adversarial-adjacent set in Zenarmor device names. See
// UnboundTopDomainsMax and the collector's leaderboard inventories.
//
// The derivable fields stay unmodelled. `pcnt` on each row, like the sibling
// blocked/local/resolved `.pcnt`, is the row's count over a total this struct
// already carries — arithmetic, not information.
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
	StartTime  flexInt           `json:"start_time"`
	Top        unboundTopDomains `json:"top"`
	TopBlocked unboundTopDomains `json:"top_blocked"`
}

// UnboundTopDomainsMax is the {max} row limit in the overview/totals endpoint URL
// AND the leaderboard key cap the collector enforces, deliberately the same number
// in one place (#587).
//
// It has to be one constant, not two knobs. {max} binds straight to the backend's
// `LIMIT ?` (src/opnsense/scripts/unbound/stats.py, handle_top), so it is a hard
// ceiling on how many domains can ever reach the exporter — a separately
// configurable in-process cap above this value would be inert while looking
// adjustable, which is the worst shape a cardinality control can have. That is also
// why the cap is a constant rather than a flag: a flag could not raise the ceiling
// without rewriting the endpoint URL, which the response cache, the contract
// manifest and the schema canary all key on.
//
// 512 is #587's decision, and matches maxZenarmorDevices for the same reason: high
// enough that a normal resolver's real working set fits, low enough that a churning
// source cannot grow the series set without bound. TestUnboundQueryStatsTotalsMax-
// MatchesLeaderboardCap pins it against the endpoint URL.
const UnboundTopDomainsMax = 512

// unboundTopDomainEntry is one leaderboard row. Only the count crosses over.
// `pcnt` is derivable; `blocklist`, `latest_policy_uuid` and the controller-added
// `category` describe WHY a domain was blocked and are deliberately left on the
// wire — they are attributes of the domain, not of its count, and per #476 an
// attribute that can change while the entity stays the same entity must never
// become part of a series' identity: a domain moving between blocklists would fork
// into two series and the stale one would sit out its full retirement.
type unboundTopDomainEntry struct {
	Total flexInt `json:"total"`
}

// unboundTopDomains is the by-domain leaderboard map. Like unboundPoliciesResponse
// above it tolerates a JSON array where an object is expected, and for the same
// reason: stats.py emits `{}` for an empty leaderboard, but
// OverviewController::totalsAction round-trips the whole payload through
// json_decode($response, true) — which turns an empty JSON object into an empty PHP
// ARRAY — before it is re-encoded, so an idle box serves "top": []. A plain map
// would fail the decode outright and take every other qstats field down with it.
type unboundTopDomains map[string]unboundTopDomainEntry

// UnmarshalJSON implements json.Unmarshaler.
func (m *unboundTopDomains) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] == '[' || string(trimmed) == "null" {
		*m = nil
		return nil
	}
	var raw map[string]unboundTopDomainEntry
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*m = raw
	return nil
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

	// TopPassedDomains and TopBlockedDomains are the by-domain leaderboards over
	// the same rolling window, each already truncated by the backend to
	// UnboundTopDomainsMax rows (#587). Gauges like everything else here.
	//
	// The two are NOT the same population split two ways: the backend selects
	// `top` over action == 0 (passed) and `top_blocked` over action == 1, so a
	// domain can appear in both — some queries for it passed, some were blocked by
	// a policy that arrived later. Domain keys are unbound's own, which means they
	// carry the trailing root dot ("ads.example."); left exactly as the wire sends
	// them, since stripping it is a transformation that has to be undone by anyone
	// correlating against the raw query log.
	TopPassedDomains  map[string]int64
	TopBlockedDomains map[string]int64
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
	data.TopPassedDomains = flattenUnboundTopDomains(totals.Top)
	data.TopBlockedDomains = flattenUnboundTopDomains(totals.TopBlocked)

	return data, nil
}

// flattenUnboundTopDomains drops each leaderboard row down to its count. A nil or
// empty map yields nil rather than an empty map, so "the box reported no
// leaderboard" and "the box reported an empty one" stay indistinguishable — they
// genuinely are the same thing here, and the caller has one case to handle.
func flattenUnboundTopDomains(rows unboundTopDomains) map[string]int64 {
	if len(rows) == 0 {
		return nil
	}
	out := make(map[string]int64, len(rows))
	for domain, row := range rows {
		out[domain] = int64(row.Total.Int())
	}
	return out
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
