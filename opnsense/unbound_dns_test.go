package opnsense

import (
	"fmt"
	"net/http"
	"testing"
)

// The fixture below is a box with `extended-statistics: yes`, and it carries
// data.num.valops and data.histogram for that reason rather than for the
// assertions: unbound prints all three from the same
// `if(daemon->cfg->stat_extended)` block (daemon/remote.c), so a payload with
// data.num but no histogram is a shape upstream cannot produce, and a fixture that
// encodes an impossible shape is how a parser gets "verified" against nothing.
func TestFetchUnboundOverview_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {
						"queries": "100000",
						"queries_ip_ratelimited": "5",
						"queries_cookie_valid": "0",
						"queries_cookie_client": "0",
						"queries_cookie_invalid": "0",
						"cachehits": "75000",
						"cachemiss": "25000",
						"prefetch": "100",
						"queries_timed_out": "10",
						"expired": "50",
						"recursivereplies": "24000",
						"queries_discard_timeout": "0",
						"queries_wait_limit": "0",
						"dns_error_reports": "0",
						"dnscrypt": {
							"crypted": "0",
							"cert": "0",
							"cleartext": "0",
							"malformed": "0"
						}
					},
					"query": {
						"queue_time_us": {"max": "100"}
					},
					"requestlist": {
						"avg": "1.5",
						"max": "50",
						"overwritten": "2",
						"exceeded": "1",
						"current": {
							"all": "10",
							"user": "5"
						}
					},
					"recursion": {
						"time": {
							"avg": "0.025",
							"median": "0.015"
						}
					},
					"tcpusage": "0.5"
				},
				"time": {
					"now": "1704067200",
					"up": "86400.5",
					"elapsed": "86400.5"
				},
				"mem": {
					"cache": {
						"rrset": "524288",
						"message": "262144",
						"dnscrypt_shared_secret": "0",
						"dnscrypt_nonce": "0"
					},
					"mod": {
						"iterator": "131072",
						"validator": "65536",
						"respip": "0",
						"dynlibmod": "0"
					},
					"streamwait": "0",
					"http": {
						"query_buffer": "0",
						"response_buffer": "0"
					}
				},
				"num": {
					"query": {
						"type": {
							"A": "60000",
							"SOA": "100",
							"PTR": "5000",
							"MX": "200",
							"TXT": "300",
							"AAAA": "30000",
							"SRV": "50",
							"SVCB": "10",
							"HTTPS": "4000",
							"NS": "20",
							"CNAME": "15",
							"NAPTR": "5",
							"DNSKEY": "100",
							"ANY": "0",
							"LOC": "0",
							"HINFO": "0"
						},
						"class": {"IN": "100000"},
						"opcode": {"QUERY": "100000"},
						"tcp": "500",
						"tcpout": "100",
						"udpout": "24000",
						"tls": {"__value__": "200", "resume": "0"},
						"ipv6": "15000",
						"https": "50",
						"flags": {
							"QR": "100000",
							"AA": "0",
							"TC": "5",
							"RD": "100000",
							"RA": "100000",
							"Z": "0",
							"AD": "1000",
							"CD": "0"
						},
						"edns": {"present": "90000", "DO": "5000"},
						"ratelimited": "0",
						"aggressive": {"NOERROR": "0", "NXDOMAIN": "0"},
						"dnscrypt": {"shared_secret": {"cachemiss": "0"}, "replay": "0"},
						"authzone": {"up": "0", "down": "0"}
					},
					"answer": {
						"rcode": {
							"NOERROR": "95000",
							"FORMERR": "0",
							"SERVFAIL": "100",
							"NXDOMAIN": "4800",
							"NOTIMPL": "0",
							"REFUSED": "50",
							"nodata": "5000"
						},
						"secure": "10000",
						"bogus": "5"
					},
					"rrset": {
						"bogus": "3"
					},
					"valops": "12345"
				},
				"histogram": [
					{"from": [0, 0], "to": [0, 1024], "value": "0"},
					{"from": [0, 1024], "to": [0, 2048], "value": "1200"},
					{"from": [0, 2048], "to": [0, 4096], "value": "800"}
				],
				"unwanted": {
					"queries": "20",
					"replies": "10"
				},
				"msg": {
					"cache": {
						"count": "50000",
						"max_collisions": "5"
					}
				},
				"rrset": {
					"cache": {
						"count": "80000",
						"max_collisions": "10"
					}
				},
				"infra": {
					"cache": {
						"count": "500"
					}
				},
				"key": {
					"cache": {
						"count": "200"
					}
				},
				"dnscrypt_shared_secret": {
					"cache": {"count": "0"}
				},
				"dnscrypt_nonce": {
					"cache": {"count": "0"}
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Uptime
	if data.UptimeSeconds != 86400.5 {
		t.Errorf("expected UptimeSeconds=86400.5, got %f", data.UptimeSeconds)
	}

	// Query totals
	if data.QueriesTotal != 100000 {
		t.Errorf("expected QueriesTotal=100000, got %d", data.QueriesTotal)
	}
	if data.CacheHits != 75000 {
		t.Errorf("expected CacheHits=75000, got %d", data.CacheHits)
	}
	if data.CacheMiss != 25000 {
		t.Errorf("expected CacheMiss=25000, got %d", data.CacheMiss)
	}
	if data.Prefetch != 100 {
		t.Errorf("expected Prefetch=100, got %d", data.Prefetch)
	}
	if data.QueriesTimedOut != 10 {
		t.Errorf("expected QueriesTimedOut=10, got %d", data.QueriesTimedOut)
	}
	if data.ExpiredTotal != 50 {
		t.Errorf("expected ExpiredTotal=50, got %d", data.ExpiredTotal)
	}
	if data.RecursiveReplies != 24000 {
		t.Errorf("expected RecursiveReplies=24000, got %d", data.RecursiveReplies)
	}
	if data.QueriesIPRateLimited != 5 {
		t.Errorf("expected QueriesIPRateLimited=5, got %d", data.QueriesIPRateLimited)
	}

	// Query types
	if data.QueryTypesByType["A"] != 60000 {
		t.Errorf("expected QueryTypesByType['A']=60000, got %d", data.QueryTypesByType["A"])
	}
	if data.QueryTypesByType["AAAA"] != 30000 {
		t.Errorf("expected QueryTypesByType['AAAA']=30000, got %d", data.QueryTypesByType["AAAA"])
	}
	if data.QueryTypesByType["HTTPS"] != 4000 {
		t.Errorf("expected QueryTypesByType['HTTPS']=4000, got %d", data.QueryTypesByType["HTTPS"])
	}

	// Query protocols
	if data.QueryTCP != 500 {
		t.Errorf("expected QueryTCP=500, got %d", data.QueryTCP)
	}
	if data.QueryUDPOut != 24000 {
		t.Errorf("expected QueryUDPOut=24000, got %d", data.QueryUDPOut)
	}
	if data.QueryTLS != 200 {
		t.Errorf("expected QueryTLS=200, got %d", data.QueryTLS)
	}
	if data.QueryIPv6 != 15000 {
		t.Errorf("expected QueryIPv6=15000, got %d", data.QueryIPv6)
	}

	// Answer rcodes
	if data.AnswerRcodesByRcode["NOERROR"] != 95000 {
		t.Errorf("expected AnswerRcodesByRcode['NOERROR']=95000, got %d", data.AnswerRcodesByRcode["NOERROR"])
	}
	if data.AnswerRcodesByRcode["NXDOMAIN"] != 4800 {
		t.Errorf("expected AnswerRcodesByRcode['NXDOMAIN']=4800, got %d", data.AnswerRcodesByRcode["NXDOMAIN"])
	}
	if data.AnswerRcodesByRcode["nodata"] != 5000 {
		t.Errorf("expected AnswerRcodesByRcode['nodata']=5000, got %d", data.AnswerRcodesByRcode["nodata"])
	}

	// DNSSEC
	if data.AnswerSecureTotal != 10000 {
		t.Errorf("expected AnswerSecureTotal=10000, got %d", data.AnswerSecureTotal)
	}
	if data.AnswerBogusTotal != 5 {
		t.Errorf("expected AnswerBogusTotal=5, got %d", data.AnswerBogusTotal)
	}
	if data.RrsetBogusTotal != 3 {
		t.Errorf("expected RrsetBogusTotal=3, got %d", data.RrsetBogusTotal)
	}

	// Cache counts
	if data.CacheRrsetCount != 80000 {
		t.Errorf("expected CacheRrsetCount=80000, got %d", data.CacheRrsetCount)
	}
	if data.CacheMessageCount != 50000 {
		t.Errorf("expected CacheMessageCount=50000, got %d", data.CacheMessageCount)
	}
	if data.CacheInfraCount != 500 {
		t.Errorf("expected CacheInfraCount=500, got %d", data.CacheInfraCount)
	}
	if data.CacheKeyCount != 200 {
		t.Errorf("expected CacheKeyCount=200, got %d", data.CacheKeyCount)
	}

	// Memory
	if data.MemCacheRrset != 524288 {
		t.Errorf("expected MemCacheRrset=524288, got %d", data.MemCacheRrset)
	}
	if data.MemCacheMessage != 262144 {
		t.Errorf("expected MemCacheMessage=262144, got %d", data.MemCacheMessage)
	}
	if data.MemModIterator != 131072 {
		t.Errorf("expected MemModIterator=131072, got %d", data.MemModIterator)
	}

	// Request list
	if data.RequestListAvg != 1.5 {
		t.Errorf("expected RequestListAvg=1.5, got %f", data.RequestListAvg)
	}
	if data.RequestListMax != 50 {
		t.Errorf("expected RequestListMax=50, got %d", data.RequestListMax)
	}
	if data.RequestListCurrentAll != 10 {
		t.Errorf("expected RequestListCurrentAll=10, got %d", data.RequestListCurrentAll)
	}

	// Recursion time
	if data.RecursionTimeAvg != 0.025 {
		t.Errorf("expected RecursionTimeAvg=0.025, got %f", data.RecursionTimeAvg)
	}
	if data.RecursionTimeMedian != 0.015 {
		t.Errorf("expected RecursionTimeMedian=0.015, got %f", data.RecursionTimeMedian)
	}

	// TCP usage
	if data.TCPUsage != 0.5 {
		t.Errorf("expected TCPUsage=0.5, got %f", data.TCPUsage)
	}

	// Flags
	if data.FlagsByFlag["RD"] != 100000 {
		t.Errorf("expected FlagsByFlag['RD']=100000, got %d", data.FlagsByFlag["RD"])
	}
	if data.FlagsByFlag["AD"] != 1000 {
		t.Errorf("expected FlagsByFlag['AD']=1000, got %d", data.FlagsByFlag["AD"])
	}

	// EDNS
	if data.EdnsPresent != 90000 {
		t.Errorf("expected EdnsPresent=90000, got %d", data.EdnsPresent)
	}
	if data.EdnsDO != 5000 {
		t.Errorf("expected EdnsDO=5000, got %d", data.EdnsDO)
	}

	// Unwanted
	if data.UnwantedQueries != 20 {
		t.Errorf("expected UnwantedQueries=20, got %d", data.UnwantedQueries)
	}
	if data.UnwantedReplies != 10 {
		t.Errorf("expected UnwantedReplies=10, got %d", data.UnwantedReplies)
	}

	// A full (extended-statistics: yes) payload must report the extended sections present.
	if !data.ExtendedPresent {
		t.Error("expected ExtendedPresent=true for a payload carrying data.num/data.mem")
	}
}

// TestFetchUnboundOverview_BaseStatDrops covers #237: queries_discard_timeout,
// queries_wait_limit, queries_replyaddr_limit, dns_error_reports and
// requestlist.current.replies all live in unbound's BASE statistics (data.total.num
// / data.total.requestlist), so they populate even with extended-statistics: no —
// unlike everything gated on ExtendedPresent — and are read unconditionally.
func TestFetchUnboundOverview_BaseStatDrops(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {
						"queries": "305",
						"cachehits": "200",
						"cachemiss": "105",
						"queries_discard_timeout": "1",
						"queries_wait_limit": "2",
						"queries_replyaddr_limit": "3",
						"dns_error_reports": "4"
					},
					"requestlist": {
						"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0",
						"current": {"all": "0", "user": "0", "replies": "5"}
					},
					"recursion": {"time": {"avg": "0", "median": "0"}},
					"tcpusage": "0"
				},
				"time": {"now": "1", "up": "1", "elapsed": "1"}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.QueriesDiscardTimeout != 1 {
		t.Errorf("QueriesDiscardTimeout = %d, want 1", data.QueriesDiscardTimeout)
	}
	if data.QueriesWaitLimit != 2 {
		t.Errorf("QueriesWaitLimit = %d, want 2", data.QueriesWaitLimit)
	}
	if data.QueriesReplyAddrLimit != 3 {
		t.Errorf("QueriesReplyAddrLimit = %d, want 3", data.QueriesReplyAddrLimit)
	}
	if data.DNSErrorReports != 4 {
		t.Errorf("DNSErrorReports = %d, want 4", data.DNSErrorReports)
	}
	if data.RequestListCurrentReplies != 5 {
		t.Errorf("RequestListCurrentReplies = %d, want 5", data.RequestListCurrentReplies)
	}
}

// TestFetchUnboundOverview_BaseStatDropsAbsent covers an older box that predates
// queries_replyaddr_limit / requestlist.current.replies: they must read 0, not
// error, same as any other absent base-stat field (tolerant safeAtoi("") = 0).
func TestFetchUnboundOverview_BaseStatDropsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "10"},
					"requestlist": {
						"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0",
						"current": {"all": "0", "user": "0"}
					},
					"recursion": {"time": {"avg": "0", "median": "0"}},
					"tcpusage": "0"
				},
				"time": {"now": "1", "up": "1", "elapsed": "1"}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.QueriesReplyAddrLimit != 0 || data.RequestListCurrentReplies != 0 {
		t.Errorf("expected zero for absent fields, got QueriesReplyAddrLimit=%d RequestListCurrentReplies=%d",
			data.QueriesReplyAddrLimit, data.RequestListCurrentReplies)
	}
}

// TestFetchUnboundOverview_ExtendedStatsAbsent covers the 26.7 default: OPNsense
// 26.7 ships unbound with `extended-statistics: no`, so api/unbound/diagnostics/stats
// serves ONLY data.total / data.time / data.threadN — every extended section
// (data.num, data.mem, data.msg, data.rrset, data.infra, data.key, data.unwanted,
// data.dnscrypt_*) is absent from the JSON. Those must be detected as absent
// (ExtendedPresent=false) rather than decoded to zero, otherwise the collector
// emits ~40 zero-valued series that read as real zero-traffic and corrupt rate()
// — same failure class as the Present gate (#90).
func TestFetchUnboundOverview_ExtendedStatsAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {
						"queries": "4321",
						"queries_ip_ratelimited": "3",
						"queries_cookie_valid": "0",
						"queries_cookie_client": "0",
						"queries_cookie_invalid": "0",
						"cachehits": "3000",
						"cachemiss": "1321",
						"prefetch": "40",
						"queries_timed_out": "7",
						"expired": "11",
						"recursivereplies": "1300",
						"queries_discard_timeout": "0",
						"queries_wait_limit": "0",
						"dns_error_reports": "0"
					},
					"query": {"queue_time_us": {"max": "12"}},
					"requestlist": {
						"avg": "2.25",
						"max": "17",
						"overwritten": "4",
						"exceeded": "1",
						"current": {"all": "6", "user": "2", "replies": "4"}
					},
					"recursion": {"time": {"avg": "0.031", "median": "0.019"}},
					"tcpusage": "0.75"
				},
				"time": {"now": "1800000000", "up": "12345.5", "elapsed": "12345.5"},
				"thread0": {
					"num": {"queries": "1100", "cachehits": "700", "cachemiss": "400", "prefetch": "10", "expired": "3", "recursivereplies": "400", "queries_timed_out": "2", "queries_ip_ratelimited": "1"},
					"query": {"queue_time_us": {"max": "12"}},
					"requestlist": {"avg": "2.0", "max": "5", "overwritten": "1", "exceeded": "0", "current": {"all": "2", "user": "1", "replies": "1"}},
					"recursion": {"time": {"avg": "0.030", "median": "0.018"}},
					"tcpusage": "0.20"
				},
				"thread1": {
					"num": {"queries": "1080", "cachehits": "760", "cachemiss": "320", "prefetch": "10", "expired": "3", "recursivereplies": "310", "queries_timed_out": "2", "queries_ip_ratelimited": "1"},
					"query": {"queue_time_us": {"max": "9"}},
					"requestlist": {"avg": "2.1", "max": "4", "overwritten": "1", "exceeded": "0", "current": {"all": "1", "user": "0", "replies": "1"}},
					"recursion": {"time": {"avg": "0.032", "median": "0.020"}},
					"tcpusage": "0.18"
				},
				"thread2": {
					"num": {"queries": "1070", "cachehits": "770", "cachemiss": "300", "prefetch": "10", "expired": "3", "recursivereplies": "295", "queries_timed_out": "2", "queries_ip_ratelimited": "1"},
					"query": {"queue_time_us": {"max": "8"}},
					"requestlist": {"avg": "2.4", "max": "4", "overwritten": "1", "exceeded": "1", "current": {"all": "2", "user": "1", "replies": "1"}},
					"recursion": {"time": {"avg": "0.031", "median": "0.019"}},
					"tcpusage": "0.19"
				},
				"thread3": {
					"num": {"queries": "1071", "cachehits": "770", "cachemiss": "301", "prefetch": "10", "expired": "2", "recursivereplies": "295", "queries_timed_out": "1", "queries_ip_ratelimited": "0"},
					"query": {"queue_time_us": {"max": "7"}},
					"requestlist": {"avg": "2.5", "max": "4", "overwritten": "1", "exceeded": "0", "current": {"all": "1", "user": "0", "replies": "1"}},
					"recursion": {"time": {"avg": "0.031", "median": "0.019"}},
					"tcpusage": "0.18"
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The envelope is "ok" and the base stats are real — those must still be exported.
	if !data.Present {
		t.Fatal("expected Present=true: the stats envelope is ok, only extended sections are absent")
	}
	if data.ExtendedPresent {
		t.Error("expected ExtendedPresent=false when data.num/data.mem are absent (extended-statistics: no)")
	}

	// Core totals (data.total.num) — populated from the base payload.
	if data.QueriesTotal != 4321 {
		t.Errorf("expected QueriesTotal=4321, got %d", data.QueriesTotal)
	}
	if data.CacheHits != 3000 {
		t.Errorf("expected CacheHits=3000, got %d", data.CacheHits)
	}
	if data.CacheMiss != 1321 {
		t.Errorf("expected CacheMiss=1321, got %d", data.CacheMiss)
	}
	if data.Prefetch != 40 {
		t.Errorf("expected Prefetch=40, got %d", data.Prefetch)
	}
	if data.QueriesTimedOut != 7 {
		t.Errorf("expected QueriesTimedOut=7, got %d", data.QueriesTimedOut)
	}
	if data.ExpiredTotal != 11 {
		t.Errorf("expected ExpiredTotal=11, got %d", data.ExpiredTotal)
	}
	if data.RecursiveReplies != 1300 {
		t.Errorf("expected RecursiveReplies=1300, got %d", data.RecursiveReplies)
	}
	if data.QueriesIPRateLimited != 3 {
		t.Errorf("expected QueriesIPRateLimited=3, got %d", data.QueriesIPRateLimited)
	}

	// Request list / recursion / tcpusage / uptime (data.total.*, data.time.*).
	if data.UptimeSeconds != 12345.5 {
		t.Errorf("expected UptimeSeconds=12345.5, got %f", data.UptimeSeconds)
	}
	if data.RequestListAvg != 2.25 {
		t.Errorf("expected RequestListAvg=2.25, got %f", data.RequestListAvg)
	}
	if data.RequestListMax != 17 {
		t.Errorf("expected RequestListMax=17, got %d", data.RequestListMax)
	}
	if data.RequestListOverwritten != 4 {
		t.Errorf("expected RequestListOverwritten=4, got %d", data.RequestListOverwritten)
	}
	if data.RequestListExceeded != 1 {
		t.Errorf("expected RequestListExceeded=1, got %d", data.RequestListExceeded)
	}
	if data.RequestListCurrentAll != 6 {
		t.Errorf("expected RequestListCurrentAll=6, got %d", data.RequestListCurrentAll)
	}
	if data.RequestListCurrentUser != 2 {
		t.Errorf("expected RequestListCurrentUser=2, got %d", data.RequestListCurrentUser)
	}
	if data.RecursionTimeAvg != 0.031 {
		t.Errorf("expected RecursionTimeAvg=0.031, got %f", data.RecursionTimeAvg)
	}
	if data.RecursionTimeMedian != 0.019 {
		t.Errorf("expected RecursionTimeMedian=0.019, got %f", data.RecursionTimeMedian)
	}
	if data.TCPUsage != 0.75 {
		t.Errorf("expected TCPUsage=0.75, got %f", data.TCPUsage)
	}

	// Extended-sourced fields must stay at their zero value AND be flagged absent,
	// so the collector can skip them rather than publish them as zeros.
	if len(data.QueryTypesByType) != 0 {
		t.Errorf("expected no query types, got %v", data.QueryTypesByType)
	}
	if len(data.AnswerRcodesByRcode) != 0 {
		t.Errorf("expected no rcodes, got %v", data.AnswerRcodesByRcode)
	}
	if len(data.FlagsByFlag) != 0 {
		t.Errorf("expected no flags, got %v", data.FlagsByFlag)
	}
}

// TestFetchUnboundOverview_DynamicQueryTypes covers #138: the per-type breakdown must
// capture LOC/HINFO (previously parsed but dropped from the exported map) AND RR types
// outside the old fixed 16-field whitelist (CAA, DS), which encoding/json used to drop
// silently against the fixed struct.
func TestFetchUnboundOverview_DynamicQueryTypes(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {"num": {"queries": "100"}},
				"time": {"up": "1"},
				"num": {
					"query": {"type": {"A": "50", "AAAA": "20", "LOC": "3", "HINFO": "2", "CAA": "7", "DS": "5"}},
					"answer": {"rcode": {"NOERROR": "100"}}
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]int64{"A": 50, "AAAA": 20, "LOC": 3, "HINFO": 2, "CAA": 7, "DS": 5}
	for rr, v := range want {
		if got := data.QueryTypesByType[rr]; got != v {
			t.Errorf("QueryTypesByType[%q] = %d, want %d (dropped RR type?)", rr, got, v)
		}
	}
	if len(data.QueryTypesByType) != len(want) {
		t.Errorf("QueryTypesByType has %d entries, want %d: %v", len(data.QueryTypesByType), len(want), data.QueryTypesByType)
	}
}

func TestFetchUnboundOverview_EmptyUptime(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "0", "queries_ip_ratelimited": "0", "queries_cookie_valid": "0", "queries_cookie_client": "0", "queries_cookie_invalid": "0", "cachehits": "0", "cachemiss": "0", "prefetch": "0", "queries_timed_out": "0", "expired": "0", "recursivereplies": "0", "queries_discard_timeout": "0", "queries_wait_limit": "0", "dns_error_reports": "0", "dnscrypt": {"crypted": "0", "cert": "0", "cleartext": "0", "malformed": "0"}},
					"query": {"queue_time_us": {"max": "0"}},
					"requestlist": {"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0", "current": {"all": "0", "user": "0"}},
					"recursion": {"time": {"avg": "0", "median": "0"}},
					"tcpusage": "0"
				},
				"time": {"now": "0", "up": "", "elapsed": "0"},
				"mem": {"cache": {"rrset": "0", "message": "0", "dnscrypt_shared_secret": "0", "dnscrypt_nonce": "0"}, "mod": {"iterator": "0", "validator": "0", "respip": "0", "dynlibmod": "0"}, "streamwait": "0", "http": {"query_buffer": "0", "response_buffer": "0"}},
				"num": {
					"query": {"type": {"A": "0", "SOA": "0", "PTR": "0", "MX": "0", "TXT": "0", "AAAA": "0", "SRV": "0", "SVCB": "0", "HTTPS": "0", "NS": "0", "CNAME": "0", "NAPTR": "0", "DNSKEY": "0", "ANY": "0", "LOC": "0", "HINFO": "0"}, "class": {"IN": "0"}, "opcode": {"QUERY": "0"}, "tcp": "0", "tcpout": "0", "udpout": "0", "tls": {"__value__": "0", "resume": "0"}, "ipv6": "0", "https": "0", "flags": {"QR": "0", "AA": "0", "TC": "0", "RD": "0", "RA": "0", "Z": "0", "AD": "0", "CD": "0"}, "edns": {"present": "0", "DO": "0"}, "ratelimited": "0", "aggressive": {"NOERROR": "0", "NXDOMAIN": "0"}, "dnscrypt": {"shared_secret": {"cachemiss": "0"}, "replay": "0"}, "authzone": {"up": "0", "down": "0"}},
					"answer": {"rcode": {"NOERROR": "0", "FORMERR": "0", "SERVFAIL": "0", "NXDOMAIN": "0", "NOTIMPL": "0", "REFUSED": "0", "nodata": "0"}, "secure": "0", "bogus": "0"},
					"rrset": {"bogus": "0"}
				},
				"unwanted": {"queries": "0", "replies": "0"},
				"msg": {"cache": {"count": "0", "max_collisions": "0"}},
				"rrset": {"cache": {"count": "0", "max_collisions": "0"}},
				"infra": {"cache": {"count": "0"}},
				"key": {"cache": {"count": "0"}},
				"dnscrypt_shared_secret": {"cache": {"count": "0"}},
				"dnscrypt_nonce": {"cache": {"count": "0"}}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("expected no error for empty uptime string, got: %v", err)
	}
	if data.UptimeSeconds != 0 {
		t.Errorf("expected UptimeSeconds=0 for empty uptime string, got %f", data.UptimeSeconds)
	}
}

func TestFetchUnboundOverview_InvalidUptime(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "0", "queries_ip_ratelimited": "0", "queries_cookie_valid": "0", "queries_cookie_client": "0", "queries_cookie_invalid": "0", "cachehits": "0", "cachemiss": "0", "prefetch": "0", "queries_timed_out": "0", "expired": "0", "recursivereplies": "0", "queries_discard_timeout": "0", "queries_wait_limit": "0", "dns_error_reports": "0", "dnscrypt": {"crypted": "0", "cert": "0", "cleartext": "0", "malformed": "0"}},
					"query": {"queue_time_us": {"max": "0"}},
					"requestlist": {"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0", "current": {"all": "0", "user": "0"}},
					"recursion": {"time": {"avg": "0", "median": "0"}},
					"tcpusage": "0"
				},
				"time": {"now": "0", "up": "not_a_number", "elapsed": "0"},
				"mem": {"cache": {"rrset": "0", "message": "0", "dnscrypt_shared_secret": "0", "dnscrypt_nonce": "0"}, "mod": {"iterator": "0", "validator": "0", "respip": "0", "dynlibmod": "0"}, "streamwait": "0", "http": {"query_buffer": "0", "response_buffer": "0"}},
				"num": {
					"query": {"type": {"A": "0", "SOA": "0", "PTR": "0", "MX": "0", "TXT": "0", "AAAA": "0", "SRV": "0", "SVCB": "0", "HTTPS": "0", "NS": "0", "CNAME": "0", "NAPTR": "0", "DNSKEY": "0", "ANY": "0", "LOC": "0", "HINFO": "0"}, "class": {"IN": "0"}, "opcode": {"QUERY": "0"}, "tcp": "0", "tcpout": "0", "udpout": "0", "tls": {"__value__": "0", "resume": "0"}, "ipv6": "0", "https": "0", "flags": {"QR": "0", "AA": "0", "TC": "0", "RD": "0", "RA": "0", "Z": "0", "AD": "0", "CD": "0"}, "edns": {"present": "0", "DO": "0"}, "ratelimited": "0", "aggressive": {"NOERROR": "0", "NXDOMAIN": "0"}, "dnscrypt": {"shared_secret": {"cachemiss": "0"}, "replay": "0"}, "authzone": {"up": "0", "down": "0"}},
					"answer": {"rcode": {"NOERROR": "0", "FORMERR": "0", "SERVFAIL": "0", "NXDOMAIN": "0", "NOTIMPL": "0", "REFUSED": "0", "nodata": "0"}, "secure": "0", "bogus": "0"},
					"rrset": {"bogus": "0"}
				},
				"unwanted": {"queries": "0", "replies": "0"},
				"msg": {"cache": {"count": "0", "max_collisions": "0"}},
				"rrset": {"cache": {"count": "0", "max_collisions": "0"}},
				"infra": {"cache": {"count": "0"}},
				"key": {"cache": {"count": "0"}},
				"dnscrypt_shared_secret": {"cache": {"count": "0"}},
				"dnscrypt_nonce": {"cache": {"count": "0"}}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("expected no error for unparseable uptime string, got: %v", err)
	}
	if data.UptimeSeconds != 0 {
		t.Errorf("expected UptimeSeconds=0 for unparseable uptime string, got %f", data.UptimeSeconds)
	}
}

func TestFetchUnboundOverview_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchUnboundOverview()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchUnboundOverview_StatusFailed guards #90: statsAction() returns HTTP
// 200 {"status":"failed"} (no data key) when unbound-control is unreachable. That
// must yield Present=false (no error), not a zero-valued struct that reads as
// success.
func TestFetchUnboundOverview_StatusFailed(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "failed"}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error (failed status should not error): %v", err)
	}
	if data.Present {
		t.Error("expected Present=false when unbound-control returns status=failed")
	}
}

// TestFetchUnboundBlockListStatus_Success covers the get_policies migration
// (#210): isBlockListEnabled is deprecated and removed in OPNsense 26.7, so
// blocklist_enabled is now derived from api/unbound/overview/get_policies —
// a PHP associative array keyed by policy UUID, each carrying a string
// "enabled" flag ("1"/"0", per the model's BooleanField). Verified against a
// live 26.7-devel box (empty policy set serializes as "[]", never "{}").
func TestFetchUnboundBlockListStatus_Success(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected bool
	}{
		{"NoPolicies_EmptyArray", `[]`, false},
		{"NoPolicies_EmptyObject", `{}`, false},
		{"NoPolicies_Null", `null`, false},
		{
			"AllDisabled",
			`{"1c9c5d5e-0000-0000-0000-000000000001":{"enabled":"0","description":"a"},` +
				`"1c9c5d5e-0000-0000-0000-000000000002":{"enabled":"0","description":"b"}}`,
			false,
		},
		{
			"OneEnabledOneDisabled",
			`{"1c9c5d5e-0000-0000-0000-000000000001":{"enabled":"1","description":"a"},` +
				`"1c9c5d5e-0000-0000-0000-000000000002":{"enabled":"0","description":"b"}}`,
			true,
		},
		{
			"AllEnabled",
			`{"1c9c5d5e-0000-0000-0000-000000000001":{"enabled":"1","description":"a"}}`,
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.json))
			})
			defer server.Close()

			result, err := client.FetchUnboundBlockListStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestFetchUnboundBlockListStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchUnboundBlockListStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchUnboundInfra_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"status": "ok",
			"data": [
				{
					"ip": "127.0.0.1@53053", "host": "10.in-addr.arpa.",
					"ttl": "765", "ping": "0", "var": "24", "rtt": "96", "rto": "96",
					"tA": "0", "tAAAA": "0", "tother": "0", "ednsknown": "1",
					"edns": "0", "delay": "0", "lame": true, "dnssec": "0",
					"rec": "0", "A": "0", "other": "0"
				},
				{
					"ip": "203.0.113.53@853", "host": ".",
					"ttl": "626", "ping": "53", "var": "43", "rtt": "225", "rto": "225",
					"tA": "0", "tAAAA": "0", "tother": "0", "ednsknown": "0",
					"edns": "0", "delay": "0", "lame": true, "dnssec": "0",
					"rec": "0", "A": "0", "other": "0"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundInfra()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Hosts) != 2 {
		t.Fatalf("expected 2 infra hosts, got %d", len(data.Hosts))
	}
	h0 := data.Hosts[0]
	if h0.IP != "127.0.0.1@53053" || h0.Host != "10.in-addr.arpa." {
		t.Errorf("unexpected host identity: %+v", h0)
	}
	if h0.RTTMilliseconds != 96 || h0.RTOMilliseconds != 96 {
		t.Errorf("expected rtt/rto 96/96, got %v/%v", h0.RTTMilliseconds, h0.RTOMilliseconds)
	}
	h1 := data.Hosts[1]
	if h1.RTTMilliseconds != 225 {
		t.Errorf("expected rtt 225, got %v", h1.RTTMilliseconds)
	}
}

func TestFetchUnboundInfra_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchUnboundInfra()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

// unboundTotalsPattern registers the api/unbound/overview/totals handler as a
// SUBTREE pattern rather than an exact path. The {max} row limit is baked into the
// endpoint URL in opnsense/client.go, and #587 raises it from 1 to the leaderboard
// cap; an exact "/api/unbound/overview/totals/1" pattern would start 404ing every
// totals call the moment that lands, and each of these tests would silently begin
// asserting against an empty payload instead of failing on the real change. The
// sibling overview endpoints stay on exact patterns, which ServeMux prefers over
// this prefix.
const unboundTotalsPattern = "/api/unbound/overview/totals/"

// TestFetchUnboundQueryStats_StatsDisabled verifies the #209 gate: when
// is_enabled reports off, FetchUnboundQueryStats must NOT call the expensive
// totals endpoint at all — captured ground truth
// (overview_totals_1_stats_disabled.json) shows totals does not self-gate and
// keeps returning its full historical payload even with stats off, so the
// caller has to skip the call itself to actually save the cost.
func TestFetchUnboundQueryStats_StatsDisabled(t *testing.T) {
	totalsCalled := false
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"0"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		totalsCalled = true
		w.Write([]byte(`{"total":1,"blocklist_size":1,"passed":1,"resolved":{"total":1,"pcnt":"1"},"blocked":{"total":1,"pcnt":"1"},"local":{"total":1,"pcnt":"1"},"start_time":1,"top":{},"top_blocked":{}}`))
	})

	data, err := client.FetchUnboundQueryStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Enabled {
		t.Error("expected Enabled=false")
	}
	if data.TotalsPresent {
		t.Error("expected TotalsPresent=false when stats are disabled")
	}
	if totalsCalled {
		t.Error("expected the expensive totals endpoint NOT to be called when stats are disabled")
	}
	if data.QueriesTotal7d != 0 || data.BlocklistSize != 0 {
		t.Errorf("expected all totals fields to stay zero, got %+v", data)
	}
}

// TestFetchUnboundQueryStats_Success uses the real captured payload
// (overview_totals_1.json, captured against a live OPNsense 26.7-devel box
// with a real DNSBL policy + real blocked/passed drill queries) to validate
// field mapping.
func TestFetchUnboundQueryStats_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"total":16236,"blocklist_size":528587,"passed":10396,"resolved":{"total":3197,"pcnt":"19.69"},"blocked":{"total":13,"pcnt":"0.08"},"local":{"total":145,"pcnt":"0.89"},"start_time":1783872391,"top":{"enc0?network.":{"total":2780,"pcnt":"26.74"}},"top_blocked":{"ade.googlesyndication.com.":{"total":4,"pcnt":"30.77","blocklist":"AdGuard List","latest_policy_uuid":"6b882f48-abe5-4a80-9670-5d7a6b81c66f","category":"General Blocklists"}}}`))
	})

	data, err := client.FetchUnboundQueryStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Enabled || !data.TotalsPresent {
		t.Fatalf("expected Enabled and TotalsPresent, got %+v", data)
	}
	if data.QueriesTotal7d != 16236 {
		t.Errorf("expected QueriesTotal7d=16236, got %d", data.QueriesTotal7d)
	}
	if data.BlocklistSize != 528587 {
		t.Errorf("expected BlocklistSize=528587, got %d", data.BlocklistSize)
	}
	if data.PassedTotal7d != 10396 {
		t.Errorf("expected PassedTotal7d=10396, got %d", data.PassedTotal7d)
	}
	if data.ResolvedTotal7d != 3197 {
		t.Errorf("expected ResolvedTotal7d=3197, got %d", data.ResolvedTotal7d)
	}
	if data.BlockedTotal7d != 13 {
		t.Errorf("expected BlockedTotal7d=13, got %d", data.BlockedTotal7d)
	}
	if data.LocalTotal7d != 145 {
		t.Errorf("expected LocalTotal7d=145, got %d", data.LocalTotal7d)
	}
	if data.StartTimeSeconds != 1783872391 {
		t.Errorf("expected StartTimeSeconds=1783872391, got %d", data.StartTimeSeconds)
	}
}

// TestFetchUnboundQueryStats_EmptyDB is a synthesized zero-value fixture (the
// dev box could not be captured in a true zero-query state — see #209
// captures README) exercising the empty/zero-data shape the issue calls out.
func TestFetchUnboundQueryStats_EmptyDB(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":0,"blocklist_size":0,"passed":0,"resolved":{"total":0,"pcnt":"0.00"},"blocked":{"total":0,"pcnt":"0.00"},"local":{"total":0,"pcnt":"0.00"},"start_time":0,"top":{},"top_blocked":{}}`))
	})

	data, err := client.FetchUnboundQueryStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Enabled || !data.TotalsPresent {
		t.Fatalf("expected Enabled and TotalsPresent even with zero data, got %+v", data)
	}
	if data.QueriesTotal7d != 0 || data.BlocklistSize != 0 || data.PassedTotal7d != 0 ||
		data.ResolvedTotal7d != 0 || data.BlockedTotal7d != 0 || data.LocalTotal7d != 0 ||
		data.StartTimeSeconds != 0 {
		t.Errorf("expected all fields zero, got %+v", data)
	}
}

func TestFetchUnboundQueryStats_IsEnabledError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchUnboundQueryStats()
	if err == nil {
		t.Fatal("expected error when is_enabled call fails")
	}
}

func TestFetchUnboundQueryStats_TotalsError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchUnboundQueryStats()
	if err == nil {
		t.Fatal("expected error when totals call fails")
	}
}

// TestFetchUnboundLocalData_Success uses the real captured payloads for the
// three #209 rider diagnostics endpoints.
func TestFetchUnboundLocalData_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/diagnostics/listlocalzones", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"status":"ok","data":[
			{"zone":"home.arpa.","type":"static"},
			{"zone":"10.in-addr.arpa.","type":"static"},
			{"zone":"example.lan","type":"transparent"},
			{"zone":"blocked.example","type":"redirect"}
		]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocaldata", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[
			{"name":"home.arpa.","ttl":"10800","type":"IN","rrtype":"NS","value":"localhost."},
			{"name":"home.arpa.","ttl":"10800","type":"IN","rrtype":"SOA","value":"localhost."},
			{"name":"router.lan.","ttl":"10800","type":"IN","rrtype":"A","value":"192.0.2.1"}
		]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listinsecure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":["insecure.example.","legacy.example."]}`))
	})

	data, err := client.FetchUnboundLocalData()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.ZonesByType["static"] != 2 {
		t.Errorf("expected 2 static zones, got %d", data.ZonesByType["static"])
	}
	if data.ZonesByType["transparent"] != 1 {
		t.Errorf("expected 1 transparent zone, got %d", data.ZonesByType["transparent"])
	}
	if data.ZonesByType["redirect"] != 1 {
		t.Errorf("expected 1 redirect zone, got %d", data.ZonesByType["redirect"])
	}
	if data.LocalDataRecords != 3 {
		t.Errorf("expected 3 local data records, got %d", data.LocalDataRecords)
	}
	if data.InsecureDomains != 2 {
		t.Errorf("expected 2 insecure domains, got %d", data.InsecureDomains)
	}
}

// TestFetchUnboundLocalData_DegenerateInsecureShape reproduces the exact
// captured shape (diagnostics_listinsecure.json) from a box with NO insecure
// domains configured: {"status":"ok","data":[""]} — one empty-string entry,
// not a truly empty array. Must count as zero, not one.
func TestFetchUnboundLocalData_DegenerateInsecureShape(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/diagnostics/listlocalzones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocaldata", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listinsecure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[""]}`))
	})

	data, err := client.FetchUnboundLocalData()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.InsecureDomains != 0 {
		t.Errorf("expected the degenerate single-empty-string shape to count as 0, got %d", data.InsecureDomains)
	}
	if len(data.ZonesByType) != 0 {
		t.Errorf("expected no zones, got %+v", data.ZonesByType)
	}
	if data.LocalDataRecords != 0 {
		t.Errorf("expected 0 local data records, got %d", data.LocalDataRecords)
	}
}

func TestFetchUnboundLocalData_PartialFailure(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/diagnostics/listlocalzones", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocaldata", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listinsecure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[""]}`))
	})

	_, err := client.FetchUnboundLocalData()
	if err == nil {
		t.Fatal("expected error when one sub-fetch fails")
	}
}

// --- #581: reply-time histogram + valops -------------------------------------

// TestFetchUnboundOverview_RecursionHistogram pins the three things that would
// each produce a histogram that LIES to histogram_quantile() rather than one that
// obviously fails:
//
//  1. unbound's buckets are per-bucket counts, not cumulative. Handing them to
//     Prometheus unaccumulated makes every quantile read low.
//  2. the accumulation must be ordered by upper bound, not by wire order.
//  3. _sum must be the real accumulated wait, reconstructed from the mean
//     unbound already divided it out of, not a zero or an invention.
//
// The wire order is deliberately shuffled here: unbound prints ascending today, so
// an implementation that folds in wire order passes on real data and silently
// corrupts the day upstream reorders.
func TestFetchUnboundOverview_RecursionHistogram(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "10", "recursivereplies": "10"},
					"requestlist": {"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0", "current": {"all": "0", "user": "0"}},
					"recursion": {"time": {"avg": "0.250000", "median": "0.2"}},
					"tcpusage": "0"
				},
				"time": {"now": "1700000000", "up": "100", "elapsed": "100"},
				"histogram": [
					{"from": [0, 512], "to": [0, 1024], "value": "3"},
					{"from": [1, 0], "to": [2, 0], "value": "1"},
					{"from": [0, 0], "to": [0, 512], "value": "6"},
					{"from": [0, 1024], "to": [1, 0], "value": "0"}
				]
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h := data.RecursionHistogram
	if !h.Present {
		t.Fatal("expected RecursionHistogram.Present with data.histogram on the wire")
	}
	// Cumulative, ascending by upper bound: 6, 6+3, 9+0, 9+1.
	want := map[float64]uint64{
		0.000512: 6,
		0.001024: 9,
		1:        9,
		2:        10,
	}
	if len(h.Buckets) != len(want) {
		t.Fatalf("expected %d buckets, got %d (%v)", len(want), len(h.Buckets), h.Buckets)
	}
	for le, count := range want {
		if got := h.Buckets[le]; got != count {
			t.Errorf("bucket le=%g: expected cumulative %d, got %d", le, count, got)
		}
	}
	if h.Count != 10 {
		t.Errorf("expected Count=10 (the top cumulative bucket), got %d", h.Count)
	}
	// _sum is unbound's own accumulator recovered by multiplying the mean back by
	// the count it was divided by: 0.25s * 10 = 2.5s.
	if h.Sum != 2.5 {
		t.Errorf("expected Sum=2.5 (avg 0.25s x 10 replies), got %v", h.Sum)
	}
}

// TestFetchUnboundOverview_RecursionHistogramAbsent covers the box state that is
// the DEFAULT on OPNsense 26.7: `extended-statistics: no`, under which unbound's
// print_hist is never reached (daemon/remote.c calls it only inside
// `if(daemon->cfg->stat_extended)`) and data.histogram is simply not in the
// payload. A fabricated 40-bucket histogram of zeros would be far worse than no
// metric: it publishes a p99 of "under a microsecond" for a resolver nobody is
// measuring.
func TestFetchUnboundOverview_RecursionHistogramAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "10", "recursivereplies": "10"},
					"requestlist": {"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0", "current": {"all": "0", "user": "0"}},
					"recursion": {"time": {"avg": "0.25", "median": "0.2"}},
					"tcpusage": "0"
				},
				"time": {"now": "1700000000", "up": "100", "elapsed": "100"}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.RecursionHistogram.Present {
		t.Error("expected RecursionHistogram.Present=false when the box omits data.histogram")
	}
	if data.RecursionHistogram.Count != 0 || len(data.RecursionHistogram.Buckets) != 0 {
		t.Errorf("expected an entirely empty histogram, got %+v", data.RecursionHistogram)
	}
}

// TestFetchUnboundOverview_ValidationOperations pins num.valops, which unbound
// prints unconditionally inside print_ext (daemon/remote.c, immediately after
// num.rrset.bogus) — so its presence tracks extended-statistics exactly, and it is
// read under the same ExtendedPresent gate as its siblings.
func TestFetchUnboundOverview_ValidationOperations(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "10"},
					"requestlist": {"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0", "current": {"all": "0", "user": "0"}},
					"recursion": {"time": {"avg": "0", "median": "0"}},
					"tcpusage": "0"
				},
				"time": {"now": "1700000000", "up": "100", "elapsed": "100"},
				"num": {"answer": {"secure": "5", "bogus": "0"}, "rrset": {"bogus": "0"}, "valops": "417"},
				"histogram": [{"from": [0, 0], "to": [0, 1], "value": "0"}]
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.ExtendedPresent {
		t.Fatal("expected ExtendedPresent with data.num on the wire")
	}
	if data.ValidationOperations != 417 {
		t.Errorf("expected ValidationOperations=417, got %d", data.ValidationOperations)
	}
}

// --- #581: infra host health flags -------------------------------------------

// TestFetchUnboundInfra_HealthFlags decodes the lameness/EDNS state out of a
// dump_infra record shaped exactly as unbound's fixed print layout produces it
// (daemon/remote.c dump_infra_host: "... ednsknown %d edns %d delay %d lame
// dnssec %d rec %d A %d other %d"), after wrapper.py's key/value pairing.
func TestFetchUnboundInfra_HealthFlags(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[
			{"ip":"1.1.1.1","host":"example.com.","ttl":"900","ping":"0","var":"94","rtt":"70","rto":"376",
			 "tA":"0","tAAAA":"0","tother":"0","ednsknown":"1","edns":"0","delay":"0","lame":true,
			 "dnssec":"0","rec":"0","A":"0","other":"0"},
			{"ip":"9.9.9.9","host":"broken.example.","ttl":"900","ping":"0","var":"94","rtt":"400","rto":"1200",
			 "tA":"2","tAAAA":"0","tother":"0","ednsknown":"1","edns":"-1","delay":"0","lame":true,
			 "dnssec":"1","rec":"1","A":"1","other":"1"}
		]}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundInfra()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(data.Hosts))
	}

	healthy := data.Hosts[0]
	if healthy.DNSSECLame || healthy.RecursionLame || healthy.TypeALame || healthy.OtherLame {
		t.Errorf("expected no lameness on the healthy upstream, got %+v", healthy)
	}
	if healthy.EDNSBroken {
		t.Error("expected EDNSBroken=false for edns=0 (EDNS0 supported)")
	}

	broken := data.Hosts[1]
	if !broken.DNSSECLame || !broken.RecursionLame || !broken.TypeALame || !broken.OtherLame {
		t.Errorf("expected every lameness flag set on the broken upstream, got %+v", broken)
	}
	if !broken.EDNSBroken {
		t.Error("expected EDNSBroken=true for edns=-1 (unbound's marker for EDNS dropped in transit)")
	}
}

// TestFetchUnboundInfra_LameKeyIsALiteralNotAFlag is the whole reason #581's
// proposal was reshaped, and it must never be "simplified" away.
//
// `lame` in unbound's dump_infra line is a bare LITERAL WORD introducing the four
// lameness values that follow it — it has no operand of its own. wrapper.py
// special-cases exactly that token (`if key == 'lame': record['lame'] = True`), so
// EVERY host in EVERY payload carries "lame": true, including a perfectly healthy
// forwarder. Exporting a metric from it would pin every upstream at 1 forever and
// look like a total resolution outage. This fixture is a completely healthy host,
// and nothing about it may read as lame.
func TestFetchUnboundInfra_LameKeyIsALiteralNotAFlag(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[
			{"ip":"8.8.8.8","host":"google.com.","ttl":"900","rtt":"20","rto":"120",
			 "ednsknown":"1","edns":"0","lame":true,"dnssec":"0","rec":"0","A":"0","other":"0"}
		]}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundInfra()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h := data.Hosts[0]
	if h.DNSSECLame || h.RecursionLame || h.TypeALame || h.OtherLame || h.EDNSBroken {
		t.Fatalf("a healthy host whose payload carries the literal \"lame\": true must report "+
			"no health problem; got %+v", h)
	}
}

// --- #587: top / top_blocked domain leaderboards ------------------------------

// TestFetchUnboundQueryStats_TopDomains decodes both leaderboards from the shape
// stats.py produces (handle_top: two DuckDB LIMIT ? queries indexed by domain).
// The derivable pcnt and the per-row blocklist/uuid/category attribution are
// deliberately not modelled; only the count crosses into the exporter.
func TestFetchUnboundQueryStats_TopDomains(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":100,"blocklist_size":5,"passed":80,
			"resolved":{"total":60,"pcnt":"60.00"},"blocked":{"total":15,"pcnt":"15.00"},
			"local":{"total":5,"pcnt":"5.00"},"start_time":1783872391,
			"top":{"example.com.":{"total":40,"pcnt":"50.00"},"news.example.":{"total":12,"pcnt":"15.00"}},
			"top_blocked":{"ads.example.":{"total":9,"pcnt":"60.00","blocklist":"AdGuard List",
				"latest_policy_uuid":"6b882f48-abe5-4a80-9670-5d7a6b81c66f","category":"General Blocklists"}}}`))
	})

	data, err := client.FetchUnboundQueryStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := data.TopPassedDomains["example.com."]; got != 40 {
		t.Errorf("expected example.com.=40 passed, got %d", got)
	}
	if got := data.TopPassedDomains["news.example."]; got != 12 {
		t.Errorf("expected news.example.=12 passed, got %d", got)
	}
	if len(data.TopPassedDomains) != 2 {
		t.Errorf("expected 2 passed-domain rows, got %d", len(data.TopPassedDomains))
	}
	if got := data.TopBlockedDomains["ads.example."]; got != 9 {
		t.Errorf("expected ads.example.=9 blocked, got %d", got)
	}
	if len(data.TopBlockedDomains) != 1 {
		t.Errorf("expected 1 blocked-domain row, got %d", len(data.TopBlockedDomains))
	}
}

// TestFetchUnboundQueryStats_TopDomainsEmptyArrayShape covers the empty
// leaderboard as OPNsense actually serves it. stats.py emits `{}`, but
// OverviewController::totalsAction round-trips the payload through
// json_decode($response, true) — which turns an empty JSON object into an empty
// PHP ARRAY — before Phalcon re-encodes it, so the wire shape is `[]`. Exactly the
// quirk unboundPoliciesResponse already documents; a plain map[string]... here
// fails the whole decode on it and takes every other qstats field down with it.
func TestFetchUnboundQueryStats_TopDomainsEmptyArrayShape(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":7,"blocklist_size":0,"passed":7,"resolved":{"total":7,"pcnt":"100.00"},
			"blocked":{"total":0,"pcnt":"0"},"local":{"total":0,"pcnt":"0"},"start_time":1,
			"top":[],"top_blocked":[]}`))
	})

	data, err := client.FetchUnboundQueryStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.TotalsPresent || data.QueriesTotal7d != 7 {
		t.Fatalf("the rest of the payload must still decode past an empty-array leaderboard, got %+v", data)
	}
	if len(data.TopPassedDomains) != 0 || len(data.TopBlockedDomains) != 0 {
		t.Errorf("expected both leaderboards empty, got %+v / %+v",
			data.TopPassedDomains, data.TopBlockedDomains)
	}
}

// TestUnboundQueryStatsTotalsMaxMatchesLeaderboardCap pins the one invariant that
// makes #587's cap real rather than decorative: the {max} row limit in the
// endpoint URL is what the backend's `LIMIT ?` binds to (stats.py handle_top), so
// the exporter can never track more domains than that number no matter what the
// in-process cap says.
//
// FAILS UNTIL opnsense/client.go's "unboundQueryStatsTotals" entry is changed from
// "api/unbound/overview/totals/1" to "api/unbound/overview/totals/512". That file
// is owned by a different lane in this change, so the edit is deliberately not
// made here — this test is the handoff. Regenerate
// testdata/schemas/unboundQueryStatsTotals.json (just schemas) and docs/security.md
// (just docs) with it; both record the URL.
func TestUnboundQueryStatsTotalsMaxMatchesLeaderboardCap(t *testing.T) {
	url := string(defaultEndpoints()["unboundQueryStatsTotals"])
	want := fmt.Sprintf("api/unbound/overview/totals/%d", UnboundTopDomainsMax)
	if url != want {
		t.Errorf("unboundQueryStatsTotals endpoint is %q, want %q: the backend LIMIT and the "+
			"exporter's leaderboard cap must be the same number, or the cap is a lie in one "+
			"direction and the payload is truncated in the other", url, want)
	}
}

// TestFetchUnboundOverview_RecursionHistogramNonContiguous covers the reshape case
// the `from` bound exists to catch. A running sum over buckets that do not tile is
// not "the count at or below this le" — it is a smaller number that still looks
// like a histogram, still satisfies every check Prometheus makes, and moves every
// quantile. There is no downstream signal for it, so the only safe answer is to
// publish nothing.
func TestFetchUnboundOverview_RecursionHistogramNonContiguous(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "10"},
					"requestlist": {"avg": "0", "max": "0", "overwritten": "0", "exceeded": "0", "current": {"all": "0", "user": "0"}},
					"recursion": {"time": {"avg": "0.1", "median": "0.1"}},
					"tcpusage": "0"
				},
				"time": {"now": "1700000000", "up": "100", "elapsed": "100"},
				"histogram": [
					{"from": [0, 0], "to": [0, 1024], "value": "5"},
					{"from": [0, 4096], "to": [0, 8192], "value": "5"}
				]
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchUnboundOverview()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.RecursionHistogram.Present {
		t.Errorf("a histogram whose buckets leave a gap must not be published, got %+v",
			data.RecursionHistogram)
	}
}
