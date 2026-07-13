package opnsense

import (
	"net/http"
	"testing"
)

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
					}
				},
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
