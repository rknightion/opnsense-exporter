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

	_, err := client.FetchUnboundOverview()
	if err == nil {
		t.Fatal("expected error for invalid uptime string")
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

func TestFetchUnboundBlockListStatus_Success(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected bool
	}{
		{"Enabled", `{"enabled": true}`, true},
		{"Disabled", `{"enabled": false}`, false},
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
