package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestUnboundDNSCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/unbound/diagnostics/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {
						"queries": "1000",
						"queries_ip_ratelimited": "5",
						"queries_cookie_valid": "0",
						"queries_cookie_client": "0",
						"queries_cookie_invalid": "0",
						"cachehits": "800",
						"cachemiss": "200",
						"prefetch": "10",
						"queries_timed_out": "2",
						"expired": "1",
						"recursivereplies": "190",
						"queries_discard_timeout": "0",
						"queries_wait_limit": "0",
						"dns_error_reports": "0",
						"dnscrypt": {"crypted":"0","cert":"0","cleartext":"0","malformed":"0"}
					},
					"query": {
						"queue_time_us": {"max": "0"}
					},
					"requestlist": {
						"avg": "0.5",
						"max": "10",
						"overwritten": "0",
						"exceeded": "0",
						"current": {"all": "1", "user": "0"}
					},
					"recursion": {
						"time": {"avg": "0.012", "median": "0.008"}
					},
					"tcpusage": "0.01"
				},
				"time": {
					"now": "1700000000",
					"up": "86400.5",
					"elapsed": "86400"
				},
				"mem": {
					"cache": {
						"rrset": "1048576",
						"message": "524288",
						"dnscrypt_shared_secret": "0",
						"dnscrypt_nonce": "0"
					},
					"mod": {
						"iterator": "16384",
						"validator": "65536",
						"respip": "0",
						"dynlibmod": "0"
					},
					"streamwait": "0",
					"http": {"query_buffer":"0","response_buffer":"0"}
				},
				"num": {
					"query": {
						"type": {
							"A": "500",
							"SOA": "10",
							"PTR": "50",
							"MX": "5",
							"TXT": "20",
							"AAAA": "300",
							"SRV": "5",
							"SVCB": "0",
							"HTTPS": "100",
							"NS": "5",
							"CNAME": "0",
							"NAPTR": "0",
							"DNSKEY": "5",
							"ANY": "0"
						},
						"class": {"IN": "1000"},
						"opcode": {"QUERY": "1000"},
						"tcp": "50",
						"tcpout": "10",
						"udpout": "180",
						"tls": {"__value__": "0", "resume": "0"},
						"ipv6": "100",
						"https": "0",
						"flags": {
							"QR": "0",
							"AA": "0",
							"TC": "0",
							"RD": "1000",
							"RA": "0",
							"Z": "0",
							"AD": "50",
							"CD": "0"
						},
						"edns": {"present": "900", "DO": "50"},
						"ratelimited": "0",
						"aggressive": {"NOERROR":"0","NXDOMAIN":"0"},
						"dnscrypt": {"shared_secret":{"cachemiss":"0"},"replay":"0"},
						"authzone": {"up":"0","down":"0"}
					},
					"answer": {
						"rcode": {
							"NOERROR": "900",
							"FORMERR": "0",
							"SERVFAIL": "10",
							"NXDOMAIN": "80",
							"NOTIMPL": "0",
							"REFUSED": "10",
							"nodata": "0"
						},
						"secure": "100",
						"bogus": "0"
					},
					"rrset": {"bogus": "0"}
				},
				"unwanted": {
					"queries": "0",
					"replies": "0"
				},
				"msg": {"cache": {"count": "500", "max_collisions": "0"}},
				"rrset": {"cache": {"count": "1000", "max_collisions": "0"}},
				"infra": {"cache": {"count": "50"}},
				"key": {"cache": {"count": "10"}},
				"dnscrypt_shared_secret": {"cache": {"count": "0"}},
				"dnscrypt_nonce": {"cache": {"count": "0"}}
			}
		}`))
	})

	mux.HandleFunc("/api/unbound/overview/isBlockListEnabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled": true}`))
	})

	mux.HandleFunc("/api/unbound/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "running"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Count expected metrics:
	// 1 uptime
	// 11 counters without labels (queriesTotal, cacheHits, cacheMiss, prefetch, expired,
	//    recursiveReplies, queriesTimedOut, queriesIPRatelimited, answersSecure, answersBogus, rrsetBogus)
	// 14 queriesByType (A, SOA, PTR, MX, TXT, AAAA, SRV, SVCB, HTTPS, NS, CNAME, NAPTR, DNSKEY, ANY)
	// 6 queriesByProto (tcp, tcpout, udpout, tls, ipv6, https)
	// 7 answersByRcode (NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMPL, REFUSED, nodata)
	// 2 unwanted (queries, replies)
	// 8 queryFlags (QR, AA, TC, RD, RA, Z, AD, CD)
	// 2 edns (present, DO)
	// 4 gauges without labels (requestListAvg, requestListMax, recursionTimeAvg, recursionTimeMedian)
	// 4 cacheCount (rrset, message, infra, key)
	// 6 memoryBytes (rrset_cache, message_cache, iterator, validator, respip, streamwait)
	// 2 requestListCurrent (all, user)
	// 2 requestListOverwritten, requestListExceeded
	// 1 tcpUsage
	// 1 blocklistEnabled
	// 1 serviceRunning
	// Total: 1+11+14+6+7+2+8+2+4+4+6+2+2+1+1+1 = 72
	expectedCount := 72
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestUnboundDNSCollector_Name(t *testing.T) {
	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	if c.Name() != UnboundDNSSubsystem {
		t.Errorf("expected %s, got %s", UnboundDNSSubsystem, c.Name())
	}
}
