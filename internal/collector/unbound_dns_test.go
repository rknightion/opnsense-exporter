package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

// unboundTestMux registers the stats, blocklist and service-status handlers
// shared by all unbound collector tests.
func unboundTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
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

	return mux
}

func TestUnboundDNSCollector_Update(t *testing.T) {
	mux := unboundTestMux(t)

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

// TestUnboundDNSCollector_Update_StatsUnavailable guards #90: when unbound-control
// is unreachable ({"status":"failed"}), the collector must not emit the ~60 zero
// stats series. Only the running-state signal should be emitted.
func TestUnboundDNSCollector_Update_StatsUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/unbound/diagnostics/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "failed"}`))
	})
	mux.HandleFunc("/api/unbound/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "stopped"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Only service_running should be emitted; no uptime/cache/counter series.
	if len(metrics) != 1 {
		t.Fatalf("expected only 1 metric (service_running) when unbound-control unavailable, got %d", len(metrics))
	}
	if !strings.Contains(metrics[0].Desc().String(), "service_running") {
		t.Errorf("expected the sole metric to be service_running, got %s", metrics[0].Desc().String())
	}
}

// TestUnboundDNSCollector_Update_ExtendedStatsAbsent covers the OPNsense 26.7
// default (`extended-statistics: no`): the stats payload carries only
// data.total/data.time/data.threadN. Every series sourced from an extended
// section must be skipped — emitting them as zeros would read as real
// zero-traffic and corrupt rate(), the same failure class as #90. The base
// series (totals, request list, recursion, tcpusage, uptime) must still be emitted.
func TestUnboundDNSCollector_Update_ExtendedStatsAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/unbound/diagnostics/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {
						"queries": "4321",
						"queries_ip_ratelimited": "3",
						"cachehits": "3000",
						"cachemiss": "1321",
						"prefetch": "40",
						"queries_timed_out": "7",
						"expired": "11",
						"recursivereplies": "1300"
					},
					"query": {"queue_time_us": {"max": "12"}},
					"requestlist": {
						"avg": "2.25", "max": "17", "overwritten": "4", "exceeded": "1",
						"current": {"all": "6", "user": "2", "replies": "4"}
					},
					"recursion": {"time": {"avg": "0.031", "median": "0.019"}},
					"tcpusage": "0.75"
				},
				"time": {"now": "1800000000", "up": "12345.5", "elapsed": "12345.5"},
				"thread0": {
					"num": {"queries": "1100", "cachehits": "700", "cachemiss": "400"},
					"requestlist": {"avg": "2.0", "max": "5", "current": {"all": "2", "user": "1", "replies": "1"}},
					"recursion": {"time": {"avg": "0.030", "median": "0.018"}},
					"tcpusage": "0.20"
				},
				"thread1": {
					"num": {"queries": "1080", "cachehits": "760", "cachemiss": "320"},
					"requestlist": {"avg": "2.1", "max": "4", "current": {"all": "1", "user": "0", "replies": "1"}},
					"recursion": {"time": {"avg": "0.032", "median": "0.020"}},
					"tcpusage": "0.18"
				}
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

	// No series sourced from an absent extended section may be emitted.
	extendedOnly := []string{
		"opnsense_unbound_dns_queries_by_type_total",
		"opnsense_unbound_dns_queries_by_protocol_total",
		"opnsense_unbound_dns_answers_by_rcode_total",
		"opnsense_unbound_dns_query_flags_total",
		"opnsense_unbound_dns_edns_total",
		"opnsense_unbound_dns_unwanted_total",
		"opnsense_unbound_dns_answers_secure_total",
		"opnsense_unbound_dns_answers_bogus_total",
		"opnsense_unbound_dns_rrset_bogus_total",
		"opnsense_unbound_dns_cache_count",
		"opnsense_unbound_dns_memory_bytes",
	}
	for _, name := range extendedOnly {
		if got := metricsByDesc(metrics, name); len(got) != 0 {
			t.Errorf("expected no %s series when extended stats are absent, got %d", name, len(got))
		}
	}

	// The base series must still be there.
	baseSeries := []string{
		"opnsense_unbound_dns_uptime_seconds",
		"opnsense_unbound_dns_queries_total",
		"opnsense_unbound_dns_cache_hits_total",
		"opnsense_unbound_dns_cache_miss_total",
		"opnsense_unbound_dns_prefetch_total",
		"opnsense_unbound_dns_expired_total",
		"opnsense_unbound_dns_recursive_replies_total",
		"opnsense_unbound_dns_queries_timed_out_total",
		"opnsense_unbound_dns_queries_ip_ratelimited_total",
		"opnsense_unbound_dns_request_list_avg",
		"opnsense_unbound_dns_request_list_max",
		"opnsense_unbound_dns_request_list_overwritten_total",
		"opnsense_unbound_dns_request_list_exceeded_total",
		"opnsense_unbound_dns_recursion_time_avg_seconds",
		"opnsense_unbound_dns_recursion_time_median_seconds",
		"opnsense_unbound_dns_tcp_usage_ratio",
		"opnsense_unbound_dns_blocklist_enabled",
		"opnsense_unbound_dns_service_running",
	}
	for _, name := range baseSeries {
		if got := metricsByDesc(metrics, name); len(got) == 0 {
			t.Errorf("expected %s to still be emitted when only extended stats are absent", name)
		}
	}
	if got := metricsByDesc(metrics, "opnsense_unbound_dns_request_list_current"); len(got) != 2 {
		t.Errorf("expected 2 request_list_current series (all, user), got %d", len(got))
	}

	// 1 uptime + 8 base counters + 4 base gauges + 2 request_list_current
	// + 2 request-list counters + tcp_usage + blocklist + service_running = 20
	if len(metrics) != 20 {
		t.Errorf("expected 20 metrics on a base-stats-only box, got %d", len(metrics))
	}

	if got := getMetricValue(metricsByDesc(metrics, "opnsense_unbound_dns_queries_total")[0]); got != 4321 {
		t.Errorf("expected queries_total=4321, got %v", got)
	}
}

func TestUnboundDNSCollector_Name(t *testing.T) {
	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	if c.Name() != UnboundDNSSubsystem {
		t.Errorf("expected %s, got %s", UnboundDNSSubsystem, c.Name())
	}
}

func TestUnboundDNSCollector_Update_InfraEnabled(t *testing.T) {
	mux := unboundTestMux(t)
	mux.HandleFunc("/api/unbound/diagnostics/dumpinfra", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": [
				{"ip": "203.0.113.53@853", "host": ".", "rtt": "225", "rto": "450", "ttl": "626", "lame": true}
			]
		}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetInfraEnabled(true)
	metrics := collectMetrics(t, c, client)

	rtts := metricsByDesc(metrics, "opnsense_unbound_dns_infra_rtt_seconds")
	if len(rtts) != 1 {
		t.Fatalf("expected 1 infra rtt metric, got %d", len(rtts))
	}
	labels := getMetricLabels(rtts[0])
	if labels["ip"] != "203.0.113.53@853" || labels["host"] != "." {
		t.Errorf("unexpected labels: %v", labels)
	}
	if got := getMetricValue(rtts[0]); got != 0.225 {
		t.Errorf("expected rtt 0.225s, got %v", got)
	}

	rtos := metricsByDesc(metrics, "opnsense_unbound_dns_infra_rto_seconds")
	if len(rtos) != 1 {
		t.Fatalf("expected 1 infra rto metric, got %d", len(rtos))
	}
	if got := getMetricValue(rtos[0]); got != 0.45 {
		t.Errorf("expected rto 0.45s, got %v", got)
	}
}

func TestUnboundDNSCollector_Update_InfraDisabledByDefault(t *testing.T) {
	mux := unboundTestMux(t)
	mux.HandleFunc("/api/unbound/diagnostics/dumpinfra", func(w http.ResponseWriter, r *http.Request) {
		t.Error("dumpinfra must not be called when infra metrics are disabled")
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	if got := metricsByDesc(metrics, "opnsense_unbound_dns_infra_rtt_seconds"); len(got) != 0 {
		t.Errorf("expected no infra metrics by default, got %d", len(got))
	}
}
