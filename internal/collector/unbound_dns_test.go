package collector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// unboundTotalsPattern registers the api/unbound/overview/totals handler as a
// SUBTREE pattern rather than an exact path. The {max} row limit is baked into the
// endpoint URL in opnsense/client.go, and #587 raises it from 1 to the leaderboard
// cap; an exact "/api/unbound/overview/totals/1" pattern would start 404ing every
// totals call the moment that lands, and each of these tests would silently begin
// asserting against an empty payload instead of failing on the real change. The
// sibling overview endpoints stay on exact patterns, which ServeMux prefers over
// this prefix.
const unboundTotalsPattern = "/api/unbound/overview/totals/"

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
					"rrset": {"bogus": "0"},
					"valops": "640"
				},
				"histogram": [
					{"from": [0, 0], "to": [0, 1024], "value": "0"},
					{"from": [0, 1024], "to": [0, 2048], "value": "120"},
					{"from": [0, 2048], "to": [0, 4096], "value": "70"}
				],
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

	mux.HandleFunc("/api/unbound/overview/get_policies", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"1c9c5d5e-0000-0000-0000-000000000001":{"enabled":"1","description":"test policy"}}`))
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
	// 4 base-stat drop/limit counters (#237: queriesDiscardTimeout, queriesWaitLimit,
	//    queriesReplyAddrLimit, dnsErrorReports)
	// 14 queriesByType (A, SOA, PTR, MX, TXT, AAAA, SRV, SVCB, HTTPS, NS, CNAME, NAPTR, DNSKEY, ANY)
	// 6 queriesByProto (tcp, tcpout, udpout, tls, ipv6, https)
	// 7 answersByRcode (NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMPL, REFUSED, nodata)
	// 2 unwanted (queries, replies)
	// 8 queryFlags (QR, AA, TC, RD, RA, Z, AD, CD)
	// 2 edns (present, DO)
	// 4 gauges without labels (requestListAvg, requestListMax, recursionTimeAvg, recursionTimeMedian)
	// 4 cacheCount (rrset, message, infra, key)
	// 6 memoryBytes (rrset_cache, message_cache, iterator, validator, respip, streamwait)
	// 3 requestListCurrent (all, user, replies (#237))
	// 2 requestListOverwritten, requestListExceeded
	// 1 tcpUsage
	// 1 blocklistEnabled
	// 1 serviceRunning
	// 1 validationOperations (#581, extended-only like the DNSSEC counters above)
	// 1 recursionHistogram (#581, one histogram metric carrying all its buckets)
	// Total: 1+11+4+14+6+7+2+8+2+4+4+6+3+2+1+1+1+1+1 = 79
	expectedCount := 79
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
	mux.HandleFunc("/api/unbound/overview/get_policies", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"1c9c5d5e-0000-0000-0000-000000000001":{"enabled":"1","description":"test policy"}}`))
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
		"opnsense_unbound_dns_queries_discard_timeout_total",
		"opnsense_unbound_dns_queries_wait_limit_total",
		"opnsense_unbound_dns_queries_replyaddr_limit_total",
		"opnsense_unbound_dns_dns_error_reports_total",
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
	if got := metricsByDesc(metrics, "opnsense_unbound_dns_request_list_current"); len(got) != 3 {
		t.Errorf("expected 3 request_list_current series (all, user, replies (#237)), got %d", len(got))
	}

	// 1 uptime + 8 base counters + 4 base-stat drop/limit counters (#237)
	// + 4 base gauges + 3 request_list_current (#237 adds replies)
	// + 2 request-list counters + tcp_usage + blocklist + service_running = 25
	if len(metrics) != 25 {
		t.Errorf("expected 25 metrics on a base-stats-only box, got %d", len(metrics))
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

// unboundQStatsMuxHandlers registers the #209 query-stats + local-data
// endpoints on top of unboundTestMux. enabled controls the is_enabled reply.
func unboundQStatsMuxHandlers(t *testing.T, mux *http.ServeMux, enabled bool, totalsCalled *bool) {
	t.Helper()

	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		if enabled {
			w.Write([]byte(`{"enabled":"1"}`))
		} else {
			w.Write([]byte(`{"enabled":"0"}`))
		}
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		if totalsCalled != nil {
			*totalsCalled = true
		}
		w.Write([]byte(`{"total":16236,"blocklist_size":528587,"passed":10396,"resolved":{"total":3197,"pcnt":"19.69"},"blocked":{"total":13,"pcnt":"0.08"},"local":{"total":145,"pcnt":"0.89"},"start_time":1783872391,"top":{"example.com.":{"total":2780,"pcnt":"26.74"},"news.example.":{"total":41,"pcnt":"0.39"}},"top_blocked":{"ade.googlesyndication.com.":{"total":4,"pcnt":"30.77","blocklist":"AdGuard List","latest_policy_uuid":"6b882f48-abe5-4a80-9670-5d7a6b81c66f","category":"General Blocklists"}}}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocalzones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[{"zone":"home.arpa.","type":"static"},{"zone":"example.lan","type":"transparent"}]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocaldata", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[{"name":"home.arpa.","ttl":"10800","type":"IN","rrtype":"NS","value":"localhost."}]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listinsecure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[""]}`))
	})
}

// TestUnboundDNSCollector_Update_QStatsDisabledByDefault guards #209 the same
// way infra does: without --exporter.enable-unbound-qstats, none of the new
// endpoints should be called and none of the new series emitted.
func TestUnboundDNSCollector_Update_QStatsDisabledByDefault(t *testing.T) {
	mux := unboundTestMux(t)
	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		t.Error("is_enabled must not be called when qstats metrics are disabled")
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		t.Error("totals must not be called when qstats metrics are disabled")
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocalzones", func(w http.ResponseWriter, r *http.Request) {
		t.Error("listlocalzones must not be called when qstats metrics are disabled")
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	for _, name := range []string{
		"opnsense_unbound_dns_qstats_enabled",
		"opnsense_unbound_dns_dnsbl_blocklist_size",
		"opnsense_unbound_dns_qstats_queries_7d",
		"opnsense_unbound_dns_qstats_queries_total_7d",
		"opnsense_unbound_dns_qstats_start_time_seconds",
		"opnsense_unbound_dns_local_zones",
		"opnsense_unbound_dns_local_data_records",
		"opnsense_unbound_dns_insecure_domains",
	} {
		if got := metricsByDesc(metrics, name); len(got) != 0 {
			t.Errorf("expected no %s metrics by default, got %d", name, len(got))
		}
	}
}

// TestUnboundDNSCollector_Update_QStatsEnabled_StatsOff covers the #90-style
// gate: when qstats metrics are opted in but the box has query-stats logging
// off, only qstats_enabled=0 should be emitted — the expensive totals call
// must be skipped entirely (never call it just to throw away a zero).
func TestUnboundDNSCollector_Update_QStatsEnabled_StatsOff(t *testing.T) {
	mux := unboundTestMux(t)
	var totalsCalled bool
	unboundQStatsMuxHandlers(t, mux, false, &totalsCalled)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetQStatsEnabled(true)
	metrics := collectMetrics(t, c, client)

	if totalsCalled {
		t.Error("expected the expensive totals endpoint NOT to be called when stats logging is off")
	}

	qe := metricsByDesc(metrics, "opnsense_unbound_dns_qstats_enabled")
	if len(qe) != 1 {
		t.Fatalf("expected exactly 1 qstats_enabled metric, got %d", len(qe))
	}
	if got := getMetricValue(qe[0]); got != 0 {
		t.Errorf("expected qstats_enabled=0, got %v", got)
	}

	for _, name := range []string{
		"opnsense_unbound_dns_dnsbl_blocklist_size",
		"opnsense_unbound_dns_qstats_queries_7d",
		"opnsense_unbound_dns_qstats_queries_total_7d",
		"opnsense_unbound_dns_qstats_start_time_seconds",
	} {
		if got := metricsByDesc(metrics, name); len(got) != 0 {
			t.Errorf("expected no %s metrics when stats logging is off, got %d", name, len(got))
		}
	}

	// Rider metrics are independent of query-stats logging and should still emit.
	if got := metricsByDesc(metrics, "opnsense_unbound_dns_local_zones"); len(got) != 2 {
		t.Errorf("expected 2 local_zones metrics, got %d", len(got))
	}
}

// TestUnboundDNSCollector_Update_QStatsEnabled_Full covers the fully-enabled
// path with the real captured payload values (#209).
func TestUnboundDNSCollector_Update_QStatsEnabled_Full(t *testing.T) {
	mux := unboundTestMux(t)
	unboundQStatsMuxHandlers(t, mux, true, nil)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetQStatsEnabled(true)
	metrics := collectMetrics(t, c, client)

	qe := metricsByDesc(metrics, "opnsense_unbound_dns_qstats_enabled")
	if len(qe) != 1 || getMetricValue(qe[0]) != 1 {
		t.Errorf("expected qstats_enabled=1, got %v", qe)
	}

	blocklistSize := metricsByDesc(metrics, "opnsense_unbound_dns_dnsbl_blocklist_size")
	if len(blocklistSize) != 1 || getMetricValue(blocklistSize[0]) != 528587 {
		t.Errorf("expected dnsbl_blocklist_size=528587, got %v", blocklistSize)
	}

	total7d := metricsByDesc(metrics, "opnsense_unbound_dns_qstats_queries_total_7d")
	if len(total7d) != 1 || getMetricValue(total7d[0]) != 16236 {
		t.Errorf("expected qstats_queries_total_7d=16236, got %v", total7d)
	}

	startTime := metricsByDesc(metrics, "opnsense_unbound_dns_qstats_start_time_seconds")
	if len(startTime) != 1 || getMetricValue(startTime[0]) != 1783872391 {
		t.Errorf("expected qstats_start_time_seconds=1783872391, got %v", startTime)
	}

	byResult := metricsByDesc(metrics, "opnsense_unbound_dns_qstats_queries_7d")
	if len(byResult) != 4 {
		t.Fatalf("expected 4 qstats_queries_7d series (passed/resolved/blocked/local), got %d", len(byResult))
	}
	want := map[string]float64{"passed": 10396, "resolved": 3197, "blocked": 13, "local": 145}
	got := map[string]float64{}
	for _, m := range byResult {
		labels := getMetricLabels(m)
		got[labels["result"]] = getMetricValue(m)
	}
	for result, expected := range want {
		if got[result] != expected {
			t.Errorf("expected result=%s to be %v, got %v", result, expected, got[result])
		}
	}

	// Rider metrics: 2 zone types from unboundQStatsMuxHandlers's fixture.
	zones := metricsByDesc(metrics, "opnsense_unbound_dns_local_zones")
	if len(zones) != 2 {
		t.Fatalf("expected 2 local_zones series, got %d", len(zones))
	}
	localData := metricsByDesc(metrics, "opnsense_unbound_dns_local_data_records")
	if len(localData) != 1 || getMetricValue(localData[0]) != 1 {
		t.Errorf("expected local_data_records=1, got %v", localData)
	}
	insecure := metricsByDesc(metrics, "opnsense_unbound_dns_insecure_domains")
	if len(insecure) != 1 || getMetricValue(insecure[0]) != 0 {
		t.Errorf("expected insecure_domains=0 (degenerate single-empty-string shape), got %v", insecure)
	}
}

// --- #581: infra host health flags -------------------------------------------

// unboundInfraHealthPayload is one healthy and one thoroughly broken upstream, in
// the shape wrapper.py produces from unbound's dump_infra line. Both carry the
// literal "lame": true, because every dump_infra record does.
const unboundInfraHealthPayload = `{"status":"ok","data":[
	{"ip":"1.1.1.1","host":"example.com.","ttl":"900","rtt":"70","rto":"376",
	 "ednsknown":"1","edns":"0","lame":true,"dnssec":"0","rec":"0","A":"0","other":"0"},
	{"ip":"9.9.9.9","host":"broken.example.","ttl":"900","rtt":"400","rto":"1200",
	 "ednsknown":"1","edns":"-1","lame":true,"dnssec":"1","rec":"1","A":"1","other":"0"}
]}`

// TestUnboundDNSCollector_InfraHealthFlags checks the operator scenario #581 was
// filed for: an upstream unbound has quietly stopped trusting, whose RTT still
// looks perfect precisely BECAUSE unbound stopped asking it. The lameness kinds
// must arrive as separate series, and a healthy host must read 0 rather than being
// omitted — a missing series and a healthy one are the same picture on a graph,
// and only one of them is true.
func TestUnboundDNSCollector_InfraHealthFlags(t *testing.T) {
	mux := unboundTestMux(t)
	mux.HandleFunc("/api/unbound/diagnostics/dumpinfra", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(unboundInfraHealthPayload))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetInfraEnabled(true)
	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	lame := metricsByDesc(metrics, "opnsense_unbound_dns_infra_host_lame")
	// 2 hosts x 3 lameness kinds.
	if len(lame) != 6 {
		t.Fatalf("expected 6 infra_host_lame series (2 hosts x 3 kinds), got %d", len(lame))
	}
	want := map[string]float64{
		"1.1.1.1|recursion": 0, "1.1.1.1|type_a": 0, "1.1.1.1|other": 0,
		"9.9.9.9|recursion": 1, "9.9.9.9|type_a": 1, "9.9.9.9|other": 0,
	}
	for _, m := range lame {
		d := &dto.Metric{}
		if err := m.Write(d); err != nil {
			t.Fatalf("write: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range d.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		key := labels["ip"] + "|" + labels["kind"]
		expected, ok := want[key]
		if !ok {
			t.Errorf("unexpected infra_host_lame series %s", key)
			continue
		}
		if got := d.GetGauge().GetValue(); got != expected {
			t.Errorf("infra_host_lame{%s}: expected %v, got %v", key, expected, got)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing infra_host_lame series: %v", want)
	}

	for name, byIP := range map[string]map[string]float64{
		"opnsense_unbound_dns_infra_host_dnssec_lame": {"1.1.1.1": 0, "9.9.9.9": 1},
		"opnsense_unbound_dns_infra_host_edns_broken": {"1.1.1.1": 0, "9.9.9.9": 1},
	} {
		series := metricsByDesc(metrics, name)
		if len(series) != len(byIP) {
			t.Errorf("expected %d %s series, got %d", len(byIP), name, len(series))
		}
		for _, m := range series {
			d := &dto.Metric{}
			_ = m.Write(d)
			var ip string
			for _, lp := range d.GetLabel() {
				if lp.GetName() == "ip" {
					ip = lp.GetValue()
				}
			}
			if got := d.GetGauge().GetValue(); got != byIP[ip] {
				t.Errorf("%s{ip=%q}: expected %v, got %v", name, ip, byIP[ip], got)
			}
		}
	}
}

// TestUnboundDNSCollector_InfraHealthFlagsGatedWithRTT keeps the health flags on
// the same opt-in switch as the timing series they explain. They are per-upstream,
// so they scale with the infra cache exactly like infra_rtt_seconds does; letting
// them default on would quietly reintroduce the cardinality --exporter.enable-
// unbound-infra exists to keep opt-in.
func TestUnboundDNSCollector_InfraHealthFlagsGatedWithRTT(t *testing.T) {
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

	for _, name := range []string{
		"opnsense_unbound_dns_infra_host_lame",
		"opnsense_unbound_dns_infra_host_dnssec_lame",
		"opnsense_unbound_dns_infra_host_edns_broken",
	} {
		if got := metricsByDesc(metrics, name); len(got) != 0 {
			t.Errorf("expected no %s series without --exporter.enable-unbound-infra, got %d", name, len(got))
		}
	}
}

// --- #581: reply-time histogram ----------------------------------------------

// TestUnboundDNSCollector_RecursionHistogram checks the collector ships a REAL
// Prometheus histogram — cumulative _bucket counts plus _sum and _count — rather
// than a pile of per-bucket gauges. histogram_quantile() is the entire point of
// the metric and it reads nothing else.
func TestUnboundDNSCollector_RecursionHistogram(t *testing.T) {
	mux := unboundTestMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)

	series := metricsByDesc(metrics, "opnsense_unbound_dns_recursion_time_seconds")
	if len(series) != 1 {
		t.Fatalf("expected exactly 1 recursion_time_seconds histogram, got %d", len(series))
	}
	d := &dto.Metric{}
	if err := series[0].Write(d); err != nil {
		t.Fatalf("write: %v", err)
	}
	h := d.GetHistogram()
	if h == nil {
		t.Fatal("recursion_time_seconds must be emitted as a histogram (TYPE histogram), not a gauge")
	}
	// Fixture buckets are 0, 120, 70 -> cumulative 0, 120, 190.
	if h.GetSampleCount() != 190 {
		t.Errorf("expected sample count 190, got %d", h.GetSampleCount())
	}
	wantCumulative := map[float64]uint64{0.001024: 0, 0.002048: 120, 0.004096: 190}
	if len(h.GetBucket()) != len(wantCumulative) {
		t.Fatalf("expected %d buckets, got %d", len(wantCumulative), len(h.GetBucket()))
	}
	for _, b := range h.GetBucket() {
		want, ok := wantCumulative[b.GetUpperBound()]
		if !ok {
			t.Errorf("unexpected bucket le=%g", b.GetUpperBound())
			continue
		}
		if b.GetCumulativeCount() != want {
			t.Errorf("bucket le=%g: expected cumulative %d, got %d",
				b.GetUpperBound(), want, b.GetCumulativeCount())
		}
	}
	// avg 0.012s x 190 replies. Guard the two failure modes that read as valid
	// data downstream: a zero sum (average latency graphs flatline at 0s) and a
	// sum in milliseconds (out by 1000, and nothing says so).
	if want := 0.012 * 190; h.GetSampleSum() < want-1e-9 || h.GetSampleSum() > want+1e-9 {
		t.Errorf("expected sample sum %v (avg 0.012s x 190), got %v", want, h.GetSampleSum())
	}
}

// TestUnboundDNSCollector_RecursionHistogramAbsent is the box-state path and the
// default on OPNsense 26.7: with `extended-statistics: no` the payload has no
// data.histogram, and the metric must simply not exist. An all-zero 40-bucket
// histogram would publish a sub-microsecond p99 for a resolver nobody is
// measuring — the same class of lie as #90's zero counters, on a metric operators
// would page on.
func TestUnboundDNSCollector_RecursionHistogramAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/unbound/diagnostics/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"status": "ok",
			"data": {
				"total": {
					"num": {"queries": "4321", "cachehits": "3000", "cachemiss": "1321", "recursivereplies": "1300"},
					"requestlist": {"avg": "2.25", "max": "17", "overwritten": "4", "exceeded": "1",
						"current": {"all": "6", "user": "2", "replies": "4"}},
					"recursion": {"time": {"avg": "0.031", "median": "0.019"}},
					"tcpusage": "0.75"
				},
				"time": {"now": "1800000000", "up": "12345.5", "elapsed": "12345.5"}
			}
		}`))
	})
	mux.HandleFunc("/api/unbound/overview/get_policies", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
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

	if got := metricsByDesc(metrics, "opnsense_unbound_dns_recursion_time_seconds"); len(got) != 0 {
		t.Errorf("expected no recursion_time_seconds histogram when the box omits data.histogram, got %d", len(got))
	}
	if got := metricsByDesc(metrics, "opnsense_unbound_dns_validation_operations_total"); len(got) != 0 {
		t.Errorf("expected no validation_operations_total when extended statistics are absent, got %d", len(got))
	}
}

// --- #587: top / top_blocked domain leaderboards ------------------------------

// TestUnboundDNSCollector_TopDomainLeaderboards covers the headline pi-hole number
// #587 reopened #209 for. One metric with a result label rather than two metrics,
// mirroring the sibling qstats_queries_7d{result} it is the per-domain breakdown of.
func TestUnboundDNSCollector_TopDomainLeaderboards(t *testing.T) {
	mux := unboundTestMux(t)
	unboundQStatsMuxHandlers(t, mux, true, nil)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetQStatsEnabled(true)
	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	got := map[string]float64{}
	for _, m := range metricsByDesc(metrics, "opnsense_unbound_dns_qstats_top_domain_queries_7d") {
		d := &dto.Metric{}
		_ = m.Write(d)
		labels := map[string]string{}
		for _, lp := range d.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if d.GetGauge() == nil {
			t.Fatalf("leaderboard series must be a gauge: the qstats window is truncated hourly "+
				"and a reset would read as a counter rollover on every domain at once (%v)", labels)
		}
		got[labels["result"]+"|"+labels["domain"]] = d.GetGauge().GetValue()
	}
	want := map[string]float64{
		"passed|example.com.":                2780,
		"passed|news.example.":               41,
		"blocked|ade.googlesyndication.com.": 4,
	}
	for key, v := range want {
		if got[key] != v {
			t.Errorf("expected %s = %v, got %v", key, v, got[key])
		}
	}
	if len(got) != len(want) {
		t.Errorf("expected %d leaderboard series, got %d (%v)", len(want), len(got), got)
	}

	// The refusal counter must exist from the first scrape, at zero. A counter that
	// only appears once it is non-zero cannot be alerted on with rate() and reads as
	// a fresh series (i.e. a reset) the moment it does appear.
	capped := metricsByDesc(metrics, "opnsense_unbound_dns_cardinality_capped_total")
	if len(capped) != 2 {
		t.Fatalf("expected a cardinality_capped_total series per leaderboard family, got %d", len(capped))
	}
	assertMetricsAreCounters(t, metrics, "opnsense_unbound_dns_cardinality_capped_total")
}

// TestUnboundDNSCollector_TopDomainsCapped is the cardinality control #209
// rejected these metrics for want of. It drives more distinct domains at the
// collector than the cap allows and requires both that the series set stops
// growing AND that the overflow is COUNTED — a quietly truncated leaderboard is
// indistinguishable from a quiet network, which is precisely how DNS-tunnelling
// traffic would hide.
func TestUnboundDNSCollector_TopDomainsCapped(t *testing.T) {
	const cap = 3
	mux := unboundTestMux(t)
	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total":10,"blocklist_size":0,"passed":10,"resolved":{"total":10},
			"blocked":{"total":0},"local":{"total":0},"start_time":1,
			"top":{"a.":{"total":5},"b.":{"total":4},"c.":{"total":3},"d.":{"total":2},"e.":{"total":1}},
			"top_blocked":[]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocalzones", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listlocaldata", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[]}`))
	})
	mux.HandleFunc("/api/unbound/diagnostics/listinsecure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[""]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetQStatsEnabled(true)
	c.setTopDomainBounds(cap, time.Hour)
	metrics := collectMetrics(t, c, client)

	if got := len(metricsByDesc(metrics, "opnsense_unbound_dns_qstats_top_domain_queries_7d")); got != cap {
		t.Errorf("expected the leaderboard to stop at the %d-key cap, got %d series", cap, got)
	}
	for _, m := range metricsByDesc(metrics, "opnsense_unbound_dns_cardinality_capped_total") {
		d := &dto.Metric{}
		_ = m.Write(d)
		var family string
		for _, lp := range d.GetLabel() {
			if lp.GetName() == "family" {
				family = lp.GetValue()
			}
		}
		if family != "top_domain_passed" {
			continue
		}
		if got := d.GetCounter().GetValue(); got != 2 {
			t.Errorf("expected 2 refusals recorded for the 5-domain payload at a %d cap, got %v", cap, got)
		}
	}
}

// TestUnboundDNSCollector_TopDomainsRetired pins the half of the bound that is easy
// to leave out and impossible to notice: expiry has to hand its budget slot BACK.
// Without it the first burst of domains owns the inventory for the life of the
// process and a genuinely new top domain never appears again — the leaderboard
// would freeze on whatever the exporter happened to see at startup.
func TestUnboundDNSCollector_TopDomainsRetired(t *testing.T) {
	payload := `{"total":1,"blocklist_size":0,"passed":1,"resolved":{"total":1},
		"blocked":{"total":0},"local":{"total":0},"start_time":1,
		"top":{"%s":{"total":5}},"top_blocked":[]}`
	domain := "first."

	mux := unboundTestMux(t)
	mux.HandleFunc("/api/unbound/overview/is_enabled", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"enabled":"1"}`))
	})
	mux.HandleFunc(unboundTotalsPattern, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, payload, domain)
	})
	for _, p := range []string{"listlocalzones", "listlocaldata"} {
		mux.HandleFunc("/api/unbound/diagnostics/"+p, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":[]}`))
		})
	}
	mux.HandleFunc("/api/unbound/diagnostics/listinsecure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":[""]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := newCollectorTestClient(t, server)

	now := time.Unix(1700000000, 0)
	c := &unboundDNSCollector{subsystem: UnboundDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	c.SetQStatsEnabled(true)
	// A cap of one, so the second domain can only be admitted if the first freed
	// its slot.
	c.setTopDomainBounds(1, 5*time.Minute)
	c.now = func() time.Time { return now }

	collectMetrics(t, c, client)

	domain = "second."
	now = now.Add(6 * time.Minute)
	metrics := collectMetrics(t, c, client)

	series := metricsByDesc(metrics, "opnsense_unbound_dns_qstats_top_domain_queries_7d")
	if len(series) != 1 {
		t.Fatalf("expected exactly 1 leaderboard series after retirement, got %d", len(series))
	}
	d := &dto.Metric{}
	_ = series[0].Write(d)
	for _, lp := range d.GetLabel() {
		if lp.GetName() == "domain" && lp.GetValue() != "second." {
			t.Errorf("expected the retired domain's budget slot to be reused by %q, still holding %q",
				"second.", lp.GetValue())
		}
	}
}
