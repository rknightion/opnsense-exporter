package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

func TestProtocolCollector_Update(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"statistics": {
				"tcp": {
					"sent-packets": 10000,
					"sent-data-packets": 8000,
					"sent-data-bytes": 5242880,
					"sent-retransmitted-packets": 50,
					"sent-retransmitted-bytes": 32768,
					"sent-unnecessary-retransmitted-packets": 0,
					"sent-resends-by-mtu-discovery": 0,
					"sent-ack-only-packets": 0,
					"sent-packets-delayed": 0,
					"sent-urg-only-packets": 0,
					"sent-window-probe-packets": 0,
					"sent-window-update-packets": 0,
					"sent-control-packets": 0,
					"received-packets": 9000,
					"received-ack-packets": 0,
					"received-ack-bytes": 0,
					"received-duplicate-acks": 0,
					"received-udp-tunneled-pkts": 0,
					"received-bad-udp-tunneled-pkts": 0,
					"received-acks-for-unsent-data": 0,
					"received-in-sequence-packets": 0,
					"received-in-sequence-bytes": 4194304,
					"received-completely-duplicate-packets": 0,
					"received-completely-duplicate-bytes": 1024,
					"received-old-duplicate-packets": 0,
					"received-some-duplicate-packets": 0,
					"received-some-duplicate-bytes": 0,
					"received-out-of-order": 0,
					"received-out-of-order-bytes": 0,
					"received-after-window-packets": 0,
					"received-after-window-bytes": 0,
					"received-window-probes": 0,
					"receive-window-update-packets": 0,
					"received-after-close-packets": 0,
					"discard-bad-checksum": 0,
					"discard-bad-header-offset": 0,
					"discard-too-short": 0,
					"discard-reassembly-queue-full": 0,
					"connection-requests": 500,
					"connections-accepts": 400,
					"bad-connection-attempts": 5,
					"listen-queue-overflows": 0,
					"ignored-in-window-resets": 0,
					"connections-established": 300,
					"connections-hostcache-rtt": 0,
					"connections-hostcache-rttvar": 0,
					"connections-hostcache-ssthresh": 0,
					"connections-closed": 250,
					"connection-drops": 10,
					"connections-updated-rtt-on-close": 0,
					"connections-updated-variance-on-close": 0,
					"connections-updated-ssthresh-on-close": 0,
					"embryonic-connections-dropped": 0,
					"segments-updated-rtt": 7000,
					"segment-update-attempts": 0,
					"retransmit-timeouts": 20,
					"connections-dropped-by-retransmit-timeout": 0,
					"persist-timeout": 0,
					"connections-dropped-by-persist-timeout": 0,
					"connections-dropped-by-finwait2-timeout": 0,
					"keepalive-timeout": 15,
					"keepalive-probes": 100,
					"connections-dropped-by-keepalives": 0,
					"ack-header-predictions": 0,
					"data-packet-header-predictions": 0,
					"syncache": {
						"entries-added": 400,
						"retransmitted": 0,
						"duplicates": 0,
						"dropped": 2,
						"completed": 0,
						"bucket-overflow": 0,
						"cache-overflow": 0,
						"reset": 0,
						"stale": 0,
						"aborted": 0,
						"bad-ack": 0,
						"unreachable": 0,
						"zone-failures": 0,
						"sent-cookies": 0,
						"receivd-cookies": 0
					},
					"hostcache": {"entries-added": 0, "buffer-overflows": 0},
					"sack": {"recovery-episodes":0,"segment-retransmits":0,"byte-retransmits":0,"received-blocks":0,"sent-option-blocks":0,"scoreboard-overflows":0},
					"ecn": {"ce-packets":0,"ect0-packets":0,"ect1-packets":0,"handshakes":0,"congestion-reductions":0},
					"tcp-signature": {"received-good-signature":0,"received-bad-signature":0,"failed-make-signature":0,"no-signature-expected":0,"no-signature-provided":0},
					"pmtud": {"pmtud-activated":0,"pmtud-activated-min-mss":0,"pmtud-failed":0},
					"tw": {"tw_responds":0,"tw_recycles":0,"tw_resets":0},
					"TCP connection count by state": {
						"CLOSED": 0,
						"LISTEN": 5,
						"SYN_SENT": 0,
						"SYN_RCVD": 0,
						"ESTABLISHED": 100,
						"CLOSE_WAIT": 2,
						"FIN_WAIT_1": 0,
						"CLOSING": 0,
						"LAST_ACK": 0,
						"FIN_WAIT_2": 1,
						"TIME_WAIT": 10
					}
				},
				"udp": {
					"received-datagrams": 5000,
					"dropped-incomplete-headers": 0,
					"dropped-bad-data-length": 0,
					"dropped-bad-checksum": 1,
					"dropped-no-checksum": 0,
					"dropped-no-socket": 5,
					"dropped-broadcast-multicast": 0,
					"dropped-full-socket-buffer": 0,
					"not-for-hashed-pcb": 0,
					"delivered-packets": 4994,
					"output-packets": 4500,
					"multicast-source-filter-matches": 0
				},
				"ip": {
					"received-packets": 50000,
					"dropped-bad-checksum": 0,
					"dropped-below-minimum-size": 0,
					"dropped-short-packets": 0,
					"dropped-too-long": 0,
					"dropped-short-header-length": 0,
					"dropped-short-data": 0,
					"dropped-bad-options": 0,
					"dropped-bad-version": 0,
					"received-fragments": 10,
					"dropped-fragments": 0,
					"dropped-fragments-after-timeout": 0,
					"reassembled-packets": 5,
					"received-local-packets": 0,
					"dropped-unknown-protocol": 0,
					"forwarded-packets": 20000,
					"fast-forwarded-packets": 15000,
					"packets-cannot-forward": 0,
					"received-unknown-multicast-group": 0,
					"redirects-sent": 0,
					"sent-packets": 30000,
					"send-packets-fabricated-header": 0,
					"discard-no-mbufs": 0,
					"discard-no-route": 0,
					"sent-fragments": 3,
					"fragments-created": 0,
					"discard-cannot-fragment": 0,
					"discard-tunnel-no-gif": 0,
					"discard-bad-address": 0
				},
				"icmp": {
					"icmp-calls": 100,
					"errors-not-from-message": 0,
					"dropped-bad-code": 1,
					"dropped-too-short": 0,
					"dropped-bad-checksum": 0,
					"dropped-bad-length": 0,
					"dropped-multicast-echo": 0,
					"dropped-multicast-timestamp": 0,
					"sent-packets": 90,
					"discard-invalid-return-address": 0,
					"discard-no-route": 0,
					"icmp-address-responses": "0"
				},
				"carp": {
					"received-inet-packets": 50,
					"received-inet6-packets": 10,
					"dropped-wrong-ttl": 0,
					"dropped-short-header": 0,
					"dropped-bad-checksum": 0,
					"dropped-bad-version": 0,
					"dropped-short-packet": 0,
					"dropped-bad-authentication": 0,
					"dropped-bad-vhid": 0,
					"dropped-bad-address-list": 0,
					"sent-inet-packets": 40,
					"sent-inet6-packets": 8,
					"send-failed-memory-error": 0
				},
				"pfsync": {
					"received-inet-packets": 20,
					"received-inet6-packets": 5,
					"input-histogram": [],
					"dropped-bad-interface": 0,
					"dropped-bad-ttl": 0,
					"dropped-short-header": 0,
					"dropped-bad-version": 0,
					"dropped-bad-auth": 0,
					"dropped-bad-action": 0,
					"dropped-short": 0,
					"dropped-bad-values": 0,
					"dropped-stale-state": 0,
					"dropped-failed-lookup": 0,
					"sent-inet-packets": 15,
					"send-inet6-packets": 3,
					"output-histogram": [],
					"discarded-no-memory": 0,
					"send-errors": 1
				},
				"arp": {
					"sent-requests": 200,
					"sent-failures": 2,
					"sent-replies": 150,
					"received-requests": 300,
					"received-replies": 280,
					"received-packets": 580,
					"dropped-no-entry": 5,
					"entries-timeout": 10,
					"dropped-duplicate-address": 1
				}
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &protocolCollector{subsystem: ProtocolSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Count expected metrics:
	// TCP connection by state: 11
	// tcpSentPackets, tcpReceivedPackets: 2
	// arpSentRequests, arpReceivedRequests: 2
	// icmpCalls, icmpSentPackets: 2
	// icmpDroppedByReason: 6 (BAD_CODE, TOO_SHORT, BAD_CHECKSUM, BAD_LENGTH, MULTICAST_ECHO, MULTICAST_TIMESTAMP)
	// udpDelivered, udpOutput, udpReceivedDatagrams: 3
	// udpDroppedByReason: 7 (INCOMPLETE_HEADERS, BAD_DATA_LENGTH, BAD_CHECKSUM, NO_CHECKSUM, NO_SOCKET, BROADCAST_MULTICAST, FULL_SOCKET_BUFFER)
	// carpReceivedPackets: 2 (inet, inet6)
	// carpSentPackets: 2 (inet, inet6)
	// carpDroppedByReason: 8
	// pfsyncReceivedPackets: 2 (inet, inet6)
	// pfsyncSentPackets: 2 (inet, inet6)
	// pfsyncDroppedByReason: 10
	// pfsyncSendErrors: 1
	// IP: 6 (received, forwarded, sent, fragments, reassembled, sentFragments)
	// ipDroppedByReason: 14
	// Detailed TCP: 9 (requests, accepts, established, closed, drops, retransmitTimeouts, keepaliveTimeouts, listenOverflows, syncacheEntries)
	// ARP detailed: 6 (sentFailures, sentReplies, receivedReplies, receivedPackets, droppedNoEntry, entriesTimeout)
	// Expanded TCP: 9 (sentDataBytes, retransmittedPackets, retransmittedBytes, receivedInSequenceBytes, receivedDuplicateBytes, segmentsUpdatedRtt, badConnectionAttempts, keepaliveProbes, syncacheDropped)
	// Expanded ARP: 1 (droppedDuplicateAddress)
	// IPv6/ICMPv6 (#165): 21 = ip6 6 (received, forwarded, sent, fragments_received,
	//   reassembled + 10 dropped_by_reason) → 5+10=15, plus icmp6 1 calls + 5
	//   dropped_by_reason = 6; the dropped_by_reason maps are always emitted (fixed keys)
	//   even when the fixture omits the ip6/icmp6 blocks (all zero).
	// TCP ECN received (#237): 3 (ce, ect0, ect1) — always emitted, resolved across
	//   the 26.1.11 rename. The sent/AccECN/syncookies/acks-for-data groups are
	//   presence-gated and this fixture sends none of those keys, so they
	//   contribute 0.
	// TCP connection drops by reason (#374): 4 (retransmit_timeout, persist_timeout,
	//   finwait2_timeout, keepalive) — this fixture sends all four
	//   connections-dropped-by-* fields as explicit literal 0s, which counts as
	//   present under presence-gating, so all four reasons get a series.
	// SACK / hostcache / TIME_WAIT / PMTUD / TCP-MD5 (#545): 24 — 8 sack (episodes,
	//   segment retransmits, retransmitted bytes, scoreboard overflows, lost
	//   retransmissions, TSO chunk retransmits, plus blocks{received,sent} = 2
	//   series from one family), 2 hostcache insert/evict + 3 hostcache
	//   hits{rtt,rttvar,ssthresh}, 3 tw, 3 pmtud, 5 tcp-signature. Unconditional:
	//   these sections are present on every release in the support window, so they
	//   are emitted even when — as in this fixture — the payload omits them
	//   entirely and every value reads zero.
	// Total: 105 + 21 + 3 + 4 + 24 = 157
	expectedCount := 157
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	// #106: icmp/udp drop-reason counters are cumulative, matching carp/pfsync/ip.
	assertMetricsAreCounters(t, metrics,
		"opnsense_protocol_icmp_dropped_by_reason_total",
		"opnsense_protocol_udp_dropped_by_reason_total",
	)
}

// TestProtocolCollector_TCPConnectionDropsByReason covers #374: only reasons
// whose wire field the box sent get a series, the existing aggregate
// tcp_connection_drops_total metric is unaffected by the split, and the new
// series is emitted as a CounterValue.
func TestProtocolCollector_TCPConnectionDropsByReason(t *testing.T) {
	t.Run("only present reasons get series, aggregate metric unchanged", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {
				"sent-packets": 1,
				"connection-drops": 99,
				"connections-dropped-by-retransmit-timeout": 7,
				"connections-dropped-by-persist-timeout": 8
			}}}`))
		}))
		defer server.Close()

		client := newCollectorTestClient(t, server)
		c := &protocolCollector{subsystem: ProtocolSubsystem}
		c.Register(namespace, "test", promslog.NewNopLogger())
		metrics := collectMetrics(t, c, client)

		byName := metricsByName(t, metrics)
		reasonMetrics := byName["opnsense_protocol_tcp_connection_drops_by_reason_total"]
		if len(reasonMetrics) != 2 {
			t.Fatalf("expected exactly 2 reason series (only the ones the box sent), got %d: %v", len(reasonMetrics), reasonMetrics)
		}
		seen := map[string]float64{}
		haveReason := map[string]bool{}
		for _, m := range reasonMetrics {
			labels := getMetricLabels(m)
			seen[labels["reason"]] = getMetricValue(m)
			haveReason[labels["reason"]] = true
		}
		if seen["retransmit_timeout"] != 7 {
			t.Errorf("retransmit_timeout = %v, want 7", seen["retransmit_timeout"])
		}
		if seen["persist_timeout"] != 8 {
			t.Errorf("persist_timeout = %v, want 8", seen["persist_timeout"])
		}
		if haveReason["finwait2_timeout"] {
			t.Error("finwait2_timeout must NOT be emitted when its wire field is absent")
		}
		if haveReason["keepalive"] {
			t.Error("keepalive must NOT be emitted when its wire field is absent")
		}
		assertMetricsAreCounters(t, metrics, "opnsense_protocol_tcp_connection_drops_by_reason_total")

		// The existing aggregate drop metric must be untouched by the new split.
		dropsAgg := byName["opnsense_protocol_tcp_connection_drops_total"]
		if len(dropsAgg) != 1 || getMetricValue(dropsAgg[0]) != 99 {
			t.Errorf("expected unchanged tcp_connection_drops_total=99, got %v", dropsAgg)
		}
	})

	t.Run("no reasons present emits no series at all", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {"sent-packets": 1}}}`))
		}))
		defer server.Close()

		client := newCollectorTestClient(t, server)
		c := &protocolCollector{subsystem: ProtocolSubsystem}
		c.Register(namespace, "test", promslog.NewNopLogger())
		metrics := collectMetrics(t, c, client)

		byName := metricsByName(t, metrics)
		if n := len(byName["opnsense_protocol_tcp_connection_drops_by_reason_total"]); n != 0 {
			t.Errorf("expected zero reason series when all four wire fields are absent, got %d", n)
		}
	})
}

func TestProtocolCollector_Name(t *testing.T) {
	c := &protocolCollector{subsystem: ProtocolSubsystem}
	if c.Name() != ProtocolSubsystem {
		t.Errorf("expected %s, got %s", ProtocolSubsystem, c.Name())
	}
}

// TestProtocolCollector_DroppedSections covers #545: the sack, hostcache, tw,
// pmtud and tcp-signature sections were decoded on every scrape and exported by
// nothing. The payload below is the real key set captured live from
// api/diagnostics/interface/get_protocol_statistics on prod (10.0.0.254,
// OPNsense 26.1); the identical key set was verified on the 26.7.1 release box and
// the 27.1.a devel box, so these series are unconditional, not presence-gated.
//
// Every one of these is a cumulative kernel counter that resets only on reboot, so
// all must be CounterValue — a Gauge here would make rate()/increase() meaningless.
func TestProtocolCollector_DroppedSections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"statistics": {
				"tcp": {
					"connections-hostcache-rtt": 41,
					"connections-hostcache-rttvar": 17,
					"connections-hostcache-ssthresh": 23,
					"sack": {
						"recovery-episodes": 9742,
						"segment-retransmits": 41516,
						"tso-chunk-retransmits": 12,
						"byte-retransmits": 58377151,
						"received-blocks": 150048,
						"sent-option-blocks": 18266,
						"lost-retransmissions": 31,
						"scoreboard-overflows": 3
					},
					"hostcache": {"entries-added": 185, "buffer-overflows": 2},
					"tw": {"tw_responds": 7, "tw_recycles": 4, "tw_resets": 9},
					"pmtud": {"pmtud-activated": 11, "pmtud-activated-min-mss": 5, "pmtud-failed": 2},
					"tcp-signature": {
						"received-good-signature": 100,
						"received-bad-signature": 3,
						"failed-make-signature": 1,
						"no-signature-expected": 6,
						"no-signature-provided": 8
					}
				}
			}
		}`))
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &protocolCollector{subsystem: ProtocolSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	// key is "<metric name fragment>" or "<fragment>/<label value>".
	got := make(map[string]float64)
	for _, m := range collectMetrics(t, c, client) {
		desc := m.Desc().String()
		d := &dto.Metric{}
		_ = m.Write(d)
		labels := getMetricLabels(m)

		for fragment, labelName := range map[string]string{
			"tcp_sack_recovery_episodes_total":     "",
			"tcp_sack_segment_retransmits_total":   "",
			"tcp_sack_retransmitted_bytes_total":   "",
			"tcp_sack_scoreboard_overflows_total":  "",
			"tcp_sack_lost_retransmissions_total":  "",
			"tcp_sack_tso_chunk_retransmits_total": "",
			"tcp_sack_blocks_total":                "direction",
			"tcp_hostcache_entries_added_total":    "",
			"tcp_hostcache_buffer_overflows_total": "",
			"tcp_hostcache_hits_total":             "metric",
			"tcp_timewait_events_total":            "event",
			"tcp_pmtud_blackhole_events_total":     "event",
			"tcp_signature_total":                  "result",
		} {
			if !strings.Contains(desc, `fqName: "opnsense_protocol_`+fragment+`"`) {
				continue
			}
			if d.Counter == nil {
				t.Errorf("%s must be a Counter (cumulative kernel counter, reset only on reboot); got %v", fragment, d)
				continue
			}
			key := fragment
			if labelName != "" {
				key = fragment + "/" + labels[labelName]
			}
			got[key] = d.Counter.GetValue()
		}
	}

	want := map[string]float64{
		"tcp_sack_recovery_episodes_total":                   9742,
		"tcp_sack_segment_retransmits_total":                 41516,
		"tcp_sack_retransmitted_bytes_total":                 58377151,
		"tcp_sack_scoreboard_overflows_total":                3,
		"tcp_sack_lost_retransmissions_total":                31,
		"tcp_sack_tso_chunk_retransmits_total":               12,
		"tcp_hostcache_hits_total/rtt":                       41,
		"tcp_hostcache_hits_total/rttvar":                    17,
		"tcp_hostcache_hits_total/ssthresh":                  23,
		"tcp_sack_blocks_total/received":                     150048,
		"tcp_sack_blocks_total/sent":                         18266,
		"tcp_hostcache_entries_added_total":                  185,
		"tcp_hostcache_buffer_overflows_total":               2,
		"tcp_timewait_events_total/responds":                 7,
		"tcp_timewait_events_total/recycles":                 4,
		"tcp_timewait_events_total/resets":                   9,
		"tcp_pmtud_blackhole_events_total/activated":         11,
		"tcp_pmtud_blackhole_events_total/activated_min_mss": 5,
		"tcp_pmtud_blackhole_events_total/failed":            2,
		"tcp_signature_total/good":                           100,
		"tcp_signature_total/bad":                            3,
		"tcp_signature_total/make_failed":                    1,
		"tcp_signature_total/not_expected":                   6,
		"tcp_signature_total/not_provided":                   8,
	}
	for key, wantValue := range want {
		gotValue, ok := got[key]
		if !ok {
			t.Errorf("missing series %s", key)
			continue
		}
		if gotValue != wantValue {
			t.Errorf("%s = %v, want %v", key, gotValue, wantValue)
		}
	}
	if len(got) != len(want) {
		t.Errorf("emitted %d series in the #545 group, want %d: %v", len(got), len(want), got)
	}
}
