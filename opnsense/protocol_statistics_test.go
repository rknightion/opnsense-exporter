package opnsense

import (
	"fmt"
	"net/http"
	"testing"
)

// TestFetchProtocolStatistics_IPv6 covers #165: the ip6/icmp6 blocks (previously
// undeclared and silently dropped) are decoded, with both stacks attributed correctly.
func TestFetchProtocolStatistics_IPv6(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"statistics": {
				"ip": {"received-packets": 1000, "forwarded-packets": 800, "packets-cannot-forward": 5},
				"icmp": {"icmp-calls": 10},
				"ip6": {
					"received-packets": 47042625, "forwarded-packets": 45452086,
					"sent-packets": 1922226, "received-fragments": 3, "reassembled-packets": 2,
					"packets-not-forwardable": 17828, "discard-no-route": 7, "dropped-header-too-long": 1
				},
				"icmp6": {"icmp6-calls": 672, "dropped-no-entry": 2107, "dropped-bad-checksum": 4}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchProtocolStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// IPv4 still attributed correctly.
	if data.IPReceivedPackets != 1000 || data.IPForwardedPackets != 800 {
		t.Errorf("IPv4 mis-attributed: received=%d forwarded=%d", data.IPReceivedPackets, data.IPForwardedPackets)
	}
	// IPv6 no longer dropped.
	if data.IP6ReceivedPackets != 47042625 || data.IP6ForwardedPackets != 45452086 || data.IP6SentPackets != 1922226 {
		t.Errorf("IPv6 counters wrong: recv=%d fwd=%d sent=%d",
			data.IP6ReceivedPackets, data.IP6ForwardedPackets, data.IP6SentPackets)
	}
	if data.IP6ReceivedFragments != 3 || data.IP6ReassembledPackets != 2 {
		t.Errorf("IPv6 fragment counters wrong: recv=%d reasm=%d", data.IP6ReceivedFragments, data.IP6ReassembledPackets)
	}
	if data.IP6DroppedByReason["CANNOT_FORWARD"] != 17828 || data.IP6DroppedByReason["NO_ROUTE"] != 7 || data.IP6DroppedByReason["HEADER_TOO_LONG"] != 1 {
		t.Errorf("IPv6 drop reasons wrong: %v", data.IP6DroppedByReason)
	}
	if data.ICMP6Calls != 672 || data.ICMP6DroppedByReason["NO_ENTRY"] != 2107 || data.ICMP6DroppedByReason["BAD_CHECKSUM"] != 4 {
		t.Errorf("ICMPv6 wrong: calls=%d drops=%v", data.ICMP6Calls, data.ICMP6DroppedByReason)
	}
}

// TestFetchProtocolStatistics_EcnKeyRenames covers the FreeBSD/OPNsense reshape of
// statistics.tcp.ecn that landed on current-stable 26.1.11: ce-packets / ect0-packets /
// ect1-packets were renamed to received-ce-packets / received-ect0-packets /
// received-ect1-packets. The reader must resolve "new wins when present, else legacy"
// so both an old box and a 26.1.11+ box report the same counters — without branching
// on version. The 26.1.11 fixture below uses the REAL key set observed live (including
// the ace-*/handshakes/sent-ect* keys we deliberately do not surface) with synthetic values.
func TestFetchProtocolStatistics_EcnKeyRenames(t *testing.T) {
	tests := []struct {
		name                    string
		ecn                     string
		wantCe, wantEct0, want1 int64
	}{
		{
			name: "legacy keys only (<=26.1.10)",
			ecn: `{
				"ce-packets": 11, "ect0-packets": 22, "ect1-packets": 33,
				"handshakes": 44, "congestion-reductions": 55
			}`,
			wantCe: 11, wantEct0: 22, want1: 33,
		},
		{
			name: "modern keys only (26.1.11, real key set)",
			ecn: `{
				"ace-ce-syn": 1, "ace-ect0-syn": 2, "ace-ect1-syn": 3, "ace-nonect-syn": 4,
				"congestion-reductions": 55, "handshakes": 44,
				"received-ce-packets": 11, "received-ect0-packets": 22, "received-ect1-packets": 33,
				"sent-ect0-packets": 66, "sent-ect1-packets": 77
			}`,
			wantCe: 11, wantEct0: 22, want1: 33,
		},
		{
			name: "both present: new wins over legacy",
			ecn: `{
				"ce-packets": 0, "ect0-packets": 0, "ect1-packets": 0,
				"received-ce-packets": 11, "received-ect0-packets": 22, "received-ect1-packets": 33
			}`,
			wantCe: 11, wantEct0: 22, want1: 33,
		},
		{
			name: "ecn block absent entirely",
			ecn:  `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"statistics": {"tcp": {"sent-packets": 7, "ecn": ` + tt.ecn + `}}}`))
			})
			defer server.Close()

			data, err := client.FetchProtocolStatistics()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if data.TCPSentPackets != 7 {
				t.Errorf("unrelated counter mis-parsed: TCPSentPackets=%d, want 7", data.TCPSentPackets)
			}
			if data.TCPEcnCePackets != tt.wantCe {
				t.Errorf("TCPEcnCePackets=%d, want %d", data.TCPEcnCePackets, tt.wantCe)
			}
			if data.TCPEcnEct0Packets != tt.wantEct0 {
				t.Errorf("TCPEcnEct0Packets=%d, want %d", data.TCPEcnEct0Packets, tt.wantEct0)
			}
			if data.TCPEcnEct1Packets != tt.want1 {
				t.Errorf("TCPEcnEct1Packets=%d, want %d", data.TCPEcnEct1Packets, tt.want1)
			}
		})
	}
}

// TestFetchProtocolStatistics_NewTcpCounters covers #237: syncookies, send-side
// ECN, AccECN handshake counters and the received-acks-for-data 3-way split are
// all new (not renamed) fields, introduced together in 26.1.11/26.7. Each group
// is presence-gated: absent entirely on an older box, never a fabricated zero.
func TestFetchProtocolStatistics_NewTcpCounters(t *testing.T) {
	t.Run("all groups present (26.7 real key set)", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {
				"sent-packets": 1,
				"received-acks-for-data-not-yet-sent": 1,
				"received-acks-for-data-never-been-sent": 2,
				"received-acks-for-data-being-too-old": 3,
				"syncache": {"sent-cookies": 0, "receivd-cookies": 0},
				"syncookies": {
					"sent-cookies": 100, "received-cookies": 0,
					"failed-cookies": 1, "spurious-cookies": 2
				},
				"ecn": {
					"received-ce-packets": 0, "received-ect0-packets": 10, "received-ect1-packets": 0,
					"sent-ect0-packets": 20, "sent-ect1-packets": 5,
					"ace-ce-syn": 1, "ace-ect0-syn": 2, "ace-ect1-syn": 3, "ace-nonect-syn": 4
				}
			}}}`))
		})
		defer server.Close()

		data, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !data.TCPSyncookiesPresent {
			t.Fatal("expected TCPSyncookiesPresent=true")
		}
		if data.TCPSyncookiesSentCookies != 100 || data.TCPSyncookiesReceivedCookies != 0 ||
			data.TCPSyncookiesFailedCookies != 1 || data.TCPSyncookiesSpuriousCookies != 2 {
			t.Errorf("unexpected syncookies: %+v", data)
		}

		if !data.TCPEcnSentPresent {
			t.Fatal("expected TCPEcnSentPresent=true")
		}
		if data.TCPEcnSentEct0Packets != 20 || data.TCPEcnSentEct1Packets != 5 {
			t.Errorf("unexpected sent ECN: ect0=%d ect1=%d", data.TCPEcnSentEct0Packets, data.TCPEcnSentEct1Packets)
		}
		// Received side must still resolve normally alongside the new sent side.
		if data.TCPEcnEct0Packets != 10 {
			t.Errorf("expected received ect0=10, got %d", data.TCPEcnEct0Packets)
		}

		if !data.TCPEcnAccEcnPresent {
			t.Fatal("expected TCPEcnAccEcnPresent=true")
		}
		if data.TCPEcnAceCeSyn != 1 || data.TCPEcnAceEct0Syn != 2 || data.TCPEcnAceEct1Syn != 3 || data.TCPEcnAceNonEctSyn != 4 {
			t.Errorf("unexpected AccECN counters: %+v", data)
		}

		if !data.TCPReceivedAcksForDataSplitPresent {
			t.Fatal("expected TCPReceivedAcksForDataSplitPresent=true")
		}
		if data.TCPReceivedAcksForDataNotYetSent != 1 || data.TCPReceivedAcksForDataNeverBeenSent != 2 ||
			data.TCPReceivedAcksForDataBeingTooOld != 3 {
			t.Errorf("unexpected acks-for-data split: %+v", data)
		}
	})

	t.Run("all groups absent (pre-26.1.11 box)", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {
				"sent-packets": 1,
				"received-acks-for-unsent-data": 9,
				"syncache": {"sent-cookies": 5, "receivd-cookies": 6},
				"ecn": {"ce-packets": 0, "ect0-packets": 0, "ect1-packets": 0}
			}}}`))
		})
		defer server.Close()

		data, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if data.TCPSyncookiesPresent {
			t.Error("expected TCPSyncookiesPresent=false when syncookies section is absent")
		}
		if data.TCPEcnSentPresent {
			t.Error("expected TCPEcnSentPresent=false when sent-ect keys are absent")
		}
		if data.TCPEcnAccEcnPresent {
			t.Error("expected TCPEcnAccEcnPresent=false when ace-*-syn keys are absent")
		}
		if data.TCPReceivedAcksForDataSplitPresent {
			t.Error("expected TCPReceivedAcksForDataSplitPresent=false when the split keys are absent")
		}
		// All presence-gated counters must read zero-value, not fabricated.
		if data.TCPSyncookiesSentCookies != 0 || data.TCPEcnSentEct0Packets != 0 ||
			data.TCPEcnAceCeSyn != 0 || data.TCPReceivedAcksForDataNotYetSent != 0 {
			t.Errorf("expected zero-value fields when groups absent, got %+v", data)
		}
	})
}

func TestFetchProtocolStatistics_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"statistics": {
				"tcp": {
					"sent-packets": 10000,
					"sent-data-packets": 8000,
					"sent-data-bytes": 5000000,
					"sent-retransmitted-packets": 50,
					"sent-retransmitted-bytes": 25000,
					"sent-unnecessary-retransmitted-packets": 2,
					"sent-resends-by-mtu-discovery": 0,
					"sent-ack-only-packets": 500,
					"sent-packets-delayed": 10,
					"sent-urg-only-packets": 0,
					"sent-window-probe-packets": 0,
					"sent-window-update-packets": 0,
					"sent-control-packets": 100,
					"received-packets": 12000,
					"received-ack-packets": 9000,
					"received-ack-bytes": 4500000,
					"received-duplicate-acks": 20,
					"received-udp-tunneled-pkts": 0,
					"received-bad-udp-tunneled-pkts": 0,
					"received-acks-for-unsent-data": 0,
					"received-in-sequence-packets": 11000,
					"received-in-sequence-bytes": 5500000,
					"received-completely-duplicate-packets": 10,
					"received-completely-duplicate-bytes": 5000,
					"received-old-duplicate-packets": 0,
					"received-some-duplicate-packets": 0,
					"received-some-duplicate-bytes": 0,
					"received-out-of-order": 5,
					"received-out-of-order-bytes": 2500,
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
					"connections-accepts": 450,
					"bad-connection-attempts": 10,
					"listen-queue-overflows": 2,
					"ignored-in-window-resets": 0,
					"connections-established": 400,
					"connections-hostcache-rtt": 0,
					"connections-hostcache-rttvar": 0,
					"connections-hostcache-ssthresh": 0,
					"connections-closed": 350,
					"connection-drops": 5,
					"connections-updated-rtt-on-close": 0,
					"connections-updated-variance-on-close": 0,
					"connections-updated-ssthresh-on-close": 0,
					"embryonic-connections-dropped": 0,
					"segments-updated-rtt": 8000,
					"segment-update-attempts": 9000,
					"retransmit-timeouts": 15,
					"connections-dropped-by-retransmit-timeout": 0,
					"persist-timeout": 0,
					"connections-dropped-by-persist-timeout": 0,
					"connections-dropped-by-finwait2-timeout": 0,
					"keepalive-timeout": 20,
					"keepalive-probes": 100,
					"connections-dropped-by-keepalives": 3,
					"ack-header-predictions": 0,
					"data-packet-header-predictions": 0,
					"syncache": {
						"entries-added": 450,
						"retransmitted": 0,
						"duplicates": 0,
						"dropped": 5,
						"completed": 445,
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
					"hostcache": {
						"entries-added": 0,
						"buffer-overflows": 0
					},
					"sack": {
						"recovery-episodes": 0,
						"segment-retransmits": 0,
						"byte-retransmits": 0,
						"received-blocks": 0,
						"sent-option-blocks": 0,
						"scoreboard-overflows": 0
					},
					"ecn": {
						"ce-packets": 0,
						"ect0-packets": 0,
						"ect1-packets": 0,
						"handshakes": 0,
						"congestion-reductions": 0
					},
					"tcp-signature": {
						"received-good-signature": 0,
						"received-bad-signature": 0,
						"failed-make-signature": 0,
						"no-signature-expected": 0,
						"no-signature-provided": 0
					},
					"pmtud": {
						"pmtud-activated": 0,
						"pmtud-activated-min-mss": 0,
						"pmtud-failed": 0
					},
					"tw": {
						"tw_responds": 0,
						"tw_recycles": 0,
						"tw_resets": 0
					},
					"TCP connection count by state": {
						"CLOSED": 10,
						"LISTEN": 5,
						"SYN_SENT": 2,
						"SYN_RCVD": 1,
						"ESTABLISHED": 50,
						"CLOSE_WAIT": 3,
						"FIN_WAIT_1": 0,
						"CLOSING": 0,
						"LAST_ACK": 0,
						"FIN_WAIT_2": 1,
						"TIME_WAIT": 20
					}
				},
				"udp": {
					"received-datagrams": 50000,
					"dropped-incomplete-headers": 0,
					"dropped-bad-data-length": 0,
					"dropped-bad-checksum": 2,
					"dropped-no-checksum": 0,
					"dropped-no-socket": 100,
					"dropped-broadcast-multicast": 0,
					"dropped-full-socket-buffer": 5,
					"not-for-hashed-pcb": 0,
					"delivered-packets": 49893,
					"output-packets": 48000,
					"multicast-source-filter-matches": 0
				},
				"ip": {
					"received-packets": 200000,
					"dropped-bad-checksum": 1,
					"dropped-below-minimum-size": 0,
					"dropped-short-packets": 0,
					"dropped-too-long": 0,
					"dropped-short-header-length": 0,
					"dropped-short-data": 0,
					"dropped-bad-options": 0,
					"dropped-bad-version": 0,
					"received-fragments": 500,
					"dropped-fragments": 10,
					"dropped-fragments-after-timeout": 0,
					"reassembled-packets": 490,
					"received-local-packets": 150000,
					"dropped-unknown-protocol": 3,
					"forwarded-packets": 50000,
					"fast-forwarded-packets": 40000,
					"packets-cannot-forward": 5,
					"received-unknown-multicast-group": 0,
					"redirects-sent": 0,
					"sent-packets": 180000,
					"send-packets-fabricated-header": 0,
					"discard-no-mbufs": 0,
					"discard-no-route": 2,
					"sent-fragments": 100,
					"fragments-created": 200,
					"discard-cannot-fragment": 1,
					"discard-tunnel-no-gif": 0,
					"discard-bad-address": 0
				},
				"icmp": {
					"icmp-calls": 5000,
					"errors-not-from-message": 0,
					"dropped-bad-code": 1,
					"dropped-too-short": 2,
					"dropped-bad-checksum": 0,
					"dropped-bad-length": 3,
					"dropped-multicast-echo": 0,
					"dropped-multicast-timestamp": 0,
					"sent-packets": 4000,
					"discard-invalid-return-address": 0,
					"discard-no-route": 0,
					"icmp-address-responses": "0"
				},
				"carp": {
					"received-inet-packets": 1000,
					"received-inet6-packets": 500,
					"dropped-wrong-ttl": 1,
					"dropped-short-header": 0,
					"dropped-bad-checksum": 0,
					"dropped-bad-version": 0,
					"dropped-short-packet": 0,
					"dropped-bad-authentication": 2,
					"dropped-bad-vhid": 0,
					"dropped-bad-address-list": 0,
					"sent-inet-packets": 800,
					"sent-inet6-packets": 400,
					"send-failed-memory-error": 0
				},
				"pfsync": {
					"received-inet-packets": 2000,
					"received-inet6-packets": 100,
					"input-histogram": [],
					"dropped-bad-interface": 1,
					"dropped-bad-ttl": 0,
					"dropped-short-header": 0,
					"dropped-bad-version": 0,
					"dropped-bad-auth": 0,
					"dropped-bad-action": 0,
					"dropped-short": 0,
					"dropped-bad-values": 2,
					"dropped-stale-state": 3,
					"dropped-failed-lookup": 0,
					"sent-inet-packets": 1800,
					"send-inet6-packets": 90,
					"output-histogram": [],
					"discarded-no-memory": 0,
					"send-errors": 5
				},
				"arp": {
					"sent-requests": 3000,
					"sent-failures": 10,
					"sent-replies": 2500,
					"received-requests": 4000,
					"received-replies": 2800,
					"received-packets": 7000,
					"dropped-no-entry": 50,
					"entries-timeout": 200,
					"dropped-duplicate-address": 0
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchProtocolStatistics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// TCP basics
	if data.TCPSentPackets != 10000 {
		t.Errorf("expected TCPSentPackets=10000, got %d", data.TCPSentPackets)
	}
	if data.TCPReceivedPackets != 12000 {
		t.Errorf("expected TCPReceivedPackets=12000, got %d", data.TCPReceivedPackets)
	}

	// TCP connection count by state
	if data.TCPConnectionCountByState["ESTABLISHED"] != 50 {
		t.Errorf("expected ESTABLISHED=50, got %d", data.TCPConnectionCountByState["ESTABLISHED"])
	}
	if data.TCPConnectionCountByState["TIME_WAIT"] != 20 {
		t.Errorf("expected TIME_WAIT=20, got %d", data.TCPConnectionCountByState["TIME_WAIT"])
	}
	if data.TCPConnectionCountByState["LISTEN"] != 5 {
		t.Errorf("expected LISTEN=5, got %d", data.TCPConnectionCountByState["LISTEN"])
	}

	// TCP detailed
	if data.TCPConnectionRequests != 500 {
		t.Errorf("expected TCPConnectionRequests=500, got %d", data.TCPConnectionRequests)
	}
	if data.TCPConnectionAccepts != 450 {
		t.Errorf("expected TCPConnectionAccepts=450, got %d", data.TCPConnectionAccepts)
	}
	if data.TCPConnectionsEstablished != 400 {
		t.Errorf("expected TCPConnectionsEstablished=400, got %d", data.TCPConnectionsEstablished)
	}
	if data.TCPRetransmitTimeouts != 15 {
		t.Errorf("expected TCPRetransmitTimeouts=15, got %d", data.TCPRetransmitTimeouts)
	}
	if data.TCPKeepaliveTimeouts != 20 {
		t.Errorf("expected TCPKeepaliveTimeouts=20, got %d", data.TCPKeepaliveTimeouts)
	}
	if data.TCPSentDataBytes != 5000000 {
		t.Errorf("expected TCPSentDataBytes=5000000, got %d", data.TCPSentDataBytes)
	}
	if data.TCPSyncacheEntriesAdded != 450 {
		t.Errorf("expected TCPSyncacheEntriesAdded=450, got %d", data.TCPSyncacheEntriesAdded)
	}
	if data.TCPSyncacheDropped != 5 {
		t.Errorf("expected TCPSyncacheDropped=5, got %d", data.TCPSyncacheDropped)
	}
	if data.TCPSegmentsUpdatedRtt != 8000 {
		t.Errorf("expected TCPSegmentsUpdatedRtt=8000, got %d", data.TCPSegmentsUpdatedRtt)
	}
	if data.TCPBadConnectionAttempts != 10 {
		t.Errorf("expected TCPBadConnectionAttempts=10, got %d", data.TCPBadConnectionAttempts)
	}

	// UDP
	if data.UDPReceivedDatagrams != 50000 {
		t.Errorf("expected UDPReceivedDatagrams=50000, got %d", data.UDPReceivedDatagrams)
	}
	if data.UDPDeliveredPackets != 49893 {
		t.Errorf("expected UDPDeliveredPackets=49893, got %d", data.UDPDeliveredPackets)
	}
	if data.UDPOutputPackets != 48000 {
		t.Errorf("expected UDPOutputPackets=48000, got %d", data.UDPOutputPackets)
	}
	if data.UDPDroppedByReason["BAD_CHECKSUM"] != 2 {
		t.Errorf("expected UDPDroppedByReason['BAD_CHECKSUM']=2, got %d", data.UDPDroppedByReason["BAD_CHECKSUM"])
	}
	if data.UDPDroppedByReason["NO_SOCKET"] != 100 {
		t.Errorf("expected UDPDroppedByReason['NO_SOCKET']=100, got %d", data.UDPDroppedByReason["NO_SOCKET"])
	}

	// ICMP
	if data.ICMPCalls != 5000 {
		t.Errorf("expected ICMPCalls=5000, got %d", data.ICMPCalls)
	}
	if data.ICMPSentPackets != 4000 {
		t.Errorf("expected ICMPSentPackets=4000, got %d", data.ICMPSentPackets)
	}
	if data.ICMPDroppedByReason["BAD_CODE"] != 1 {
		t.Errorf("expected ICMPDroppedByReason['BAD_CODE']=1, got %d", data.ICMPDroppedByReason["BAD_CODE"])
	}
	if data.ICMPDroppedByReason["BAD_LENGTH"] != 3 {
		t.Errorf("expected ICMPDroppedByReason['BAD_LENGTH']=3, got %d", data.ICMPDroppedByReason["BAD_LENGTH"])
	}

	// IP
	if data.IPReceivedPackets != 200000 {
		t.Errorf("expected IPReceivedPackets=200000, got %d", data.IPReceivedPackets)
	}
	if data.IPForwardedPackets != 50000 {
		t.Errorf("expected IPForwardedPackets=50000, got %d", data.IPForwardedPackets)
	}
	if data.IPFastForwardedPackets != 40000 {
		t.Errorf("expected IPFastForwardedPackets=40000, got %d", data.IPFastForwardedPackets)
	}
	if data.IPSentPackets != 180000 {
		t.Errorf("expected IPSentPackets=180000, got %d", data.IPSentPackets)
	}
	if data.IPDroppedByReason["BAD_CHECKSUM"] != 1 {
		t.Errorf("expected IPDroppedByReason['BAD_CHECKSUM']=1, got %d", data.IPDroppedByReason["BAD_CHECKSUM"])
	}
	if data.IPDroppedByReason["CANNOT_FORWARD"] != 5 {
		t.Errorf("expected IPDroppedByReason['CANNOT_FORWARD']=5, got %d", data.IPDroppedByReason["CANNOT_FORWARD"])
	}
	if data.IPReceivedFragments != 500 {
		t.Errorf("expected IPReceivedFragments=500, got %d", data.IPReceivedFragments)
	}
	if data.IPReassembledPackets != 490 {
		t.Errorf("expected IPReassembledPackets=490, got %d", data.IPReassembledPackets)
	}

	// ARP
	if data.ARPSentRequests != 3000 {
		t.Errorf("expected ARPSentRequests=3000, got %d", data.ARPSentRequests)
	}
	if data.ARPReceivedRequests != 4000 {
		t.Errorf("expected ARPReceivedRequests=4000, got %d", data.ARPReceivedRequests)
	}
	if data.ARPSentFailures != 10 {
		t.Errorf("expected ARPSentFailures=10, got %d", data.ARPSentFailures)
	}
	if data.ARPEntriesTimeout != 200 {
		t.Errorf("expected ARPEntriesTimeout=200, got %d", data.ARPEntriesTimeout)
	}

	// CARP
	if data.CARPReceivedInet != 1000 {
		t.Errorf("expected CARPReceivedInet=1000, got %d", data.CARPReceivedInet)
	}
	if data.CARPSentInet != 800 {
		t.Errorf("expected CARPSentInet=800, got %d", data.CARPSentInet)
	}
	if data.CARPDroppedByReason["WRONG_TTL"] != 1 {
		t.Errorf("expected CARPDroppedByReason['WRONG_TTL']=1, got %d", data.CARPDroppedByReason["WRONG_TTL"])
	}
	if data.CARPDroppedByReason["BAD_AUTH"] != 2 {
		t.Errorf("expected CARPDroppedByReason['BAD_AUTH']=2, got %d", data.CARPDroppedByReason["BAD_AUTH"])
	}

	// Pfsync
	if data.PfsyncReceivedInet != 2000 {
		t.Errorf("expected PfsyncReceivedInet=2000, got %d", data.PfsyncReceivedInet)
	}
	if data.PfsyncSentInet != 1800 {
		t.Errorf("expected PfsyncSentInet=1800, got %d", data.PfsyncSentInet)
	}
	if data.PfsyncSentInet6 != 90 {
		t.Errorf("expected PfsyncSentInet6=90, got %d", data.PfsyncSentInet6)
	}
	if data.PfsyncSendErrors != 5 {
		t.Errorf("expected PfsyncSendErrors=5, got %d", data.PfsyncSendErrors)
	}
	if data.PfsyncDroppedByReason["BAD_VALUES"] != 2 {
		t.Errorf("expected PfsyncDroppedByReason['BAD_VALUES']=2, got %d", data.PfsyncDroppedByReason["BAD_VALUES"])
	}
	if data.PfsyncDroppedByReason["STALE_STATE"] != 3 {
		t.Errorf("expected PfsyncDroppedByReason['STALE_STATE']=3, got %d", data.PfsyncDroppedByReason["STALE_STATE"])
	}
}

func TestFetchProtocolStatistics_ScientificNotationCounters(t *testing.T) {
	// OPNsense can return counter values like max uint64 (18446744073709551615) serialized
	// as scientific notation (1.8446744073709552e+19). Go's encoding/json cannot unmarshal
	// a number with an exponent into an int, so such values must degrade to 0.
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"statistics": {
				"tcp": {
					"sent-packets": 100,
					"sent-data-packets": 0,
					"sent-data-bytes": 0,
					"sent-retransmitted-packets": 0,
					"sent-retransmitted-bytes": 0,
					"sent-unnecessary-retransmitted-packets": 0,
					"sent-resends-by-mtu-discovery": 0,
					"sent-ack-only-packets": 0,
					"sent-packets-delayed": 0,
					"sent-urg-only-packets": 0,
					"sent-window-probe-packets": 0,
					"sent-window-update-packets": 0,
					"sent-control-packets": 0,
					"received-packets": 200,
					"received-ack-packets": 0,
					"received-ack-bytes": 0,
					"received-duplicate-acks": 0,
					"received-udp-tunneled-pkts": 0,
					"received-bad-udp-tunneled-pkts": 0,
					"received-acks-for-unsent-data": 0,
					"received-in-sequence-packets": 0,
					"received-in-sequence-bytes": 0,
					"received-completely-duplicate-packets": 0,
					"received-completely-duplicate-bytes": 0,
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
					"connection-requests": 0,
					"connections-accepts": 0,
					"bad-connection-attempts": 0,
					"listen-queue-overflows": 0,
					"ignored-in-window-resets": 0,
					"connections-established": 0,
					"connections-hostcache-rtt": 0,
					"connections-hostcache-rttvar": 0,
					"connections-hostcache-ssthresh": 0,
					"connections-closed": 0,
					"connection-drops": 0,
					"connections-updated-rtt-on-close": 0,
					"connections-updated-variance-on-close": 0,
					"connections-updated-ssthresh-on-close": 0,
					"embryonic-connections-dropped": 0,
					"segments-updated-rtt": 0,
					"segment-update-attempts": 0,
					"retransmit-timeouts": 0,
					"connections-dropped-by-retransmit-timeout": 0,
					"persist-timeout": 0,
					"connections-dropped-by-persist-timeout": 0,
					"connections-dropped-by-finwait2-timeout": 0,
					"keepalive-timeout": 0,
					"keepalive-probes": 0,
					"connections-dropped-by-keepalives": 0,
					"ack-header-predictions": 0,
					"data-packet-header-predictions": 0,
					"syncache": {
						"entries-added": 0, "retransmitted": 0, "duplicates": 0,
						"dropped": 0, "completed": 0, "bucket-overflow": 0,
						"cache-overflow": 0, "reset": 0, "stale": 0, "aborted": 0,
						"bad-ack": 0, "unreachable": 0, "zone-failures": 0,
						"sent-cookies": 0, "receivd-cookies": 0
					},
					"hostcache": {"entries-added": 0, "buffer-overflows": 0},
					"sack": {"recovery-episodes": 0, "segment-retransmits": 0,
						"byte-retransmits": 0, "received-blocks": 0,
						"sent-option-blocks": 0, "scoreboard-overflows": 0},
					"ecn": {"ce-packets": 0, "ect0-packets": 0, "ect1-packets": 0,
						"handshakes": 0, "congestion-reductions": 0},
					"tcp-signature": {"received-good-signature": 0,
						"received-bad-signature": 0, "failed-make-signature": 0,
						"no-signature-expected": 0, "no-signature-provided": 0},
					"pmtud": {"pmtud-activated": 0, "pmtud-activated-min-mss": 0,
						"pmtud-failed": 0},
					"tw": {"tw_responds": 0, "tw_recycles": 0, "tw_resets": 0},
					"TCP connection count by state": {
						"CLOSED": 0, "LISTEN": 0, "SYN_SENT": 0, "SYN_RCVD": 0,
						"ESTABLISHED": 0, "CLOSE_WAIT": 0, "FIN_WAIT_1": 0,
						"CLOSING": 0, "LAST_ACK": 0, "FIN_WAIT_2": 0, "TIME_WAIT": 0
					}
				},
				"udp": {
					"received-datagrams": 42,
					"dropped-incomplete-headers": 0,
					"dropped-bad-data-length": 0,
					"dropped-bad-checksum": 0,
					"dropped-no-checksum": 0,
					"dropped-no-socket": 0,
					"dropped-broadcast-multicast": 0,
					"dropped-full-socket-buffer": 0,
					"not-for-hashed-pcb": 0,
					"delivered-packets": 1.8446744073709552e+19,
					"output-packets": 99,
					"multicast-source-filter-matches": 0
				},
				"ip": {
					"received-packets": 0, "dropped-bad-checksum": 0,
					"dropped-below-minimum-size": 0, "dropped-short-packets": 0,
					"dropped-too-long": 0, "dropped-short-header-length": 0,
					"dropped-short-data": 0, "dropped-bad-options": 0,
					"dropped-bad-version": 0, "received-fragments": 0,
					"dropped-fragments": 0, "dropped-fragments-after-timeout": 0,
					"reassembled-packets": 0, "received-local-packets": 0,
					"dropped-unknown-protocol": 0, "forwarded-packets": 0,
					"fast-forwarded-packets": 0, "packets-cannot-forward": 0,
					"received-unknown-multicast-group": 0, "redirects-sent": 0,
					"sent-packets": 0, "send-packets-fabricated-header": 0,
					"discard-no-mbufs": 0, "discard-no-route": 0,
					"sent-fragments": 0, "fragments-created": 0,
					"discard-cannot-fragment": 0, "discard-tunnel-no-gif": 0,
					"discard-bad-address": 0
				},
				"icmp": {
					"icmp-calls": 0, "errors-not-from-message": 0,
					"dropped-bad-code": 0, "dropped-too-short": 0,
					"dropped-bad-checksum": 0, "dropped-bad-length": 0,
					"dropped-multicast-echo": 0, "dropped-multicast-timestamp": 0,
					"sent-packets": 0, "discard-invalid-return-address": 0,
					"discard-no-route": 0, "icmp-address-responses": "0"
				},
				"carp": {
					"received-inet-packets": 0, "received-inet6-packets": 0,
					"dropped-wrong-ttl": 0, "dropped-short-header": 0,
					"dropped-bad-checksum": 0, "dropped-bad-version": 0,
					"dropped-short-packet": 0, "dropped-bad-authentication": 0,
					"dropped-bad-vhid": 0, "dropped-bad-address-list": 0,
					"sent-inet-packets": 0, "sent-inet6-packets": 0,
					"send-failed-memory-error": 0
				},
				"pfsync": {
					"received-inet-packets": 0, "received-inet6-packets": 0,
					"input-histogram": [],
					"dropped-bad-interface": 0, "dropped-bad-ttl": 0,
					"dropped-short-header": 0, "dropped-bad-version": 0,
					"dropped-bad-auth": 0, "dropped-bad-action": 0,
					"dropped-short": 0, "dropped-bad-values": 0,
					"dropped-stale-state": 0, "dropped-failed-lookup": 0,
					"sent-inet-packets": 0, "send-inet6-packets": 0,
					"output-histogram": [], "discarded-no-memory": 0,
					"send-errors": 0
				},
				"arp": {
					"sent-requests": 0, "sent-failures": 0, "sent-replies": 0,
					"received-requests": 0, "received-replies": 0,
					"received-packets": 0, "dropped-no-entry": 0,
					"entries-timeout": 0, "dropped-duplicate-address": 0
				}
			}
		}`))
	})
	defer server.Close()

	data, err := client.FetchProtocolStatistics()
	if err != nil {
		t.Fatalf("FetchProtocolStatistics returned error for scientific-notation counter: %v", err)
	}
	// The huge value (max uint64 in scientific notation) must degrade to 0.
	if data.UDPDeliveredPackets != 0 {
		t.Errorf("expected UDPDeliveredPackets=0 for scientific-notation overflow, got %d", data.UDPDeliveredPackets)
	}
	// Normal counters must still parse correctly.
	if data.TCPSentPackets != 100 {
		t.Errorf("expected TCPSentPackets=100, got %d", data.TCPSentPackets)
	}
	if data.TCPReceivedPackets != 200 {
		t.Errorf("expected TCPReceivedPackets=200, got %d", data.TCPReceivedPackets)
	}
	if data.UDPReceivedDatagrams != 42 {
		t.Errorf("expected UDPReceivedDatagrams=42, got %d", data.UDPReceivedDatagrams)
	}
	if data.UDPOutputPackets != 99 {
		t.Errorf("expected UDPOutputPackets=99, got %d", data.UDPOutputPackets)
	}
}

// TestFetchProtocolStatistics_TCPConnectionDropsByReason covers #374: the four
// TCP connection-drop reasons (retransmit_timeout, persist_timeout,
// finwait2_timeout, keepalive) each map from their own wire field
// independently, and a reason absent from the payload is omitted from the
// map entirely rather than reported as a fabricated zero — that presence
// gating is the entire point of the metric.
func TestFetchProtocolStatistics_TCPConnectionDropsByReason(t *testing.T) {
	t.Run("all four reasons present with distinct values", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {
				"sent-packets": 1,
				"connections-dropped-by-retransmit-timeout": 11,
				"connections-dropped-by-persist-timeout": 22,
				"connections-dropped-by-finwait2-timeout": 33,
				"connections-dropped-by-keepalives": 44
			}}}`))
		})
		defer server.Close()

		data, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[string]int64{
			"retransmit_timeout": 11,
			"persist_timeout":    22,
			"finwait2_timeout":   33,
			"keepalive":          44,
		}
		if len(data.TCPConnectionDropsByReason) != len(want) {
			t.Fatalf("expected %d reasons, got %d: %v", len(want), len(data.TCPConnectionDropsByReason), data.TCPConnectionDropsByReason)
		}
		// Assert each reason independently against a distinct expected value — a
		// test that would still pass with two reasons swapped is not sufficient.
		for reason, val := range want {
			if got := data.TCPConnectionDropsByReason[reason]; got != val {
				t.Errorf("reason %q = %d, want %d", reason, got, val)
			}
		}
	})

	t.Run("some reasons absent are omitted, not zeroed", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {
				"sent-packets": 1,
				"connections-dropped-by-retransmit-timeout": 5,
				"connections-dropped-by-finwait2-timeout": 0
			}}}`))
		})
		defer server.Close()

		data, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, ok := data.TCPConnectionDropsByReason["retransmit_timeout"]; !ok || got != 5 {
			t.Errorf("expected retransmit_timeout=5 present, got %d ok=%v", got, ok)
		}
		if got, ok := data.TCPConnectionDropsByReason["finwait2_timeout"]; !ok || got != 0 {
			t.Errorf("expected finwait2_timeout=0 present (box sent a literal 0), got %d ok=%v", got, ok)
		}
		if _, ok := data.TCPConnectionDropsByReason["persist_timeout"]; ok {
			t.Error("expected persist_timeout to be OMITTED (absent wire field), not present as a fabricated zero")
		}
		if _, ok := data.TCPConnectionDropsByReason["keepalive"]; ok {
			t.Error("expected keepalive to be OMITTED (absent wire field), not present as a fabricated zero")
		}
	})

	t.Run("all four absent yields an empty map", func(t *testing.T) {
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"statistics": {"tcp": {"sent-packets": 1}}}`))
		})
		defer server.Close()

		data, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(data.TCPConnectionDropsByReason) != 0 {
			t.Errorf("expected no reasons when all four wire fields are absent, got %v", data.TCPConnectionDropsByReason)
		}
	})

	t.Run("monotonic across repeated scrapes", func(t *testing.T) {
		// The reader is a straight pass-through of the box's cumulative kernel
		// counter (reset only on reboot), so successive scrapes of an increasing
		// counter must read back increasing values.
		values := []int64{10, 25}
		call := 0
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
			v := values[call]
			if call < len(values)-1 {
				call++
			}
			fmt.Fprintf(w, `{"statistics": {"tcp": {"sent-packets": 1, "connections-dropped-by-retransmit-timeout": %d}}}`, v)
		})
		defer server.Close()

		first, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error on first scrape: %v", err)
		}
		second, err := client.FetchProtocolStatistics()
		if err != nil {
			t.Fatalf("unexpected error on second scrape: %v", err)
		}
		if first.TCPConnectionDropsByReason["retransmit_timeout"] != 10 {
			t.Fatalf("first scrape retransmit_timeout = %d, want 10", first.TCPConnectionDropsByReason["retransmit_timeout"])
		}
		if second.TCPConnectionDropsByReason["retransmit_timeout"] != 25 {
			t.Fatalf("second scrape retransmit_timeout = %d, want 25", second.TCPConnectionDropsByReason["retransmit_timeout"])
		}
		if second.TCPConnectionDropsByReason["retransmit_timeout"] <= first.TCPConnectionDropsByReason["retransmit_timeout"] {
			t.Error("expected the counter to be monotonically non-decreasing across scrapes")
		}
	})
}

func TestFetchProtocolStatistics_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchProtocolStatistics()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}
