package opnsense

import (
	"net/http"
	"testing"
)

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
