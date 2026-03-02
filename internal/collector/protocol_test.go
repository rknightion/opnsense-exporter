package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
	// Total: 11+2+2+2+6+3+7+2+2+8+2+2+10+1+6+14+9+6+9+1 = 105
	expectedCount := 105
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestProtocolCollector_Name(t *testing.T) {
	c := &protocolCollector{subsystem: ProtocolSubsystem}
	if c.Name() != ProtocolSubsystem {
		t.Errorf("expected %s, got %s", ProtocolSubsystem, c.Name())
	}
}
