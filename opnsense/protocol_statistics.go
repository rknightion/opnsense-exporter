package opnsense

import "encoding/json"

// numToInt converts a json.Number counter to int.
// If the value cannot be represented as int64 (e.g. scientific notation like
// 1.8446744073709552e+19 returned for max-uint64 counters), it returns 0 so
// a single out-of-range field does not cause the entire scrape to fail.
func numToInt(n json.Number) int {
	i, err := n.Int64()
	if err != nil {
		return 0
	}
	return int(i)
}

type protocolStatisticsResponse struct {
	Statistics struct {
		TCP struct {
			SentPackets                           json.Number `json:"sent-packets"`
			SentDataPackets                       json.Number `json:"sent-data-packets"`
			SentDataBytes                         json.Number `json:"sent-data-bytes"`
			SentRetransmittedPackets              json.Number `json:"sent-retransmitted-packets"`
			SentRetransmittedBytes                json.Number `json:"sent-retransmitted-bytes"`
			SentUnnecessaryRetransmittedPackets   json.Number `json:"sent-unnecessary-retransmitted-packets"`
			SentResendsByMtuDiscovery             json.Number `json:"sent-resends-by-mtu-discovery"`
			SentAckOnlyPackets                    json.Number `json:"sent-ack-only-packets"`
			SentPacketsDelayed                    json.Number `json:"sent-packets-delayed"`
			SentUrgOnlyPackets                    json.Number `json:"sent-urg-only-packets"`
			SentWindowProbePackets                json.Number `json:"sent-window-probe-packets"`
			SentWindowUpdatePackets               json.Number `json:"sent-window-update-packets"`
			SentControlPackets                    json.Number `json:"sent-control-packets"`
			ReceivedPackets                       json.Number `json:"received-packets"`
			ReceivedAckPackets                    json.Number `json:"received-ack-packets"`
			ReceivedAckBytes                      json.Number `json:"received-ack-bytes"`
			ReceivedDuplicateAcks                 json.Number `json:"received-duplicate-acks"`
			ReceivedUDPTunneledPkts               json.Number `json:"received-udp-tunneled-pkts"`
			ReceivedBadUDPTunneledPkts            json.Number `json:"received-bad-udp-tunneled-pkts"`
			ReceivedAcksForUnsentData             json.Number `json:"received-acks-for-unsent-data"`
			ReceivedInSequencePackets             json.Number `json:"received-in-sequence-packets"`
			ReceivedInSequenceBytes               json.Number `json:"received-in-sequence-bytes"`
			ReceivedCompletelyDuplicatePackets    json.Number `json:"received-completely-duplicate-packets"`
			ReceivedCompletelyDuplicateBytes      json.Number `json:"received-completely-duplicate-bytes"`
			ReceivedOldDuplicatePackets           json.Number `json:"received-old-duplicate-packets"`
			ReceivedSomeDuplicatePackets          json.Number `json:"received-some-duplicate-packets"`
			ReceivedSomeDuplicateBytes            json.Number `json:"received-some-duplicate-bytes"`
			ReceivedOutOfOrder                    json.Number `json:"received-out-of-order"`
			ReceivedOutOfOrderBytes               json.Number `json:"received-out-of-order-bytes"`
			ReceivedAfterWindowPackets            json.Number `json:"received-after-window-packets"`
			ReceivedAfterWindowBytes              json.Number `json:"received-after-window-bytes"`
			ReceivedWindowProbes                  json.Number `json:"received-window-probes"`
			ReceiveWindowUpdatePackets            json.Number `json:"receive-window-update-packets"`
			ReceivedAfterClosePackets             json.Number `json:"received-after-close-packets"`
			DiscardBadChecksum                    json.Number `json:"discard-bad-checksum"`
			DiscardBadHeaderOffset                json.Number `json:"discard-bad-header-offset"`
			DiscardTooShort                       json.Number `json:"discard-too-short"`
			DiscardReassemblyQueueFull            json.Number `json:"discard-reassembly-queue-full"`
			ConnectionRequests                    json.Number `json:"connection-requests"`
			ConnectionsAccepts                    json.Number `json:"connections-accepts"`
			BadConnectionAttempts                 json.Number `json:"bad-connection-attempts"`
			ListenQueueOverflows                  json.Number `json:"listen-queue-overflows"`
			IgnoredInWindowResets                 json.Number `json:"ignored-in-window-resets"`
			ConnectionsEstablished                json.Number `json:"connections-established"`
			ConnectionsHostcacheRtt               json.Number `json:"connections-hostcache-rtt"`
			ConnectionsHostcacheRttvar            json.Number `json:"connections-hostcache-rttvar"`
			ConnectionsHostcacheSsthresh          json.Number `json:"connections-hostcache-ssthresh"`
			ConnectionsClosed                     json.Number `json:"connections-closed"`
			ConnectionDrops                       json.Number `json:"connection-drops"`
			ConnectionsUpdatedRttOnClose          json.Number `json:"connections-updated-rtt-on-close"`
			ConnectionsUpdatedVarianceOnClose     json.Number `json:"connections-updated-variance-on-close"`
			ConnectionsUpdatedSsthreshOnClose     json.Number `json:"connections-updated-ssthresh-on-close"`
			EmbryonicConnectionsDropped           json.Number `json:"embryonic-connections-dropped"`
			SegmentsUpdatedRtt                    json.Number `json:"segments-updated-rtt"`
			SegmentUpdateAttempts                 json.Number `json:"segment-update-attempts"`
			RetransmitTimeouts                    json.Number `json:"retransmit-timeouts"`
			ConnectionsDroppedByRetransmitTimeout json.Number `json:"connections-dropped-by-retransmit-timeout"`
			PersistTimeout                        json.Number `json:"persist-timeout"`
			ConnectionsDroppedByPersistTimeout    json.Number `json:"connections-dropped-by-persist-timeout"`
			ConnectionsDroppedByFinwait2Timeout   json.Number `json:"connections-dropped-by-finwait2-timeout"`
			KeepaliveTimeout                      json.Number `json:"keepalive-timeout"`
			KeepaliveProbes                       json.Number `json:"keepalive-probes"`
			ConnectionsDroppedByKeepalives        json.Number `json:"connections-dropped-by-keepalives"`
			AckHeaderPredictions                  json.Number `json:"ack-header-predictions"`
			DataPacketHeaderPredictions           json.Number `json:"data-packet-header-predictions"`
			Syncache                              struct {
				EntriesAdded   json.Number `json:"entries-added"`
				Retransmitted  json.Number `json:"retransmitted"`
				Duplicates     json.Number `json:"duplicates"`
				Dropped        json.Number `json:"dropped"`
				Completed      json.Number `json:"completed"`
				BucketOverflow json.Number `json:"bucket-overflow"`
				CacheOverflow  json.Number `json:"cache-overflow"`
				Reset          json.Number `json:"reset"`
				Stale          json.Number `json:"stale"`
				Aborted        json.Number `json:"aborted"`
				BadAck         json.Number `json:"bad-ack"`
				Unreachable    json.Number `json:"unreachable"`
				ZoneFailures   json.Number `json:"zone-failures"`
				SentCookies    json.Number `json:"sent-cookies"`
				ReceivdCookies json.Number `json:"receivd-cookies"`
			} `json:"syncache"`
			Hostcache struct {
				EntriesAdded    json.Number `json:"entries-added"`
				BufferOverflows json.Number `json:"buffer-overflows"`
			} `json:"hostcache"`
			Sack struct {
				RecoveryEpisodes    json.Number `json:"recovery-episodes"`
				SegmentRetransmits  json.Number `json:"segment-retransmits"`
				ByteRetransmits     json.Number `json:"byte-retransmits"`
				ReceivedBlocks      json.Number `json:"received-blocks"`
				SentOptionBlocks    json.Number `json:"sent-option-blocks"`
				ScoreboardOverflows json.Number `json:"scoreboard-overflows"`
			} `json:"sack"`
			Ecn struct {
				CePackets            json.Number `json:"ce-packets"`
				Ect0Packets          json.Number `json:"ect0-packets"`
				Ect1Packets          json.Number `json:"ect1-packets"`
				Handshakes           json.Number `json:"handshakes"`
				CongestionReductions json.Number `json:"congestion-reductions"`
			} `json:"ecn"`
			TCPSignature struct {
				ReceivedGoodSignature json.Number `json:"received-good-signature"`
				ReceivedBadSignature  json.Number `json:"received-bad-signature"`
				FailedMakeSignature   json.Number `json:"failed-make-signature"`
				NoSignatureExpected   json.Number `json:"no-signature-expected"`
				NoSignatureProvided   json.Number `json:"no-signature-provided"`
			} `json:"tcp-signature"`
			Pmtud struct {
				PmtudActivated       json.Number `json:"pmtud-activated"`
				PmtudActivatedMinMss json.Number `json:"pmtud-activated-min-mss"`
				PmtudFailed          json.Number `json:"pmtud-failed"`
			} `json:"pmtud"`
			Tw struct {
				TwResponds json.Number `json:"tw_responds"`
				TwRecycles json.Number `json:"tw_recycles"`
				TwResets   json.Number `json:"tw_resets"`
			} `json:"tw"`
			TCPConnectionCountByState struct {
				Closed      json.Number `json:"CLOSED"`
				Listen      json.Number `json:"LISTEN"`
				SynSent     json.Number `json:"SYN_SENT"`
				SynRcvd     json.Number `json:"SYN_RCVD"`
				Established json.Number `json:"ESTABLISHED"`
				CloseWait   json.Number `json:"CLOSE_WAIT"`
				FinWait1    json.Number `json:"FIN_WAIT_1"`
				Closing     json.Number `json:"CLOSING"`
				LastAck     json.Number `json:"LAST_ACK"`
				FinWait2    json.Number `json:"FIN_WAIT_2"`
				TimeWait    json.Number `json:"TIME_WAIT"`
			} `json:"TCP connection count by state"`
		} `json:"tcp"`
		UDP struct {
			ReceivedDatagrams            json.Number `json:"received-datagrams"`
			DroppedIncompleteHeaders     json.Number `json:"dropped-incomplete-headers"`
			DroppedBadDataLength         json.Number `json:"dropped-bad-data-length"`
			DroppedBadChecksum           json.Number `json:"dropped-bad-checksum"`
			DroppedNoChecksum            json.Number `json:"dropped-no-checksum"`
			DroppedNoSocket              json.Number `json:"dropped-no-socket"`
			DroppedBroadcastMulticast    json.Number `json:"dropped-broadcast-multicast"`
			DroppedFullSocketBuffer      json.Number `json:"dropped-full-socket-buffer"`
			NotForHashedPcb              json.Number `json:"not-for-hashed-pcb"`
			DeliveredPackets             json.Number `json:"delivered-packets"`
			OutputPackets                json.Number `json:"output-packets"`
			MulticastSourceFilterMatches json.Number `json:"multicast-source-filter-matches"`
		} `json:"udp"`
		IP struct {
			ReceivedPackets               json.Number `json:"received-packets"`
			DroppedBadChecksum            json.Number `json:"dropped-bad-checksum"`
			DroppedBelowMinimumSize       json.Number `json:"dropped-below-minimum-size"`
			DroppedShortPackets           json.Number `json:"dropped-short-packets"`
			DroppedTooLong                json.Number `json:"dropped-too-long"`
			DroppedShortHeaderLength      json.Number `json:"dropped-short-header-length"`
			DroppedShortData              json.Number `json:"dropped-short-data"`
			DroppedBadOptions             json.Number `json:"dropped-bad-options"`
			DroppedBadVersion             json.Number `json:"dropped-bad-version"`
			ReceivedFragments             json.Number `json:"received-fragments"`
			DroppedFragments              json.Number `json:"dropped-fragments"`
			DroppedFragmentsAfterTimeout  json.Number `json:"dropped-fragments-after-timeout"`
			ReassembledPackets            json.Number `json:"reassembled-packets"`
			ReceivedLocalPackets          json.Number `json:"received-local-packets"`
			DroppedUnknownProtocol        json.Number `json:"dropped-unknown-protocol"`
			ForwardedPackets              json.Number `json:"forwarded-packets"`
			FastForwardedPackets          json.Number `json:"fast-forwarded-packets"`
			PacketsCannotForward          json.Number `json:"packets-cannot-forward"`
			ReceivedUnknownMulticastGroup json.Number `json:"received-unknown-multicast-group"`
			RedirectsSent                 json.Number `json:"redirects-sent"`
			SentPackets                   json.Number `json:"sent-packets"`
			SendPacketsFabricatedHeader   json.Number `json:"send-packets-fabricated-header"`
			DiscardNoMbufs                json.Number `json:"discard-no-mbufs"`
			DiscardNoRoute                json.Number `json:"discard-no-route"`
			SentFragments                 json.Number `json:"sent-fragments"`
			FragmentsCreated              json.Number `json:"fragments-created"`
			DiscardCannotFragment         json.Number `json:"discard-cannot-fragment"`
			DiscardTunnelNoGif            json.Number `json:"discard-tunnel-no-gif"`
			DiscardBadAddress             json.Number `json:"discard-bad-address"`
		} `json:"ip"`
		Icmp struct {
			IcmpCalls                   json.Number `json:"icmp-calls"`
			ErrorsNotFromMessage        json.Number `json:"errors-not-from-message"`
			DroppedBadCode              json.Number `json:"dropped-bad-code"`
			DroppedTooShort             json.Number `json:"dropped-too-short"`
			DroppedBadChecksum          json.Number `json:"dropped-bad-checksum"`
			DroppedBadLength            json.Number `json:"dropped-bad-length"`
			DroppedMulticastEcho        json.Number `json:"dropped-multicast-echo"`
			DroppedMulticastTimestamp   json.Number `json:"dropped-multicast-timestamp"`
			SentPackets                 json.Number `json:"sent-packets"`
			DiscardInvalidReturnAddress json.Number `json:"discard-invalid-return-address"`
			DiscardNoRoute              json.Number `json:"discard-no-route"`
			IcmpAddressResponses        string      `json:"icmp-address-responses"`
		} `json:"icmp"`
		Carp struct {
			ReceivedInetPackets      json.Number `json:"received-inet-packets"`
			ReceivedInet6Packets     json.Number `json:"received-inet6-packets"`
			DroppedWrongTTL          json.Number `json:"dropped-wrong-ttl"`
			DroppedShortHeader       json.Number `json:"dropped-short-header"`
			DroppedBadChecksum       json.Number `json:"dropped-bad-checksum"`
			DroppedBadVersion        json.Number `json:"dropped-bad-version"`
			DroppedShortPacket       json.Number `json:"dropped-short-packet"`
			DroppedBadAuthentication json.Number `json:"dropped-bad-authentication"`
			DroppedBadVhid           json.Number `json:"dropped-bad-vhid"`
			DroppedBadAddressList    json.Number `json:"dropped-bad-address-list"`
			SentInetPackets          json.Number `json:"sent-inet-packets"`
			SentInet6Packets         json.Number `json:"sent-inet6-packets"`
			SendFailedMemoryError    json.Number `json:"send-failed-memory-error"`
		} `json:"carp"`
		Pfsync struct {
			ReceivedInetPackets  json.Number `json:"received-inet-packets"`
			ReceivedInet6Packets json.Number `json:"received-inet6-packets"`
			InputHistogram       []struct {
				Name  string      `json:"name"`
				Count json.Number `json:"count"`
			} `json:"input-histogram"`
			DroppedBadInterface json.Number `json:"dropped-bad-interface"`
			DroppedBadTTL       json.Number `json:"dropped-bad-ttl"`
			DroppedShortHeader  json.Number `json:"dropped-short-header"`
			DroppedBadVersion   json.Number `json:"dropped-bad-version"`
			DroppedBadAuth      json.Number `json:"dropped-bad-auth"`
			DroppedBadAction    json.Number `json:"dropped-bad-action"`
			DroppedShort        json.Number `json:"dropped-short"`
			DroppedBadValues    json.Number `json:"dropped-bad-values"`
			DroppedStaleState   json.Number `json:"dropped-stale-state"`
			DroppedFailedLookup json.Number `json:"dropped-failed-lookup"`
			SentInetPackets     json.Number `json:"sent-inet-packets"`
			SendInet6Packets    json.Number `json:"send-inet6-packets"`
			OutputHistogram     []struct {
				Name  string      `json:"name"`
				Count json.Number `json:"count"`
			} `json:"output-histogram"`
			DiscardedNoMemory json.Number `json:"discarded-no-memory"`
			SendErrors        json.Number `json:"send-errors"`
		} `json:"pfsync"`
		Arp struct {
			SentRequests            json.Number `json:"sent-requests"`
			SentFailures            json.Number `json:"sent-failures"`
			SentReplies             json.Number `json:"sent-replies"`
			ReceivedRequests        json.Number `json:"received-requests"`
			ReceivedReplies         json.Number `json:"received-replies"`
			ReceivedPackets         json.Number `json:"received-packets"`
			DroppedNoEntry          json.Number `json:"dropped-no-entry"`
			EntriesTimeout          json.Number `json:"entries-timeout"`
			DroppedDuplicateAddress json.Number `json:"dropped-duplicate-address"`
		} `json:"arp"`
	} `json:"statistics"`
}

type ProtocolStatistics struct {
	TCPSentPackets            int
	TCPReceivedPackets        int
	ARPSentRequests           int
	ARPReceivedRequests       int
	TCPConnectionCountByState map[string]int
	ICMPCalls                 int
	ICMPSentPackets           int
	ICMPDroppedByReason       map[string]int
	UDPDeliveredPackets       int
	UDPOutputPackets          int
	UDPReceivedDatagrams      int
	UDPDroppedByReason        map[string]int

	// CARP
	CARPReceivedInet    int
	CARPReceivedInet6   int
	CARPSentInet        int
	CARPSentInet6       int
	CARPDroppedByReason map[string]int

	// Pfsync
	PfsyncReceivedInet    int
	PfsyncReceivedInet6   int
	PfsyncSentInet        int
	PfsyncSentInet6       int
	PfsyncDroppedByReason map[string]int
	PfsyncSendErrors      int

	// IP
	IPReceivedPackets      int
	IPForwardedPackets     int
	IPFastForwardedPackets int
	IPSentPackets          int
	IPDroppedByReason      map[string]int
	IPReceivedFragments    int
	IPReassembledPackets   int
	IPSentFragments        int

	// Detailed TCP
	TCPRetransmitTimeouts            int
	TCPConnectionRequests            int
	TCPConnectionAccepts             int
	TCPConnectionsEstablished        int
	TCPConnectionsClosed             int
	TCPConnectionDrops               int
	TCPKeepaliveTimeouts             int
	TCPKeepaliveProbes               int
	TCPConnectionsDroppedByKeepalive int
	TCPListenQueueOverflows          int
	TCPSyncacheEntriesAdded          int
	TCPSyncacheDropped               int
	TCPSentDataBytes                 int
	TCPRetransmittedPackets          int
	TCPRetransmittedBytes            int
	TCPReceivedInSequenceBytes       int
	TCPReceivedDuplicateBytes        int
	TCPSegmentsUpdatedRtt            int
	TCPBadConnectionAttempts         int

	// ARP detailed
	ARPSentFailures            int
	ARPSentReplies             int
	ARPReceivedReplies         int
	ARPReceivedPackets         int
	ARPDroppedNoEntry          int
	ARPEntriesTimeout          int
	ARPDroppedDuplicateAddress int
}

func (c *Client) FetchProtocolStatistics() (ProtocolStatistics, *APICallError) {
	var resp protocolStatisticsResponse
	url, ok := c.endpoints["protocolStatistics"]
	if !ok {
		return ProtocolStatistics{}, &APICallError{
			Endpoint:   "protocolStatistics",
			StatusCode: 404,
			Message:    "endpoint not found in client endpoints",
		}
	}
	if err := c.do("GET", url, nil, &resp); err != nil {
		return ProtocolStatistics{}, err
	}

	out := ProtocolStatistics{
		TCPSentPackets:      numToInt(resp.Statistics.TCP.SentPackets),
		TCPReceivedPackets:  numToInt(resp.Statistics.TCP.ReceivedPackets),
		ARPSentRequests:     numToInt(resp.Statistics.Arp.SentRequests),
		ARPReceivedRequests: numToInt(resp.Statistics.Arp.ReceivedRequests),
		TCPConnectionCountByState: map[string]int{
			"CLOSED":      numToInt(resp.Statistics.TCP.TCPConnectionCountByState.Closed),
			"LISTEN":      numToInt(resp.Statistics.TCP.TCPConnectionCountByState.Listen),
			"SYN_SENT":    numToInt(resp.Statistics.TCP.TCPConnectionCountByState.SynSent),
			"SYN_RCVD":    numToInt(resp.Statistics.TCP.TCPConnectionCountByState.SynRcvd),
			"ESTABLISHED": numToInt(resp.Statistics.TCP.TCPConnectionCountByState.Established),
			"CLOSE_WAIT":  numToInt(resp.Statistics.TCP.TCPConnectionCountByState.CloseWait),
			"FIN_WAIT_1":  numToInt(resp.Statistics.TCP.TCPConnectionCountByState.FinWait1),
			"CLOSING":     numToInt(resp.Statistics.TCP.TCPConnectionCountByState.Closing),
			"LAST_ACK":    numToInt(resp.Statistics.TCP.TCPConnectionCountByState.LastAck),
			"FIN_WAIT_2":  numToInt(resp.Statistics.TCP.TCPConnectionCountByState.FinWait2),
			"TIME_WAIT":   numToInt(resp.Statistics.TCP.TCPConnectionCountByState.TimeWait),
		},
		ICMPCalls:       numToInt(resp.Statistics.Icmp.IcmpCalls),
		ICMPSentPackets: numToInt(resp.Statistics.Icmp.SentPackets),
		ICMPDroppedByReason: map[string]int{
			"BAD_CODE":            numToInt(resp.Statistics.Icmp.DroppedBadCode),
			"TOO_SHORT":           numToInt(resp.Statistics.Icmp.DroppedTooShort),
			"BAD_CHECKSUM":        numToInt(resp.Statistics.Icmp.DroppedBadChecksum),
			"BAD_LENGTH":          numToInt(resp.Statistics.Icmp.DroppedBadLength),
			"MULTICAST_ECHO":      numToInt(resp.Statistics.Icmp.DroppedMulticastEcho),
			"MULTICAST_TIMESTAMP": numToInt(resp.Statistics.Icmp.DroppedMulticastTimestamp),
		},
		UDPDeliveredPackets:  numToInt(resp.Statistics.UDP.DeliveredPackets),
		UDPOutputPackets:     numToInt(resp.Statistics.UDP.OutputPackets),
		UDPReceivedDatagrams: numToInt(resp.Statistics.UDP.ReceivedDatagrams),
		UDPDroppedByReason: map[string]int{
			"INCOMPLETE_HEADERS":  numToInt(resp.Statistics.UDP.DroppedIncompleteHeaders),
			"BAD_DATA_LENGTH":     numToInt(resp.Statistics.UDP.DroppedBadDataLength),
			"BAD_CHECKSUM":        numToInt(resp.Statistics.UDP.DroppedBadChecksum),
			"NO_CHECKSUM":         numToInt(resp.Statistics.UDP.DroppedNoChecksum),
			"NO_SOCKET":           numToInt(resp.Statistics.UDP.DroppedNoSocket),
			"BROADCAST_MULTICAST": numToInt(resp.Statistics.UDP.DroppedBroadcastMulticast),
			"FULL_SOCKET_BUFFER":  numToInt(resp.Statistics.UDP.DroppedFullSocketBuffer),
		},

		// CARP
		CARPReceivedInet:  numToInt(resp.Statistics.Carp.ReceivedInetPackets),
		CARPReceivedInet6: numToInt(resp.Statistics.Carp.ReceivedInet6Packets),
		CARPSentInet:      numToInt(resp.Statistics.Carp.SentInetPackets),
		CARPSentInet6:     numToInt(resp.Statistics.Carp.SentInet6Packets),
		CARPDroppedByReason: map[string]int{
			"WRONG_TTL":        numToInt(resp.Statistics.Carp.DroppedWrongTTL),
			"SHORT_HEADER":     numToInt(resp.Statistics.Carp.DroppedShortHeader),
			"BAD_CHECKSUM":     numToInt(resp.Statistics.Carp.DroppedBadChecksum),
			"BAD_VERSION":      numToInt(resp.Statistics.Carp.DroppedBadVersion),
			"SHORT_PACKET":     numToInt(resp.Statistics.Carp.DroppedShortPacket),
			"BAD_AUTH":         numToInt(resp.Statistics.Carp.DroppedBadAuthentication),
			"BAD_VHID":         numToInt(resp.Statistics.Carp.DroppedBadVhid),
			"BAD_ADDRESS_LIST": numToInt(resp.Statistics.Carp.DroppedBadAddressList),
		},

		// Pfsync
		PfsyncReceivedInet:  numToInt(resp.Statistics.Pfsync.ReceivedInetPackets),
		PfsyncReceivedInet6: numToInt(resp.Statistics.Pfsync.ReceivedInet6Packets),
		PfsyncSentInet:      numToInt(resp.Statistics.Pfsync.SentInetPackets),
		PfsyncSentInet6:     numToInt(resp.Statistics.Pfsync.SendInet6Packets),
		PfsyncDroppedByReason: map[string]int{
			"BAD_INTERFACE": numToInt(resp.Statistics.Pfsync.DroppedBadInterface),
			"BAD_TTL":       numToInt(resp.Statistics.Pfsync.DroppedBadTTL),
			"SHORT_HEADER":  numToInt(resp.Statistics.Pfsync.DroppedShortHeader),
			"BAD_VERSION":   numToInt(resp.Statistics.Pfsync.DroppedBadVersion),
			"BAD_AUTH":      numToInt(resp.Statistics.Pfsync.DroppedBadAuth),
			"BAD_ACTION":    numToInt(resp.Statistics.Pfsync.DroppedBadAction),
			"SHORT":         numToInt(resp.Statistics.Pfsync.DroppedShort),
			"BAD_VALUES":    numToInt(resp.Statistics.Pfsync.DroppedBadValues),
			"STALE_STATE":   numToInt(resp.Statistics.Pfsync.DroppedStaleState),
			"FAILED_LOOKUP": numToInt(resp.Statistics.Pfsync.DroppedFailedLookup),
		},
		PfsyncSendErrors: numToInt(resp.Statistics.Pfsync.SendErrors),

		// IP
		IPReceivedPackets:      numToInt(resp.Statistics.IP.ReceivedPackets),
		IPForwardedPackets:     numToInt(resp.Statistics.IP.ForwardedPackets),
		IPFastForwardedPackets: numToInt(resp.Statistics.IP.FastForwardedPackets),
		IPSentPackets:          numToInt(resp.Statistics.IP.SentPackets),
		IPDroppedByReason: map[string]int{
			"BAD_CHECKSUM":        numToInt(resp.Statistics.IP.DroppedBadChecksum),
			"BELOW_MINIMUM_SIZE":  numToInt(resp.Statistics.IP.DroppedBelowMinimumSize),
			"SHORT_PACKETS":       numToInt(resp.Statistics.IP.DroppedShortPackets),
			"TOO_LONG":            numToInt(resp.Statistics.IP.DroppedTooLong),
			"SHORT_HEADER_LENGTH": numToInt(resp.Statistics.IP.DroppedShortHeaderLength),
			"SHORT_DATA":          numToInt(resp.Statistics.IP.DroppedShortData),
			"BAD_OPTIONS":         numToInt(resp.Statistics.IP.DroppedBadOptions),
			"BAD_VERSION":         numToInt(resp.Statistics.IP.DroppedBadVersion),
			"UNKNOWN_PROTOCOL":    numToInt(resp.Statistics.IP.DroppedUnknownProtocol),
			"CANNOT_FORWARD":      numToInt(resp.Statistics.IP.PacketsCannotForward),
			"NO_MBUFS":            numToInt(resp.Statistics.IP.DiscardNoMbufs),
			"NO_ROUTE":            numToInt(resp.Statistics.IP.DiscardNoRoute),
			"CANNOT_FRAGMENT":     numToInt(resp.Statistics.IP.DiscardCannotFragment),
			"BAD_ADDRESS":         numToInt(resp.Statistics.IP.DiscardBadAddress),
		},
		IPReceivedFragments:  numToInt(resp.Statistics.IP.ReceivedFragments),
		IPReassembledPackets: numToInt(resp.Statistics.IP.ReassembledPackets),
		IPSentFragments:      numToInt(resp.Statistics.IP.SentFragments),

		// Detailed TCP
		TCPRetransmitTimeouts:            numToInt(resp.Statistics.TCP.RetransmitTimeouts),
		TCPConnectionRequests:            numToInt(resp.Statistics.TCP.ConnectionRequests),
		TCPConnectionAccepts:             numToInt(resp.Statistics.TCP.ConnectionsAccepts),
		TCPConnectionsEstablished:        numToInt(resp.Statistics.TCP.ConnectionsEstablished),
		TCPConnectionsClosed:             numToInt(resp.Statistics.TCP.ConnectionsClosed),
		TCPConnectionDrops:               numToInt(resp.Statistics.TCP.ConnectionDrops),
		TCPKeepaliveTimeouts:             numToInt(resp.Statistics.TCP.KeepaliveTimeout),
		TCPKeepaliveProbes:               numToInt(resp.Statistics.TCP.KeepaliveProbes),
		TCPConnectionsDroppedByKeepalive: numToInt(resp.Statistics.TCP.ConnectionsDroppedByKeepalives),
		TCPListenQueueOverflows:          numToInt(resp.Statistics.TCP.ListenQueueOverflows),
		TCPSyncacheEntriesAdded:          numToInt(resp.Statistics.TCP.Syncache.EntriesAdded),
		TCPSyncacheDropped:               numToInt(resp.Statistics.TCP.Syncache.Dropped),
		TCPSentDataBytes:                 numToInt(resp.Statistics.TCP.SentDataBytes),
		TCPRetransmittedPackets:          numToInt(resp.Statistics.TCP.SentRetransmittedPackets),
		TCPRetransmittedBytes:            numToInt(resp.Statistics.TCP.SentRetransmittedBytes),
		TCPReceivedInSequenceBytes:       numToInt(resp.Statistics.TCP.ReceivedInSequenceBytes),
		TCPReceivedDuplicateBytes:        numToInt(resp.Statistics.TCP.ReceivedCompletelyDuplicateBytes),
		TCPSegmentsUpdatedRtt:            numToInt(resp.Statistics.TCP.SegmentsUpdatedRtt),
		TCPBadConnectionAttempts:         numToInt(resp.Statistics.TCP.BadConnectionAttempts),

		// ARP detailed
		ARPSentFailures:            numToInt(resp.Statistics.Arp.SentFailures),
		ARPSentReplies:             numToInt(resp.Statistics.Arp.SentReplies),
		ARPReceivedReplies:         numToInt(resp.Statistics.Arp.ReceivedReplies),
		ARPReceivedPackets:         numToInt(resp.Statistics.Arp.ReceivedPackets),
		ARPDroppedNoEntry:          numToInt(resp.Statistics.Arp.DroppedNoEntry),
		ARPEntriesTimeout:          numToInt(resp.Statistics.Arp.EntriesTimeout),
		ARPDroppedDuplicateAddress: numToInt(resp.Statistics.Arp.DroppedDuplicateAddress),
	}

	return out, nil
}
