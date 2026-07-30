package opnsense

import "encoding/json"

// numToInt converts a json.Number counter to int64.
// If the value cannot be represented as int64 (e.g. scientific notation like
// 1.8446744073709552e+19 returned for max-uint64 counters), it returns 0 so
// a single out-of-range field does not cause the entire scrape to fail.
// int64 (not int) so large counters (>2^31) are not narrowed into negative
// garbage on 32-bit source builds (#103).
func numToInt(n json.Number) int64 {
	i, err := n.Int64()
	if err != nil {
		return 0
	}
	return i
}

// firstPresentNum resolves a counter across payload shapes: it returns the first
// argument the box actually sent, so callers can pass the modern key first and the
// legacy key as the fallback ("new wins when present, else legacy"). An absent JSON
// key leaves json.Number at its zero value (""), which is what "not sent" means here
// — a box that sends the key with value 0 yields "0" and is honoured as present.
// This is how the reader stays version-tolerant without ever branching on version.
func firstPresentNum(nums ...json.Number) json.Number {
	for _, n := range nums {
		if n != "" {
			return n
		}
	}
	return ""
}

// ecnStatistics is statistics.tcp.ecn. FreeBSD/OPNsense renamed the three received-side
// ECN counters in current-stable 26.1.11 (ce-packets -> received-ce-packets, etc.), so
// both spellings are declared and resolved by the ReceivedCe/Ect0/Ect1 accessors below.
// The legacy fields MUST stay: older boxes still send only those, and dropping them
// would zero the counters for every user who has not upgraded.
//
// The ace-*-syn and sent-ect{0,1}-packets keys 26.1.11 added are exported as
// presence-gated metrics (#237, see AccEcnPresent/SentEctPresent below).
type ecnStatistics struct {
	// ≤26.1.x only: superseded by ReceivedCePackets ("received-ce-packets") on 26.1.11+.
	CePackets json.Number `json:"ce-packets"`
	// ≤26.1.x only: superseded by ReceivedEct0Packets ("received-ect0-packets") on 26.1.11+.
	Ect0Packets json.Number `json:"ect0-packets"`
	// ≤26.1.x only: superseded by ReceivedEct1Packets ("received-ect1-packets") on 26.1.11+.
	Ect1Packets json.Number `json:"ect1-packets"`

	// 26.1.11+ spellings of the three counters above.
	ReceivedCePackets   json.Number `json:"received-ce-packets"`
	ReceivedEct0Packets json.Number `json:"received-ect0-packets"`
	ReceivedEct1Packets json.Number `json:"received-ect1-packets"`

	Handshakes           json.Number `json:"handshakes"`
	CongestionReductions json.Number `json:"congestion-reductions"`

	// 26.1.11+ additions (#237). AccECN handshake counters (FreeBSD 15) and the
	// send-side twins of the received-* ECT counters above. Both groups are new
	// fields (not renames), so presence is checked before exporting — absent on
	// an older box must read as "not reported", never a fabricated zero.
	AceCeSyn        json.Number `json:"ace-ce-syn"`
	AceEct0Syn      json.Number `json:"ace-ect0-syn"`
	AceEct1Syn      json.Number `json:"ace-ect1-syn"`
	AceNonEctSyn    json.Number `json:"ace-nonect-syn"`
	SentEct0Packets json.Number `json:"sent-ect0-packets"`
	SentEct1Packets json.Number `json:"sent-ect1-packets"`
}

// SentEctPresent reports whether the box sends the 26.1.11+ send-side ECT
// counters (sent-ect0-packets / sent-ect1-packets are introduced together).
func (e ecnStatistics) SentEctPresent() bool {
	return e.SentEct0Packets != "" || e.SentEct1Packets != ""
}

// AccEcnPresent reports whether the box sends the FreeBSD 15 AccECN handshake
// counters (the four ace-*-syn fields are introduced together).
func (e ecnStatistics) AccEcnPresent() bool {
	return e.AceCeSyn != "" || e.AceEct0Syn != "" || e.AceEct1Syn != "" || e.AceNonEctSyn != ""
}

// ReceivedCe resolves the received CE-marked packet counter across both key spellings.
func (e ecnStatistics) ReceivedCe() json.Number {
	return firstPresentNum(e.ReceivedCePackets, e.CePackets)
}

// ReceivedEct0 resolves the received ECT(0) packet counter across both key spellings.
func (e ecnStatistics) ReceivedEct0() json.Number {
	return firstPresentNum(e.ReceivedEct0Packets, e.Ect0Packets)
}

// ReceivedEct1 resolves the received ECT(1) packet counter across both key spellings.
func (e ecnStatistics) ReceivedEct1() json.Number {
	return firstPresentNum(e.ReceivedEct1Packets, e.Ect1Packets)
}

type protocolStatisticsResponse struct {
	Statistics struct {
		TCP struct {
			SentPackets                         json.Number `json:"sent-packets"`
			SentDataPackets                     json.Number `json:"sent-data-packets"`
			SentDataBytes                       json.Number `json:"sent-data-bytes"`
			SentRetransmittedPackets            json.Number `json:"sent-retransmitted-packets"`
			SentRetransmittedBytes              json.Number `json:"sent-retransmitted-bytes"`
			SentUnnecessaryRetransmittedPackets json.Number `json:"sent-unnecessary-retransmitted-packets"`
			SentResendsByMtuDiscovery           json.Number `json:"sent-resends-by-mtu-discovery"`
			SentAckOnlyPackets                  json.Number `json:"sent-ack-only-packets"`
			SentPacketsDelayed                  json.Number `json:"sent-packets-delayed"`
			SentUrgOnlyPackets                  json.Number `json:"sent-urg-only-packets"`
			SentWindowProbePackets              json.Number `json:"sent-window-probe-packets"`
			SentWindowUpdatePackets             json.Number `json:"sent-window-update-packets"`
			SentControlPackets                  json.Number `json:"sent-control-packets"`
			ReceivedPackets                     json.Number `json:"received-packets"`
			ReceivedAckPackets                  json.Number `json:"received-ack-packets"`
			ReceivedAckBytes                    json.Number `json:"received-ack-bytes"`
			ReceivedDuplicateAcks               json.Number `json:"received-duplicate-acks"`
			ReceivedUDPTunneledPkts             json.Number `json:"received-udp-tunneled-pkts"`
			ReceivedBadUDPTunneledPkts          json.Number `json:"received-bad-udp-tunneled-pkts"`
			// ≤26.1.x only: FreeBSD dropped "received-acks-for-unsent-data" in 26.1.11 with
			// no replacement key, so this reads zero on newer boxes. Kept so older boxes,
			// which still send it, keep reporting. Decoded only — the split below is the
			// exported metric (#237).
			ReceivedAcksForUnsentData json.Number `json:"received-acks-for-unsent-data"`
			// 26.7+ three-way split of the legacy field above. Introduced together, so
			// presence is checked once (ReceivedAcksForDataSplitPresent) rather than per
			// field.
			ReceivedAcksForDataNotYetSent         json.Number `json:"received-acks-for-data-not-yet-sent"`
			ReceivedAcksForDataNeverBeenSent      json.Number `json:"received-acks-for-data-never-been-sent"`
			ReceivedAcksForDataBeingTooOld        json.Number `json:"received-acks-for-data-being-too-old"`
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
			// Syncookies is a new 26.7+ top-level section: the syncache cookie
			// counters moved out of statistics.tcp.syncache.{sent-cookies,receivd-cookies}
			// (upstream's typo included) into their own object, gaining
			// failed/spurious counters and fixing the "receivd" typo along the way.
			// A pointer so nil means the box predates the move (#237); the legacy
			// syncache fields above stay decoded for the support window but never fed
			// a metric, so there is nothing to fall back to.
			Syncookies *struct {
				SentCookies     json.Number `json:"sent-cookies"`
				ReceivedCookies json.Number `json:"received-cookies"`
				FailedCookies   json.Number `json:"failed-cookies"`
				SpuriousCookies json.Number `json:"spurious-cookies"`
			} `json:"syncookies"`
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
				// Added in #545. Both are sent by every release in the support window
				// (verified live on 26.1, 26.7.1 and 27.1.a) — they were simply never
				// declared, so encoding/json silently discarded them. Declaring them
				// changes the reflected golden schema: `make schemas` is required.
				LostRetransmissions json.Number `json:"lost-retransmissions"`
				TsoChunkRetransmits json.Number `json:"tso-chunk-retransmits"`
			} `json:"sack"`
			Ecn          ecnStatistics `json:"ecn"`
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
		// IPv6 / ICMPv6 blocks (#165): previously undeclared, so encoding/json silently
		// dropped them — undercounting a dual-stack box's forwarded traffic by ~20%.
		// Field names are the FreeBSD netstat --libxo tags for ip6/icmp6 (verified live).
		IP6 struct {
			ReceivedPackets         json.Number `json:"received-packets"`
			DroppedBelowMinimumSize json.Number `json:"dropped-below-minimum-size"`
			DroppedShortPackets     json.Number `json:"dropped-short-packets"`
			DroppedBadOptions       json.Number `json:"dropped-bad-options"`
			DroppedBadVersion       json.Number `json:"dropped-bad-version"`
			ReceivedFragments       json.Number `json:"received-fragments"`
			ReassembledPackets      json.Number `json:"reassembled-packets"`
			ForwardedPackets        json.Number `json:"forwarded-packets"`
			PacketsNotForwardable   json.Number `json:"packets-not-forwardable"`
			SentPackets             json.Number `json:"sent-packets"`
			DiscardNoMbufs          json.Number `json:"discard-no-mbufs"`
			DiscardNoRoute          json.Number `json:"discard-no-route"`
			DiscardCannotFragment   json.Number `json:"discard-cannot-fragment"`
			DroppedHeaderTooLong    json.Number `json:"dropped-header-too-long"`
			DroppedTooManyHeaders   json.Number `json:"dropped-too-many-headers"`
		} `json:"ip6"`
		Icmp6 struct {
			IcmpCalls          json.Number `json:"icmp6-calls"`
			DroppedBadCode     json.Number `json:"dropped-bad-code"`
			DroppedTooShort    json.Number `json:"dropped-too-short"`
			DroppedBadChecksum json.Number `json:"dropped-bad-checksum"`
			DroppedBadLength   json.Number `json:"dropped-bad-length"`
			DroppedNoEntry     json.Number `json:"dropped-no-entry"`
		} `json:"icmp6"`
	} `json:"statistics"`
}

// ProtocolStatistics counters are int64 (and map[string]int64) so large byte/
// packet totals (>2^31) are not narrowed into negative garbage on 32-bit source
// builds (#103).
type ProtocolStatistics struct {
	TCPSentPackets            int64
	TCPReceivedPackets        int64
	ARPSentRequests           int64
	ARPReceivedRequests       int64
	TCPConnectionCountByState map[string]int64
	ICMPCalls                 int64
	ICMPSentPackets           int64
	ICMPDroppedByReason       map[string]int64
	UDPDeliveredPackets       int64
	UDPOutputPackets          int64
	UDPReceivedDatagrams      int64
	UDPDroppedByReason        map[string]int64

	// CARP
	CARPReceivedInet    int64
	CARPReceivedInet6   int64
	CARPSentInet        int64
	CARPSentInet6       int64
	CARPDroppedByReason map[string]int64

	// Pfsync
	PfsyncReceivedInet    int64
	PfsyncReceivedInet6   int64
	PfsyncSentInet        int64
	PfsyncSentInet6       int64
	PfsyncDroppedByReason map[string]int64
	PfsyncSendErrors      int64

	// IP
	IPReceivedPackets      int64
	IPForwardedPackets     int64
	IPFastForwardedPackets int64
	IPSentPackets          int64
	IPDroppedByReason      map[string]int64
	IPReceivedFragments    int64
	IPReassembledPackets   int64
	IPSentFragments        int64

	// IPv6 / ICMPv6 (#165)
	IP6ReceivedPackets    int64
	IP6ForwardedPackets   int64
	IP6SentPackets        int64
	IP6ReceivedFragments  int64
	IP6ReassembledPackets int64
	IP6DroppedByReason    map[string]int64
	ICMP6Calls            int64
	ICMP6DroppedByReason  map[string]int64

	// Detailed TCP
	TCPRetransmitTimeouts            int64
	TCPConnectionRequests            int64
	TCPConnectionAccepts             int64
	TCPConnectionsEstablished        int64
	TCPConnectionsClosed             int64
	TCPConnectionDrops               int64
	TCPKeepaliveTimeouts             int64
	TCPKeepaliveProbes               int64
	TCPConnectionsDroppedByKeepalive int64
	TCPListenQueueOverflows          int64

	// TCPConnectionDropsByReason (#374) splits the aggregate TCPConnectionDrops
	// above into the four kernel-lifetime reasons FreeBSD's netstat --libxo
	// reports: retransmit_timeout, persist_timeout, finwait2_timeout, keepalive.
	// Each reason is presence-gated INDEPENDENTLY of the others (see
	// tcpConnectionDropReasons below) — a reason whose wire field the box does
	// not send is left out of the map entirely rather than reported as a
	// fabricated zero, so an operator can trust an absent series to mean "not
	// reported by this box", not "zero this scrape". A nil/empty map means none
	// of the four wire fields were present.
	TCPConnectionDropsByReason map[string]int64
	TCPSyncacheEntriesAdded    int64
	TCPSyncacheDropped         int64
	TCPSentDataBytes           int64
	TCPRetransmittedPackets    int64
	TCPRetransmittedBytes      int64
	TCPReceivedInSequenceBytes int64
	TCPReceivedDuplicateBytes  int64
	TCPSegmentsUpdatedRtt      int64
	TCPBadConnectionAttempts   int64

	// TCP ECN (statistics.tcp.ecn). Resolved across the 26.1.11 key rename
	// (ce-packets -> received-ce-packets, ect0/ect1 likewise), so these carry the
	// same values on an old box and a new one.
	TCPEcnCePackets   int64
	TCPEcnEct0Packets int64
	TCPEcnEct1Packets int64

	// TCP ECN send-side (statistics.tcp.ecn.sent-ect{0,1}-packets, 26.1.11+): twins of
	// the received-side counters above. New fields, not a rename, so gated on
	// TCPEcnSentPresent — absent on an older box, never a fabricated zero (#237).
	TCPEcnSentPresent     bool
	TCPEcnSentEct0Packets int64
	TCPEcnSentEct1Packets int64

	// TCP AccECN handshake counters (statistics.tcp.ecn.ace-*-syn, FreeBSD 15 /
	// 26.1.11+). Gated on TCPEcnAccEcnPresent (#237).
	TCPEcnAccEcnPresent bool
	TCPEcnAceCeSyn      int64
	TCPEcnAceEct0Syn    int64
	TCPEcnAceEct1Syn    int64
	TCPEcnAceNonEctSyn  int64

	// TCP syncookies (statistics.tcp.syncookies, 26.7+): replaces the legacy
	// syncache.{sent-cookies,receivd-cookies} pair, which never fed a metric. Gated
	// on TCPSyncookiesPresent (#237).
	TCPSyncookiesPresent         bool
	TCPSyncookiesSentCookies     int64
	TCPSyncookiesReceivedCookies int64
	TCPSyncookiesFailedCookies   int64
	TCPSyncookiesSpuriousCookies int64

	// TCP received-acks-for-data 3-way split (26.7+): replaces the legacy
	// received-acks-for-unsent-data aggregate, which never fed a metric. Gated on
	// TCPReceivedAcksForDataSplitPresent (#237).
	TCPReceivedAcksForDataSplitPresent  bool
	TCPReceivedAcksForDataNotYetSent    int64
	TCPReceivedAcksForDataNeverBeenSent int64
	TCPReceivedAcksForDataBeingTooOld   int64

	// TCP SACK (statistics.tcp.sack, #545). Selective-ACK recovery: how often the
	// box entered loss recovery and how much it had to retransmit to get out. These
	// were decoded but never mapped — byte-retransmits alone was 58.4M live on prod.
	//
	// NOT presence-gated: all five sections in this #545 group are present on every
	// release in the support window (verified live on 26.1, 26.7.1 and 27.1.a), so
	// there is no version-conditional shape to resolve here.
	TCPSackRecoveryEpisodes    int64
	TCPSackSegmentRetransmits  int64
	TCPSackByteRetransmits     int64
	TCPSackReceivedBlocks      int64
	TCPSackSentOptionBlocks    int64
	TCPSackScoreboardOverflows int64
	TCPSackLostRetransmissions int64
	TCPSackTsoChunkRetransmits int64

	// TCP host cache (statistics.tcp.hostcache, #545). EntriesAdded rising is peer
	// churn; BufferOverflows rising means the cache is full and evicting, so the
	// kernel is losing the cached RTT/ssthresh it would otherwise warm-start with.
	TCPHostcacheEntriesAdded    int64
	TCPHostcacheBufferOverflows int64

	// TCP host cache HITS (#545). These are the counters the issue asked for under
	// "hostcache hits", but on the real box they are NOT inside the hostcache
	// section — they are top-level statistics.tcp fields
	// (connections-hostcache-{rtt,rttvar,ssthresh}), each counting connections that
	// warm-started that one metric from a cached entry. Already decoded since
	// before #545 and, like the sections above, exported by nothing.
	TCPHostcacheHitsByMetric map[string]int64

	// TCP TIME_WAIT recycling (statistics.tcp.tw, #545). Fixed key set, always
	// populated — a zero is reported as a zero, never as an absent series.
	TCPTimeWaitByEvent map[string]int64

	// TCP path-MTU-discovery blackhole detection (statistics.tcp.pmtud, #545).
	// The headline reason this issue exists: a PMTUD blackhole is the classic
	// cause of "some sites load, some hang" and is otherwise invisible from
	// outside the box.
	TCPPmtudBlackholeByEvent map[string]int64

	// TCP-MD5 signatures (statistics.tcp.tcp-signature, RFC 2385, #545). In
	// practice only ever used to authenticate BGP sessions, so all five read zero
	// on a box with no MD5-authenticated peer.
	TCPSignatureByResult map[string]int64

	// ARP detailed
	ARPSentFailures            int64
	ARPSentReplies             int64
	ARPReceivedReplies         int64
	ARPReceivedPackets         int64
	ARPDroppedNoEntry          int64
	ARPEntriesTimeout          int64
	ARPDroppedDuplicateAddress int64
}

// tcpConnectionDropReasons builds the presence-gated reason map for #374.
// Each of the four fixed reasons maps from its own wire field independently:
// a field the box did not send (json.Number zero value, "") is left out of
// the map entirely, while a field the box sent as a literal "0" is kept as a
// present zero. This mirrors the presence-gating convention used elsewhere in
// this file (see TCPEcnSentPresent / TCPEcnAccEcnPresent above), except gated
// per-reason rather than per-group, because presence here is the entire point
// of the metric: an older box that omits one of these fields must omit that
// series, not report a manufactured zero.
func tcpConnectionDropReasons(retransmitTimeout, persistTimeout, finwait2Timeout, keepalives json.Number) map[string]int64 {
	m := make(map[string]int64, 4)
	if retransmitTimeout != "" {
		m["retransmit_timeout"] = numToInt(retransmitTimeout)
	}
	if persistTimeout != "" {
		m["persist_timeout"] = numToInt(persistTimeout)
	}
	if finwait2Timeout != "" {
		m["finwait2_timeout"] = numToInt(finwait2Timeout)
	}
	if keepalives != "" {
		m["keepalive"] = numToInt(keepalives)
	}
	if len(m) == 0 {
		return nil
	}
	return m
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
		TCPConnectionCountByState: map[string]int64{
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
		ICMPDroppedByReason: map[string]int64{
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
		UDPDroppedByReason: map[string]int64{
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
		CARPDroppedByReason: map[string]int64{
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
		PfsyncDroppedByReason: map[string]int64{
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
		IPDroppedByReason: map[string]int64{
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

		IP6ReceivedPackets:    numToInt(resp.Statistics.IP6.ReceivedPackets),
		IP6ForwardedPackets:   numToInt(resp.Statistics.IP6.ForwardedPackets),
		IP6SentPackets:        numToInt(resp.Statistics.IP6.SentPackets),
		IP6ReceivedFragments:  numToInt(resp.Statistics.IP6.ReceivedFragments),
		IP6ReassembledPackets: numToInt(resp.Statistics.IP6.ReassembledPackets),
		IP6DroppedByReason: map[string]int64{
			"BELOW_MINIMUM_SIZE": numToInt(resp.Statistics.IP6.DroppedBelowMinimumSize),
			"SHORT_PACKETS":      numToInt(resp.Statistics.IP6.DroppedShortPackets),
			"BAD_OPTIONS":        numToInt(resp.Statistics.IP6.DroppedBadOptions),
			"BAD_VERSION":        numToInt(resp.Statistics.IP6.DroppedBadVersion),
			"CANNOT_FORWARD":     numToInt(resp.Statistics.IP6.PacketsNotForwardable),
			"NO_MBUFS":           numToInt(resp.Statistics.IP6.DiscardNoMbufs),
			"NO_ROUTE":           numToInt(resp.Statistics.IP6.DiscardNoRoute),
			"CANNOT_FRAGMENT":    numToInt(resp.Statistics.IP6.DiscardCannotFragment),
			"HEADER_TOO_LONG":    numToInt(resp.Statistics.IP6.DroppedHeaderTooLong),
			"TOO_MANY_HEADERS":   numToInt(resp.Statistics.IP6.DroppedTooManyHeaders),
		},
		ICMP6Calls: numToInt(resp.Statistics.Icmp6.IcmpCalls),
		ICMP6DroppedByReason: map[string]int64{
			"BAD_CODE":     numToInt(resp.Statistics.Icmp6.DroppedBadCode),
			"TOO_SHORT":    numToInt(resp.Statistics.Icmp6.DroppedTooShort),
			"BAD_CHECKSUM": numToInt(resp.Statistics.Icmp6.DroppedBadChecksum),
			"BAD_LENGTH":   numToInt(resp.Statistics.Icmp6.DroppedBadLength),
			"NO_ENTRY":     numToInt(resp.Statistics.Icmp6.DroppedNoEntry),
		},

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
		TCPConnectionDropsByReason: tcpConnectionDropReasons(
			resp.Statistics.TCP.ConnectionsDroppedByRetransmitTimeout,
			resp.Statistics.TCP.ConnectionsDroppedByPersistTimeout,
			resp.Statistics.TCP.ConnectionsDroppedByFinwait2Timeout,
			resp.Statistics.TCP.ConnectionsDroppedByKeepalives,
		),
		TCPSyncacheEntriesAdded:    numToInt(resp.Statistics.TCP.Syncache.EntriesAdded),
		TCPSyncacheDropped:         numToInt(resp.Statistics.TCP.Syncache.Dropped),
		TCPSentDataBytes:           numToInt(resp.Statistics.TCP.SentDataBytes),
		TCPRetransmittedPackets:    numToInt(resp.Statistics.TCP.SentRetransmittedPackets),
		TCPRetransmittedBytes:      numToInt(resp.Statistics.TCP.SentRetransmittedBytes),
		TCPReceivedInSequenceBytes: numToInt(resp.Statistics.TCP.ReceivedInSequenceBytes),
		TCPReceivedDuplicateBytes:  numToInt(resp.Statistics.TCP.ReceivedCompletelyDuplicateBytes),
		TCPSegmentsUpdatedRtt:      numToInt(resp.Statistics.TCP.SegmentsUpdatedRtt),
		TCPBadConnectionAttempts:   numToInt(resp.Statistics.TCP.BadConnectionAttempts),

		// TCP ECN — accessors resolve the 26.1.11 rename (new key wins, legacy is the fallback).
		TCPEcnCePackets:   numToInt(resp.Statistics.TCP.Ecn.ReceivedCe()),
		TCPEcnEct0Packets: numToInt(resp.Statistics.TCP.Ecn.ReceivedEct0()),
		TCPEcnEct1Packets: numToInt(resp.Statistics.TCP.Ecn.ReceivedEct1()),

		// TCP ECN send-side (26.1.11+, #237) — presence-gated, new fields not a rename.
		TCPEcnSentPresent:     resp.Statistics.TCP.Ecn.SentEctPresent(),
		TCPEcnSentEct0Packets: numToInt(resp.Statistics.TCP.Ecn.SentEct0Packets),
		TCPEcnSentEct1Packets: numToInt(resp.Statistics.TCP.Ecn.SentEct1Packets),

		// TCP AccECN handshake counters (26.1.11+, #237) — presence-gated.
		TCPEcnAccEcnPresent: resp.Statistics.TCP.Ecn.AccEcnPresent(),
		TCPEcnAceCeSyn:      numToInt(resp.Statistics.TCP.Ecn.AceCeSyn),
		TCPEcnAceEct0Syn:    numToInt(resp.Statistics.TCP.Ecn.AceEct0Syn),
		TCPEcnAceEct1Syn:    numToInt(resp.Statistics.TCP.Ecn.AceEct1Syn),
		TCPEcnAceNonEctSyn:  numToInt(resp.Statistics.TCP.Ecn.AceNonEctSyn),

		// TCP received-acks-for-data 3-way split (26.7+, #237) — presence-gated;
		// the legacy aggregate (received-acks-for-unsent-data) never fed a metric.
		TCPReceivedAcksForDataSplitPresent: resp.Statistics.TCP.ReceivedAcksForDataNotYetSent != "" ||
			resp.Statistics.TCP.ReceivedAcksForDataNeverBeenSent != "" ||
			resp.Statistics.TCP.ReceivedAcksForDataBeingTooOld != "",
		TCPReceivedAcksForDataNotYetSent:    numToInt(resp.Statistics.TCP.ReceivedAcksForDataNotYetSent),
		TCPReceivedAcksForDataNeverBeenSent: numToInt(resp.Statistics.TCP.ReceivedAcksForDataNeverBeenSent),
		TCPReceivedAcksForDataBeingTooOld:   numToInt(resp.Statistics.TCP.ReceivedAcksForDataBeingTooOld),

		// TCP SACK / hostcache / TIME_WAIT / PMTUD / TCP-MD5 (#545) — five whole
		// sections that were decoded on the response struct but never mapped here.
		TCPSackRecoveryEpisodes:    numToInt(resp.Statistics.TCP.Sack.RecoveryEpisodes),
		TCPSackSegmentRetransmits:  numToInt(resp.Statistics.TCP.Sack.SegmentRetransmits),
		TCPSackByteRetransmits:     numToInt(resp.Statistics.TCP.Sack.ByteRetransmits),
		TCPSackReceivedBlocks:      numToInt(resp.Statistics.TCP.Sack.ReceivedBlocks),
		TCPSackSentOptionBlocks:    numToInt(resp.Statistics.TCP.Sack.SentOptionBlocks),
		TCPSackScoreboardOverflows: numToInt(resp.Statistics.TCP.Sack.ScoreboardOverflows),
		TCPSackLostRetransmissions: numToInt(resp.Statistics.TCP.Sack.LostRetransmissions),
		TCPSackTsoChunkRetransmits: numToInt(resp.Statistics.TCP.Sack.TsoChunkRetransmits),

		TCPHostcacheEntriesAdded:    numToInt(resp.Statistics.TCP.Hostcache.EntriesAdded),
		TCPHostcacheBufferOverflows: numToInt(resp.Statistics.TCP.Hostcache.BufferOverflows),
		TCPHostcacheHitsByMetric: map[string]int64{
			"rtt":      numToInt(resp.Statistics.TCP.ConnectionsHostcacheRtt),
			"rttvar":   numToInt(resp.Statistics.TCP.ConnectionsHostcacheRttvar),
			"ssthresh": numToInt(resp.Statistics.TCP.ConnectionsHostcacheSsthresh),
		},

		TCPTimeWaitByEvent: map[string]int64{
			"responds": numToInt(resp.Statistics.TCP.Tw.TwResponds),
			"recycles": numToInt(resp.Statistics.TCP.Tw.TwRecycles),
			"resets":   numToInt(resp.Statistics.TCP.Tw.TwResets),
		},
		TCPPmtudBlackholeByEvent: map[string]int64{
			"activated":         numToInt(resp.Statistics.TCP.Pmtud.PmtudActivated),
			"activated_min_mss": numToInt(resp.Statistics.TCP.Pmtud.PmtudActivatedMinMss),
			"failed":            numToInt(resp.Statistics.TCP.Pmtud.PmtudFailed),
		},
		TCPSignatureByResult: map[string]int64{
			"good":         numToInt(resp.Statistics.TCP.TCPSignature.ReceivedGoodSignature),
			"bad":          numToInt(resp.Statistics.TCP.TCPSignature.ReceivedBadSignature),
			"make_failed":  numToInt(resp.Statistics.TCP.TCPSignature.FailedMakeSignature),
			"not_expected": numToInt(resp.Statistics.TCP.TCPSignature.NoSignatureExpected),
			"not_provided": numToInt(resp.Statistics.TCP.TCPSignature.NoSignatureProvided),
		},

		// ARP detailed
		ARPSentFailures:            numToInt(resp.Statistics.Arp.SentFailures),
		ARPSentReplies:             numToInt(resp.Statistics.Arp.SentReplies),
		ARPReceivedReplies:         numToInt(resp.Statistics.Arp.ReceivedReplies),
		ARPReceivedPackets:         numToInt(resp.Statistics.Arp.ReceivedPackets),
		ARPDroppedNoEntry:          numToInt(resp.Statistics.Arp.DroppedNoEntry),
		ARPEntriesTimeout:          numToInt(resp.Statistics.Arp.EntriesTimeout),
		ARPDroppedDuplicateAddress: numToInt(resp.Statistics.Arp.DroppedDuplicateAddress),
	}

	// TCP syncookies (26.7+, #237): a whole new top-level section, so presence is a
	// nil pointer check rather than a per-field empty-string check.
	if sc := resp.Statistics.TCP.Syncookies; sc != nil {
		out.TCPSyncookiesPresent = true
		out.TCPSyncookiesSentCookies = numToInt(sc.SentCookies)
		out.TCPSyncookiesReceivedCookies = numToInt(sc.ReceivedCookies)
		out.TCPSyncookiesFailedCookies = numToInt(sc.FailedCookies)
		out.TCPSyncookiesSpuriousCookies = numToInt(sc.SpuriousCookies)
	}

	return out, nil
}
