package opnsense

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// netbirdManagementState mirrors the "management" object in the wire JSON
// (client/status/status.go ManagementStateOutput, github.com/netbirdio/netbird).
// Only Connected is consumed; URL/Error are not modeled.
type netbirdManagementState struct {
	Connected bool `json:"connected"`
}

// netbirdSignalState mirrors the "signal" object (SignalStateOutput).
type netbirdSignalState struct {
	Connected bool `json:"connected"`
}

// netbirdRelayState mirrors the "relays" object (RelayStateOutput). Only the
// aggregate counts are consumed; per-relay Details are not modeled (no
// per-relay metric is proposed for #211).
type netbirdRelayState struct {
	Total     int `json:"total"`
	Available int `json:"available"`
}

// netbirdPeerDetail mirrors one element of "peers.details[]"
// (PeerStateDetailOutput). Only the fields backing #211's proposed per-peer
// metrics are modeled: fqdn, status, connectionType, lastWireguardHandshake,
// transferReceived/Sent, latency. Fields such as pubKey/ip/ipv6/
// iceCandidateType/iceCandidateEndpoint/relayAddress/quantumResistance/
// networks are deliberately not modeled.
//
// LIVE-VERIFIED 2026-07-25 (#377), superseding the previous "source-derived,
// never observed live" note from #211: the dev box was enrolled into a real
// tenant on netbird 0.74.4 and every path in the committed netbirdStatus golden
// was validated against live captures — 22 verified, 0 mismatched, 0 unverified
// — in both the Connected and the lazy-connection Idle state. The field guesses
// below all proved correct, including the RFC3339Nano + !IsZero() handling of
// lastWireguardHandshake, which arrives as a local-offset timestamp when set and
// as "0001-01-01T00:00:00Z" when the peer has never handshaken.
//
// Two zero-value traps live in this payload. lastWireguardHandshake's zero is
// the ordinary Go zero time, so IsZero() catches it. lastStatusUpdate's zero
// renders as "0000-12-31T23:58:45-00:01" (pre-Gregorian, local offset), which
// IsZero() does NOT catch — it is not consumed here, and anyone adding it must
// not assume a sane zero.
//
// Reproducing this state needs a second peer: a peer never lists itself, so a
// single-peer tenant reports peers.total 0 and an empty details[]. See the
// exercise recipe in opnsense/testdata/schemas/coverage.json.
type netbirdPeerDetail struct {
	FQDN                   string `json:"fqdn"`
	Status                 string `json:"status"`
	ConnType               string `json:"connectionType"`
	LastWireguardHandshake string `json:"lastWireguardHandshake"`
	TransferReceived       int64  `json:"transferReceived"`
	TransferSent           int64  `json:"transferSent"`
	// Latency is netbird's time.Duration (nanoseconds); time.Duration has no
	// custom JSON marshaling, so the wire value is a plain integer.
	Latency int64 `json:"latency"`
}

// netbirdPeersState mirrors the "peers" object (PeersStateOutput).
type netbirdPeersState struct {
	Total     int                 `json:"total"`
	Connected int                 `json:"connected"`
	Details   []netbirdPeerDetail `json:"details"`
}

// netbirdStatusObject mirrors the OBJECT-shaped payload of
// api/netbird/status/status (os-netbird plugin), which relays `netbird
// status --json` verbatim through configd
// (Netbird\Api\StatusController::statusAction ->
// json_decode($backend->configdRun("netbird status-json"), true)). The CLI's
// own JSON shape is client/status/status.go's OutputOverview
// (github.com/netbirdio/netbird).
//
// Deliberately unmapped OutputOverview top-level fields (node identity/config,
// never fed into a metric): netbirdIp, netbirdIpv6, publicKey,
// usesKernelInterface, wireguardPort, fqdn (node's own FQDN — distinct from a
// peer's fqdn), quantumResistance, quantumResistancePermissive, networks,
// forwardingRules, dnsServers, events, lazyConnectionEnabled, profileName,
// sshServer, sessionExpiresAt.
//
// VERIFICATION: peers.total/connected, cliVersion, daemonVersion, daemonStatus,
// management.connected, signal.connected are live-verified against a dev-box
// capture (2026-07-13, os-netbird installed, never enrolled — daemonStatus
// "NeedsLogin", nothing connected, peers.total 0). relays.total/available and
// every peers.details[] field are SOURCE-DERIVED ONLY from
// client/status/status.go (RelayStateOutput / PeerStateDetailOutput) — no
// enrolled netbird network was available to observe them live.
type netbirdStatusObject struct {
	Peers         netbirdPeersState      `json:"peers"`
	CliVersion    string                 `json:"cliVersion"`
	DaemonVersion string                 `json:"daemonVersion"`
	DaemonStatus  string                 `json:"daemonStatus"`
	Management    netbirdManagementState `json:"management"`
	Signal        netbirdSignalState     `json:"signal"`
	Relays        netbirdRelayState      `json:"relays"`
}

// NetbirdPeer is the node-local view of one netbird peer.
type NetbirdPeer struct {
	FQDN             string
	Connected        bool // Status == "Connected"
	Direct           bool // meaningful only when Connected: ConnType == "P2P" (vs "Relayed")
	ReceivedBytes    float64
	TransmittedBytes float64
	// LastHandshakeSeconds/HasHandshake and LatencySeconds/HasLatency are
	// meaningful only when Connected — an idle peer's CLI values are the
	// zero-value handshake time and zero latency (see mapPeers in
	// client/status/status.go), which would otherwise look like a real
	// (but suspiciously precise) zero measurement.
	LastHandshakeSeconds float64
	HasHandshake         bool
	LatencySeconds       float64
	HasLatency           bool
}

// NetbirdStatus holds the aggregated result of FetchNetbirdStatus.
type NetbirdStatus struct {
	Present bool // false when the os-netbird plugin is absent (HTTP 404)
	// DaemonUp is false when the wire payload was the bare-[] fallback the
	// StatusController returns when `netbird status --json` produced no
	// parseable output (daemon down / unreachable). Present can be true while
	// DaemonUp is false: the plugin (and its API route) is installed, but the
	// daemon itself did not answer.
	DaemonUp            bool
	CliVersion          string
	DaemonVersion       string
	DaemonStatus        string
	ManagementConnected bool
	SignalConnected     bool
	RelaysTotal         int
	RelaysAvailable     int
	PeersTotal          int
	PeersConnected      int
	Peers               []NetbirdPeer
}

// FetchNetbirdStatus calls the os-netbird status endpoint. A HTTP 404 means
// the plugin is absent: zero-value data (Present=false) and nil error,
// mirroring FetchACMECertificates.
//
// The wire payload has two shapes even when the plugin IS installed (verified
// live on a dev box, 2026-07-13): a rich object when the netbird daemon
// answered `status --json`, and a bare JSON array `[]` when it did not (see
// netbirdStatusObject's doc comment). The array case is decoded via
// json.RawMessage first (rather than a custom json.Unmarshaler on the whole
// object, which would collapse the schema-registry entry to KindAny and lose
// per-field drift detection for the common object-shaped case) and treated as
// "nothing connected, no version info" — DaemonUp is false and every counter
// reads zero, matching the live capture.
func (c *Client) FetchNetbirdStatus() (NetbirdStatus, *APICallError) {
	var raw json.RawMessage
	var data NetbirdStatus

	url, ok := c.endpoints["netbirdStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "netbirdStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &raw); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}
	data.Present = true

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || trimmed[0] == '[' {
		// Daemon down: the CLI produced no parseable status and
		// StatusController fell back to a bare array. Present stays true
		// (the plugin/route answered); DaemonUp stays false.
		return data, nil
	}

	var obj netbirdStatusObject
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return data, &APICallError{
			Endpoint:   "netbirdStatus",
			Message:    fmt.Sprintf("failed to decode netbird status object: %s", err.Error()),
			StatusCode: 0,
		}
	}

	data.DaemonUp = true
	data.CliVersion = obj.CliVersion
	data.DaemonVersion = obj.DaemonVersion
	data.DaemonStatus = obj.DaemonStatus
	data.ManagementConnected = obj.Management.Connected
	data.SignalConnected = obj.Signal.Connected
	data.RelaysTotal = obj.Relays.Total
	data.RelaysAvailable = obj.Relays.Available
	data.PeersTotal = obj.Peers.Total
	data.PeersConnected = obj.Peers.Connected

	seen := make(map[string]bool, len(obj.Peers.Details))
	for _, p := range obj.Peers.Details {
		if p.FQDN == "" || seen[p.FQDN] {
			// FQDN is unique per netbird network; skip blanks/duplicates
			// defensively rather than emit colliding series (mirrors
			// tailscale.go's peer dedup).
			continue
		}
		seen[p.FQDN] = true

		peer := NetbirdPeer{
			FQDN:             p.FQDN,
			Connected:        p.Status == "Connected",
			ReceivedBytes:    float64(p.TransferReceived),
			TransmittedBytes: float64(p.TransferSent),
		}
		if peer.Connected {
			peer.Direct = p.ConnType == "P2P"
			if t, err := time.Parse(time.RFC3339Nano, p.LastWireguardHandshake); err == nil && !t.IsZero() {
				peer.LastHandshakeSeconds = float64(t.Unix())
				peer.HasHandshake = true
			}
			if p.Latency > 0 {
				peer.LatencySeconds = float64(p.Latency) / float64(time.Second)
				peer.HasLatency = true
			}
		}
		data.Peers = append(data.Peers, peer)
	}

	return data, nil
}
