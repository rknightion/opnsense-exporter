package opnsense

import (
	"net/http"
	"strings"
	"time"
)

// tailscaleStatusResponse mirrors api/tailscale/status/status (os-tailscale),
// which proxies `tailscale status --json`. Only node-local fields are
// captured: this exporter complements tailscale2otel (control-plane/fleet
// coverage) and deliberately does not model fleet inventory fields.
//
// The JSON also carries an Online field. It is intentionally NOT parsed:
// Online is coordination-server state relayed to the node, not a local
// observation (live evidence: 15/30 peers reported Online:true with zero
// LastHandshake and empty CurAddr). Exporting it would duplicate
// tailscale2otel's fleet inventory. The genuinely node-local signals are
// LastHandshake, CurAddr and RxBytes/TxBytes.
//
// NOTE: api/tailscale/status/get returns {"Tailscale":[]} and is useless —
// status/status is the working verb (verified on a live 26.1 box, plugin 1.4).
type tailscaleStatusPeer struct {
	HostName      string  `json:"HostName"`
	DNSName       string  `json:"DNSName"`
	RxBytes       float64 `json:"RxBytes"`
	TxBytes       float64 `json:"TxBytes"`
	LastHandshake string  `json:"LastHandshake"`
	CurAddr       string  `json:"CurAddr"`
	Relay         string  `json:"Relay"`
}

type tailscaleStatusResponse struct {
	Version      string                         `json:"Version"`
	BackendState string                         `json:"BackendState"`
	Self         tailscaleStatusPeer            `json:"Self"`
	Peer         map[string]tailscaleStatusPeer `json:"Peer"`
	// Health carries live warning strings from the local tailscaled client (e.g.
	// update available, DERP unreachable, key expiry). The strings themselves are
	// unbounded free text and are never exported as a label — only the count is a
	// metric (#237). Absent/empty means "no warnings", not "not reported": the
	// local client always includes this key, empty when healthy.
	Health []string `json:"Health"`
}

// TailscalePeer is the node-local view of one tailnet peer.
type TailscalePeer struct {
	Name                 string
	Direct               bool // CurAddr != ""; only meaningful when HasHandshake
	RxBytes              float64
	TxBytes              float64
	LastHandshakeSeconds float64
	HasHandshake         bool // non-zero LastHandshake — local WireGuard session exists
}

// TailscaleStatus holds the aggregated result of FetchTailscaleStatus.
type TailscaleStatus struct {
	Present                bool // false when the plugin is not installed (HTTP 404)
	Version                string
	BackendState           string
	SelfRelay              string
	Peers                  []TailscalePeer
	PeersTotal             int
	PeersWithActiveSession int // peers with a recorded WireGuard handshake
	HealthWarnings         int // count of live client health warning strings (#237)
}

// peerName derives a stable, unique peer label: the first DNS label of the
// MagicDNS name (unique per tailnet), falling back to HostName.
func peerName(p tailscaleStatusPeer) string {
	if p.DNSName != "" {
		return strings.SplitN(strings.TrimSuffix(p.DNSName, "."), ".", 2)[0]
	}
	return p.HostName
}

// tailscaleZeroTime is the zero value tailscaled reports for LastHandshake.
const tailscaleZeroTime = "0001-01-01T00:00:00Z"

// FetchTailscaleStatus calls the os-tailscale status endpoint. A 404 means
// the plugin is absent: zero-value data (Present=false) and nil error.
func (c *Client) FetchTailscaleStatus() (TailscaleStatus, *APICallError) {
	var resp tailscaleStatusResponse
	var data TailscaleStatus

	url, ok := c.endpoints["tailscaleStatus"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "tailscaleStatus",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	data.Present = true
	data.Version = resp.Version
	data.BackendState = resp.BackendState
	data.SelfRelay = resp.Self.Relay
	data.PeersTotal = len(resp.Peer)
	data.HealthWarnings = len(resp.Health)

	seen := make(map[string]bool, len(resp.Peer))
	for _, p := range resp.Peer {
		name := peerName(p)
		if seen[name] {
			// Duplicate labels would make the scrape fail with duplicate
			// series; MagicDNS names are unique so this is defensive only.
			c.log.Debug("tailscale: skipping peer with duplicate name", "peer", name)
			continue
		}
		seen[name] = true

		peer := TailscalePeer{
			Name:    name,
			Direct:  p.CurAddr != "",
			RxBytes: p.RxBytes,
			TxBytes: p.TxBytes,
		}
		if p.LastHandshake != "" && p.LastHandshake != tailscaleZeroTime {
			if t, err := time.Parse(time.RFC3339Nano, p.LastHandshake); err == nil {
				peer.LastHandshakeSeconds = float64(t.Unix())
				peer.HasHandshake = true
				data.PeersWithActiveSession++
			}
		}
		data.Peers = append(data.Peers, peer)
	}
	return data, nil
}
