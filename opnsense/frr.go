package opnsense

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// VERIFICATION: unvalidated against a live os-frr (quagga) box.
// Shapes derived from net/frr/src/opnsense/mvc/app/controllers/OPNsense/Quagga/Api/DiagnosticsController.php
// and FRR vtysh JSON output formats (FRR 8.x+).
// Re-check on real hardware when available:
//   - bgpsummary: per-AF field set, numeric types (remoteAs may exceed int32)
//   - ospfoverview: areas key structure, nbrFullAdjacencyCount vs nbrFullAdjacentCounter
//   - searchOspfneighbor: old vs new field names (state/nbrState, address/ifaceAddress)
//   - bfdneighbors/bfdcounters: peer-keyed map structure, uptime field presence

// --- BGP ---

// frrBGPPeerEntry is the raw per-peer JSON shape from FRR bgpsummary.
// Numbers are native JSON numbers from FRR output (not PHP-mangled strings).
type frrBGPPeerEntry struct {
	RemoteAs   float64 `json:"remoteAs"`
	MsgRcvd    float64 `json:"msgRcvd"`
	MsgSent    float64 `json:"msgSent"`
	PeerUpMsec float64 `json:"peerUptimeMsec"`
	PfxRcd     float64 `json:"pfxRcd"`
	PfxSnt     float64 `json:"pfxSnt"`
	State      string  `json:"state"`
}

// frrBGPFamily is the raw per-address-family block from bgpsummary.
type frrBGPFamily struct {
	RibCount    float64                    `json:"ribCount"`
	PeerCount   float64                    `json:"peerCount"`
	FailedPeers float64                    `json:"failedPeers"`
	Peers       map[string]frrBGPPeerEntry `json:"peers"`
}

// frrBGPSummaryResponseBody holds the `response` value from bgpsummary.
// Each key is an AF name like "ipv4Unicast" or "ipv6Unicast".
type frrBGPSummaryResponseBody map[string]frrBGPFamily

// frrBGPSummaryEnvelope wraps the API response `{"response": ...}`.
// Response is decoded as RawMessage to tolerate the `[]` fallback when
// the BGP daemon is disabled (configd returns [] for an empty result).
type frrBGPSummaryEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// frrAFLabel converts an FRR address-family key like "ipv4Unicast" to a
// lowercase label. It is lossless per SAFI: the (overwhelmingly common) unicast
// families keep the short "ipv4"/"ipv6" label for backward compatibility, while
// any non-unicast SAFI retains its suffix (e.g. "ipv4multicast") so distinct
// upstream families never collapse onto the same label tuple — which would emit
// duplicate series and fail the whole scrape (#162). Unknown keys pass through
// lowercased.
func frrAFLabel(key string) string {
	lower := strings.ToLower(key)
	if trimmed, ok := strings.CutSuffix(lower, "unicast"); ok {
		return trimmed
	}
	return lower
}

// FRRBGPPeer holds normalised per-peer BGP metrics.
type FRRBGPPeer struct {
	Peer, RemoteAS, AF             string
	Up                             float64 // 1 when state == "Established"
	PrefixesReceived, PrefixesSent float64
	UptimeSeconds                  float64
	MessagesReceived, MessagesSent float64
}

// FRRBGPFamily holds normalised per-address-family BGP summary metrics.
type FRRBGPFamily struct {
	AF                               string
	PeerCount, FailedPeers, RibCount float64
}

// FRRBGP holds the aggregated result of FetchFRRBGP.
type FRRBGP struct {
	Present  bool
	Families []FRRBGPFamily
	Peers    []FRRBGPPeer
}

// FetchFRRBGP calls api/quagga/diagnostics/bgpsummary and returns aggregated
// per-family and per-peer BGP data.
//
// A 404 (plugin absent) returns Present=false, nil.
// A daemon-disabled array response (`{"response":[]}`) also returns Present=false, nil.
func (c *Client) FetchFRRBGP() (FRRBGP, *APICallError) {
	var data FRRBGP

	endpointURL, ok := c.endpoints["quaggaBgpSummary"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaBgpSummary",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope frrBGPSummaryEnvelope
	if err := c.do("GET", endpointURL, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	// Tolerate the configd `[]` fallback (daemon disabled).
	if len(envelope.Response) == 0 || (len(envelope.Response) > 0 && envelope.Response[0] == '[') {
		return data, nil
	}

	var families frrBGPSummaryResponseBody
	if err := json.Unmarshal(envelope.Response, &families); err != nil {
		// Non-object response; treat as daemon disabled.
		return data, nil
	}
	if len(families) == 0 {
		return data, nil
	}

	data.Present = true
	for afKey, fam := range families {
		af := frrAFLabel(afKey)
		data.Families = append(data.Families, FRRBGPFamily{
			AF:          af,
			PeerCount:   fam.PeerCount,
			FailedPeers: fam.FailedPeers,
			RibCount:    fam.RibCount,
		})
		for peerIP, peer := range fam.Peers {
			up := 0.0
			if peer.State == "Established" {
				up = 1.0
			}
			uptimeSec := peer.PeerUpMsec / 1000
			remoteAS := strconv.FormatFloat(peer.RemoteAs, 'f', -1, 64)
			data.Peers = append(data.Peers, FRRBGPPeer{
				Peer:             peerIP,
				RemoteAS:         remoteAS,
				AF:               af,
				Up:               up,
				PrefixesReceived: peer.PfxRcd,
				PrefixesSent:     peer.PfxSnt,
				UptimeSeconds:    uptimeSec,
				MessagesReceived: peer.MsgRcvd,
				MessagesSent:     peer.MsgSent,
			})
		}
	}

	return data, nil
}

// --- OSPF ---

// frrOSPFNeighborRow holds a single row from the searchOspfneighbor bootgrid.
// FRR renamed fields across versions; both old and new names are decoded.
type frrOSPFNeighborRow struct {
	NeighborID   flexString `json:"neighborid"`
	Priority     flexString `json:"priority"`     // old FRR
	NbrPriority  flexString `json:"nbrPriority"`  // new FRR
	State        flexString `json:"state"`        // old, e.g. "Full/DR"
	NbrState     flexString `json:"nbrState"`     // new
	Address      flexString `json:"address"`      // old
	IfaceAddress flexString `json:"ifaceAddress"` // new
	IfaceName    flexString `json:"ifaceName"`
}

// frrOSPFNeighborSearch is the bootgrid envelope for searchOspfneighbor.
type frrOSPFNeighborSearch struct {
	Total    int                  `json:"total"`
	RowCount int                  `json:"rowCount"`
	Current  int                  `json:"current"`
	Rows     []frrOSPFNeighborRow `json:"rows"`
}

// frrOSPFAreaData holds a single area's statistics from ospfoverview.
type frrOSPFAreaData struct {
	AreaIfActiveCounter    float64 `json:"areaIfActiveCounter"`
	NbrFullAdjacentCounter float64 `json:"nbrFullAdjacentCounter"`
	// Some FRR versions use a slightly different field name:
	NbrFullAdjacencyCount float64 `json:"nbrFullAdjacencyCount"`
	LsaNumber             float64 `json:"lsaNumber"`
	SpfExecutedCounter    float64 `json:"spfExecutedCounter"`
}

// frrOSPFOverviewBody holds the parsed ospfoverview `response` object.
type frrOSPFOverviewBody struct {
	Areas map[string]frrOSPFAreaData `json:"areas"`
}

// frrOSPFOverviewEnvelope wraps the API `{"response": ...}`.
type frrOSPFOverviewEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// FRROSPFNeighbor holds normalised per-OSPF-neighbor metrics.
type FRROSPFNeighbor struct {
	NeighborID, Address, Interface string
	Adjacent                       float64 // 1 when state has prefix "Full"
}

// FRROSPFArea holds normalised per-OSPF-area metrics.
type FRROSPFArea struct {
	Area                                                           string
	InterfacesActive, NeighborsFullAdjacent, LSACount, SPFExecuted float64
}

// FRROSPF holds the aggregated result of FetchFRROSPF.
type FRROSPF struct {
	Present   bool
	Neighbors []FRROSPFNeighbor
	Areas     []FRROSPFArea
}

// FetchFRROSPF fetches OSPF overview and neighbor data from the quagga plugin.
//
// A 404 (plugin absent) returns Present=false, nil.
func (c *Client) FetchFRROSPF() (FRROSPF, *APICallError) {
	var data FRROSPF

	overviewURL, ok := c.endpoints["quaggaOspfOverview"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaOspfOverview",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	neighborsURL, ok := c.endpoints["quaggaOspfNeighbors"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaOspfNeighbors",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// Fetch overview (areas/summary).
	var overviewEnv frrOSPFOverviewEnvelope
	if err := c.do("GET", overviewURL, nil, &overviewEnv); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	// Tolerate array fallback.
	if len(overviewEnv.Response) > 0 && overviewEnv.Response[0] != '[' {
		var overview frrOSPFOverviewBody
		if jsonErr := json.Unmarshal(overviewEnv.Response, &overview); jsonErr == nil {
			for areaID, areaData := range overview.Areas {
				fullAdj := areaData.NbrFullAdjacentCounter
				if fullAdj == 0 {
					fullAdj = areaData.NbrFullAdjacencyCount
				}
				data.Areas = append(data.Areas, FRROSPFArea{
					Area:                  areaID,
					InterfacesActive:      areaData.AreaIfActiveCounter,
					NeighborsFullAdjacent: fullAdj,
					LSACount:              areaData.LsaNumber,
					SPFExecuted:           areaData.SpfExecutedCounter,
				})
			}
		}
	}

	// Fetch neighbors via bootgrid POST.
	var nbrSearch frrOSPFNeighborSearch
	form := url.Values{
		"current":  {"1"},
		"rowCount": {"-1"},
	}
	if err := c.doForm(neighborsURL, form, &nbrSearch); err != nil {
		if err.StatusCode == http.StatusNotFound {
			data.Present = true
			return data, nil
		}
		return data, err
	}

	for _, row := range nbrSearch.Rows {
		// Coalesce old/new field names.
		state := row.State.String()
		if state == "" {
			state = row.NbrState.String()
		}
		address := row.Address.String()
		if address == "" {
			address = row.IfaceAddress.String()
		}
		adjacent := 0.0
		if strings.HasPrefix(state, "Full") {
			adjacent = 1.0
		}
		data.Neighbors = append(data.Neighbors, FRROSPFNeighbor{
			NeighborID: row.NeighborID.String(),
			Address:    address,
			Interface:  row.IfaceName.String(),
			Adjacent:   adjacent,
		})
	}

	data.Present = true
	return data, nil
}

// --- BFD ---

// frrBFDNeighborEntry holds a single BFD peer from the bfdneighbors response.
type frrBFDNeighborEntry struct {
	Peer      string  `json:"peer"`
	Local     string  `json:"local"`
	Interface string  `json:"interface"`
	Status    string  `json:"status"`
	Uptime    float64 `json:"uptime"` // seconds; only present when up
}

// frrBFDCounterEntry holds a single BFD peer's counters from bfdcounters.
type frrBFDCounterEntry struct {
	Peer              string  `json:"peer"`
	ControlIn         float64 `json:"control-packet-input"`
	ControlOut        float64 `json:"control-packet-output"`
	SessionUpEvents   float64 `json:"session-up-events"`
	SessionDownEvents float64 `json:"session-down-events"`
}

// frrBFDNeighborsEnvelope wraps the bfdneighbors `{"response": {...}}`.
type frrBFDNeighborsEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// frrBFDCountersEnvelope wraps the bfdcounters `{"response": {...}}`.
type frrBFDCountersEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// FRRBFDPeer holds normalised per-BFD-peer metrics.
type FRRBFDPeer struct {
	Peer, Interface                    string
	Up, UptimeSeconds                  float64
	HasCounters                        bool
	ControlIn, ControlOut              float64
	SessionUpEvents, SessionDownEvents float64
}

// FRRBFD holds the aggregated result of FetchFRRBFD.
type FRRBFD struct {
	Present bool
	Peers   []FRRBFDPeer
}

// FetchFRRBFD fetches BFD neighbor and counter data from the quagga plugin,
// merging both responses by peer key.
//
// A 404 on the neighbors endpoint (plugin absent) returns Present=false, nil.
// A 404 on the counters endpoint while neighbors responded returns HasCounters=false
// for all peers — the call still succeeds (nil error).
func (c *Client) FetchFRRBFD() (FRRBFD, *APICallError) {
	var data FRRBFD

	neighborsURL, ok := c.endpoints["quaggaBfdNeighbors"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaBfdNeighbors",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}
	countersURL, ok := c.endpoints["quaggaBfdCounters"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaBfdCounters",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	// Fetch neighbors.
	var nbrsEnv frrBFDNeighborsEnvelope
	if err := c.do("GET", neighborsURL, nil, &nbrsEnv); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	// Parse neighbors map.
	var nbrsMap map[string]frrBFDNeighborEntry
	if len(nbrsEnv.Response) > 0 && nbrsEnv.Response[0] != '[' {
		if jsonErr := json.Unmarshal(nbrsEnv.Response, &nbrsMap); jsonErr != nil {
			nbrsMap = nil
		}
	}

	if len(nbrsMap) == 0 {
		// Daemon disabled or empty response; treat as plugin absent.
		return data, nil
	}

	data.Present = true

	// Build peer map from neighbors (no counters yet).
	peerMap := make(map[string]*FRRBFDPeer)
	for peerIP, nbr := range nbrsMap {
		up := 0.0
		if nbr.Status == "up" {
			up = 1.0
		}
		p := &FRRBFDPeer{
			Peer:          peerIP,
			Interface:     nbr.Interface,
			Up:            up,
			UptimeSeconds: nbr.Uptime,
		}
		peerMap[peerIP] = p
		data.Peers = append(data.Peers, *p)
	}

	// Fetch counters; a 404 is tolerated (counters may be absent for some configs).
	var ctrsEnv frrBFDCountersEnvelope
	if err := c.do("GET", countersURL, nil, &ctrsEnv); err != nil {
		if err.StatusCode == http.StatusNotFound {
			// HasCounters stays false for all peers.
			return data, nil
		}
		return data, err
	}

	// Parse counters map.
	var ctrsMap map[string]frrBFDCounterEntry
	if len(ctrsEnv.Response) > 0 && ctrsEnv.Response[0] != '[' {
		if jsonErr := json.Unmarshal(ctrsEnv.Response, &ctrsMap); jsonErr != nil {
			ctrsMap = nil
		}
	}

	// Merge counters into peers slice.
	for i := range data.Peers {
		if ctr, found := ctrsMap[data.Peers[i].Peer]; found {
			data.Peers[i].HasCounters = true
			data.Peers[i].ControlIn = ctr.ControlIn
			data.Peers[i].ControlOut = ctr.ControlOut
			data.Peers[i].SessionUpEvents = ctr.SessionUpEvents
			data.Peers[i].SessionDownEvents = ctr.SessionDownEvents
		}
	}

	return data, nil
}
