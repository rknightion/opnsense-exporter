package opnsense

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// VERIFICATION: bgpsummary/ospfoverview/searchOspfneighbor/bfd* below were
// re-verified 2026-07-13 against a real os-frr dev-box lab (see #195/#197/#198/
// #199 dev-box validation checklists) — an eBGP session AS65001<->AS65002 and an
// OSPFv2 Full/DR adjacency, both bounced at least once. The BGP/OSPFv2/BFD shapes
// and field names below match the live captures.
//
// The OSPFv3 (ospf6) structs added for #198 were source-derived for a long time
// because no live v3 adjacency could be brought up. That gap is CLOSED as of
// 2026-07-25 (#377): OSPFv3 was enabled on the dev box and a Full adjacency
// established across the isolated testbed bridge, and all 13 ospf6 field names
// below were confirmed present in the live payload — routerId,
// numberOfAsScopedLsa, areas and areas.*.numberOfAreaScopedLsa on the overview;
// status, type, areaId, cost, priority, ospf6InterfaceState,
// numberOfInterfaceScopedLsa, pendingLsaLsUpdateCount and pendingLsaLsAckCount
// per interface. ospf6InterfaceState returns a real non-Down value (BDR) on the
// adjacency-bearing interface.
//
// Why the earlier attempts failed, recorded so it is not re-investigated: the
// Proxmox HOST kernel is booted with ipv6.disable=1, so /proc/sys/net/ipv6 is
// absent in every namespace on that host and no LXC there can ever run an IPv6
// stack. That is a host-kernel property, not the container-privilege issue #227
// concluded. A VM (own kernel) works fine on the same bridge.
//
// These two endpoints remain INVISIBLE TO THE CANARY regardless, and that is a
// code limit rather than a lab gap: schema_registry.go registers the envelope
// types, whose sole field is `Response json.RawMessage` → KindAny, so the
// derived golden carries one path and accepts any payload. Tracked in #459;
// until it lands, coverage.json marks them required-but-opaque so the blind spot
// is named rather than silently counted. Do not re-provision the lab chasing
// this — provisioning cannot fix it.
//
//   - bgpsummary: per-AF field set, numeric types (remoteAs may exceed int32) — verified
//   - bgpneighbors: per-peer flap/message/AF-prefix detail — verified (#197)
//   - ospfoverview: areas key structure, nbrFullAdjacencyCount vs nbrFullAdjacentCounter — verified
//   - ospfinterface: per-interface detail — verified ("interfaces"-wrapped shape, FRR>=8, this box's FRR 10.3); older flat top-level shape is decoded tolerantly but unverified live
//   - ospfv3overview/ospfv3interface: field names VERIFIED against a live v3 adjacency 2026-07-25 (#377); still opaque to the canary via the RawMessage envelope (#459)
//   - searchOspfneighbor: old vs new field names (state/nbrState, address/ifaceAddress) — verified
//   - bfdneighbors/bfdcounters: peer-keyed map structure, uptime field presence
//
// CORRECTION (#480, 2026-07-28): the "field names below match the live captures"
// claim above did NOT hold for bfdcounters. Two of its five fields were tagged
// "session-up-events"/"session-down-events", which FRR has never emitted on any
// release, so they decoded to zero on every real box while the hand-written
// fixture — which encoded the same invented names — kept the unit test green.
// The live-box canary caught it only because it reported the two tagged names as
// missing and FRR's real "session-up"/"session-down" as unexpected extras on the
// same response. Verify BFD field names against FRR's bfdd/bfdd_vty.c, not
// against OPNsense: the quagga plugin is a pure vtysh passthrough and renames
// nothing.

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

// frrOSPFAreaMap is the ospfoverview `areas` map. It tolerates the OPNsense PHP
// quirk where an empty map is serialized as a JSON array ([]) rather than an
// object (the same quirk flexStringMap exists for): the quagga controller
// json_decodes FRR's output into a PHP assoc array and the framework re-encodes
// it, so an OSPF instance running with zero areas legitimately arrives as
// "areas":[]. Absorbing that here keeps the decode-failure error in
// FetchFRROSPF (#378) aimed at genuine corruption rather than an idle box.
type frrOSPFAreaMap map[string]frrOSPFAreaData

// UnmarshalJSON implements json.Unmarshaler.
func (m *frrOSPFAreaMap) UnmarshalJSON(data []byte) error {
	// Null or any JSON array (the PHP empty-map quirk) → empty map.
	if string(data) == "null" || (len(data) > 0 && data[0] == '[') {
		*m = make(frrOSPFAreaMap)
		return nil
	}

	areas := make(map[string]frrOSPFAreaData)
	if err := json.Unmarshal(data, &areas); err != nil {
		return fmt.Errorf("ospf areas: %w", err)
	}
	*m = areas
	return nil
}

// frrOSPFOverviewBody holds the parsed ospfoverview `response` object.
type frrOSPFOverviewBody struct {
	Areas frrOSPFAreaMap `json:"areas"`
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
		if jsonErr := json.Unmarshal(overviewEnv.Response, &overview); jsonErr != nil {
			// The payload claims to be an object, so the daemon-disabled `[]`
			// fallback does not apply, and the PHP empty-map-as-[] quirk on
			// `areas` is already absorbed by frrOSPFAreaMap. A failure here is
			// genuine corruption or upstream drift, so surface it instead of
			// reporting partial success: Present stays false, no OSPF series are
			// emitted, and the collector records the failed poll (#378).
			return data, &APICallError{
				Endpoint:   "quaggaOspfOverview",
				Message:    "failed to decode ospf overview response: " + jsonErr.Error(),
				StatusCode: 0,
			}
		}
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
	Peer       string  `json:"peer"`
	ControlIn  float64 `json:"control-packet-input"`
	ControlOut float64 `json:"control-packet-output"`
	// FRR names these "session-up"/"session-down" (bfdd/bfdd_vty.c). They were
	// tagged "session-up-events"/"session-down-events" until #480 — names that
	// exist nowhere in FRR on master or on any release in the support window, so
	// both counters silently decoded to zero on every real box. Do not "restore"
	// the -events suffix; the Go field names keep it only for continuity with the
	// exported metric names.
	SessionUpEvents   float64 `json:"session-up"`
	SessionDownEvents float64 `json:"session-down"`
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

// --- BGP Neighbor Session Detail (#197) ---

// frrBGPNeighborMessageStats holds the per-message-type send/receive counters
// from a bgpneighbors peer entry, plus the current in/out work-queue depth.
type frrBGPNeighborMessageStats struct {
	OpensSent         float64 `json:"opensSent"`
	OpensRecv         float64 `json:"opensRecv"`
	UpdatesSent       float64 `json:"updatesSent"`
	UpdatesRecv       float64 `json:"updatesRecv"`
	NotificationsSent float64 `json:"notificationsSent"`
	NotificationsRecv float64 `json:"notificationsRecv"`
	KeepalivesSent    float64 `json:"keepalivesSent"`
	KeepalivesRecv    float64 `json:"keepalivesRecv"`
	RouteRefreshSent  float64 `json:"routeRefreshSent"`
	RouteRefreshRecv  float64 `json:"routeRefreshRecv"`
	CapabilitySent    float64 `json:"capabilitySent"`
	CapabilityRecv    float64 `json:"capabilityRecv"`
	DepthInq          float64 `json:"depthInq"`
	DepthOutq         float64 `json:"depthOutq"`
}

// frrBGPNeighborAFInfo holds one address-family's post-policy prefix count
// from a bgpneighbors peer's addressFamilyInfo block.
type frrBGPNeighborAFInfo struct {
	AcceptedPrefixCounter float64 `json:"acceptedPrefixCounter"`
}

// frrBGPNeighborEntry is the raw per-peer JSON shape from FRR bgpneighbors
// (`show bgp neighbors json`), keyed by peer IP in the response object.
type frrBGPNeighborEntry struct {
	BgpState               string                          `json:"bgpState"`
	RemoteAs               float64                         `json:"remoteAs"`
	ConnectionsEstablished float64                         `json:"connectionsEstablished"`
	ConnectionsDropped     float64                         `json:"connectionsDropped"`
	LastResetTimerMsecs    float64                         `json:"lastResetTimerMsecs"`
	LastResetDueTo         string                          `json:"lastResetDueTo"`
	MessageStats           frrBGPNeighborMessageStats      `json:"messageStats"`
	AddressFamilyInfo      map[string]frrBGPNeighborAFInfo `json:"addressFamilyInfo"`
}

// frrBGPNeighborsEnvelope wraps the API `{"response": {<peerIP>: {...}}}`.
type frrBGPNeighborsEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// FRRBGPNeighborMessageCount holds one (type, direction) message counter for a peer.
type FRRBGPNeighborMessageCount struct {
	Type, Direction string
	Count           float64
}

// FRRBGPNeighborPrefixCount holds one address-family's accepted-prefix count for a peer.
type FRRBGPNeighborPrefixCount struct {
	AF    string
	Count float64
}

// FRRBGPNeighborDetail holds normalised per-peer session-detail metrics: flap
// counters, per-message-type counts, per-AF accepted-prefix counts and
// in/out work-queue depth.
type FRRBGPNeighborDetail struct {
	Peer                                       string
	ConnectionsEstablished, ConnectionsDropped float64
	LastResetSeconds                           float64
	LastResetDueTo                             string
	QueueDepthIn, QueueDepthOut                float64
	Messages                                   []FRRBGPNeighborMessageCount
	Prefixes                                   []FRRBGPNeighborPrefixCount
}

// FRRBGPNeighbors holds the aggregated result of FetchFRRBGPNeighbors.
type FRRBGPNeighbors struct {
	Present bool
	Peers   []FRRBGPNeighborDetail
}

// FetchFRRBGPNeighbors calls api/quagga/diagnostics/bgpneighbors and returns
// normalised per-peer session-detail metrics. Peer labels are bounded by the
// number of configured BGP peers (same cardinality class as FetchFRRBGP's
// bgp_peer_up).
//
// A 404 (plugin absent) returns Present=false, nil. The daemon-disabled
// configd `[]` fallback also returns Present=false, nil.
func (c *Client) FetchFRRBGPNeighbors() (FRRBGPNeighbors, *APICallError) {
	var data FRRBGPNeighbors

	endpointURL, ok := c.endpoints["quaggaBgpNeighbors"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaBgpNeighbors",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope frrBGPNeighborsEnvelope
	if err := c.do("GET", endpointURL, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	if len(envelope.Response) == 0 || envelope.Response[0] == '[' {
		return data, nil
	}

	var peers map[string]frrBGPNeighborEntry
	if jsonErr := json.Unmarshal(envelope.Response, &peers); jsonErr != nil {
		// Non-object response; treat as daemon disabled.
		return data, nil
	}
	if len(peers) == 0 {
		return data, nil
	}

	data.Present = true
	for peerIP, peer := range peers {
		ms := peer.MessageStats
		detail := FRRBGPNeighborDetail{
			Peer:                   peerIP,
			ConnectionsEstablished: peer.ConnectionsEstablished,
			ConnectionsDropped:     peer.ConnectionsDropped,
			LastResetSeconds:       peer.LastResetTimerMsecs / 1000,
			LastResetDueTo:         peer.LastResetDueTo,
			QueueDepthIn:           ms.DepthInq,
			QueueDepthOut:          ms.DepthOutq,
			Messages: []FRRBGPNeighborMessageCount{
				{Type: "open", Direction: "sent", Count: ms.OpensSent},
				{Type: "open", Direction: "received", Count: ms.OpensRecv},
				{Type: "update", Direction: "sent", Count: ms.UpdatesSent},
				{Type: "update", Direction: "received", Count: ms.UpdatesRecv},
				{Type: "keepalive", Direction: "sent", Count: ms.KeepalivesSent},
				{Type: "keepalive", Direction: "received", Count: ms.KeepalivesRecv},
				{Type: "notification", Direction: "sent", Count: ms.NotificationsSent},
				{Type: "notification", Direction: "received", Count: ms.NotificationsRecv},
				{Type: "route_refresh", Direction: "sent", Count: ms.RouteRefreshSent},
				{Type: "route_refresh", Direction: "received", Count: ms.RouteRefreshRecv},
				{Type: "capability", Direction: "sent", Count: ms.CapabilitySent},
				{Type: "capability", Direction: "received", Count: ms.CapabilityRecv},
			},
		}
		for afKey, afInfo := range peer.AddressFamilyInfo {
			detail.Prefixes = append(detail.Prefixes, FRRBGPNeighborPrefixCount{
				AF:    frrAFLabel(afKey),
				Count: afInfo.AcceptedPrefixCounter,
			})
		}
		data.Peers = append(data.Peers, detail)
	}

	return data, nil
}

// --- OSPF Interface Detail + OSPFv3 (ospf6) parity (#198) ---

// frrOSPFInterfaceEntry is the raw per-interface JSON shape from FRR
// `show ip ospf interface json`, as verified against this box's FRR 10.3.
type frrOSPFInterfaceEntry struct {
	IfUp             bool    `json:"ifUp"`
	OspfEnabled      bool    `json:"ospfEnabled"`
	Area             string  `json:"area"`
	NetworkType      string  `json:"networkType"`
	Cost             float64 `json:"cost"`
	State            string  `json:"state"`
	Priority         float64 `json:"priority"`
	NbrCount         float64 `json:"nbrCount"`
	NbrAdjacentCount float64 `json:"nbrAdjacentCount"`
	MtuBytes         float64 `json:"mtuBytes"`
	BandwidthMbit    float64 `json:"bandwidthMbit"`
}

// frrOSPFInterfaceWrapped is the FRR >= 8 shape, which wraps the per-interface
// map in an "interfaces" object — verified against this box's FRR 10.3. Older
// FRR returns the per-interface map directly at the top level instead (per
// the plugin's own doc comments) — see FetchFRROSPFInterfaces, which decodes
// both, though only the wrapped shape has been confirmed live.
type frrOSPFInterfaceWrapped struct {
	Interfaces map[string]frrOSPFInterfaceEntry `json:"interfaces"`
}

// frrOSPFInterfaceEnvelope wraps the API `{"response": ...}`.
type frrOSPFInterfaceEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// FRROSPFInterface holds normalised per-OSPF-interface metrics.
type FRROSPFInterface struct {
	Interface, Area, NetworkType, State string
	Up, Cost, Priority                  float64
	NbrCount, NbrAdjacentCount          float64
	MtuBytes, BandwidthMbit             float64
}

// FRROSPFInterfaces holds the aggregated result of FetchFRROSPFInterfaces.
type FRROSPFInterfaces struct {
	Present    bool
	Interfaces []FRROSPFInterface
}

// FetchFRROSPFInterfaces calls api/quagga/diagnostics/ospfinterface. Interface
// labels are bounded by NIC count.
//
// A 404 (plugin absent) or the daemon-disabled configd `[]` fallback returns
// Present=false, nil.
func (c *Client) FetchFRROSPFInterfaces() (FRROSPFInterfaces, *APICallError) {
	var data FRROSPFInterfaces

	endpointURL, ok := c.endpoints["quaggaOspfInterface"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaOspfInterface",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope frrOSPFInterfaceEnvelope
	if err := c.do("GET", endpointURL, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	if len(envelope.Response) == 0 || envelope.Response[0] == '[' {
		return data, nil
	}

	var wrapped frrOSPFInterfaceWrapped
	_ = json.Unmarshal(envelope.Response, &wrapped)
	ifaces := wrapped.Interfaces
	if len(ifaces) == 0 {
		var flat map[string]frrOSPFInterfaceEntry
		if jsonErr := json.Unmarshal(envelope.Response, &flat); jsonErr == nil {
			ifaces = flat
		}
	}
	if len(ifaces) == 0 {
		return data, nil
	}

	data.Present = true
	for name, iface := range ifaces {
		up := 0.0
		if iface.IfUp {
			up = 1.0
		}
		data.Interfaces = append(data.Interfaces, FRROSPFInterface{
			Interface:        name,
			Area:             iface.Area,
			NetworkType:      iface.NetworkType,
			State:            iface.State,
			Up:               up,
			Cost:             iface.Cost,
			Priority:         iface.Priority,
			NbrCount:         iface.NbrCount,
			NbrAdjacentCount: iface.NbrAdjacentCount,
			MtuBytes:         iface.MtuBytes,
			BandwidthMbit:    iface.BandwidthMbit,
		})
	}

	return data, nil
}

// frrOSPFv3AreaData holds a single area's LSA count from ospfv3overview.
// UNVERIFIED against a live payload (see the VERIFICATION banner at the top of
// this file): field name grounded in FRR ospf6d source
// (ospf6_area.c ospf6_area_show -> "numberOfAreaScopedLsa").
type frrOSPFv3AreaData struct {
	NumberOfAreaScopedLsa float64 `json:"numberOfAreaScopedLsa"`
}

// frrOSPFv3OverviewBody holds the parsed ospfv3overview `response` object.
// UNVERIFIED against a live payload: field names grounded in FRR ospf6d source
// (ospf6_top.c ospf6_show), mirroring `show ipv6 ospf6 json`.
type frrOSPFv3OverviewBody struct {
	RouterID            string                       `json:"routerId"`
	NumberOfAsScopedLsa float64                      `json:"numberOfAsScopedLsa"`
	Areas               map[string]frrOSPFv3AreaData `json:"areas"`
}

// frrOSPFv3OverviewEnvelope wraps the API `{"response": ...}`.
type frrOSPFv3OverviewEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// FRROSPFv3Area holds normalised per-area OSPFv3 LSA-count metrics.
type FRROSPFv3Area struct {
	Area     string
	LSACount float64
}

// FRROSPFv3Overview holds the aggregated result of FetchFRROSPFv3Overview.
type FRROSPFv3Overview struct {
	Present bool
	Areas   []FRROSPFv3Area
}

// FetchFRROSPFv3Overview calls api/quagga/diagnostics/ospfv3overview.
//
// A 404 (plugin absent) or the array fallback (`{"response":[]}`, ospf6d
// disabled — the only shape confirmed on the dev-box lab, which has no IPv6
// stack) returns Present=false, nil.
func (c *Client) FetchFRROSPFv3Overview() (FRROSPFv3Overview, *APICallError) {
	var data FRROSPFv3Overview

	endpointURL, ok := c.endpoints["quaggaOspfv3Overview"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaOspfv3Overview",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope frrOSPFv3OverviewEnvelope
	if err := c.do("GET", endpointURL, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	if len(envelope.Response) == 0 || envelope.Response[0] == '[' {
		return data, nil
	}

	var body frrOSPFv3OverviewBody
	if jsonErr := json.Unmarshal(envelope.Response, &body); jsonErr != nil {
		return data, nil
	}
	if len(body.Areas) == 0 {
		return data, nil
	}

	data.Present = true
	for areaID, area := range body.Areas {
		data.Areas = append(data.Areas, FRROSPFv3Area{
			Area:     areaID,
			LSACount: area.NumberOfAreaScopedLsa,
		})
	}

	return data, nil
}

// frrOSPFv3InterfaceEntry is the raw per-interface JSON shape from FRR
// `show ipv6 ospf6 interface json`. UNVERIFIED against a live payload (see the
// VERIFICATION banner at the top of this file): field names grounded in FRR
// ospf6d source (ospf6_interface.c ospf6_interface_show). There is no OSPFv3
// neighbor endpoint in the quagga plugin API — interface state is the best
// available proxy for adjacency.
type frrOSPFv3InterfaceEntry struct {
	Status                     string  `json:"status"`
	Type                       string  `json:"type"`
	AreaID                     string  `json:"areaId"`
	Cost                       float64 `json:"cost"`
	Priority                   float64 `json:"priority"`
	State                      string  `json:"ospf6InterfaceState"`
	NumberOfInterfaceScopedLsa float64 `json:"numberOfInterfaceScopedLsa"`
	PendingLsaLsUpdateCount    float64 `json:"pendingLsaLsUpdateCount"`
	PendingLsaLsAckCount       float64 `json:"pendingLsaLsAckCount"`
}

// frrOSPFv3InterfaceEnvelope wraps the API `{"response": ...}`.
type frrOSPFv3InterfaceEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// FRROSPFv3Interface holds normalised per-OSPFv3-interface metrics.
type FRROSPFv3Interface struct {
	Interface, Area, State          string
	Up, Cost                        float64
	PendingLsaUpdate, PendingLsaAck float64
}

// FRROSPFv3Interfaces holds the aggregated result of FetchFRROSPFv3Interfaces.
type FRROSPFv3Interfaces struct {
	Present    bool
	Interfaces []FRROSPFv3Interface
}

// FetchFRROSPFv3Interfaces calls api/quagga/diagnostics/ospfv3interface.
// Interface labels are bounded by NIC count.
//
// A 404 (plugin absent) or the array fallback (`{"response":[]}`, ospf6d
// disabled) returns Present=false, nil.
func (c *Client) FetchFRROSPFv3Interfaces() (FRROSPFv3Interfaces, *APICallError) {
	var data FRROSPFv3Interfaces

	endpointURL, ok := c.endpoints["quaggaOspfv3Interface"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "quaggaOspfv3Interface",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var envelope frrOSPFv3InterfaceEnvelope
	if err := c.do("GET", endpointURL, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	if len(envelope.Response) == 0 || envelope.Response[0] == '[' {
		return data, nil
	}

	var ifaces map[string]frrOSPFv3InterfaceEntry
	if jsonErr := json.Unmarshal(envelope.Response, &ifaces); jsonErr != nil {
		return data, nil
	}
	if len(ifaces) == 0 {
		return data, nil
	}

	data.Present = true
	for name, iface := range ifaces {
		up := 0.0
		if iface.Status == "up" {
			up = 1.0
		}
		data.Interfaces = append(data.Interfaces, FRROSPFv3Interface{
			Interface:        name,
			Area:             iface.AreaID,
			State:            iface.State,
			Up:               up,
			Cost:             iface.Cost,
			PendingLsaUpdate: iface.PendingLsaLsUpdateCount,
			PendingLsaAck:    iface.PendingLsaLsAckCount,
		})
	}

	return data, nil
}

// --- Routing-state volume gauges (#199, opt-in via --exporter.enable-frr-routes) ---

// frrGeneralRouteRow is one flattened per-nexthop row from
// search_generalroute4/6 (zebra RIB, `show ip[v6] route json`, flattened one
// row per nexthop by the quagga plugin's searchGeneralroute4/6 action).
type frrGeneralRouteRow struct {
	Prefix   flexString `json:"prefix"`
	Protocol flexString `json:"protocol"`
}

// frrGeneralRouteSearch is the bootgrid envelope for search_generalroute4/6.
type frrGeneralRouteSearch struct {
	Rows []frrGeneralRouteRow `json:"rows"`
}

// frrOSPFRouteRow is one row from search_ospfroute (OSPFv2 route table).
// FRR's composed route code (e.g. "N E2", "R ") lives directly under "type".
type frrOSPFRouteRow struct {
	Type flexString `json:"type"`
}

// frrOSPFRouteSearch is the bootgrid envelope for search_ospfroute.
type frrOSPFRouteSearch struct {
	Rows []frrOSPFRouteRow `json:"rows"`
}

// frrOSPFv3RouteRow is one row from search_ospfv3route (OSPFv3 route table).
// Verified live 2026-07-25 against a real Full-adjacency OSPFv3 box (#458):
// unlike v2, v3 rows carry NO "type" key at all — the same information v2
// packs into one composed "type" string is split across two fields,
// destinationType (e.g. "N") and pathType (e.g. "IA").
type frrOSPFv3RouteRow struct {
	DestinationType flexString `json:"destinationType"`
	PathType        flexString `json:"pathType"`
}

// resolvedType composes v3's split destinationType/pathType into the same
// notation v2's single "type" field uses (destinationType + " " + pathType,
// e.g. "N" + "IA" -> "N IA" — the live-captured pair from #458). Falls back
// to whichever single field is non-empty, and "" when both are empty (the
// caller must not turn that into a type="" series — see countOSPFv3Routes).
func (r frrOSPFv3RouteRow) resolvedType() string {
	dst := strings.TrimSpace(r.DestinationType.String())
	path := strings.TrimSpace(r.PathType.String())
	switch {
	case dst != "" && path != "":
		return dst + " " + path
	case dst != "":
		return dst
	case path != "":
		return path
	default:
		return ""
	}
}

// frrOSPFv3RouteSearch is the bootgrid envelope for search_ospfv3route.
type frrOSPFv3RouteSearch struct {
	Rows []frrOSPFv3RouteRow `json:"rows"`
}

// frrOSPFDatabaseAreaEntry holds one area's per-LSA-type counts from
// ospfdatabase (`show ip ospf database json`). router/network are verified
// against the dev-box capture; the summary/asbr/nssa/opaque families FRR
// emits when those LSA types are present are unverified (this box's lab
// topology never exercised them).
type frrOSPFDatabaseAreaEntry struct {
	RouterLinkStatesCount       float64 `json:"routerLinkStatesCount"`
	NetworkLinkStatesCount      float64 `json:"networkLinkStatesCount"`
	SummaryLinkStatesCount      float64 `json:"summaryLinkStatesCount"`
	AsbrSummaryLinkStatesCount  float64 `json:"asbrSummaryLinkStatesCount"`
	NssaExternalLinkStatesCount float64 `json:"nssaExternalLinkStatesCount"`
	OpaqueLinkLinkStatesCount   float64 `json:"opaqueLinkLinkStatesCount"`
	OpaqueAreaLinkStatesCount   float64 `json:"opaqueAreaLinkStatesCount"`
}

// frrOSPFDatabaseBody holds the parsed ospfdatabase `response` object.
type frrOSPFDatabaseBody struct {
	Areas                     map[string]frrOSPFDatabaseAreaEntry `json:"areas"`
	AsExternalLinkStatesCount float64                             `json:"asExternalLinkStatesCount"`
}

// frrOSPFDatabaseEnvelope wraps the API `{"response": ...}`.
type frrOSPFDatabaseEnvelope struct {
	Response json.RawMessage `json:"response"`
}

// frrOSPFv3DatabaseRow is one row from search_ospfv3database; "dbname" is the
// LSA's flooding scope (link/area/AS-scoped) per the quagga plugin's
// searchOspfv3database action. UNVERIFIED against a live payload (see the
// VERIFICATION banner at the top of this file).
type frrOSPFv3DatabaseRow struct {
	Dbname flexString `json:"dbname"`
}

// frrOSPFv3DatabaseSearch is the bootgrid envelope for search_ospfv3database.
type frrOSPFv3DatabaseSearch struct {
	Rows []frrOSPFv3DatabaseRow `json:"rows"`
}

// FRRRouteCount holds a distinct-prefix and nexthop-row count for one
// (af, protocol) pair from the zebra RIB.
type FRRRouteCount struct {
	AF, Protocol             string
	RouteCount, NexthopCount float64
}

// FRRRouteTypeCount holds a row count for one OSPF/OSPFv3 route type.
type FRRRouteTypeCount struct {
	Type  string
	Count float64
}

// FRROSPFLSACount holds an LSA count for one (area, lsa_type) pair.
type FRROSPFLSACount struct {
	Area, LSAType string
	Count         float64
}

// FRROSPFv3LSAScopeCount holds an LSA count for one v3 flooding scope.
type FRROSPFv3LSAScopeCount struct {
	Scope string
	Count float64
}

// FRRRouteVolumes holds the aggregated result of FetchFRRRouteVolumes.
type FRRRouteVolumes struct {
	Present      bool
	Routes       []FRRRouteCount
	OSPFRoutes   []FRRRouteTypeCount
	OSPFv3Routes []FRRRouteTypeCount
	OSPFLSA      []FRROSPFLSACount
	OSPFv3LSA    []FRROSPFv3LSAScopeCount
}

// countGeneralRoutes fetches one zebra RIB search endpoint
// (quaggaGeneralRoute4 or quaggaGeneralRoute6) and returns per-protocol
// distinct-prefix and nexthop-row counts labelled with af. A nil, nil result
// means the endpoint 404'd (plugin absent); a non-nil, possibly empty, slice
// means the request succeeded (even with zero rows).
func (c *Client) countGeneralRoutes(endpointName EndpointName, af string) ([]FRRRouteCount, *APICallError) {
	endpointURL, ok := c.endpoints[endpointName]
	if !ok {
		return nil, &APICallError{Endpoint: string(endpointName), Message: "endpoint not found in client endpoints", StatusCode: 0}
	}

	var search frrGeneralRouteSearch
	if err := c.do("GET", endpointURL, nil, &search); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	type protoKey struct{ protocol string }
	prefixSets := map[protoKey]map[string]struct{}{}
	nexthopCounts := map[protoKey]float64{}
	var order []protoKey
	for _, row := range search.Rows {
		k := protoKey{protocol: row.Protocol.String()}
		if _, ok := prefixSets[k]; !ok {
			prefixSets[k] = map[string]struct{}{}
			order = append(order, k)
		}
		prefixSets[k][row.Prefix.String()] = struct{}{}
		nexthopCounts[k]++
	}

	counts := make([]FRRRouteCount, 0, len(order))
	for _, k := range order {
		counts = append(counts, FRRRouteCount{
			AF:           af,
			Protocol:     k.protocol,
			RouteCount:   float64(len(prefixSets[k])),
			NexthopCount: nexthopCounts[k],
		})
	}
	return counts, nil
}

// countOSPFRoutes fetches one OSPF route-table search endpoint
// (quaggaOspfRoute or quaggaOspfv3Route) and returns a row count per route
// type. A nil, nil result means the endpoint 404'd (plugin absent); a
// non-nil, possibly empty, slice means the request succeeded.
func (c *Client) countOSPFRoutes(endpointName EndpointName) ([]FRRRouteTypeCount, *APICallError) {
	endpointURL, ok := c.endpoints[endpointName]
	if !ok {
		return nil, &APICallError{Endpoint: string(endpointName), Message: "endpoint not found in client endpoints", StatusCode: 0}
	}

	var search frrOSPFRouteSearch
	if err := c.do("GET", endpointURL, nil, &search); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	counts := map[string]float64{}
	var order []string
	for _, row := range search.Rows {
		t := strings.TrimSpace(row.Type.String())
		if _, ok := counts[t]; !ok {
			order = append(order, t)
		}
		counts[t]++
	}
	result := make([]FRRRouteTypeCount, 0, len(order))
	for _, t := range order {
		result = append(result, FRRRouteTypeCount{Type: t, Count: counts[t]})
	}
	return result, nil
}

// countOSPFv3Routes fetches quaggaOspfv3Route and returns a row count per
// route type, resolved via frrOSPFv3RouteRow.resolvedType (#458). A row
// resolving to "" (neither destinationType nor pathType present) is dropped
// rather than counted under an empty-string type label — see the
// resolvedType doc comment and #458's acceptance criteria. A nil, nil result
// means the endpoint 404'd (plugin absent); a non-nil, possibly empty, slice
// means the request succeeded.
func (c *Client) countOSPFv3Routes(endpointName EndpointName) ([]FRRRouteTypeCount, *APICallError) {
	endpointURL, ok := c.endpoints[endpointName]
	if !ok {
		return nil, &APICallError{Endpoint: string(endpointName), Message: "endpoint not found in client endpoints", StatusCode: 0}
	}

	var search frrOSPFv3RouteSearch
	if err := c.do("GET", endpointURL, nil, &search); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	counts := map[string]float64{}
	var order []string
	for _, row := range search.Rows {
		t := row.resolvedType()
		if t == "" {
			continue
		}
		if _, ok := counts[t]; !ok {
			order = append(order, t)
		}
		counts[t]++
	}
	result := make([]FRRRouteTypeCount, 0, len(order))
	for _, t := range order {
		result = append(result, FRRRouteTypeCount{Type: t, Count: counts[t]})
	}
	return result, nil
}

// fetchOSPFDatabaseCounts fetches quaggaOspfDatabase and returns an LSA count
// per (area, lsa_type) pair, plus a synthetic area="" lsa_type="external" row
// for the domain-wide (not area-scoped) AS-external LSA count. A nil, nil
// result means the endpoint 404'd (plugin absent); a non-nil, possibly empty,
// slice means the request succeeded.
func (c *Client) fetchOSPFDatabaseCounts() ([]FRROSPFLSACount, *APICallError) {
	endpointURL, ok := c.endpoints["quaggaOspfDatabase"]
	if !ok {
		return nil, &APICallError{Endpoint: "quaggaOspfDatabase", Message: "endpoint not found in client endpoints", StatusCode: 0}
	}

	var envelope frrOSPFDatabaseEnvelope
	if err := c.do("GET", endpointURL, nil, &envelope); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	counts := []FRROSPFLSACount{}
	if len(envelope.Response) == 0 || envelope.Response[0] == '[' {
		return counts, nil
	}

	var body frrOSPFDatabaseBody
	if jsonErr := json.Unmarshal(envelope.Response, &body); jsonErr != nil {
		return counts, nil
	}

	areaIDs := make([]string, 0, len(body.Areas))
	for areaID := range body.Areas {
		areaIDs = append(areaIDs, areaID)
	}
	sort.Strings(areaIDs)
	for _, areaID := range areaIDs {
		area := body.Areas[areaID]
		for _, lc := range []struct {
			lsaType string
			count   float64
		}{
			{"router", area.RouterLinkStatesCount},
			{"network", area.NetworkLinkStatesCount},
			{"summary", area.SummaryLinkStatesCount},
			{"asbrSummary", area.AsbrSummaryLinkStatesCount},
			{"nssaExternal", area.NssaExternalLinkStatesCount},
			{"opaqueLink", area.OpaqueLinkLinkStatesCount},
			{"opaqueArea", area.OpaqueAreaLinkStatesCount},
		} {
			counts = append(counts, FRROSPFLSACount{Area: areaID, LSAType: lc.lsaType, Count: lc.count})
		}
	}
	counts = append(counts, FRROSPFLSACount{Area: "", LSAType: "external", Count: body.AsExternalLinkStatesCount})

	return counts, nil
}

// fetchOSPFv3DatabaseCounts fetches quaggaOspfv3Database and returns an LSA
// row count per flooding scope ("dbname"). A nil, nil result means the
// endpoint 404'd (plugin absent); a non-nil, possibly empty, slice means the
// request succeeded.
func (c *Client) fetchOSPFv3DatabaseCounts() ([]FRROSPFv3LSAScopeCount, *APICallError) {
	endpointURL, ok := c.endpoints["quaggaOspfv3Database"]
	if !ok {
		return nil, &APICallError{Endpoint: "quaggaOspfv3Database", Message: "endpoint not found in client endpoints", StatusCode: 0}
	}

	var search frrOSPFv3DatabaseSearch
	if err := c.do("GET", endpointURL, nil, &search); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	counts := map[string]float64{}
	var order []string
	for _, row := range search.Rows {
		scope := row.Dbname.String()
		if _, ok := counts[scope]; !ok {
			order = append(order, scope)
		}
		counts[scope]++
	}
	result := make([]FRROSPFv3LSAScopeCount, 0, len(order))
	for _, scope := range order {
		result = append(result, FRROSPFv3LSAScopeCount{Scope: scope, Count: counts[scope]})
	}
	return result, nil
}

// FetchFRRRouteVolumes fetches the zebra RIB, OSPF/OSPFv3 route tables and
// OSPF/OSPFv3 LSDBs, and returns aggregate counts only — never a per-prefix or
// per-LSA series. Deliberately excludes search_bgproute4/6 (catastrophic
// payload size against a real BGP table; RIB size per AF is already covered by
// FetchFRRBGP's bgp_rib_entries).
//
// Only called when --exporter.enable-frr-routes is set: the underlying
// bootgrid endpoints have no success-body caching and their payload size
// scales with route-table size (see cache.go).
//
// Present reflects whether any sub-endpoint answered at all (plugin present).
// An individual sub-endpoint's own 404 (e.g. ospf6d disabled, or a route
// family this device doesn't run) just omits that slice rather than failing
// the whole fetch; a non-404 error still fails the whole fetch and is
// returned to the caller.
func (c *Client) FetchFRRRouteVolumes() (FRRRouteVolumes, *APICallError) {
	var data FRRRouteVolumes
	var sawAny bool

	if v4, err := c.countGeneralRoutes("quaggaGeneralRoute4", "ipv4"); err != nil {
		return data, err
	} else if v4 != nil {
		sawAny = true
		data.Routes = append(data.Routes, v4...)
	}

	if v6, err := c.countGeneralRoutes("quaggaGeneralRoute6", "ipv6"); err != nil {
		return data, err
	} else if v6 != nil {
		sawAny = true
		data.Routes = append(data.Routes, v6...)
	}

	if ospfRoutes, err := c.countOSPFRoutes("quaggaOspfRoute"); err != nil {
		return data, err
	} else if ospfRoutes != nil {
		sawAny = true
		data.OSPFRoutes = ospfRoutes
	}

	if ospfv3Routes, err := c.countOSPFv3Routes("quaggaOspfv3Route"); err != nil {
		return data, err
	} else if ospfv3Routes != nil {
		sawAny = true
		data.OSPFv3Routes = ospfv3Routes
	}

	if lsa, err := c.fetchOSPFDatabaseCounts(); err != nil {
		return data, err
	} else if lsa != nil {
		sawAny = true
		data.OSPFLSA = lsa
	}

	if v3lsa, err := c.fetchOSPFv3DatabaseCounts(); err != nil {
		return data, err
	} else if v3lsa != nil {
		sawAny = true
		data.OSPFv3LSA = v3lsa
	}

	data.Present = sawAny
	return data, nil
}
