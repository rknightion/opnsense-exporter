package opnsense

import (
	"encoding/json"
	"strings"
)

// --- netisr types ---

type netisrWorkItem struct {
	Workstream       int    `json:"workstream"`
	CPU              int    `json:"cpu"`
	Name             string `json:"name"`
	Length           int    `json:"length"`
	Watermark        int    `json:"watermark"`
	Dispatched       int64  `json:"dispatched"`
	HybridDispatched int64  `json:"hybrid-dispatched"`
	QueueDrops       int64  `json:"queue-drops"`
	Queued           int64  `json:"queued"`
	Handled          int64  `json:"handled"`
}

type netisrProtocol struct {
	Name       string `json:"name"`
	Protocol   int    `json:"protocol"`
	QueueLimit int    `json:"queue-limit"`
	PolicyType string `json:"policy-type"`
	Policy     string `json:"policy"`
	Flags      string `json:"flags"`
}

type netisrWorkstream struct {
	Work []netisrWorkItem `json:"work"`
}

type netisrData struct {
	Protocol   []netisrProtocol   `json:"protocol"`
	Workstream []netisrWorkstream `json:"workstream"`
}

type netisrResponse struct {
	Netisr netisrData `json:"netisr"`
}

// NetisrWorkstreamStats holds one netisr work row: the statistics for a single
// protocol on a single netisr workstream (and therefore, on every box observed
// so far, a single CPU). Workstream index and CPU binding coincide in practice
// but are not the same thing — net.isr.bindthreads can be turned off — so both
// are carried.
type NetisrWorkstreamStats struct {
	Workstream       int
	CPU              int
	Length           int
	Watermark        int
	Dispatched       int64
	HybridDispatched int64
	QueueDrops       int64
	Queued           int64
	Handled          int64
}

// Active reports whether this workstream has ever carried traffic for its
// protocol. An all-zero row means the CPU is not participating in netisr
// processing for that protocol at all, which is itself a finding.
func (w NetisrWorkstreamStats) Active() bool {
	return w.Handled > 0 || w.Queued > 0 || w.Dispatched > 0 || w.HybridDispatched > 0
}

// NetisrProtocolStats holds aggregated netisr statistics per protocol, plus the
// protocol's configuration metadata and the unaggregated per-workstream rows it
// was aggregated from.
type NetisrProtocolStats struct {
	Dispatched       int64
	HybridDispatched int64
	QueueDrops       int64
	Queued           int64
	Handled          int64
	Length           int
	Watermark        int
	QueueLimit       int

	// Protocol metadata, straight from the netisr.protocol array.
	Protocol   int
	Policy     string
	PolicyType string
	Flags      string

	// Workstreams holds every work row the box reported for this protocol, in
	// the order the box reported them, including entirely idle ones.
	Workstreams []NetisrWorkstreamStats
}

// ActiveWorkstreams counts the workstreams that have carried any traffic for
// this protocol. On a 12-CPU box a value of 4 for a cpu-policy protocol means
// eight CPUs are sitting idle while four carry the whole load.
func (s NetisrProtocolStats) ActiveWorkstreams() int {
	n := 0
	for _, w := range s.Workstreams {
		if w.Active() {
			n++
		}
	}
	return n
}

// WorkstreamsAtLimit counts the workstreams whose high watermark has reached
// the protocol's configured queue limit — the lanes that have actually run out
// of queue. A zero queue limit means "unbounded/unset" and never counts.
func (s NetisrProtocolStats) WorkstreamsAtLimit() int {
	if s.QueueLimit <= 0 {
		return 0
	}
	n := 0
	for _, w := range s.Workstreams {
		if w.Watermark >= s.QueueLimit {
			n++
		}
	}
	return n
}

// QueueImbalanceRatio is the maximum watermark over the ACTIVE workstreams
// divided by the mean watermark over those same rows. 1.0 is a perfectly even
// spread; higher means one lane is absorbing disproportionately more depth.
// Idle rows are excluded deliberately — including them would dilute the mean
// and make an affinity problem look milder the more CPUs the box has.
// Returns 0 when the ratio is undefined (fewer than two active rows, or every
// active watermark is zero).
func (s NetisrProtocolStats) QueueImbalanceRatio() float64 {
	var sum, max int
	n := 0
	for _, w := range s.Workstreams {
		if !w.Active() {
			continue
		}
		n++
		sum += w.Watermark
		if w.Watermark > max {
			max = w.Watermark
		}
	}
	if n < 2 || sum == 0 {
		return 0
	}
	mean := float64(sum) / float64(n)
	return float64(max) / mean
}

// DropConcentrationRatio is the largest queue-drop count on any single
// workstream divided by the total across all of them. 1.0 means every drop
// landed on one lane, which points at CPU affinity rather than queue depth;
// a value near 1/N means the whole protocol is genuinely over its queue limit.
// Returns 0 when nothing has dropped.
func (s NetisrProtocolStats) DropConcentrationRatio() float64 {
	var total, max int64
	for _, w := range s.Workstreams {
		total += w.QueueDrops
		if w.QueueDrops > max {
			max = w.QueueDrops
		}
	}
	if total == 0 {
		return 0
	}
	return float64(max) / float64(total)
}

// --- socket types ---

// SocketCounts holds socket statistics grouped by type.
type SocketCounts struct {
	ByType    map[string]int
	UnixTotal int
}

// --- route types ---

type routeEntry struct {
	Proto           string `json:"proto"`
	Destination     string `json:"destination"`
	Gateway         string `json:"gateway"`
	Flags           string `json:"flags"`
	NetIf           string `json:"netif"`
	IntfDescription string `json:"intf_description"`
}

// RouteInterfaceKey identifies a route group by address family and egress
// interface. Device is the raw kernel device (netif) and Interface the
// human-assigned description; they diverge on VLAN children, PPPoE links and
// anything unassigned, and only the raw device joins against the interface
// metrics.
type RouteInterfaceKey struct {
	Proto     string
	Device    string
	Interface string
}

// RouteFlagsKey identifies a route group by address family and netstat flag
// string. The flag vocabulary is closed and short (U, G, H, S, B, 1 ...), so
// this stays bounded regardless of table size.
type RouteFlagsKey struct {
	Proto string
	Flags string
}

// DefaultRoute is one default route as the box reports it. There is normally
// one per address family; more than one means multiple default routes are
// installed, and none at all is a total-outage condition for that family.
type DefaultRoute struct {
	Proto     string
	Device    string
	Interface string
	Gateway   string
}

// RouteCounts holds route counts grouped by protocol, plus the per-interface
// and per-flags breakdowns and the default routes. ByProto is the original
// aggregate and is kept exactly as it was.
type RouteCounts struct {
	ByProto       map[string]int
	ByInterface   map[RouteInterfaceKey]int
	ByFlags       map[RouteFlagsKey]int
	DefaultRoutes []DefaultRoute
}

// isDefaultDestination reports whether a route's destination is the default
// route for its family. netstat's libxo output renders it as the literal
// "default" on every release observed (26.1, 26.7.1, 27.1.a); the CIDR forms
// are accepted as well so a rendering change cannot silently blind the
// default-route signal rather than merely renaming it.
func isDefaultDestination(dst string) bool {
	switch dst {
	case "default", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

// FetchNetisrStatistics retrieves netisr statistics from OPNsense and
// aggregates them per protocol name across all workstreams.
func (c *Client) FetchNetisrStatistics() (map[string]NetisrProtocolStats, *APICallError) {
	var resp netisrResponse
	data := make(map[string]NetisrProtocolStats)

	url, ok := c.endpoints["netisrStatistics"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "netisrStatistics",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	// Build protocol-metadata lookup from protocol array
	protoMeta := make(map[string]netisrProtocol, len(resp.Netisr.Protocol))
	for _, p := range resp.Netisr.Protocol {
		protoMeta[p.Name] = p
	}

	// Aggregate work items across all workstreams per protocol name, keeping
	// the unaggregated rows alongside (idle rows included — "these CPUs do no
	// netisr work" is exactly the signal a per-CPU view exists to surface).
	for _, ws := range resp.Netisr.Workstream {
		for _, w := range ws.Work {
			s := data[w.Name]
			s.Dispatched += w.Dispatched
			s.HybridDispatched += w.HybridDispatched
			s.QueueDrops += w.QueueDrops
			s.Queued += w.Queued
			s.Handled += w.Handled
			if w.Length > s.Length {
				s.Length = w.Length
			}
			if w.Watermark > s.Watermark {
				s.Watermark = w.Watermark
			}
			s.Workstreams = append(s.Workstreams, NetisrWorkstreamStats{
				Workstream:       w.Workstream,
				CPU:              w.CPU,
				Length:           w.Length,
				Watermark:        w.Watermark,
				Dispatched:       w.Dispatched,
				HybridDispatched: w.HybridDispatched,
				QueueDrops:       w.QueueDrops,
				Queued:           w.Queued,
				Handled:          w.Handled,
			})
			data[w.Name] = s
		}
	}

	// Set queue-limit and protocol metadata from the protocol array
	for name, s := range data {
		if p, ok := protoMeta[name]; ok {
			s.QueueLimit = p.QueueLimit
			s.Protocol = p.Protocol
			s.Policy = p.Policy
			s.PolicyType = p.PolicyType
			s.Flags = p.Flags
			data[name] = s
		}
	}

	return data, nil
}

// FetchSocketStatistics retrieves socket statistics from OPNsense.
// The API nests entries under a top-level "statistics" object keyed by section
// name: "Active Internet connections" (keys formatted "proto/[details]", e.g.
// "tcp4/[...]") and "Active UNIX domain sockets" (keys are kernel addresses with
// no proto prefix). We count Internet sockets by protocol prefix and Unix
// sockets by section membership.
func (c *Client) FetchSocketStatistics() (SocketCounts, *APICallError) {
	// Each section is an object keyed by socket; decode lazily because OPNsense
	// (PHP) serializes an empty section as [] rather than {}, which would fail a
	// map decode for the whole response.
	var resp struct {
		Statistics map[string]json.RawMessage `json:"statistics"`
	}
	data := SocketCounts{
		ByType: make(map[string]int),
	}

	url, ok := c.endpoints["socketStatistics"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "socketStatistics",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for section, raw := range resp.Statistics {
		var entries map[string]any
		if err := json.Unmarshal(raw, &entries); err != nil {
			// Empty section serialized as [] (or otherwise not an object) → skip.
			continue
		}
		// Unix domain sockets have opaque address keys (no proto prefix), so
		// they are identified by their section rather than by key shape.
		if strings.Contains(section, "UNIX") {
			data.ByType["unix"] += len(entries)
			data.UnixTotal += len(entries)
			continue
		}
		for key := range entries {
			prefix, _, _ := strings.Cut(key, "/")
			data.ByType[prefix]++
		}
	}

	return data, nil
}

// FetchRouteStatistics retrieves the routing table from OPNsense and counts
// entries by protocol, by egress interface and by netstat flag string, and
// picks out the default route of each address family.
//
// Per-route values (destination, gateway) are deliberately NOT carried per row:
// a router's table is dominated by dynamically learned host routes that come and
// go, so a series per destination would churn continuously for no diagnostic
// gain. The one exception is the default route's gateway, which is carried
// because there are only ever one or two of them and a change to it is itself
// the event an operator wants to see.
func (c *Client) FetchRouteStatistics() (RouteCounts, *APICallError) {
	var resp []routeEntry
	data := RouteCounts{
		ByProto:     make(map[string]int),
		ByInterface: make(map[RouteInterfaceKey]int),
		ByFlags:     make(map[RouteFlagsKey]int),
	}

	url, ok := c.endpoints["routingTable"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "routingTable",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, entry := range resp {
		data.ByProto[entry.Proto]++
		data.ByInterface[RouteInterfaceKey{
			Proto:     entry.Proto,
			Device:    entry.NetIf,
			Interface: entry.IntfDescription,
		}]++
		data.ByFlags[RouteFlagsKey{Proto: entry.Proto, Flags: entry.Flags}]++
		if isDefaultDestination(entry.Destination) {
			data.DefaultRoutes = append(data.DefaultRoutes, DefaultRoute{
				Proto:     entry.Proto,
				Device:    entry.NetIf,
				Interface: entry.IntfDescription,
				Gateway:   entry.Gateway,
			})
		}
	}

	return data, nil
}

// --- pfsync types ---

type pfsyncNodeEntry struct {
	CreatorID string `json:"creatorid"`
	This      int    `json:"this"`
}

type pfsyncNodesResponse struct {
	Total    int               `json:"total"`
	RowCount int               `json:"rowCount"`
	Current  int               `json:"current"`
	Rows     []pfsyncNodeEntry `json:"rows"`
}

type PFSyncNode struct {
	CreatorID string
	IsLocal   bool
}

type PFSyncNodes struct {
	Total int
	Nodes []PFSyncNode
}

func (c *Client) FetchPFSyncNodes() (PFSyncNodes, *APICallError) {
	var resp pfsyncNodesResponse
	var data PFSyncNodes

	url, ok := c.endpoints["pfsyncNodes"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "pfsyncNodes",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	data.Total = resp.Total
	for _, row := range resp.Rows {
		data.Nodes = append(data.Nodes, PFSyncNode{
			CreatorID: row.CreatorID,
			IsLocal:   row.This == 1,
		})
	}
	return data, nil
}
