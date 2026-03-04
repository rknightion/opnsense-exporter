package opnsense

import "strings"

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
	Policy     string `json:"policy"`
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

// NetisrProtocolStats holds aggregated netisr statistics per protocol.
type NetisrProtocolStats struct {
	Dispatched       int64
	HybridDispatched int64
	QueueDrops       int64
	Queued           int64
	Handled          int64
	Length           int
	Watermark        int
	QueueLimit       int
}

// --- socket types ---

// SocketCounts holds socket statistics grouped by type.
type SocketCounts struct {
	ByType    map[string]int
	UnixTotal int
}

// --- route types ---

type routeEntry struct {
	Proto string `json:"proto"`
}

// RouteCounts holds route counts grouped by protocol.
type RouteCounts struct {
	ByProto map[string]int
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

	// Build queue-limit lookup from protocol array
	queueLimits := make(map[string]int, len(resp.Netisr.Protocol))
	for _, p := range resp.Netisr.Protocol {
		queueLimits[p.Name] = p.QueueLimit
	}

	// Aggregate work items across all workstreams per protocol name
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
			data[w.Name] = s
		}
	}

	// Set queue-limit from the protocol array
	for name, s := range data {
		if ql, ok := queueLimits[name]; ok {
			s.QueueLimit = ql
			data[name] = s
		}
	}

	return data, nil
}

// FetchSocketStatistics retrieves socket statistics from OPNsense.
// The API returns a map where keys are formatted as "proto/[details]".
func (c *Client) FetchSocketStatistics() (SocketCounts, *APICallError) {
	var resp map[string]any
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

	for key := range resp {
		parts := strings.SplitN(key, "/", 2)
		prefix := parts[0]
		data.ByType[prefix]++
		if prefix == "unix" {
			data.UnixTotal++
		}
	}

	return data, nil
}

// FetchRouteStatistics retrieves the routing table from OPNsense and
// counts entries by protocol.
func (c *Client) FetchRouteStatistics() (RouteCounts, *APICallError) {
	var resp []routeEntry
	data := RouteCounts{
		ByProto: make(map[string]int),
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
