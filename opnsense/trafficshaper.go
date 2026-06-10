package opnsense

import (
	"net/http"
	"strings"
)

// tsFlow holds the per-flow statistics for one flow entry in a pipe or queue
// item. Values are JSON numbers (not strings) per the OPNsense trafficshaper
// source.
//
// VERIFICATION: core endpoint — verified live as "shaper unconfigured →
// {status:ok,items:[]}" on the test box. The populated shape is derived from
// TrafficShaper/Api/ServiceController.php::statisticsAction and
// scripts/shaper/lib/__init__.py. Re-check on a box with active shaper rules
// when available: confirm pkt/bytes/drop_pkt/drop_bytes are real JSON numbers,
// template-queue behavior (pipe's flows always empty, template row carries them),
// and that non-template queues lack a "pipe" key (derive from id prefix).
type tsFlow struct {
	Pkt       float64 `json:"pkt"`
	Bytes     float64 `json:"bytes"`
	DropPkt   float64 `json:"drop_pkt"`
	DropBytes float64 `json:"drop_bytes"`
}

// tsRule holds one ipfw rule counter row attached to a pipe/queue item.
type tsRule struct {
	Rule        flexString `json:"rule"`
	Pkts        float64    `json:"pkts"`
	Bytes       float64    `json:"bytes"`
	AttachedTo  flexString `json:"attached_to"`
	Description flexString `json:"description"`
}

// tsItem mirrors one element of the api/trafficshaper/service/statistics response.
// Items may be pipes or queues; a template queue carries the pipe's flow stats.
type tsItem struct {
	Type        flexString `json:"type"`
	ID          flexString `json:"id"`
	Description flexString `json:"description"`
	Pipe        flexString `json:"pipe"`     // template queues: the owning pipe ID
	Template    flexBool   `json:"template"` // true on the synthetic per-pipe template queue
	Flows       []tsFlow   `json:"flows"`
	Rules       []tsRule   `json:"rules"`
}

// trafficShaperStatsResponse is the top-level API response shape.
type trafficShaperStatsResponse struct {
	Status flexString `json:"status"`
	Items  []tsItem   `json:"items"`
}

// TrafficShaperEntity is the normalised view of one pipe or queue.
// Kind is "pipe" or "queue"; Pipe is the owning pipe ID (equals ID for pipes).
// Flow stats are summed over all Flows entries.
type TrafficShaperEntity struct {
	Kind        string // "pipe" | "queue"
	ID          string
	Pipe        string
	Description string
	ActiveFlows float64
	Packets     float64
	Bytes       float64
	DropPackets float64
	DropBytes   float64
}

// TrafficShaperRule is the normalised view of one ipfw rule counter.
// TargetType is "pipe" when the rule is attached to a pipe (via its template
// queue), otherwise "queue".
type TrafficShaperRule struct {
	Rule        string
	AttachedTo  string
	TargetType  string // "pipe" | "queue"
	Description string
	Packets     float64
	Bytes       float64
}

// TrafficShaperStatistics is the result returned by FetchTrafficShaperStatistics.
// Present is false when the endpoint returned 404 or a non-ok status.
type TrafficShaperStatistics struct {
	Present bool
	Pipes   []TrafficShaperEntity
	Queues  []TrafficShaperEntity
	Rules   []TrafficShaperRule
}

// idPipePrefix returns the part of an item ID before the first dot, used to
// derive the owning pipe for non-template queues (e.g. "00001.66" → "00001").
func idPipePrefix(id string) string {
	if i := strings.IndexByte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

// FetchTrafficShaperStatistics fetches per-pipe/queue/rule statistics from
// api/trafficshaper/service/statistics.
//
// Template-queue attribution (locked in the plan):
//   - statisticsAction moves every pipe's flows onto a synthetic "template:true"
//     queue item; pipe items themselves always have empty flows[].
//   - Pipe flow metrics are sourced from their matching template-queue row
//     (linked by the template row's "pipe" field). The pipe item's own flows
//     are empty and are ignored.
//   - Template-queue rows are EXCLUDED from the queue_* metrics to avoid
//     double-counting.
//
// A HTTP 404 or status != "ok" response yields Present=false with a nil error.
func (c *Client) FetchTrafficShaperStatistics() (TrafficShaperStatistics, *APICallError) {
	var data TrafficShaperStatistics

	url, ok := c.endpoints["trafficShaperStatistics"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "trafficShaperStatistics",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp trafficShaperStatsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // feature absent
		}
		return data, err
	}

	if resp.Status.String() != "ok" {
		// status:"failed" (stats unavailable) or any other non-ok response.
		return data, nil
	}

	data.Present = true

	if len(resp.Items) == 0 {
		// Shaper unconfigured: items is empty, return silently.
		return data, nil
	}

	// First pass: collect pipe metadata keyed by pipe ID. Template-queue rows
	// carry the pipe's flow stats; we need to know which pipes exist so we can
	// build TrafficShaperEntity records for them.
	type pipeAccum struct {
		description string
		activeFlows float64
		packets     float64
		bytes       float64
		dropPackets float64
		dropBytes   float64
	}
	pipeMap := make(map[string]*pipeAccum)

	for _, item := range resp.Items {
		if item.Type.String() != "pipe" {
			continue
		}
		id := item.ID.String()
		if id == "" {
			continue
		}
		pipeMap[id] = &pipeAccum{
			description: item.Description.String(),
		}
	}

	// Second pass: process queues and rules.
	var queues []TrafficShaperEntity
	var rules []TrafficShaperRule

	for _, item := range resp.Items {
		itemType := item.Type.String()
		if itemType == "unknown" {
			continue
		}

		// Accumulate rules from every item (pipes and queues carry rules).
		isTemplate := item.Template.Bool()
		targetType := "queue"
		if isTemplate {
			targetType = "pipe"
		}
		for _, r := range item.Rules {
			rules = append(rules, TrafficShaperRule{
				Rule:        r.Rule.String(),
				AttachedTo:  r.AttachedTo.String(),
				TargetType:  targetType,
				Description: r.Description.String(),
				Packets:     r.Pkts,
				Bytes:       r.Bytes,
			})
		}

		if itemType != "queue" {
			continue
		}

		// Sum flows for this item.
		var activeFlows, pkt, byt, dropPkt, dropByt float64
		for _, f := range item.Flows {
			activeFlows++
			pkt += f.Pkt
			byt += f.Bytes
			dropPkt += f.DropPkt
			dropByt += f.DropBytes
		}

		if isTemplate {
			// Template-queue: attribute its flows to the owning pipe.
			// The pipe field tells us which pipe this belongs to.
			pipeID := item.Pipe.String()
			if pipeID == "" {
				// Fall back to id prefix before the dot.
				pipeID = idPipePrefix(item.ID.String())
			}
			if acc, found := pipeMap[pipeID]; found {
				acc.activeFlows = activeFlows
				acc.packets = pkt
				acc.bytes = byt
				acc.dropPackets = dropPkt
				acc.dropBytes = dropByt
			}
			// Template rows are NOT emitted as queue metrics.
			continue
		}

		// Non-template queue: derive pipe from id prefix when pipe field absent.
		pipeID := item.Pipe.String()
		if pipeID == "" {
			pipeID = idPipePrefix(item.ID.String())
		}
		queues = append(queues, TrafficShaperEntity{
			Kind:        "queue",
			ID:          item.ID.String(),
			Pipe:        pipeID,
			Description: item.Description.String(),
			ActiveFlows: activeFlows,
			Packets:     pkt,
			Bytes:       byt,
			DropPackets: dropPkt,
			DropBytes:   dropByt,
		})
	}

	// Build the pipe slice in iteration order (stable via range over resp.Items).
	for _, item := range resp.Items {
		if item.Type.String() != "pipe" {
			continue
		}
		id := item.ID.String()
		if id == "" {
			continue
		}
		acc := pipeMap[id]
		data.Pipes = append(data.Pipes, TrafficShaperEntity{
			Kind:        "pipe",
			ID:          id,
			Pipe:        id,
			Description: acc.description,
			ActiveFlows: acc.activeFlows,
			Packets:     acc.packets,
			Bytes:       acc.bytes,
			DropPackets: acc.dropPackets,
			DropBytes:   acc.dropBytes,
		})
	}

	data.Queues = queues
	data.Rules = rules

	return data, nil
}
