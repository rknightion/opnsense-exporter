package opnsense

import (
	"net/http"
	"regexp"
	"strconv"
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
//
// AccessedEpoch mirrors scripts/shaper/lib/__init__.py:
// 'accessed_epoch': int(parts[3]) if parts[3].isdigit() else 0 — a rule that
// has never matched traffic reports 0, which is a sentinel, not a real Unix
// timestamp (#224).
type tsRule struct {
	Rule          flexString `json:"rule"`
	Pkts          float64    `json:"pkts"`
	Bytes         float64    `json:"bytes"`
	AttachedTo    flexString `json:"attached_to"`
	Description   flexString `json:"description"`
	AccessedEpoch float64    `json:"accessed_epoch"`
}

// tsItem mirrors one element of the api/trafficshaper/service/statistics response.
// Items may be pipes or queues; a template queue carries the pipe's flow stats.
//
// Bw/Delay/Burst are dn_link (pipe) fields -- present only on type:"pipe" items,
// straight from parse_ipfw_pipes()'s slice of a `dnctl pipe show` line
// (FreeBSD sbin/ipfw/dummynet.c:625-649, DN_LINK case). QueueSize/Weight are
// dn_fs (flowset/queue) fields -- present on every type:"queue" item, template
// or not, from parse_flowset_params()'s regex over a `dnctl queue show` line
// (dummynet.c:470-528, print_flowset_parms). None of the five carry a
// separate machine-readable unit: the unit is baked into the formatted string
// (see parseShaperBandwidthBps/parseShaperBurstBytes/parseShaperQueueSize),
// which is why they sat in exemptions.json as an OPPORTUNITY rather than
// already being modeled (#584).
type tsItem struct {
	Type        flexString `json:"type"`
	ID          flexString `json:"id"`
	Description flexString `json:"description"`
	Pipe        flexString `json:"pipe"`     // template queues: the owning pipe ID
	Template    flexBool   `json:"template"` // true on the synthetic per-pipe template queue
	Flows       []tsFlow   `json:"flows"`
	Rules       []tsRule   `json:"rules"`

	Bw        flexString `json:"bw"`         // pipe only: e.g. "10.000 Mbit/s" or "unlimited"
	Delay     flexString `json:"delay"`      // pipe only: milliseconds, plain digits
	Burst     flexString `json:"burst"`      // pipe only: humanize_number()-scaled bytes, e.g. "10K"
	QueueSize flexString `json:"queue_size"` // queue (incl. template) only: "NNN sl." or "NNN B"/"NNN KB"
	Weight    flexString `json:"weight"`     // queue (incl. template) only: plain integer, no unit
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

	// Configured-capacity fields (#584) -- the limits the live counters above
	// are measured AGAINST, letting an operator tell "saturated" from "just
	// busy". Every field has an OK companion and must be presence-gated by
	// the caller: an absent/unparseable/"unlimited" value means "no cap
	// configured", which is a real, distinct state from a cap of 0 and must
	// never be reported as one.

	// ConfiguredBandwidthBps/ConfiguredBurstBytes/ConfiguredDelayMs are
	// PIPE-only (Kind=="pipe"): the pipe's own dn_link bandwidth/burst/delay.
	// ConfiguredBandwidthOK is false for bw=="unlimited" (bandwidth==0 in
	// dummynet's own model -- a real "no cap", not 0 bps).
	ConfiguredBandwidthBps float64
	ConfiguredBandwidthOK  bool
	ConfiguredBurstBytes   float64
	ConfiguredBurstOK      bool
	ConfiguredDelayMs      float64
	ConfiguredDelayOK      bool

	// ConfiguredQueueSize/ConfiguredWeight apply to BOTH kinds: for a "queue"
	// entity they are that queue's own flowset config; for a "pipe" entity
	// they are folded from its auto-attached template queue (#584), the same
	// attribution the live ActiveFlows/Packets/Bytes/Drop* fields above
	// already use for template-queue data. ConfiguredQueueSizeUnit is
	// "packets" or "bytes" -- dnctl reports queue depth as EITHER a packet-
	// slot count OR a byte count depending on the queue's configured mode,
	// two different physical quantities behind the one wire field, so the
	// unit is never assumed.
	ConfiguredQueueSize     float64
	ConfiguredQueueSizeUnit string
	ConfiguredQueueSizeOK   bool
	ConfiguredWeight        float64
	ConfiguredWeightOK      bool
}

// TrafficShaperRule is the normalised view of one ipfw rule counter.
// TargetType is "pipe" when the rule is attached to a pipe (via its template
// queue), otherwise "queue". LastMatchEpoch is 0 when the rule has never
// matched traffic (a sentinel, not the Unix epoch — see tsRule).
type TrafficShaperRule struct {
	Rule           string
	AttachedTo     string
	TargetType     string // "pipe" | "queue"
	Description    string
	Packets        float64
	Bytes          float64
	LastMatchEpoch float64
}

// TrafficShaperStatistics is the result returned by FetchTrafficShaperStatistics.
// Present is false when the endpoint returned 404 or a non-ok status.
type TrafficShaperStatistics struct {
	Present bool
	Pipes   []TrafficShaperEntity
	Queues  []TrafficShaperEntity
	Rules   []TrafficShaperRule
}

// shaperBandwidthRegexp matches dnctl's pre-formatted bandwidth string:
// FreeBSD sbin/ipfw/dummynet.c:634-643 (DN_LINK print) emits exactly one of
// "%7.3f Gbit/s", "%7.3f Mbit/s", "%7.3f Kbit/s", "%7.3f bit/s " (trailing
// space trimmed by OPNsense's trim_dict) or the literal "unlimited" when the
// configured bandwidth is 0 (dummynet's own "no cap" sentinel, checked
// separately below since it carries no numeric match at all).
var shaperBandwidthRegexp = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*(Gbit|Mbit|Kbit|bit)/s$`)

// parseShaperBandwidthBps normalizes a dnctl pipe bandwidth string to bits
// per second. "unlimited" (dummynet's own sentinel for a configured
// bandwidth of exactly 0 -- i.e. no cap at all, not a 0 bps cap) and any
// unparseable value yield ok=false; a raw number with no unit would be a bug,
// not a metric, so nothing is emitted rather than guessing a scale.
func parseShaperBandwidthBps(raw string) (bps float64, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "unlimited") {
		return 0, false
	}
	m := shaperBandwidthRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	switch m[2] {
	case "Gbit":
		return v * 1e9, true
	case "Mbit":
		return v * 1e6, true
	case "Kbit":
		return v * 1e3, true
	case "bit":
		return v, true
	default:
		return 0, false
	}
}

// parseShaperDelayMs parses the pipe's configured delay, a plain-integer
// millisecond count with no unit ambiguity (dummynet.c:648, "%4d ms" --
// OPNsense's python slices out the digits before "ms"). Unlike bandwidth,
// there is no "unlimited" sentinel: 0 ms is a real, meaningful "no added
// delay" configuration, so it is presence-gated only on the string actually
// being a parseable integer.
func parseShaperDelayMs(raw string) (ms float64, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// shaperHumanizedRegexp matches FreeBSD libutil's humanize_number() output as
// dummynet.c:645-647 produces it for a pipe's burst size: an integer byte
// count optionally followed by a single binary-scale letter (K/M/G/T/P/E =
// *1024^n; no letter = bytes). humanize_number is called with an empty units
// suffix (dummynet.c's third argument ""), so there is never a trailing "B" —
// distinguishing this from queue_size's "NNN B"/"NNN KB" shape below, which
// DOES carry a "B" unit token.
var shaperHumanizedRegexp = regexp.MustCompile(`^([0-9]+)([KMGTPE]?)$`)

var shaperBinaryScale = map[string]float64{
	"":  1,
	"K": 1 << 10,
	"M": 1 << 20,
	"G": 1 << 30,
	"T": 1 << 40,
	"P": 1 << 50,
	"E": 1 << 60,
}

// parseShaperBurstBytes normalizes a pipe's humanize_number()-scaled burst
// size to bytes. Unparseable input yields ok=false rather than a guess.
func parseShaperBurstBytes(raw string) (bytesVal float64, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	m := shaperHumanizedRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	scale, known := shaperBinaryScale[m[2]]
	if !known {
		return 0, false
	}
	return v * scale, true
}

// shaperQueueSizeRegexp matches a queue's configured depth as dummynet.c:
// 477-484 (print_flowset_parms) formats it: "%3d sl." when the queue is
// slot/packet-count limited (the DN_QSIZE_BYTES flag is unset -- OPNsense's
// python trims the %3d field-width padding), or "%d B"/"%d KB" when it is
// byte limited. These are two DIFFERENT physical quantities behind the one
// wire field, which is why the unit is returned rather than assumed.
var shaperQueueSizeRegexp = regexp.MustCompile(`^([0-9]+)\s*(sl\.|KB|B)$`)

// parseShaperQueueSize normalizes a queue's configured depth, reporting which
// unit it was measured in ("packets" for the slot-count mode, "bytes" for
// the byte-count mode -- dummynet.c divides by 1024 for its "KB" print, so
// that case is scaled back up here). Unparseable input yields ok=false.
func parseShaperQueueSize(raw string) (value float64, unit string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, "", false
	}
	m := shaperQueueSizeRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0, "", false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, "", false
	}
	switch m[2] {
	case "sl.":
		return v, "packets", true
	case "B":
		return v, "bytes", true
	case "KB":
		return v * 1024, "bytes", true
	default:
		return 0, "", false
	}
}

// parseShaperWeight parses a queue's WF2Q+/scheduler weight: a plain integer
// with no unit at all (dummynet.c:522, "weight %d").
func parseShaperWeight(raw string) (weight float64, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
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

		// Configured-capacity fields (#584). bandwidth/burst/delay come from
		// this pipe item's own bw/burst/delay; queueSize/weight are folded in
		// below from the matching template-queue item, mirroring how the
		// live flow stats above are already attributed.
		bandwidthBps  float64
		bandwidthOK   bool
		burstBytes    float64
		burstOK       bool
		delayMs       float64
		delayOK       bool
		queueSize     float64
		queueSizeUnit string
		queueSizeOK   bool
		weight        float64
		weightOK      bool
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
		acc := &pipeAccum{
			description: item.Description.String(),
		}
		acc.bandwidthBps, acc.bandwidthOK = parseShaperBandwidthBps(item.Bw.String())
		acc.burstBytes, acc.burstOK = parseShaperBurstBytes(item.Burst.String())
		acc.delayMs, acc.delayOK = parseShaperDelayMs(item.Delay.String())
		pipeMap[id] = acc
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
				Rule:           r.Rule.String(),
				AttachedTo:     r.AttachedTo.String(),
				TargetType:     targetType,
				Description:    r.Description.String(),
				Packets:        r.Pkts,
				Bytes:          r.Bytes,
				LastMatchEpoch: r.AccessedEpoch,
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
				// Fold the template queue's own queue_size/weight onto the
				// pipe, same attribution as the flow stats above (#584).
				acc.queueSize, acc.queueSizeUnit, acc.queueSizeOK = parseShaperQueueSize(item.QueueSize.String())
				acc.weight, acc.weightOK = parseShaperWeight(item.Weight.String())
			}
			// Template rows are NOT emitted as queue metrics.
			continue
		}

		// Non-template queue: derive pipe from id prefix when pipe field absent.
		pipeID := item.Pipe.String()
		if pipeID == "" {
			pipeID = idPipePrefix(item.ID.String())
		}
		queueSize, queueSizeUnit, queueSizeOK := parseShaperQueueSize(item.QueueSize.String())
		weight, weightOK := parseShaperWeight(item.Weight.String())
		queues = append(queues, TrafficShaperEntity{
			Kind:                    "queue",
			ID:                      item.ID.String(),
			Pipe:                    pipeID,
			Description:             item.Description.String(),
			ActiveFlows:             activeFlows,
			Packets:                 pkt,
			Bytes:                   byt,
			DropPackets:             dropPkt,
			DropBytes:               dropByt,
			ConfiguredQueueSize:     queueSize,
			ConfiguredQueueSizeUnit: queueSizeUnit,
			ConfiguredQueueSizeOK:   queueSizeOK,
			ConfiguredWeight:        weight,
			ConfiguredWeightOK:      weightOK,
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
			Kind:                    "pipe",
			ID:                      id,
			Pipe:                    id,
			Description:             acc.description,
			ActiveFlows:             acc.activeFlows,
			Packets:                 acc.packets,
			Bytes:                   acc.bytes,
			DropPackets:             acc.dropPackets,
			DropBytes:               acc.dropBytes,
			ConfiguredBandwidthBps:  acc.bandwidthBps,
			ConfiguredBandwidthOK:   acc.bandwidthOK,
			ConfiguredBurstBytes:    acc.burstBytes,
			ConfiguredBurstOK:       acc.burstOK,
			ConfiguredDelayMs:       acc.delayMs,
			ConfiguredDelayOK:       acc.delayOK,
			ConfiguredQueueSize:     acc.queueSize,
			ConfiguredQueueSizeUnit: acc.queueSizeUnit,
			ConfiguredQueueSizeOK:   acc.queueSizeOK,
			ConfiguredWeight:        acc.weight,
			ConfiguredWeightOK:      acc.weightOK,
		})
	}

	data.Queues = queues
	data.Rules = rules

	return data, nil
}
