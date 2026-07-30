package opnsense

import (
	"encoding/json"
	"net/http"
	"sort"
)

// bpfEntry mirrors one element of the api/diagnostics/interface/get_bpf_statistics
// response. Values are JSON numbers.
//
// VERIFICATION: verified live against OPNsense 26.1 at 10.0.0.254 per todos.txt
// TODO 23. The pid and the optional boolean fields (immediate, header-complete,
// locked) are intentionally not modeled — pid churns on process restart (D9),
// and the booleans are not needed for the metrics. `direction` IS modelled as of
// #544: it is a closed three-value vocabulary and summing it away hid that
// lldpd's descriptors are input-only while filterlog's is bidirectional.
type bpfEntry struct {
	InterfaceName   string  `json:"interface-name"`
	Process         string  `json:"process"`
	Direction       string  `json:"direction"`
	ReceivedPackets float64 `json:"received-packets"`
	DroppedPackets  float64 `json:"dropped-packets"`
	FilterPackets   float64 `json:"filter-packets"`
	StoreBufferLen  float64 `json:"store-buffer-length"`
	HoldBufferLen   float64 `json:"hold-buffer-length"`
}

// BPFListener is the normalised, aggregated result for a single (process,
// interface) pair. Multiple raw bpf-entry rows sharing the same process and
// interface name are summed into one BPFListener per D9.
type BPFListener struct {
	Process, Interface                              string
	ReceivedPackets, DroppedPackets, MatchedPackets float64
	StoreBufferBytes, HoldBufferBytes               float64
}

// BPFDirectionListener is the same aggregation as BPFListener but keyed by
// (process, interface, direction) as well — the capture direction the kernel
// recorded for the descriptor. Direction is one of "input", "output",
// "bidirectional", or "unknown" when the box did not report one.
type BPFDirectionListener struct {
	Process, Interface, Direction                   string
	Listeners                                       int
	ReceivedPackets, DroppedPackets, MatchedPackets float64
}

// BPFStatistics holds the result of FetchBPFStatistics.
type BPFStatistics struct {
	ListenersTotal int // raw entry count BEFORE aggregation
	Listeners      []BPFListener
	// ByDirection is the same data as Listeners with the capture direction kept
	// on the key instead of summed away. Listeners is retained unchanged
	// because dashboards and alerts already read it.
	ByDirection []BPFDirectionListener
}

// bpfDirection normalises the wire value. An absent direction still has to
// produce a row: dropping it would silently lose a listener from the breakdown.
func bpfDirection(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// bpfStatisticsResponse mirrors the outer JSON envelope returned by
// api/diagnostics/interface/get_bpf_statistics.
type bpfStatisticsResponse struct {
	BPFStatistics struct {
		// bpf-entry may be an array (multiple listeners) or a single object
		// (one listener, some FreeBSD/PHP serialization paths). Decode as
		// json.RawMessage and handle both forms.
		BPFEntry json.RawMessage `json:"bpf-entry"`
	} `json:"bpf-statistics"`
}

// decodeBPFEntries decodes the bpf-entry field from either a JSON array or a
// single JSON object, handling the FreeBSD/PHP single-item serialization quirk.
func decodeBPFEntries(raw json.RawMessage) ([]bpfEntry, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	// Try array first (common case).
	if raw[0] == '[' {
		var entries []bpfEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, err
		}
		return entries, nil
	}

	// Single object (one listener).
	var entry bpfEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}
	return []bpfEntry{entry}, nil
}

// FetchBPFStatistics calls api/diagnostics/interface/get_bpf_statistics and
// returns BPF listener statistics aggregated by (process, interface) per D9.
// Multiple listeners for the same (process, interface) pair are summed. The
// Listeners slice is sorted by process then interface for deterministic output.
//
// A 404 response is treated as "feature absent" — empty data, no error
// (defensive; the endpoint is a core OPNsense endpoint so 404 is unlikely,
// but mirrors the plugin-absent pattern for uniformity).
func (c *Client) FetchBPFStatistics() (BPFStatistics, *APICallError) {
	var data BPFStatistics

	url, ok := c.endpoints["bpfStatistics"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "bpfStatistics",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp bpfStatisticsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil
		}
		return data, err
	}

	entries, decodeErr := decodeBPFEntries(resp.BPFStatistics.BPFEntry)
	if decodeErr != nil {
		return data, &APICallError{
			Endpoint:   string(url),
			Message:    "failed to decode bpf-entry: " + decodeErr.Error(),
			StatusCode: 0,
		}
	}

	data.ListenersTotal = len(entries)

	// Aggregate by (process, interface) key.
	type aggKey struct{ process, iface string }
	agg := make(map[aggKey]*BPFListener)
	keyOrder := make([]aggKey, 0, len(entries))

	for _, e := range entries {
		k := aggKey{e.Process, e.InterfaceName}
		if l, exists := agg[k]; exists {
			l.ReceivedPackets += e.ReceivedPackets
			l.DroppedPackets += e.DroppedPackets
			l.MatchedPackets += e.FilterPackets
			l.StoreBufferBytes += e.StoreBufferLen
			l.HoldBufferBytes += e.HoldBufferLen
		} else {
			agg[k] = &BPFListener{
				Process:          e.Process,
				Interface:        e.InterfaceName,
				ReceivedPackets:  e.ReceivedPackets,
				DroppedPackets:   e.DroppedPackets,
				MatchedPackets:   e.FilterPackets,
				StoreBufferBytes: e.StoreBufferLen,
				HoldBufferBytes:  e.HoldBufferLen,
			}
			keyOrder = append(keyOrder, k)
		}
	}

	// Sort by process then interface for determinism.
	sort.Slice(keyOrder, func(i, j int) bool {
		if keyOrder[i].process != keyOrder[j].process {
			return keyOrder[i].process < keyOrder[j].process
		}
		return keyOrder[i].iface < keyOrder[j].iface
	})

	data.Listeners = make([]BPFListener, 0, len(keyOrder))
	for _, k := range keyOrder {
		data.Listeners = append(data.Listeners, *agg[k])
	}

	// Same aggregation with direction kept on the key.
	type dirKey struct{ process, iface, dir string }
	dirAgg := make(map[dirKey]*BPFDirectionListener)
	dirOrder := make([]dirKey, 0, len(entries))
	for _, e := range entries {
		k := dirKey{e.Process, e.InterfaceName, bpfDirection(e.Direction)}
		l, exists := dirAgg[k]
		if !exists {
			l = &BPFDirectionListener{Process: k.process, Interface: k.iface, Direction: k.dir}
			dirAgg[k] = l
			dirOrder = append(dirOrder, k)
		}
		l.Listeners++
		l.ReceivedPackets += e.ReceivedPackets
		l.DroppedPackets += e.DroppedPackets
		l.MatchedPackets += e.FilterPackets
	}
	sort.Slice(dirOrder, func(i, j int) bool {
		a, b := dirOrder[i], dirOrder[j]
		if a.process != b.process {
			return a.process < b.process
		}
		if a.iface != b.iface {
			return a.iface < b.iface
		}
		return a.dir < b.dir
	})
	data.ByDirection = make([]BPFDirectionListener, 0, len(dirOrder))
	for _, k := range dirOrder {
		data.ByDirection = append(data.ByDirection, *dirAgg[k])
	}

	return data, nil
}
