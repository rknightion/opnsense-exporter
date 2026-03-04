package opnsense

import (
	"strconv"
	"strings"
)

// Internal response DTOs matching OPNsense JSON exactly.

type pfStatsCounterEntry struct {
	Total float64 `json:"total"`
	Rate  float64 `json:"rate"`
}

type pfStatsTableData struct {
	CurrentEntries pfStatsCounterEntry `json:"current-entries"`
	Searches       pfStatsCounterEntry `json:"searches"`
	Inserts        pfStatsCounterEntry `json:"inserts"`
	Removals       pfStatsCounterEntry `json:"removals"`
}

type pfStatsInfoData struct {
	StateTable          pfStatsTableData               `json:"state-table"`
	SourceTrackingTable pfStatsTableData               `json:"source-tracking-table"`
	Counters            map[string]pfStatsCounterEntry `json:"counters"`
	LimitCounters       map[string]pfStatsCounterEntry `json:"limit-counters"`
}

type pfStatsInfoResponse struct {
	Info pfStatsInfoData `json:"info"`
}

type pfStatsMemoryResponse struct {
	Memory map[string]int `json:"memory"`
}

type pfStatsTimeoutsResponse struct {
	Timeouts map[string]string `json:"timeouts"`
}

// Public data struct.

type PFStatistics struct {
	StateTableEntries     int
	StateTableSearches    float64
	StateTableInserts     float64
	StateTableRemovals    float64
	SourceTrackingEntries int
	Counters              map[string]float64
	LimitCounters         map[string]float64
	MemoryLimits          map[string]int
	Timeouts              map[string]float64
}

func (c *Client) fetchPFStatsInfo(data *PFStatistics) *APICallError {
	var resp pfStatsInfoResponse

	url, ok := c.endpoints["pfStatsInfo"]
	if !ok {
		return &APICallError{
			Endpoint:   "pfStatsInfo",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	data.StateTableEntries = int(resp.Info.StateTable.CurrentEntries.Total)
	data.StateTableSearches = resp.Info.StateTable.Searches.Total
	data.StateTableInserts = resp.Info.StateTable.Inserts.Total
	data.StateTableRemovals = resp.Info.StateTable.Removals.Total

	data.SourceTrackingEntries = int(resp.Info.SourceTrackingTable.CurrentEntries.Total)

	data.Counters = make(map[string]float64, len(resp.Info.Counters))
	for name, entry := range resp.Info.Counters {
		data.Counters[name] = entry.Total
	}

	data.LimitCounters = make(map[string]float64, len(resp.Info.LimitCounters))
	for name, entry := range resp.Info.LimitCounters {
		data.LimitCounters[name] = entry.Total
	}

	return nil
}

func (c *Client) fetchPFStatsMemory(data *PFStatistics) *APICallError {
	var resp pfStatsMemoryResponse

	url, ok := c.endpoints["pfStatsMemory"]
	if !ok {
		return &APICallError{
			Endpoint:   "pfStatsMemory",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	data.MemoryLimits = make(map[string]int, len(resp.Memory))
	for name, value := range resp.Memory {
		data.MemoryLimits[name] = value
	}

	return nil
}

func (c *Client) fetchPFStatsTimeouts(data *PFStatistics) *APICallError {
	var resp pfStatsTimeoutsResponse

	url, ok := c.endpoints["pfStatsTimeouts"]
	if !ok {
		return &APICallError{
			Endpoint:   "pfStatsTimeouts",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	data.Timeouts = make(map[string]float64)
	for name, value := range resp.Timeouts {
		if strings.HasSuffix(value, " states") {
			continue
		}
		trimmed := strings.TrimSuffix(value, "s")
		v, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			continue
		}
		data.Timeouts[name] = v
	}

	return nil
}

// FetchPFStatistics calls 3 OPNsense endpoints to gather PF statistics data.
// It tolerates partial failure: if some calls fail but others succeed, it logs warnings
// and returns partial data. It only returns an error if all 3 calls fail.
func (c *Client) FetchPFStatistics() (PFStatistics, *APICallError) {
	var data PFStatistics

	type fetchResult struct {
		name string
		err  *APICallError
	}

	results := []fetchResult{
		{"pfStatsInfo", c.fetchPFStatsInfo(&data)},
		{"pfStatsMemory", c.fetchPFStatsMemory(&data)},
		{"pfStatsTimeouts", c.fetchPFStatsTimeouts(&data)},
	}

	var firstErr *APICallError
	failCount := 0

	for _, r := range results {
		if r.err != nil {
			failCount++
			if firstErr == nil {
				firstErr = r.err
			}
			c.log.Warn("pf statistics sub-call failed",
				"endpoint", r.name,
				"error", r.err.Error(),
			)
		}
	}

	if failCount == len(results) {
		return data, firstErr
	}

	return data, nil
}
