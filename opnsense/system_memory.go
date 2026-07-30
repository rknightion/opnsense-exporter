package opnsense

import (
	"encoding/json"
	"sort"
)

// This file models api/diagnostics/system/memory (Diagnostics\Api\SystemController::
// memoryAction), which shells out to `vmstat -m -z --libxo json` via the configd
// action `system show vmstat_mem`. It is the kernel allocator's own accounting:
// one row per UMA zone and one row per malloc type, each carrying the counters
// FreeBSD increments when an allocation could not be satisfied.
//
// SHAPE, VERIFIED LIVE (2026-07-30) on three boxes — prod 26.1, dev 26.7.1 and dev
// 27.1.a — all three identical:
//
//	{"__version":"2","vmstat":{
//	   "malloc-statistics":{"memory":[{"type":..,"in-use":..,"memory-use":..,"requests":..,"size":[..]}]},
//	   "memory-zone-statistics":{"zone":[{"name":..,"size":..,"limit":..,"used":..,"free":..,
//	                                      "requests":..,"fail":..,"sleep":..,"xdomain":..}]}}}
//
// THE UPSTREAM TRANSFORM IS DEAD CODE — do not model its output. memoryAction
// contains a block that renames each malloc row's `type` to `name` and adds
// `totals`/`totals.used_fmt` to both sections. It is guarded on
// `!empty($data['malloc-statistics'])`, but libxo nests everything one level down
// under `vmstat`, so `$data['malloc-statistics']` is never set and the block never
// runs. Confirmed against both core stable/26.7 and master, and against all three
// live boxes: no `totals` key and `type` intact on every one of them. Modelling the
// renamed shape would encode a payload upstream has never produced (#284), so the
// reader models only what the wire actually carries. If OPNsense ever unwraps the
// libxo envelope the canary flags `vmstat` as missing, which is the correct signal.
//
// Counters are json.Number throughout: `requests` on a busy zone runs into the
// billions and has been seen in scientific notation elsewhere in this API, and
// numToInt degrades a single unrepresentable field to 0 rather than failing the
// whole scrape.

type systemMemoryZoneEntry struct {
	Name string `json:"name"`
	// Size is the zone's per-item size in bytes (uma_zone item size), NOT the
	// zone's total footprint. Total bytes = Size * (Used + Free).
	Size     json.Number `json:"size"`
	Limit    json.Number `json:"limit"`
	Used     json.Number `json:"used"`
	Free     json.Number `json:"free"`
	Requests json.Number `json:"requests"`
	Fail     json.Number `json:"fail"`
	Sleep    json.Number `json:"sleep"`
	XDomain  json.Number `json:"xdomain"`
}

type systemMemoryMallocEntry struct {
	Type      string      `json:"type"`
	InUse     json.Number `json:"in-use"`
	MemoryUse json.Number `json:"memory-use"`
	Requests  json.Number `json:"requests"`
	// Size is the set of power-of-two allocation size classes this malloc type has
	// used (vmstat -m's "Size(s)" column), e.g. [16,32,64,128]. Modelled so the live
	// schema canary sees it rather than flagging it as an unknown extra key; it is
	// deliberately not exported as a metric, because a variable-length set of size
	// classes has no honest scalar representation.
	Size []json.Number `json:"size"`
}

type systemMemoryVmstat struct {
	MallocStatistics struct {
		Memory []systemMemoryMallocEntry `json:"memory"`
	} `json:"malloc-statistics"`
	ZoneStatistics struct {
		Zone []systemMemoryZoneEntry `json:"zone"`
	} `json:"memory-zone-statistics"`
}

// systemMemoryResponse is the libxo envelope. __version is libxo's own schema
// version marker ("2" on all three live boxes), kept so a bump is visible to the
// canary rather than silently absorbed.
type systemMemoryResponse struct {
	Version string             `json:"__version"`
	Vmstat  systemMemoryVmstat `json:"vmstat"`
}

// KernelMemoryZone is one UMA zone, with every row the box reported under that
// name already merged (see mergeKernelMemoryZones for why that is necessary).
type KernelMemoryZone struct {
	Name string
	// ItemSizeBytes is the size of a single item in this zone. Where duplicate rows
	// disagreed it is the largest of them.
	ItemSizeBytes int64
	// Limit is the configured item ceiling. Zero means NO ceiling is configured —
	// not a ceiling of zero. Proven on the live prod box, where `pf state keys`
	// reports limit=0 with used=16275, which a real ceiling of zero could not
	// produce. Any used/limit ratio must therefore skip Limit == 0.
	Limit    int64
	Used     int64
	Free     int64
	Requests int64
	Failures int64
	Sleeps   int64
	XDomain  int64
	// Rows is how many raw rows the box reported under this zone name (1 for the
	// overwhelming majority). >1 means the values above are a sum across NUMA
	// domains or across independent instances of a kernel module's zone.
	Rows int
}

// KernelMemoryMallocType is one kernel malloc type, duplicates merged.
type KernelMemoryMallocType struct {
	Name     string
	InUse    int64
	Bytes    int64
	Requests int64
	Rows     int
}

// KernelMemoryStatistics is the parsed api/diagnostics/system/memory payload.
type KernelMemoryStatistics struct {
	Zones       []KernelMemoryZone
	MallocTypes []KernelMemoryMallocType
	// ZoneFailuresTotal is `fail` summed across every zone row on the box, including
	// zones nobody has thought to look at. It is computed from the RAW rows, so it
	// stays correct regardless of how duplicates merge.
	ZoneFailuresTotal int64
}

// FetchKernelMemory returns the kernel allocator statistics from
// api/diagnostics/system/memory.
//
// memoryAction returns a bare `[]` when configd hands back nothing parseable, so
// the body is decoded in two stages: anything that is not a JSON object yields an
// empty result and no error, because "the box had nothing to report" must not fail
// the scrape.
func (c *Client) FetchKernelMemory() (KernelMemoryStatistics, *APICallError) {
	var stats KernelMemoryStatistics

	url, ok := c.endpoints["systemMemory"]
	if !ok {
		return stats, &APICallError{
			Endpoint:   "systemMemory",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var raw json.RawMessage
	if err := c.do("GET", url, nil, &raw); err != nil {
		return stats, err
	}

	var resp systemMemoryResponse
	if uerr := json.Unmarshal(raw, &resp); uerr != nil {
		// `[]` (memoryAction's empty-payload return) lands here. Treat it as "no
		// data", the same way an object with empty sections is treated.
		return stats, nil
	}

	stats.Zones, stats.ZoneFailuresTotal = mergeKernelMemoryZones(resp.Vmstat.ZoneStatistics.Zone)
	stats.MallocTypes = mergeKernelMemoryMallocTypes(resp.Vmstat.MallocStatistics.Memory)
	return stats, nil
}

// mergeKernelMemoryZones collapses the raw zone rows to one entry per zone name and
// returns the failure total across every raw row.
//
// ZONE NAMES ARE NOT UNIQUE ON THE WIRE. UMA reports one row per NUMA domain, and a
// kernel module that creates a zone per instance reports one row per instance. Live
// prod (2026-07-30) sends `vm pgcache` twice, `buffer arena-40` twice and both
// `NetFlow IPv4 cache` and `NetFlow IPv6 cache` SEVEN times each. Emitting those as
// separate series under a single {zone=} label would make every scrape fail
// Gather() with a duplicate-series error, so the counters are summed — which is also
// what an operator wants, since the per-domain split is an allocator implementation
// detail rather than an operational dimension. Item size is the one field that is
// not additive (the two `buffer arena-40` rows report 4096 and 40960), so the
// largest is kept and Rows records that a merge happened.
func mergeKernelMemoryZones(entries []systemMemoryZoneEntry) ([]KernelMemoryZone, int64) {
	byName := make(map[string]*KernelMemoryZone, len(entries))
	var failuresTotal int64

	for _, e := range entries {
		if e.Name == "" {
			continue
		}
		fail := numToInt(e.Fail)
		failuresTotal += fail

		z, ok := byName[e.Name]
		if !ok {
			z = &KernelMemoryZone{Name: e.Name}
			byName[e.Name] = z
		}
		if size := numToInt(e.Size); size > z.ItemSizeBytes {
			z.ItemSizeBytes = size
		}
		z.Limit += numToInt(e.Limit)
		z.Used += numToInt(e.Used)
		z.Free += numToInt(e.Free)
		z.Requests += numToInt(e.Requests)
		z.Failures += fail
		z.Sleeps += numToInt(e.Sleep)
		z.XDomain += numToInt(e.XDomain)
		z.Rows++
	}

	zones := make([]KernelMemoryZone, 0, len(byName))
	for _, z := range byName {
		zones = append(zones, *z)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return zones, failuresTotal
}

// mergeKernelMemoryMallocTypes collapses the raw malloc rows to one entry per type.
// Duplicates occur here too — dev 27.1.a and 26.7.1 both report `dummynet` twice —
// for the same reason and with the same consequence if left unmerged.
func mergeKernelMemoryMallocTypes(entries []systemMemoryMallocEntry) []KernelMemoryMallocType {
	byName := make(map[string]*KernelMemoryMallocType, len(entries))

	for _, e := range entries {
		if e.Type == "" {
			continue
		}
		m, ok := byName[e.Type]
		if !ok {
			m = &KernelMemoryMallocType{Name: e.Type}
			byName[e.Type] = m
		}
		m.InUse += numToInt(e.InUse)
		m.Bytes += numToInt(e.MemoryUse)
		m.Requests += numToInt(e.Requests)
		m.Rows++
	}

	types := make([]KernelMemoryMallocType, 0, len(byName))
	for _, m := range byName {
		types = append(types, *m)
	}
	sort.Slice(types, func(i, j int) bool { return types[i].Name < types[j].Name })
	return types
}
