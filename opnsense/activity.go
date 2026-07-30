package opnsense

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// threadsHeaderRegex matches the "N threads:" prefix and captures the total.
	// FreeBSD's top only prints thread states that are non-zero, in a fixed order
	// (starting, running, sleeping, stopped, zombie, waiting, lock), so the
	// individual states cannot be matched as one contiguous sequence — they are
	// scanned independently by threadStateRegex below.
	threadsHeaderRegex = regexp.MustCompile(`(\d+)\s+threads:`)
	threadStateRegex   = regexp.MustCompile(`(\d+)\s+(starting|running|sleeping|stopped|zombie|waiting|lock)\b`)

	// ZFS ARC composition, from top's ARC header (#551). Two lines, and top emits
	// them as two SEPARATE entries in the headers array:
	//
	//	ARC: 7818M Total, 3034M MFU, 4222M MRU, 22M Anon, 46M Header, 483M Other
	//	     6772M Compressed, 11G Uncompressed, 1.70:1 Ratio
	//
	// Each component is matched independently rather than as one fixed sequence, for
	// the same reason the thread states are: a future top that reorders them, drops a
	// zero-valued one, or inserts a new one then degrades to a missing series instead
	// of breaking the whole parse.
	arcComponentRegex = regexp.MustCompile(`(\S+)\s+(Total|MFU|MRU|Anon|Header|Other)\b`)
	// The continuation line carries no "ARC:" prefix, so it is identified by its own
	// content. Nothing else in a top header pairs Compressed with Uncompressed.
	arcCompressionRegex = regexp.MustCompile(`(\S+)\s+Compressed,\s+(\S+)\s+Uncompressed`)
	// A size as top writes it: a number with an optional single-letter unit.
	topSizeRegex = regexp.MustCompile(`^([\d.]+)([BKMGTP]?)$`)
)

// parseTopSize parses a size as top prints it ("483M", "11G", "512") into bytes.
// Units are base-2, matching top. Reports false for anything unparseable, so a
// caller emits nothing rather than a fabricated zero.
func parseTopSize(s string) (float64, bool) {
	m := topSizeRegex.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	value, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	multiplier, ok := firmwareSizeMultiplier(m[2])
	if !ok {
		return 0, false
	}
	return value * multiplier, true
}

// ARCStats is the ZFS ARC composition breakdown from top's ARC header (#551). Free
// data: the activity poll already fetches this payload and used to discard these two
// lines entirely.
//
// The exporter's ARC TOTAL is deliberately NOT here. It comes from systemResources as
// opnsense_system_memory_arc_bytes and must keep coming from there — one series with
// two sources, sampled at different moments, would disagree with itself.
//
// Present is the absence test, and it is not "was there an ARC line". A UFS box does
// emit an ARC header; it emits it EMPTY, as the bare string "ARC: " (verified on a
// live UFS box 2026-07-30). Testing for the line rather than for parsed content would
// read that as an ARC of size zero on every non-ZFS install.
type ARCStats struct {
	Present     bool
	MFUBytes    float64
	MRUBytes    float64
	AnonBytes   float64
	HeaderBytes float64
	OtherBytes  float64

	// HasCompression is tracked separately: the composition line can arrive without
	// its continuation, and an unreported compression ratio must be absent rather
	// than a 1:1 that reads as "compression is doing nothing".
	HasCompression    bool
	CompressedBytes   float64
	UncompressedBytes float64
}

// threadStateMatchLimit caps how many thread-state segments are materialized
// from one `top` header (#321).
//
// Why a bound is safe: threadStateRegex alternates over exactly 7 states and
// FreeBSD's top prints each at most once, so 16 cannot truncate anything a
// real header contains — the limit is more than double the maximum.
//
// Why the bound exists: the header is appliance-controlled text bounded only
// by the 64 MiB response cap (maxResponseBodyBytes), and an unbounded scan
// (FindAllStringSubmatch with -1) materializes one 3-element []string per
// match, so a crafted or corrupted header could force millions of submatch
// slices in a single scrape. This is allocation amplification, NOT ReDoS —
// Go's RE2 engine cannot backtrack, so the scan itself stays linear; it is
// only the result slice that grows without limit.
const threadStateMatchLimit = 16

// arcComponentMatchLimit bounds the ARC composition scan for the same reason
// threadStateMatchLimit bounds the thread-state scan: the header is
// appliance-controlled text and an unbounded FindAllStringSubmatch materialises a
// slice per match. Six components exist; 12 cannot truncate a real header.
const arcComponentMatchLimit = 12

// parseThreadStates extracts the thread-state segments from a `top` header,
// bounded by threadStateMatchLimit.
func parseThreadStates(header string) [][]string {
	return threadStateRegex.FindAllStringSubmatch(header, threadStateMatchLimit)
}

type activityResponse struct {
	Headers []string `json:"headers"`
	Details []any    `json:"details"`
}

// SystemActivity carries the thread-state counts parsed from `top`'s header.
//
// CPU utilisation deliberately does NOT live here any more (#559). It now comes from
// the api/diagnostics/cpu_usage SSE stream as cumulative counters, which gives 100%
// timeline coverage against this endpoint's ~13% and costs the firewall essentially
// nothing against this endpoint's measured 2.15 s per call. Thread-state counts are
// the only thing get_activity uniquely provides, and they are instantaneous gauges
// with no sub-minute alerting story — which is why this collector is now medium tier.
type SystemActivity struct {
	ThreadsTotal    int
	ThreadsRunning  int
	ThreadsSleeping int
	ThreadsWaiting  int
	ARC             ARCStats
}

func (c *Client) FetchActivity() (SystemActivity, *APICallError) {
	var resp activityResponse
	var data SystemActivity

	url, ok := c.endpoints["systemActivity"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "systemActivity",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	for _, header := range resp.Headers {
		if matches := threadsHeaderRegex.FindStringSubmatch(header); matches != nil {
			total, err := strconv.Atoi(matches[1])
			if err != nil {
				c.log.Warn("failed to parse threads total", "value", matches[1], "err", err)
				continue
			}
			data.ThreadsTotal = total

			// Scan each thread-state segment independently: top prints only the
			// non-zero states, in a fixed order, so any absent state defaults to 0
			// and an inserted state (zombie/stopped/starting) no longer breaks the
			// running/sleeping/waiting parse.
			states := parseThreadStates(header)
			if len(states) == 0 {
				c.log.Warn("threads header present but no thread-state segments parsed", "header", header)
			}
			for _, s := range states {
				n, err := strconv.Atoi(s[1])
				if err != nil {
					c.log.Warn("failed to parse thread-state count", "state", s[2], "value", s[1], "err", err)
					continue
				}
				switch s[2] {
				case "running":
					data.ThreadsRunning = n
				case "sleeping":
					data.ThreadsSleeping = n
				case "waiting":
					data.ThreadsWaiting = n
				}
			}
		}

		data.parseARCHeader(header)
	}

	return data, nil
}

// parseARCHeader folds one header line into the ARC composition, matching either the
// "ARC:" composition line or its unprefixed continuation. Both are no-ops on any
// other line.
func (d *SystemActivity) parseARCHeader(header string) {
	if strings.HasPrefix(strings.TrimSpace(header), "ARC:") {
		for _, m := range arcComponentRegex.FindAllStringSubmatch(header, arcComponentMatchLimit) {
			bytes, ok := parseTopSize(m[1])
			if !ok {
				continue
			}
			switch m[2] {
			case "MFU":
				d.ARC.MFUBytes = bytes
			case "MRU":
				d.ARC.MRUBytes = bytes
			case "Anon":
				d.ARC.AnonBytes = bytes
			case "Header":
				d.ARC.HeaderBytes = bytes
			case "Other":
				d.ARC.OtherBytes = bytes
			case "Total":
				// Matched so it cannot be mistaken for a component, then discarded:
				// the total belongs to the system collector. See ARCStats.
				continue
			}
			d.ARC.Present = true
		}
		return
	}

	m := arcCompressionRegex.FindStringSubmatch(header)
	if m == nil {
		return
	}
	compressed, cok := parseTopSize(m[1])
	uncompressed, uok := parseTopSize(m[2])
	if !cok || !uok {
		return
	}
	d.ARC.CompressedBytes = compressed
	d.ARC.UncompressedBytes = uncompressed
	d.ARC.HasCompression = true
}
