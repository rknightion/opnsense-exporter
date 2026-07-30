package opnsense

import (
	"regexp"
	"strconv"
)

var (
	// threadsHeaderRegex matches the "N threads:" prefix and captures the total.
	// FreeBSD's top only prints thread states that are non-zero, in a fixed order
	// (starting, running, sleeping, stopped, zombie, waiting, lock), so the
	// individual states cannot be matched as one contiguous sequence — they are
	// scanned independently by threadStateRegex below.
	threadsHeaderRegex = regexp.MustCompile(`(\d+)\s+threads:`)
	threadStateRegex   = regexp.MustCompile(`(\d+)\s+(starting|running|sleeping|stopped|zombie|waiting|lock)\b`)
)

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
	}

	return data, nil
}
