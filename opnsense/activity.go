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
	cpuRegex           = regexp.MustCompile(`([\d.]+)%\s+user,\s+([\d.]+)%\s+nice,\s+([\d.]+)%\s+system,\s+([\d.]+)%\s+interrupt,\s+([\d.]+)%\s+idle`)
)

type activityResponse struct {
	Headers []string `json:"headers"`
	Details []any    `json:"details"`
}

type SystemActivity struct {
	ThreadsTotal    int
	ThreadsRunning  int
	ThreadsSleeping int
	ThreadsWaiting  int
	CPUUser         float64
	CPUNice         float64
	CPUSystem       float64
	CPUInterrupt    float64
	CPUIdle         float64
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
			states := threadStateRegex.FindAllStringSubmatch(header, -1)
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

		if matches := cpuRegex.FindStringSubmatch(header); matches != nil {
			user, err := strconv.ParseFloat(matches[1], 64)
			if err != nil {
				c.log.Warn("failed to parse CPU user", "value", matches[1], "err", err)
				continue
			}
			nice, err := strconv.ParseFloat(matches[2], 64)
			if err != nil {
				c.log.Warn("failed to parse CPU nice", "value", matches[2], "err", err)
				continue
			}
			system, err := strconv.ParseFloat(matches[3], 64)
			if err != nil {
				c.log.Warn("failed to parse CPU system", "value", matches[3], "err", err)
				continue
			}
			interrupt, err := strconv.ParseFloat(matches[4], 64)
			if err != nil {
				c.log.Warn("failed to parse CPU interrupt", "value", matches[4], "err", err)
				continue
			}
			idle, err := strconv.ParseFloat(matches[5], 64)
			if err != nil {
				c.log.Warn("failed to parse CPU idle", "value", matches[5], "err", err)
				continue
			}
			data.CPUUser = user
			data.CPUNice = nice
			data.CPUSystem = system
			data.CPUInterrupt = interrupt
			data.CPUIdle = idle
		}
	}

	return data, nil
}
