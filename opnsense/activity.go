package opnsense

import (
	"regexp"
	"strconv"
)

var (
	threadsRegex = regexp.MustCompile(`(\d+)\s+threads:\s+(\d+)\s+running,\s+(\d+)\s+sleeping,\s+(\d+)\s+waiting`)
	cpuRegex     = regexp.MustCompile(`([\d.]+)%\s+user,\s+([\d.]+)%\s+nice,\s+([\d.]+)%\s+system,\s+([\d.]+)%\s+interrupt,\s+([\d.]+)%\s+idle`)
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
		if matches := threadsRegex.FindStringSubmatch(header); matches != nil {
			total, err := strconv.Atoi(matches[1])
			if err != nil {
				c.log.Warn("failed to parse threads total", "value", matches[1], "err", err)
				continue
			}
			running, err := strconv.Atoi(matches[2])
			if err != nil {
				c.log.Warn("failed to parse threads running", "value", matches[2], "err", err)
				continue
			}
			sleeping, err := strconv.Atoi(matches[3])
			if err != nil {
				c.log.Warn("failed to parse threads sleeping", "value", matches[3], "err", err)
				continue
			}
			waiting, err := strconv.Atoi(matches[4])
			if err != nil {
				c.log.Warn("failed to parse threads waiting", "value", matches[4], "err", err)
				continue
			}
			data.ThreadsTotal = total
			data.ThreadsRunning = running
			data.ThreadsSleeping = sleeping
			data.ThreadsWaiting = waiting
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
