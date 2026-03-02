package opnsense

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Internal response DTOs matching OPNsense JSON exactly.

type systemResourcesMemory struct {
	Total string      `json:"total"`
	Used  json.Number `json:"used"`
	Arc   string      `json:"arc"`
}

type systemResourcesResponse struct {
	Memory systemResourcesMemory `json:"memory"`
}

type systemTimeResponse struct {
	Uptime   string `json:"uptime"`
	Datetime string `json:"datetime"`
	Boottime string `json:"boottime"`
	Config   string `json:"config"`
	Loadavg  string `json:"loadavg"`
}

type systemDiskDevice struct {
	Device    string `json:"device"`
	Type      string `json:"type"`
	Blocks    string `json:"blocks"`
	Used      string `json:"used"`
	Available string `json:"available"`
	UsedPct   int    `json:"used_pct"`
	MountPt   string `json:"mountpoint"`
}

type systemDiskResponse struct {
	Devices []systemDiskDevice `json:"devices"`
}

type systemSwapDevice struct {
	Device string `json:"device"`
	Total  string `json:"total"`
	Used   string `json:"used"`
}

type systemSwapResponse struct {
	Swap []systemSwapDevice `json:"swap"`
}

// Public data structs.

type SystemMemory struct {
	Total  int64
	Used   int64
	Arc    int64
	HasArc bool
}

type SystemTime struct {
	Uptime           float64
	LoadAverage      [3]float64
	ConfigLastChange float64
}

type SystemDisk struct {
	Device     string
	Type       string
	Mountpoint string
	Total      int64
	Used       int64
	UsageRatio float64
}

type SystemSwap struct {
	Device string
	Total  int64
	Used   int64
}

type SystemResources struct {
	Memory SystemMemory
	Time   SystemTime
	Disks  []SystemDisk
	Swaps  []SystemSwap
}

// parseHumanBytes parses strings like "876G", "17M", "512K" to bytes.
func parseHumanBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return 0
	}

	suffix := s[len(s)-1]
	var multiplier int64

	switch suffix {
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
	case 'M', 'm':
		multiplier = 1024 * 1024
	case 'K', 'k':
		multiplier = 1024
	case 'B', 'b':
		multiplier = 1
	default:
		// No suffix, treat as raw number
		v, _ := strconv.ParseFloat(s, 64)
		return int64(v)
	}

	v, _ := strconv.ParseFloat(s[:len(s)-1], 64)
	return int64(v * float64(multiplier))
}

const opnsenseTimeFormat = "Mon Jan 2 15:04:05 MST 2006"

func (c *Client) fetchSystemMemory(data *SystemResources) *APICallError {
	var resp systemResourcesResponse

	url, ok := c.endpoints["systemResources"]
	if !ok {
		return &APICallError{
			Endpoint:   "systemResources",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	total, _ := strconv.ParseInt(resp.Memory.Total, 10, 64)
	used, _ := resp.Memory.Used.Int64()

	data.Memory.Total = total
	data.Memory.Used = used

	arc := strings.TrimSpace(resp.Memory.Arc)
	if arc != "" && arc != "0" {
		arcVal, _ := strconv.ParseInt(arc, 10, 64)
		data.Memory.Arc = arcVal
		data.Memory.HasArc = true
	}

	return nil
}

func (c *Client) fetchSystemTime(data *SystemResources) *APICallError {
	var resp systemTimeResponse

	url, ok := c.endpoints["systemTime"]
	if !ok {
		return &APICallError{
			Endpoint:   "systemTime",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	// Parse boottime to compute uptime
	bootTime, err := time.Parse(opnsenseTimeFormat, resp.Boottime)
	if err == nil {
		data.Time.Uptime = time.Since(bootTime).Seconds()
	}

	// Parse config last change time
	configTime, err := time.Parse(opnsenseTimeFormat, resp.Config)
	if err == nil {
		data.Time.ConfigLastChange = float64(configTime.Unix())
	}

	// Parse loadavg: "0.12, 0.34, 0.56"
	parts := strings.Split(resp.Loadavg, ", ")
	if len(parts) >= 3 {
		data.Time.LoadAverage = [3]float64{
			safeParseFloat(parts[0]),
			safeParseFloat(parts[1]),
			safeParseFloat(parts[2]),
		}
	}

	return nil
}

func (c *Client) fetchSystemDisk(data *SystemResources) *APICallError {
	var resp systemDiskResponse

	url, ok := c.endpoints["systemDisk"]
	if !ok {
		return &APICallError{
			Endpoint:   "systemDisk",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	for _, d := range resp.Devices {
		disk := SystemDisk{
			Device:     d.Device,
			Type:       d.Type,
			Mountpoint: d.MountPt,
			Total:      parseHumanBytes(d.Blocks),
			Used:       parseHumanBytes(d.Used),
			UsageRatio: float64(d.UsedPct) / 100.0,
		}
		data.Disks = append(data.Disks, disk)
	}

	return nil
}

func (c *Client) fetchSystemSwap(data *SystemResources) *APICallError {
	var resp systemSwapResponse

	url, ok := c.endpoints["systemSwap"]
	if !ok {
		return &APICallError{
			Endpoint:   "systemSwap",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	for _, s := range resp.Swap {
		totalKB, _ := strconv.ParseInt(strings.TrimSpace(s.Total), 10, 64)
		usedKB, _ := strconv.ParseInt(strings.TrimSpace(s.Used), 10, 64)

		swap := SystemSwap{
			Device: s.Device,
			Total:  totalKB * 1024,
			Used:   usedKB * 1024,
		}
		data.Swaps = append(data.Swaps, swap)
	}

	return nil
}

// FetchSystemResources calls 4 OPNsense endpoints to gather system resource data.
// It tolerates partial failure: if some calls fail but others succeed, it logs warnings
// and returns partial data. It only returns an error if all 4 calls fail.
func (c *Client) FetchSystemResources() (SystemResources, *APICallError) {
	var data SystemResources

	type fetchResult struct {
		name string
		err  *APICallError
	}

	results := []fetchResult{
		{"systemResources", c.fetchSystemMemory(&data)},
		{"systemTime", c.fetchSystemTime(&data)},
		{"systemDisk", c.fetchSystemDisk(&data)},
		{"systemSwap", c.fetchSystemSwap(&data)},
	}

	var firstErr *APICallError
	failCount := 0

	for _, r := range results {
		if r.err != nil {
			failCount++
			if firstErr == nil {
				firstErr = r.err
			}
			c.log.Warn("system resources sub-call failed",
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
