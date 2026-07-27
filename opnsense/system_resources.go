package opnsense

import (
	"encoding/json"
	"regexp"
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

type systemInformationResponse struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	Updates  string   `json:"updates"`
}

// FetchSystemHostname returns the hostname the OPNsense firewall reports for
// itself (the "name" field of api/diagnostics/system/system_information, e.g.
// "opnsense.example.com"). It is used to derive a default instance label when
// the user does not set one explicitly.
func (c *Client) FetchSystemHostname() (string, *APICallError) {
	var resp systemInformationResponse

	url, ok := c.endpoints["systemInformation"]
	if !ok {
		return "", &APICallError{
			Endpoint:   "systemInformation",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return "", err
	}

	return resp.Name, nil
}

// Public data structs.

type SystemMemory struct {
	// Available is true only when the systemResources sub-call succeeded. Total
	// and Used come solely from that call, so the collector gates them on this to
	// avoid emitting a fabricated 0 (which breaks used/total ratio panels) on a
	// partial fetch (#91).
	Available bool
	Total     int64
	Used      int64
	Arc       int64
	HasArc    bool
}

type SystemTime struct {
	// Available is true only when the systemTime sub-call succeeded. Uptime and
	// LoadAverage come solely from that call; the collector gates them on this so
	// a partial fetch does not emit uptime=0 (reads as a host reboot) (#91).
	Available        bool
	Uptime           float64
	LoadAverage      [3]float64
	ConfigLastChange float64

	// BootTimestamp is the absolute Unix instant the box booted, resolved from
	// boottime's own zone abbreviation exactly as ConfigLastChange is. It exists
	// because a query-time `time() - uptime` is not stable enough to anchor a
	// dashboard annotation: it is recomputed on every evaluation and drifts by a
	// second or more between them (#421). Zero when boottime was unparseable.
	BootTimestamp float64
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

type SystemInfo struct {
	Hostname        string
	OPNsenseVersion string
	FreeBSDVersion  string
	OpenSSLVersion  string
	CPUModel        string
	CPUCores        string
	CPUThreads      string
}

type SystemResources struct {
	Memory SystemMemory
	Time   SystemTime
	Disks  []SystemDisk
	Swaps  []SystemSwap
	Info   *SystemInfo
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

// dstAbbrevOffset maps the timezone abbreviations OPNsense commonly renders (via
// PHP's date('T', ts), i.e. the abbreviation in effect at each timestamp) to
// their real UTC offset in seconds. It is used only to correct the difference
// between two of the box's timestamps when they carry DIFFERENT abbreviations —
// the signature of a DST transition between them. When the abbreviations match,
// their offsets cancel and no correction is applied, so non-DST zones (and any
// abbreviation absent from this table) are unaffected and keep the pre-#107
// behaviour. Ambiguous abbreviations (e.g. IST, CST elsewhere) are intentionally
// limited to the DST-observing zones where the pairing is unambiguous within a
// single box.
var dstAbbrevOffset = map[string]int{
	"UTC": 0, "GMT": 0, "WET": 0,
	"BST": 3600, "WEST": 3600, "CET": 3600, "MET": 3600,
	"CEST": 7200, "MEST": 7200, "EET": 7200,
	"EEST": 10800,
	"EST":  -18000, "EDT": -14400,
	"CST": -21600, "CDT": -18000,
	"MST": -25200, "MDT": -21600,
	"PST": -28800, "PDT": -25200,
}

// absUnixFromAbbrev returns the true Unix instant of a timestamp parsed from an
// OPNsense abbreviation-only string, recovering the real offset from
// dstAbbrevOffset. It returns ok=false when the parse failed or the abbreviation
// is not in the table (so the caller can fall back). Correct under any exporter
// TZ: it adjusts relative to whatever offset time.Parse actually assigned (#107).
func absUnixFromAbbrev(t time.Time, parseErr error) (int64, bool) {
	if parseErr != nil {
		return 0, false
	}
	name, assigned := t.Zone()
	real, ok := dstAbbrevOffset[name]
	if !ok {
		return 0, false
	}
	// t.Unix() = wall - assigned; true = wall - real.
	return t.Unix() - int64(real-assigned), true
}

// dstCorrectedDiffSeconds returns (later - earlier) in seconds, correcting for a
// DST transition between the two timestamps. OPNsense renders each timestamp with
// only a zone abbreviation, not a numeric offset; time.Parse can only resolve
// that to a real offset when the exporter's own TZ matches the box's zone. So a
// boottime rendered "GMT" and a datetime rendered "BST" (a box booted before a
// spring-forward and scraped after it) are otherwise both parsed at a zero offset
// under the common container TZ=UTC, overstating the difference by the DST delta.
// We recover the real offset each timestamp should carry from dstAbbrevOffset and
// subtract the residual delta relative to whatever offset time.Parse actually
// assigned — so the result is correct under TZ=UTC and unchanged when the
// exporter TZ already resolved the abbreviations. Unknown abbreviations fall back
// to the raw difference (#107).
func dstCorrectedDiffSeconds(later, earlier time.Time) float64 {
	raw := later.Sub(earlier).Seconds()
	lName, lAssigned := later.Zone()
	eName, eAssigned := earlier.Zone()
	lReal, lok := dstAbbrevOffset[lName]
	eReal, eok := dstAbbrevOffset[eName]
	if !lok || !eok {
		return raw
	}
	// true = (laterWall - lReal) - (earlierWall - eReal); time.Sub gives
	// (laterWall - lAssigned) - (earlierWall - eAssigned) as instants.
	return raw - float64((lReal-lAssigned)-(eReal-eAssigned))
}

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

	data.Memory.Available = true
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
	data.Time.Available = true

	// OPNsense renders these timestamps with only a timezone abbreviation
	// (PHP date('T', ts) — the abbreviation in effect AT each timestamp), not a
	// numeric offset. time.Parse can only resolve an abbreviation to a real UTC
	// offset when the exporter's own TZ matches the box's zone; under the common
	// container TZ=UTC it fabricates a zero-offset zone. When boottime and
	// datetime (or config) straddle a DST transition they carry DIFFERENT
	// abbreviations (e.g. "GMT" vs "BST"), so a naive difference is skewed by the
	// DST delta (~3600s). dstCorrectedDiffSeconds recovers each timestamp's real
	// offset from its abbreviation and cancels that delta; when abbreviations
	// match (same DST period) or are unknown it degrades to the raw difference.
	// Residual caveat: for a box in an unlisted/ambiguous zone scraped across a
	// DST boundary, up to a ±1h skew can remain (#107).
	now := time.Now()
	bootTime, errBoot := time.Parse(opnsenseTimeFormat, resp.Boottime)
	dateTime, errDate := time.Parse(opnsenseTimeFormat, resp.Datetime)
	configTime, errConfig := time.Parse(opnsenseTimeFormat, resp.Config)

	// Uptime: datetime - boottime, corrected for any DST transition between them.
	// Fall back to comparing boottime against the exporter clock if datetime is
	// unavailable.
	switch {
	case errDate == nil && errBoot == nil:
		data.Time.Uptime = dstCorrectedDiffSeconds(dateTime, bootTime)
	case errBoot == nil:
		data.Time.Uptime = time.Since(bootTime).Seconds()
	}

	// Boot instant: same resolution ladder as ConfigLastChange below. Prefer
	// boottime's own abbreviation (exporter-clock independent); otherwise anchor
	// the DST-corrected uptime to the exporter clock, which cancels the box's base
	// offset; only fall back to the raw parse when there is nothing else, since
	// that one carries the full unresolved-offset error (#421).
	if abs, ok := absUnixFromAbbrev(bootTime, errBoot); ok {
		data.Time.BootTimestamp = float64(abs)
	} else {
		switch {
		case errDate == nil && errBoot == nil:
			age := time.Duration(dstCorrectedDiffSeconds(dateTime, bootTime)) * time.Second
			data.Time.BootTimestamp = float64(now.Add(-age).Unix())
		case errBoot == nil:
			data.Time.BootTimestamp = float64(bootTime.Unix())
		}
	}

	// Config last change: prefer the absolute instant recovered from config's own
	// abbreviation (DST-correct and independent of the exporter clock). When the
	// abbreviation is unknown, fall back to the DST-corrected age anchored to the
	// exporter clock, which cancels the box's base offset.
	if abs, ok := absUnixFromAbbrev(configTime, errConfig); ok {
		data.Time.ConfigLastChange = float64(abs)
	} else {
		switch {
		case errDate == nil && errConfig == nil:
			age := time.Duration(dstCorrectedDiffSeconds(dateTime, configTime)) * time.Second
			data.Time.ConfigLastChange = float64(now.Add(-age).Unix())
		case errConfig == nil:
			data.Time.ConfigLastChange = float64(configTime.Unix())
		}
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

var cpuCoresThreadsRegex = regexp.MustCompile(`\((\d+) cores?, (\d+) threads?\)`)

func (c *Client) fetchSystemInfo(data *SystemResources) *APICallError {
	var resp systemInformationResponse

	url, ok := c.endpoints["systemInformation"]
	if !ok {
		return &APICallError{
			Endpoint:   "systemInformation",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	if data.Info == nil {
		data.Info = &SystemInfo{}
	}

	data.Info.Hostname = resp.Name

	if len(resp.Versions) > 0 {
		data.Info.OPNsenseVersion = strings.TrimPrefix(resp.Versions[0], "OPNsense ")
	}
	if len(resp.Versions) > 1 {
		data.Info.FreeBSDVersion = strings.TrimPrefix(resp.Versions[1], "FreeBSD ")
	}
	if len(resp.Versions) > 2 {
		data.Info.OpenSSLVersion = strings.TrimPrefix(resp.Versions[2], "OpenSSL ")
	}

	return nil
}

func (c *Client) fetchCPUType(data *SystemResources) *APICallError {
	var resp []string

	url, ok := c.endpoints["cpuType"]
	if !ok {
		return &APICallError{
			Endpoint:   "cpuType",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return err
	}

	if data.Info == nil {
		data.Info = &SystemInfo{}
	}

	if len(resp) > 0 {
		raw := resp[0]

		// Extract CPU model by trimming from " (" onwards
		if before, _, found := strings.Cut(raw, " ("); found {
			data.Info.CPUModel = before
		} else {
			data.Info.CPUModel = raw
		}

		// Extract cores and threads using regex
		matches := cpuCoresThreadsRegex.FindStringSubmatch(raw)
		if len(matches) == 3 {
			data.Info.CPUCores = matches[1]
			data.Info.CPUThreads = matches[2]
		}
	}

	return nil
}

// FetchSystemResources calls 6 OPNsense endpoints to gather system resource data.
// It tolerates partial failure: if some calls fail but others succeed, it logs warnings
// and returns partial data. It only returns an error if all calls fail.
func (c *Client) FetchSystemResources() (SystemResources, *APICallError) {
	var data SystemResources

	type fetchResult struct {
		name string
		err  *APICallError
	}

	// The six sub-fetches hit independent endpoints and write disjoint fields of data
	// (Memory / Times / Disks / Swaps / Info / CPUType), so run them concurrently —
	// wall time is bounded by the slowest single call, not the sum (#129). fetchSystemInfo
	// and fetchCPUType both populate data.Info, so pre-allocate it here (single-threaded)
	// to avoid a lazy-init race; they then write disjoint FIELDS of the shared struct.
	data.Info = &SystemInfo{}
	names := []string{"systemResources", "systemTime", "systemDisk", "systemSwap", "systemInformation", "cpuType"}
	errs := runConcurrentFetches(
		func() *APICallError { return c.fetchSystemMemory(&data) },
		func() *APICallError { return c.fetchSystemTime(&data) },
		func() *APICallError { return c.fetchSystemDisk(&data) },
		func() *APICallError { return c.fetchSystemSwap(&data) },
		func() *APICallError { return c.fetchSystemInfo(&data) },
		func() *APICallError { return c.fetchCPUType(&data) },
	)
	results := make([]fetchResult, len(names))
	for i, name := range names {
		results[i] = fetchResult{name, errs[i]}
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
