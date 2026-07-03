package opnsense

type mbufStatisticsData struct {
	MbufCurrent    int   `json:"mbuf-current"`
	MbufCache      int   `json:"mbuf-cache"`
	MbufTotal      int   `json:"mbuf-total"`
	MbufMax        int   `json:"mbuf-max"`
	ClusterCurrent int   `json:"cluster-current"`
	ClusterCache   int   `json:"cluster-cache"`
	ClusterTotal   int   `json:"cluster-total"`
	ClusterMax     int   `json:"cluster-max"`
	MbufFails      int   `json:"mbuf-failures"`
	ClusterFails   int   `json:"cluster-failures"`
	PacketFails    int   `json:"packet-failures"`
	MbufSleeps     int   `json:"mbuf-sleeps"`
	ClusterSleeps  int   `json:"cluster-sleeps"`
	PacketSleeps   int   `json:"packet-sleeps"`
	JumbopCurrent  int   `json:"jumbop-current"`
	JumbopCache    int   `json:"jumbop-cache"`
	JumbopTotal    int   `json:"jumbop-total"`
	JumbopMax      int   `json:"jumbop-max"`
	JumbopFails    int   `json:"jumbop-failures"`
	JumbopSleeps   int   `json:"jumbop-sleeps"`
	BytesInUse     int64 `json:"bytes-in-use"`
	BytesTotal     int64 `json:"bytes-total"`
	BytesPercent   int   `json:"percentage"`
	MbufAndCluster int   `json:"mbuf-and-cluster"`
	// Extended fields present in systemMbuf on OPNsense 26.1+ (both endpoints wrap the
	// same `netstat -m` output). Pointers so a nil distinguishes "key absent" (older
	// release) from "present with value 0", which decides whether the redundant
	// memoryStatistics call is needed (#137).
	Jumbo9Failures    *int `json:"jumbo9-failures"`
	Jumbo16Failures   *int `json:"jumbo16-failures"`
	Jumbo9Sleeps      *int `json:"jumbo9-sleeps"`
	Jumbo16Sleeps     *int `json:"jumbo16-sleeps"`
	SendfileSyscalls  *int `json:"sendfile-syscalls"`
	SendfileIOCount   *int `json:"sendfile-io-count"`
	SendfilePagesSent *int `json:"sendfile-pages-sent"`
}

type mbufResponse struct {
	MbufStatistics mbufStatisticsData `json:"mbuf-statistics"`
}

type memoryStatisticsData struct {
	Jumbo9Failures    int `json:"jumbo9-failures"`
	Jumbo16Failures   int `json:"jumbo16-failures"`
	Jumbo9Sleeps      int `json:"jumbo9-sleeps"`
	Jumbo16Sleeps     int `json:"jumbo16-sleeps"`
	SendfileSyscalls  int `json:"sendfile-syscalls"`
	SendfileIOCount   int `json:"sendfile-io-count"`
	SendfilePagesSent int `json:"sendfile-pages-sent"`
}

type memoryStatisticsResponse struct {
	MbufStatistics memoryStatisticsData `json:"mbuf-statistics"`
}

type MbufStatistics struct {
	MbufCurrent    int
	MbufCache      int
	MbufTotal      int
	ClusterCurrent int
	ClusterCache   int
	ClusterTotal   int
	ClusterMax     int
	// int64: byte totals ×1024 can exceed 2^31 on large-memory boxes (#103).
	BytesInUse        int64
	BytesTotal        int64
	FailuresByType    map[string]int
	SleepsByType      map[string]int
	SendfileSyscalls  int
	SendfileIOCount   int
	SendfilePagesSent int
}

func (c *Client) FetchMbufStatistics() (MbufStatistics, *APICallError) {
	var resp mbufResponse
	var data MbufStatistics

	url, ok := c.endpoints["systemMbuf"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "systemMbuf",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	s := resp.MbufStatistics

	data.MbufCurrent = s.MbufCurrent
	data.MbufCache = s.MbufCache
	data.MbufTotal = s.MbufTotal
	data.ClusterCurrent = s.ClusterCurrent
	data.ClusterCache = s.ClusterCache
	data.ClusterTotal = s.ClusterTotal
	data.ClusterMax = s.ClusterMax
	// OPNsense sources these from netstat -m, which reports the mbuf memory
	// pool in KILOBYTES. The exporter's bytes_in_use / bytes_total metrics are
	// declared in bytes, so convert here.
	data.BytesInUse = s.BytesInUse * 1024
	data.BytesTotal = s.BytesTotal * 1024

	data.FailuresByType = map[string]int{
		"mbuf":    s.MbufFails,
		"cluster": s.ClusterFails,
		"packet":  s.PacketFails,
		"jumbop":  s.JumbopFails,
	}

	data.SleepsByType = map[string]int{
		"mbuf":    s.MbufSleeps,
		"cluster": s.ClusterSleeps,
		"packet":  s.PacketSleeps,
		"jumbop":  s.JumbopSleeps,
	}

	// On OPNsense 26.1+ the jumbo9/jumbo16/sendfile keys are already in the systemMbuf
	// response, so read them from there and skip the redundant memoryStatistics
	// round-trip entirely (#137). A nil pointer means the key was absent (older release).
	if s.Jumbo9Failures != nil || s.SendfileSyscalls != nil {
		data.FailuresByType["jumbo9"] = derefInt(s.Jumbo9Failures)
		data.FailuresByType["jumbo16"] = derefInt(s.Jumbo16Failures)
		data.SleepsByType["jumbo9"] = derefInt(s.Jumbo9Sleeps)
		data.SleepsByType["jumbo16"] = derefInt(s.Jumbo16Sleeps)
		data.SendfileSyscalls = derefInt(s.SendfileSyscalls)
		data.SendfileIOCount = derefInt(s.SendfileIOCount)
		data.SendfilePagesSent = derefInt(s.SendfilePagesSent)
		return data, nil
	}

	// Fallback for older releases whose systemMbuf lacks the extended keys: fetch them
	// from the separate memoryStatistics endpoint (partial-failure tolerant).
	var memResp memoryStatisticsResponse
	memURL, ok := c.endpoints["memoryStatistics"]
	if ok {
		if memErr := c.do("GET", memURL, nil, &memResp); memErr != nil {
			c.log.Warn("memory statistics sub-call failed",
				"endpoint", "memoryStatistics",
				"error", memErr.Error(),
			)
		} else {
			ms := memResp.MbufStatistics
			data.FailuresByType["jumbo9"] = ms.Jumbo9Failures
			data.FailuresByType["jumbo16"] = ms.Jumbo16Failures
			data.SleepsByType["jumbo9"] = ms.Jumbo9Sleeps
			data.SleepsByType["jumbo16"] = ms.Jumbo16Sleeps
			data.SendfileSyscalls = ms.SendfileSyscalls
			data.SendfileIOCount = ms.SendfileIOCount
			data.SendfilePagesSent = ms.SendfilePagesSent
		}
	}

	return data, nil
}

// derefInt returns the pointed-to int, or 0 when the pointer is nil (JSON key absent).
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
