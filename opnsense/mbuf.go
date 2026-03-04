package opnsense

type mbufStatisticsData struct {
	MbufCurrent    int `json:"mbuf-current"`
	MbufCache      int `json:"mbuf-cache"`
	MbufTotal      int `json:"mbuf-total"`
	MbufMax        int `json:"mbuf-max"`
	ClusterCurrent int `json:"cluster-current"`
	ClusterCache   int `json:"cluster-cache"`
	ClusterTotal   int `json:"cluster-total"`
	ClusterMax     int `json:"cluster-max"`
	MbufFails      int `json:"mbuf-failures"`
	ClusterFails   int `json:"cluster-failures"`
	PacketFails    int `json:"packet-failures"`
	MbufSleeps     int `json:"mbuf-sleeps"`
	ClusterSleeps  int `json:"cluster-sleeps"`
	PacketSleeps   int `json:"packet-sleeps"`
	JumbopCurrent  int `json:"jumbop-current"`
	JumbopCache    int `json:"jumbop-cache"`
	JumbopTotal    int `json:"jumbop-total"`
	JumbopMax      int `json:"jumbop-max"`
	JumbopFails    int `json:"jumbop-failures"`
	JumbopSleeps   int `json:"jumbop-sleeps"`
	BytesInUse     int `json:"bytes-in-use"`
	BytesTotal     int `json:"bytes-total"`
	BytesPercent   int `json:"percentage"`
	MbufAndCluster int `json:"mbuf-and-cluster"`
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
	MbufCurrent       int
	MbufCache         int
	MbufTotal         int
	ClusterCurrent    int
	ClusterCache      int
	ClusterTotal      int
	ClusterMax        int
	BytesInUse        int
	BytesTotal        int
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
	data.BytesInUse = s.BytesInUse
	data.BytesTotal = s.BytesTotal

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

	// Fetch additional memory statistics (partial failure tolerant)
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
