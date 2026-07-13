package opnsense

// mbufStatisticsData is the `mbuf-statistics` object returned by BOTH systemMbuf and
// memoryStatistics (they wrap the same `netstat -m` output). OPNsense modernised that
// payload in 26.1.11: several keys were renamed and a few dropped, while older 26.1.x /
// 25.7 boxes still send the original names. Every legacy key is therefore kept and
// resolved new-wins-else-legacy at read time — never branch on a version number.
type mbufStatisticsData struct {
	MbufCurrent int `json:"mbuf-current"`
	MbufCache   int `json:"mbuf-cache"`
	MbufTotal   int `json:"mbuf-total"`
	// ≤26.1.x only: removed upstream, reads zero on ≥26.1.11 (unused by any metric).
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
	// Jumbo-page pool, legacy names. ≤26.1.x only: replaced on ≥26.1.11 by
	// jumbo-count / jumbo-cache / jumbo-total / jumbo-max below. Resolved by
	// jumboPage*(); pointers so nil == "key absent" rather than "present and zero".
	JumbopCurrent *int `json:"jumbop-current"`
	JumbopCache   *int `json:"jumbop-cache"`
	JumbopTotal   *int `json:"jumbop-total"`
	JumbopMax     *int `json:"jumbop-max"`
	// NOT renamed — jumbop-failures / jumbop-sleeps keep their names on ≥26.1.11.
	JumbopFails  int `json:"jumbop-failures"`
	JumbopSleeps int `json:"jumbop-sleeps"`
	// Jumbo-page pool, ≥26.1.11 names. Nil on older releases, where the jumbop-*
	// fields above carry the same values.
	JumboCount *int `json:"jumbo-count"`
	JumboCache *int `json:"jumbo-cache"`
	JumboTotal *int `json:"jumbo-total"`
	JumboMax   *int `json:"jumbo-max"`

	BytesInUse int64 `json:"bytes-in-use"`
	BytesTotal int64 `json:"bytes-total"`
	// ≤26.1.x only: removed upstream, reads zero on ≥26.1.11 (unused by any metric).
	BytesPercent int `json:"percentage"`
	// ≤26.1.x only: removed upstream, reads zero on ≥26.1.11 (unused by any metric).
	MbufAndCluster int `json:"mbuf-and-cluster"`
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

	// Sfbufs allocation-pressure counters, present alongside the jumbo9/16/sendfile
	// keys above on OPNsense 26.1.11+ (#237). Pointers so nil distinguishes "key
	// absent" (older release) from "present with value 0" — same convention as the
	// jumbo9/jumbo16/sendfile fields.
	SfbufsAllocFailed *int `json:"sfbufs-alloc-failed"`
	SfbufsAllocWait   *int `json:"sfbufs-alloc-wait"`
}

// jumboPageCurrent resolves the jumbo-page pool's in-use count across the 26.1.11
// rename: the new jumbo-count key wins when the box sends it, else the legacy
// jumbop-current. Zero when neither is present.
func (s mbufStatisticsData) jumboPageCurrent() int {
	return firstPresentInt(s.JumboCount, s.JumbopCurrent)
}

// jumboPageCache resolves jumbo-cache (≥26.1.11) else jumbop-cache (≤26.1.x).
func (s mbufStatisticsData) jumboPageCache() int {
	return firstPresentInt(s.JumboCache, s.JumbopCache)
}

// jumboPageTotal resolves jumbo-total (≥26.1.11) else jumbop-total (≤26.1.x).
func (s mbufStatisticsData) jumboPageTotal() int {
	return firstPresentInt(s.JumboTotal, s.JumbopTotal)
}

// jumboPageMax resolves jumbo-max (≥26.1.11) else jumbop-max (≤26.1.x).
func (s mbufStatisticsData) jumboPageMax() int {
	return firstPresentInt(s.JumboMax, s.JumbopMax)
}

// firstPresentInt returns the first non-nil pointer's value, or 0 when all are nil
// (i.e. none of the candidate JSON keys was sent).
func firstPresentInt(candidates ...*int) int {
	for _, c := range candidates {
		if c != nil {
			return *c
		}
	}
	return 0
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
	// Jumbo-page pool, already resolved across the 26.1.11 key rename (jumbop-* on
	// ≤26.1.x, jumbo-* on ≥26.1.11) — callers never see the two spellings.
	JumboPageCurrent int
	JumboPageCache   int
	JumboPageTotal   int
	JumboPageMax     int
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
	data.JumboPageCurrent = s.jumboPageCurrent()
	data.JumboPageCache = s.jumboPageCache()
	data.JumboPageTotal = s.jumboPageTotal()
	data.JumboPageMax = s.jumboPageMax()
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

		// Sfbufs allocation-pressure counters (26.1.11+, #237): gated separately
		// since they landed slightly after the jumbo9/jumbo16/sendfile keys above —
		// a nil pointer here means an older release within this same branch.
		if s.SfbufsAllocFailed != nil || s.SfbufsAllocWait != nil {
			data.FailuresByType["sfbufs"] = derefInt(s.SfbufsAllocFailed)
			data.SleepsByType["sfbufs"] = derefInt(s.SfbufsAllocWait)
		}

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
