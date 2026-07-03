package opnsense

import (
	"net/http"
	"strconv"
	"strings"
)

// ChronyTracking holds the parsed output of `chronyc tracking`.
// VERIFICATION: unvalidated against a live chrony box — shape derived from
// net/chrony/.../Api/ServiceController.php which returns
// {"response": "<raw chronyc text>"}. Pool-rotation note: with a `pool`
// directive chrony rotates the resolved servers over time, so the source
// label set churns — bounded by pool size; dashboards should use instant
// queries/tables rather than long-range per-source rates.
type ChronyTracking struct {
	Valid                   bool
	ReferenceID             string
	ReferenceName           string
	LeapStatus              string
	LeapStatusValue         float64 // 0=Normal,1=Insert,2=Delete,3=Not synchronised
	Stratum                 float64
	SystemTimeOffsetSeconds float64 // fast=+, slow=−
	LastOffsetSeconds       float64
	RMSOffsetSeconds        float64
	FrequencyPPM            float64
	ResidualFrequencyPPM    float64
	SkewPPM                 float64
	RootDelaySeconds        float64
	RootDispersionSeconds   float64
	UpdateIntervalSeconds   float64
}

// ChronySource holds one row of `chronyc sources` output.
type ChronySource struct {
	Mode          string // ^ = server, = = peer, # = refclock
	State         string // * + - ? x ~
	Name          string
	Stratum       float64
	Reachability  float64 // 0–255 (octal register parsed to decimal)
	LastRxSeconds float64
	HasLastRx     bool
	OffsetSeconds float64
	HasOffset     bool
}

// ChronySourceStats holds one row of `chronyc sourcestats` output.
type ChronySourceStats struct {
	Name          string
	Samples       float64
	StdDevSeconds float64
	HasStdDev     bool
}

// ChronyStatus is the normalised result returned by FetchChronyStatus.
type ChronyStatus struct {
	Present bool
	// HasSources/HasSourceStats are true only when the respective sub-fetch
	// succeeded, so the collector can distinguish "fetch failed" from "genuinely
	// zero sources" and skip emitting a false sources_total=0 (#163).
	HasSources     bool
	HasSourceStats bool
	Tracking       ChronyTracking
	Sources        []ChronySource
	SourceStats    []ChronySourceStats
}

// chronyResponseEnvelope matches the {"response": "<raw text>"} wrapper that
// every api/chrony/service/* endpoint returns.
type chronyResponseEnvelope struct {
	Response flexString `json:"response"`
}

// parseChronyDuration converts chronyc's compact unit values (+123us, -45ns,
// 12ms, 1.5s) to seconds. Returns (0, false) for non-numeric values like "-".
func parseChronyDuration(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "ns"):
		mult, s = 1e-9, strings.TrimSuffix(s, "ns")
	case strings.HasSuffix(s, "us"):
		mult, s = 1e-6, strings.TrimSuffix(s, "us")
	case strings.HasSuffix(s, "ms"):
		mult, s = 1e-3, strings.TrimSuffix(s, "ms")
	case strings.HasSuffix(s, "s"):
		s = strings.TrimSuffix(s, "s")
	default:
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimPrefix(s, "+"), 64)
	if err != nil {
		return 0, false
	}
	return v * mult, true
}

// parseChronyInterval converts chronyc LastRx/Span values (34, 10m, 2h, 1d)
// to seconds.
func parseChronyInterval(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "m"):
		mult, s = 60, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "h"):
		mult, s = 3600, strings.TrimSuffix(s, "h")
	case strings.HasSuffix(s, "d"):
		mult, s = 86400, strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "y"):
		mult, s = 31557600, strings.TrimSuffix(s, "y")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v * mult, true
}

// parseChronyTracking parses `chronyc tracking` output. Unknown lines are
// ignored; missing fields leave zero values with Has=false flags where needed.
func parseChronyTracking(raw string) ChronyTracking {
	t := ChronyTracking{LeapStatusValue: 3} // default: not synchronised
	for _, line := range strings.Split(raw, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		fields := strings.Fields(value)
		first := ""
		if len(fields) > 0 {
			first = fields[0]
		}
		switch key {
		case "Reference ID":
			t.ReferenceID = first
			if i, j := strings.Index(value, "("), strings.Index(value, ")"); i >= 0 && j > i {
				t.ReferenceName = value[i+1 : j]
			}
		case "Stratum":
			t.Stratum = safeParseFloat(first)
		case "System time":
			v := safeParseFloat(first)
			if strings.Contains(value, "slow") {
				v = -v
			}
			t.SystemTimeOffsetSeconds = v
		case "Last offset":
			t.LastOffsetSeconds = safeParseFloat(first)
		case "RMS offset":
			t.RMSOffsetSeconds = safeParseFloat(first)
		case "Frequency":
			v := safeParseFloat(first)
			if strings.Contains(value, "slow") {
				v = -v
			}
			t.FrequencyPPM = v
		case "Residual freq":
			t.ResidualFrequencyPPM = safeParseFloat(strings.TrimPrefix(first, "+"))
		case "Skew":
			t.SkewPPM = safeParseFloat(first)
		case "Root delay":
			t.RootDelaySeconds = safeParseFloat(first)
		case "Root dispersion":
			t.RootDispersionSeconds = safeParseFloat(first)
		case "Update interval":
			t.UpdateIntervalSeconds = safeParseFloat(first)
		case "Leap status":
			t.LeapStatus = value
			switch value {
			case "Normal":
				t.LeapStatusValue = 0
			case "Insert second":
				t.LeapStatusValue = 1
			case "Delete second":
				t.LeapStatusValue = 2
			default:
				t.LeapStatusValue = 3
			}
		}
	}
	t.Valid = t.ReferenceID != ""
	return t
}

// parseChronySources parses `chronyc sources` table rows
// ("^* name  2 6 377 34  +123us[+145us] +/- 12ms").
// Mode chars: ^ = server, = = peer, # = refclock.
// State chars: * + - ? x ~
func parseChronySources(raw string) []ChronySource {
	var out []ChronySource
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || len(f[0]) != 2 || strings.HasPrefix(line, "MS") || strings.HasPrefix(line, "==") {
			continue
		}
		src := ChronySource{
			Mode:    string(f[0][0]), // ^ = server, = = peer, # = refclock
			State:   string(f[0][1]), // * + - ? x ~
			Name:    f[1],
			Stratum: safeParseFloat(f[2]),
		}
		if r, err := strconv.ParseUint(f[4], 8, 16); err == nil {
			src.Reachability = float64(r)
		}
		if v, ok := parseChronyInterval(f[5]); ok {
			src.LastRxSeconds, src.HasLastRx = v, true
		}
		// f[6] is "+123us[" or "+123us[+145us]" depending on spacing — strip at '['
		offsetTok := f[6]
		if i := strings.Index(offsetTok, "["); i >= 0 {
			offsetTok = offsetTok[:i]
		}
		if v, ok := parseChronyDuration(offsetTok); ok {
			src.OffsetSeconds, src.HasOffset = v, true
		}
		out = append(out, src)
	}
	return out
}

// parseChronySourceStats parses `chronyc sourcestats` rows
// ("name  25 12 19m  -0.002  0.060  -45us  113us").
func parseChronySourceStats(raw string) []ChronySourceStats {
	var out []ChronySourceStats
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) != 8 || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "==") {
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			continue // header or garbage
		}
		st := ChronySourceStats{Name: f[0], Samples: safeParseFloat(f[1])}
		if v, ok := parseChronyDuration(f[7]); ok {
			st.StdDevSeconds, st.HasStdDev = v, true
		}
		out = append(out, st)
	}
	return out
}

// FetchChronyStatus fetches chrony tracking, sources, and sourcestats from the
// OPNsense API. A 404 on the tracking endpoint means the chrony plugin is
// absent; Present is set to false and nil is returned. Failures on sources or
// sourcestats are tolerated with a warn-log (partial data kept).
func (c *Client) FetchChronyStatus() (ChronyStatus, *APICallError) {
	var trackingEnv chronyResponseEnvelope
	trackingURL, ok := c.endpoints["chronyTracking"]
	if !ok {
		return ChronyStatus{}, &APICallError{
			Endpoint:   "chronyTracking",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", trackingURL, nil, &trackingEnv); err != nil {
		if err.StatusCode == http.StatusNotFound {
			// Plugin absent.
			return ChronyStatus{Present: false}, nil
		}
		return ChronyStatus{}, err
	}

	status := ChronyStatus{
		Present:  true,
		Tracking: parseChronyTracking(trackingEnv.Response.String()),
	}

	// Sources and SourceStats hit independent endpoints and write disjoint fields of
	// status, so fetch them concurrently (the tracking call above gated Present and must
	// stay first). Both tolerate failure and keep partial data (#129).
	sourcesURL, hasSources := c.endpoints["chronySources"]
	sourceStatsURL, hasSourceStats := c.endpoints["chronySourceStats"]
	runConcurrentFetches(
		func() *APICallError {
			if !hasSources {
				return nil
			}
			var sourcesEnv chronyResponseEnvelope
			if err := c.do("GET", sourcesURL, nil, &sourcesEnv); err != nil {
				c.log.Warn("failed to fetch chrony sources", "err", err)
				return nil // tolerated
			}
			status.Sources = parseChronySources(sourcesEnv.Response.String())
			status.HasSources = true
			return nil
		},
		func() *APICallError {
			if !hasSourceStats {
				return nil
			}
			var statsEnv chronyResponseEnvelope
			if err := c.do("GET", sourceStatsURL, nil, &statsEnv); err != nil {
				c.log.Warn("failed to fetch chrony sourcestats", "err", err)
				return nil // tolerated
			}
			status.SourceStats = parseChronySourceStats(statsEnv.Response.String())
			status.HasSourceStats = true
			return nil
		},
	)

	return status, nil
}
