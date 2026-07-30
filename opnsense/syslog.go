package opnsense

import "strings"

// syslogTargetStateVocabulary is syslog-ng's own closed state vocabulary for
// a stats counter group (single-char codes on the wire; verified against
// upstream syslog-ng documentation/source, not yet observed with anything
// but "a" on a live OPNsense box): "a" active -- the object is currently
// alive and receiving stat updates; "d" dynamic -- a runtime-created object
// (e.g. one keyed on a sender's hostname) that may cease to exist; "o"
// orphaned -- the underlying config element was removed (e.g. after a
// reload) but its last-known counters are retained. An orphaned or
// no-longer-dynamic target is exactly the "counters stopped moving" stall
// this field exists to surface -- byte/message counters alone cannot
// distinguish that from an idle-but-healthy active target.
var syslogTargetStateVocabulary = map[string]string{
	"a": "active",
	"d": "dynamic",
	"o": "orphaned",
}

// canonicalizeSyslogTargetState maps a raw syslog-ng state code onto the
// closed vocabulary above. Anything else -- an empty field, a future
// syslog-ng state, or a value from the wrong key -- collapses to "unknown"
// so this label is never emitted empty and never carries a free-form value.
func canonicalizeSyslogTargetState(raw string) string {
	if s, ok := syslogTargetStateVocabulary[strings.ToLower(strings.TrimSpace(raw))]; ok {
		return s
	}
	return "unknown"
}

// syslogStatRow mirrors api/syslog/service/stats bootgrid rows.
// Field names confirmed against a live OPNsense 26.1 box: capitalised keys,
// Number arrives as a string.
type syslogStatRow struct {
	Description    string `json:"Description"`
	SourceName     string `json:"SourceName"`
	SourceID       string `json:"SourceId"`
	SourceInstance string `json:"SourceInstance"`
	State          string `json:"State"`
	Type           string `json:"Type"`
	Number         string `json:"Number"`
}

type syslogStatsResponse struct {
	Total    int             `json:"total"`
	RowCount int             `json:"rowCount"`
	Current  int             `json:"current"`
	Rows     []syslogStatRow `json:"rows"`
}

// SyslogStat is one normalised syslog-ng statistic.
type SyslogStat struct {
	SourceName     string
	SourceID       string
	SourceInstance string
	Type           string
	Value          float64
}

// SyslogTargetState is the canonicalized lifecycle state of one syslog-ng
// source/target object (#557) -- a remote target whose byte/message counters
// have stopped moving is otherwise indistinguishable from an idle-but-fine
// target, since only the raw counters were exported before this.
type SyslogTargetState struct {
	SourceName     string
	SourceID       string
	SourceInstance string
	// State is canonicalizeSyslogTargetState's output: active/dynamic/
	// orphaned/unknown. Never empty.
	State string
}

// SyslogStats holds the result of FetchSyslogStats.
type SyslogStats struct {
	Stats []SyslogStat
	Total int
	// TargetStates is one entry per distinct (SourceName, SourceID,
	// SourceInstance) triple seen in the response, deduplicated across the
	// several counter rows (processed/dropped/written/...) each real target
	// produces -- they all share one State at a given scrape, so the first
	// row for a target decides it.
	TargetStates []SyslogTargetState
}

// FetchSyslogStats returns the syslog-ng statistics grid. Rows of Type
// "stamp" (unix timestamp of the stats epoch, not a statistic) are skipped.
func (c *Client) FetchSyslogStats() (SyslogStats, *APICallError) {
	var resp syslogStatsResponse
	var data SyslogStats

	url, ok := c.endpoints["syslogStats"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "syslogStats",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", url, nil, &resp); err != nil {
		return data, err
	}

	type targetKey struct {
		name     string
		id       string
		instance string
	}
	seenTargets := map[targetKey]bool{}

	data.Total = resp.Total
	for _, row := range resp.Rows {
		key := targetKey{row.SourceName, row.SourceID, row.SourceInstance}
		if !seenTargets[key] {
			seenTargets[key] = true
			data.TargetStates = append(data.TargetStates, SyslogTargetState{
				SourceName:     row.SourceName,
				SourceID:       row.SourceID,
				SourceInstance: row.SourceInstance,
				State:          canonicalizeSyslogTargetState(row.State),
			})
		}

		if row.Type == "stamp" {
			continue
		}
		data.Stats = append(data.Stats, SyslogStat{
			SourceName:     row.SourceName,
			SourceID:       row.SourceID,
			SourceInstance: row.SourceInstance,
			Type:           row.Type,
			Value:          safeParseFloat(row.Number),
		})
	}
	return data, nil
}
