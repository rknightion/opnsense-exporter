package syslog

import (
	"strings"
)

// Filtering exists because a firewall at debug level is genuinely loud — radvd logs
// a timer tick every two minutes and says nothing, HAProxy logs every request — and
// some people pay per GB of Loki ingest.
//
// It DEFAULTS TO OFF. The receiver's contract is that an unknown program is never
// dropped; plenty of users have no ingest limits and would rather have the data than
// have us decide for them. Filtering is a thing you opt into, not a thing you opt out
// of.
//
// Whatever is dropped is COUNTED (logs_dropped_total{reason="filtered"}). A silent
// drop is indistinguishable from a receiver that is broken, and "I configured it and
// then saw nothing" is the worst possible failure mode for a log pipeline.
type Filter struct {
	include     map[string]bool // if non-empty, ONLY these programs pass
	exclude     map[string]bool // these programs are dropped
	minSeverity int             // drop anything numerically above this (syslog: lower == worse)
	hasSeverity bool
}

// NewFilter builds a filter. An empty include list and an empty exclude list with no
// severity floor means "pass everything", which is the default.
func NewFilter(include, exclude []string, minSeverity int, hasSeverity bool) *Filter {
	f := &Filter{minSeverity: minSeverity, hasSeverity: hasSeverity}
	if len(include) > 0 {
		f.include = make(map[string]bool, len(include))
		for _, p := range include {
			if p = strings.TrimSpace(p); p != "" {
				f.include[p] = true
			}
		}
	}
	if len(exclude) > 0 {
		f.exclude = make(map[string]bool, len(exclude))
		for _, p := range exclude {
			if p = strings.TrimSpace(p); p != "" {
				f.exclude[p] = true
			}
		}
	}
	return f
}

// Allow reports whether a record from this program at this severity should ship.
//
// Severity is RFC5424's scale, where LOWER IS WORSE (0 emerg … 7 debug). So a
// min-severity of "notice" (5) drops info (6) and debug (7) and keeps everything at
// or above notice. Getting that comparison backwards would drop precisely the lines
// an operator cares about, so it is spelled out here and tested.
func (f *Filter) Allow(program string, severity int) bool {
	if f == nil {
		return true
	}
	if f.hasSeverity && severity > f.minSeverity {
		return false
	}
	if len(f.include) > 0 {
		return f.include[program]
	}
	if f.exclude[program] {
		return false
	}
	return true
}

// Enabled reports whether this filter can drop anything at all. Used to skip the
// check (and the metric lookup) entirely in the default no-filtering case.
func (f *Filter) Enabled() bool {
	return f != nil && (len(f.include) > 0 || len(f.exclude) > 0 || f.hasSeverity)
}
