package collector

import (
	"fmt"
	"sort"
	"time"
)

// Poll cadence follows the lane that consumes it (#550).
//
// #336 decoupled the API poll from the Prometheus scrape so a scrape stopped
// triggering a firewall fetch. That was correct, but it left the poll interval and
// the export interval with no relationship at all — and once OTLP push became the
// primary delivery path, nothing re-established one. The result on a push-only
// deployment: fast-tier collectors poll the firewall every 15s into a snapshot that
// is only read every 60s, so three of every four polls are overwritten unread. Each
// of those wasted polls still costs two configd RPCs and two audit lines on the box
// (#535), which is what makes the waste worth removing rather than merely untidy.
//
// The rule is `effective = max(declared, laneInterval)`, applied only when OTLP is a
// delivery path:
//
//   - max, never replace. A cold collector must not start polling every 60s because
//     the export lane is 60s. The rule only ever makes polling SLOWER, so it cannot
//     increase load on anyone's firewall — which matters for a change shipping to
//     other people's boxes.
//   - `--collector.poll-interval-override` still wins outright and is never clamped.
//     It is explicit operator intent; it gets a startup warning (see
//     PollLaneWarnings), not a silent correction.
//   - Prometheus-scrape-only deployments are untouched (#550 Q1). The exporter cannot
//     know the scrape interval, so there is no lane to clamp against and today's tier
//     intervals stand exactly.
//
// DECLARED vs EFFECTIVE — the trap this file exists to avoid. Fast-lane membership
// (#390, FastCollectorNames) is derived from the interval a collector DECLARES:
// `resolveInterval(coll) <= IntervalFast`. That is deliberate, because it is what
// lets an operator override move a collector between export lanes. So the clamp must
// NOT be written back into resolveInterval — membership would then depend on the
// clamp that depends on membership, and at any intermediate
// --otlp.fast-export-interval (30s, say) the clamped interval exceeds IntervalFast,
// the lane is built over an empty gatherer set, and it exports nothing at all
// without a word. 15s and unset both happen to survive that bug, so casual testing
// does not catch it.
//
// The dependency therefore runs one direction only:
//
//	declared interval → lane membership → lane interval → effective cadence
//
// resolveInterval keeps returning the declared interval and keeps feeding membership.
// effectiveInterval below applies the clamp and is what the scheduler ticks on, what
// collector_poll_interval_seconds reports, and what StatusTracker records.

// laneInterval returns the interval of the OTLP export lane that consumes coll's
// snapshot, or 0 when no OTLP lane does (Prometheus-scrape-only). Membership reads
// the DECLARED interval — see the file comment.
func (c *Collector) laneInterval(coll CollectorInstance) time.Duration {
	if c.laneBase <= 0 {
		return 0
	}
	if c.laneFast > 0 && c.resolveInterval(coll) <= IntervalFast {
		return c.laneFast
	}
	return c.laneBase
}

// effectiveInterval returns the interval the scheduler actually polls coll on:
// max(declared, consuming lane), clamped. An operator override is returned as-is.
func (c *Collector) effectiveInterval(coll CollectorInstance) time.Duration {
	declared := c.resolveInterval(coll)
	if _, overridden := c.pollOverrides[coll.Name()]; overridden {
		return declared
	}
	if lane := c.laneInterval(coll); lane > declared {
		return clampInterval(lane)
	}
	return declared
}

// Warning kinds emitted by PollLaneWarnings.
const (
	// WarnPollFasterThanLane: this collector polls the firewall more often than the
	// export lane that reads its snapshot, so some polls are overwritten unread.
	// After the clamp above this is only reachable via an explicit
	// --collector.poll-interval-override.
	WarnPollFasterThanLane = "poll_faster_than_lane"
	// WarnFastLaneEmpty: --otlp.fast-export-interval is set but no enabled collector
	// is fast-tier, so the second export lane is constructed over an empty gatherer
	// set and exports nothing. Silent today.
	WarnFastLaneEmpty = "fast_lane_empty"
)

// PollLaneWarning is one poll-cadence/export-lane mismatch found at startup (#550
// §2). This is the general form of the bug: it catches the whole class rather than
// the one instance the clamp fixes.
type PollLaneWarning struct {
	Kind string
	// Collector is empty for warnings that are not about one collector.
	Collector string
	Poll      time.Duration
	Lane      time.Duration
}

// String renders the warning as the operator-facing sentence logged at startup.
func (w PollLaneWarning) String() string {
	switch w.Kind {
	case WarnPollFasterThanLane:
		wasted := int(w.Lane / w.Poll)
		return fmt.Sprintf(
			"collector %q polls every %s but its OTLP export lane reads the snapshot every %s; "+
				"roughly %d of every %d polls are overwritten unread, each costing the firewall a request",
			w.Collector, w.Poll, w.Lane, wasted-1, wasted)
	case WarnFastLaneEmpty:
		return fmt.Sprintf(
			"--otlp.fast-export-interval=%s is set but no enabled collector is fast-tier; "+
				"the second export lane will carry no series", w.Lane)
	default:
		return w.Kind
	}
}

// PollLaneWarnings reports poll intervals that are shorter than the export lane
// consuming them, plus a configured-but-empty fast lane. Deterministically ordered
// so the startup log is stable.
func (c *Collector) PollLaneWarnings() []PollLaneWarning {
	var out []PollLaneWarning
	if c.laneBase <= 0 {
		return out
	}

	for _, coll := range c.collectors {
		poll := c.effectiveInterval(coll)
		lane := c.laneInterval(coll)
		if lane > poll {
			out = append(out, PollLaneWarning{
				Kind:      WarnPollFasterThanLane,
				Collector: coll.Name(),
				Poll:      poll,
				Lane:      lane,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Collector < out[j].Collector })

	if c.laneFast > 0 && len(c.FastCollectorNames()) == 0 {
		out = append(out, PollLaneWarning{Kind: WarnFastLaneEmpty, Lane: c.laneFast})
	}
	return out
}
