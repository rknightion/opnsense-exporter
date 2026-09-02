package webui

import (
	"sort"

	dto "github.com/prometheus/client_model/go"
)

// PipelineStats is the receiver and flow-pipeline view shown on the console.
// Every value comes from the last metricsnap capture passed to
// parsePipelineStats; it never reads a registry or calls a receiver.
type PipelineStats struct {
	Rejects     []ReceiverRejectRow
	ParseErrors []ParseStageRow
	Flow        FlowPipelineStats
}

// ReceiverRejectRow is one source/reason series from logs_rejected_total.
// Zero-valued rows are retained because the receiver pre-initialises its closed
// reason vocabulary, making a healthy zero distinguishable from an absent
// receiver.
type ReceiverRejectRow struct {
	Source string
	Reason string
	Count  float64
}

// ParseStageRow is one source/stage series from logs_parse_errors_total.
type ParseStageRow struct {
	Source string
	Stage  string
	Count  float64
}

// FlowPipelineStats contains the bounded flow accumulator and correlator
// self-metrics. Availability is tracked separately for the rollup and
// correlator because the correlator is optional when flow-log emission is off.
type FlowPipelineStats struct {
	RollupAvailable  bool
	RollupKeys       float64
	RollupKeysMax    float64
	RollupTopN       float64
	RollupKeysFolded float64
	RollupCapped     float64

	CorrelatorAvailable             bool
	CorrelatorEntries               float64
	CorrelatorEmitted               float64
	CorrelatorMatched               float64
	CorrelatorEvicted               float64
	CorrelatorExpired               float64
	CorrelatorEnrichmentOverwrites  float64
	CorrelatorFragmentDisagreements float64
	CorrelatorFragmentMirrored      float64
}

// parsePipelineStats reduces the passive metric family snapshot to the small
// model the console needs. Names are matched by suffix, as in parseAPIStats, so
// the reducer tolerates a namespace prefix without ever broadening its input
// beyond the supplied metricsnap capture.
func parsePipelineStats(families []*dto.MetricFamily) PipelineStats {
	stats := PipelineStats{
		Rejects:     make([]ReceiverRejectRow, 0),
		ParseErrors: make([]ParseStageRow, 0),
	}
	stats.Rejects = parseReceiverRejects(families)
	stats.ParseErrors = parseParseErrors(families)
	stats.Flow = parseFlowPipelineStats(families)
	return stats
}

func parseReceiverRejects(families []*dto.MetricFamily) []ReceiverRejectRow {
	mf := familyBySuffix(families, "exporter_logs_rejected_total")
	if mf == nil {
		return []ReceiverRejectRow{}
	}
	totals := make(map[receiverRejectKey]float64, len(mf.GetMetric()))
	for _, m := range mf.GetMetric() {
		key := receiverRejectKey{
			source: labelValue(m, "source"),
			reason: labelValue(m, "reason"),
		}
		totals[key] += pipelineMetricValue(m)
	}
	rows := make([]ReceiverRejectRow, 0, len(totals))
	for key, count := range totals {
		rows = append(rows, ReceiverRejectRow{Source: key.source, Reason: key.reason, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		return rows[i].Reason < rows[j].Reason
	})
	return rows
}

type receiverRejectKey struct {
	source string
	reason string
}

func parseParseErrors(families []*dto.MetricFamily) []ParseStageRow {
	mf := familyBySuffix(families, "exporter_logs_parse_errors_total")
	if mf == nil {
		return []ParseStageRow{}
	}
	totals := make(map[parseStageKey]float64, len(mf.GetMetric()))
	for _, m := range mf.GetMetric() {
		key := parseStageKey{
			source: labelValue(m, "source"),
			stage:  labelValue(m, "stage"),
		}
		totals[key] += pipelineMetricValue(m)
	}
	rows := make([]ParseStageRow, 0, len(totals))
	for key, count := range totals {
		rows = append(rows, ParseStageRow{Source: key.source, Stage: key.stage, Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		return rows[i].Stage < rows[j].Stage
	})
	return rows
}

type parseStageKey struct {
	source string
	stage  string
}

func parseFlowPipelineStats(families []*dto.MetricFamily) FlowPipelineStats {
	stats := FlowPipelineStats{}
	stats.RollupKeys, stats.RollupAvailable = pipelineFamilyValue(families, "flow_rollup_keys")
	stats.RollupKeysMax, _ = pipelineFamilyValue(families, "flow_rollup_keys_max")
	stats.RollupTopN, _ = pipelineFamilyValue(families, "flow_rollup_top_n")
	stats.RollupKeysFolded, _ = pipelineFamilyValue(families, "flow_rollup_keys_folded")
	stats.RollupCapped, _ = pipelineFamilyValue(families, "flow_rollup_capped_total")

	stats.CorrelatorEntries, stats.CorrelatorAvailable = pipelineFamilyValue(families, "flow_correlator_entries")
	stats.CorrelatorEmitted, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_emitted_total", stats.CorrelatorAvailable)
	stats.CorrelatorMatched, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_matched_total", stats.CorrelatorAvailable)
	stats.CorrelatorEvicted, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_evicted_total", stats.CorrelatorAvailable)
	stats.CorrelatorExpired, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_expired_total", stats.CorrelatorAvailable)
	stats.CorrelatorEnrichmentOverwrites, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_enrichment_overwrites_total", stats.CorrelatorAvailable)
	stats.CorrelatorFragmentDisagreements, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_fragment_disagreement_total", stats.CorrelatorAvailable)
	stats.CorrelatorFragmentMirrored, stats.CorrelatorAvailable = pipelineFamilyValueOrExisting(
		families, "flow_correlator_fragment_mirrored_total", stats.CorrelatorAvailable)
	return stats
}

func pipelineFamilyValueOrExisting(families []*dto.MetricFamily, suffix string, available bool) (float64, bool) {
	value, found := pipelineFamilyValue(families, suffix)
	return value, available || found
}

func pipelineFamilyValue(families []*dto.MetricFamily, suffix string) (float64, bool) {
	mf := familyBySuffix(families, suffix)
	if mf == nil {
		return 0, false
	}
	var value float64
	for _, m := range mf.GetMetric() {
		value += pipelineMetricValue(m)
	}
	return value, true
}

func pipelineMetricValue(m *dto.Metric) float64 {
	switch {
	case m == nil:
		return 0
	case m.Counter != nil:
		return m.GetCounter().GetValue()
	case m.Gauge != nil:
		return m.GetGauge().GetValue()
	case m.Untyped != nil:
		return m.GetUntyped().GetValue()
	default:
		return 0
	}
}
