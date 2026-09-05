package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/rknightion/opnsense2otel/v4/internal/metricsnap"
)

func pipelineGauge(value float64) *dto.Metric {
	return &dto.Metric{Gauge: &dto.Gauge{Value: &value}}
}

func pipelineCounter(value float64, labels ...string) *dto.Metric {
	m := counterMetric(value, labels...)
	return m
}

func TestParsePipelineStats_ReceiversAndFlow(t *testing.T) {
	families := []*dto.MetricFamily{
		{Name: sp("opnsense_exporter_logs_rejected_total"), Metric: []*dto.Metric{
			pipelineCounter(3, "source", "syslog", "reason", "peer"),
			pipelineCounter(2, "source", "syslog", "reason", "filtered"),
			pipelineCounter(0, "source", "zenarmor", "reason", "auth"),
		}},
		{Name: sp("opnsense_exporter_logs_parse_errors_total"), Metric: []*dto.Metric{
			pipelineCounter(4, "source", "syslog", "stage", "envelope"),
			pipelineCounter(1, "source", "zenarmor", "stage", "document"),
		}},
		{Name: sp("opnsense_flow_rollup_keys"), Metric: []*dto.Metric{pipelineGauge(8)}},
		{Name: sp("opnsense_flow_rollup_keys_max"), Metric: []*dto.Metric{pipelineGauge(10)}},
		{Name: sp("opnsense_flow_rollup_top_n"), Metric: []*dto.Metric{pipelineGauge(5)}},
		{Name: sp("opnsense_flow_rollup_keys_folded"), Metric: []*dto.Metric{pipelineGauge(3)}},
		{Name: sp("opnsense_flow_rollup_capped_total"), Metric: []*dto.Metric{pipelineCounter(6)}},
		{Name: sp("opnsense_flow_correlator_entries"), Metric: []*dto.Metric{pipelineGauge(2)}},
		{Name: sp("opnsense_flow_correlator_emitted_total"), Metric: []*dto.Metric{pipelineCounter(9)}},
		{Name: sp("opnsense_flow_correlator_matched_total"), Metric: []*dto.Metric{pipelineCounter(7)}},
		{Name: sp("opnsense_flow_correlator_evicted_total"), Metric: []*dto.Metric{pipelineCounter(1)}},
		{Name: sp("opnsense_flow_correlator_expired_total"), Metric: []*dto.Metric{pipelineCounter(8)}},
	}

	got := parsePipelineStats(families)
	if len(got.Rejects) != 3 {
		t.Fatalf("reject rows = %d, want 3", len(got.Rejects))
	}
	if got.Rejects[0].Source != "syslog" || got.Rejects[0].Reason != "filtered" || got.Rejects[0].Count != 2 {
		t.Fatalf("reject rows not sorted/source-labelled as expected: %+v", got.Rejects)
	}
	if got.Rejects[2].Source != "zenarmor" || got.Rejects[2].Reason != "auth" || got.Rejects[2].Count != 0 {
		t.Fatalf("zero-valued reject row missing or changed: %+v", got.Rejects)
	}
	if len(got.ParseErrors) != 2 || got.ParseErrors[0].Stage != "envelope" || got.ParseErrors[1].Stage != "document" {
		t.Fatalf("parse rows = %+v, want source/stage rows in order", got.ParseErrors)
	}
	if got.Flow.RollupKeys != 8 || got.Flow.RollupKeysMax != 10 || got.Flow.RollupTopN != 5 || got.Flow.RollupKeysFolded != 3 || got.Flow.RollupCapped != 6 {
		t.Fatalf("rollup stats = %+v", got.Flow)
	}
	if !got.Flow.RollupAvailable || !got.Flow.CorrelatorAvailable {
		t.Fatalf("flow availability = %+v, want both available", got.Flow)
	}
	if got.Flow.CorrelatorEntries != 2 || got.Flow.CorrelatorEmitted != 9 || got.Flow.CorrelatorMatched != 7 || got.Flow.CorrelatorEvicted != 1 || got.Flow.CorrelatorExpired != 8 {
		t.Fatalf("correlator stats = %+v", got.Flow)
	}
}

func TestBuildStatusCarriesPipelineFromPassiveCapture(t *testing.T) {
	families := []*dto.MetricFamily{
		{Name: sp("opnsense_exporter_logs_rejected_total"), Metric: []*dto.Metric{
			pipelineCounter(5, "source", "syslog", "reason", "peer"),
		}},
		{Name: sp("opnsense_flow_correlator_entries"), Metric: []*dto.Metric{pipelineGauge(4)}},
	}
	st := buildStatus(nil, metricsnap.Capture{Families: families}, nil, ServiceInfo{}, nil, nil)
	if len(st.Pipeline.Rejects) != 1 || st.Pipeline.Rejects[0].Count != 5 {
		t.Fatalf("status pipeline rejects = %+v", st.Pipeline.Rejects)
	}
	if st.Pipeline.Flow.CorrelatorEntries != 4 {
		t.Fatalf("status pipeline correlator entries = %v, want 4", st.Pipeline.Flow.CorrelatorEntries)
	}
}

func TestHandler_StatusJSONCarriesPipelineFromPassiveCapture(t *testing.T) {
	d := testDeps()
	d.Capture = func() metricsnap.Capture {
		return metricsnap.Capture{Families: []*dto.MetricFamily{
			{Name: sp("opnsense_exporter_logs_rejected_total"), Metric: []*dto.Metric{
				pipelineCounter(5, "source", "syslog", "reason", "peer"),
			}},
			{Name: sp("opnsense_flow_correlator_entries"), Metric: []*dto.Metric{pipelineGauge(4)}},
		}}
	}
	srv := NewServer(d)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("json want 200, got %d", rec.Code)
	}
	var st struct {
		Pipeline PipelineStats
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(st.Pipeline.Rejects) != 1 || st.Pipeline.Rejects[0].Count != 5 {
		t.Fatalf("status.json pipeline rejects = %+v", st.Pipeline.Rejects)
	}
	if st.Pipeline.Flow.CorrelatorEntries != 4 {
		t.Fatalf("status.json pipeline correlator entries = %v, want 4", st.Pipeline.Flow.CorrelatorEntries)
	}
}

func TestRenderPage_PipelineTab(t *testing.T) {
	var out strings.Builder
	err := renderPage(&out, view{Data: Status{Pipeline: PipelineStats{
		Rejects:     []ReceiverRejectRow{{Source: "syslog", Reason: "peer", Count: 3}},
		ParseErrors: []ParseStageRow{{Source: "syslog", Stage: "envelope", Count: 1}},
		Flow:        FlowPipelineStats{RollupAvailable: true, CorrelatorAvailable: true, CorrelatorEntries: 2, RollupCapped: 4},
	}}})
	if err != nil {
		t.Fatalf("renderPage: %v", err)
	}
	for _, want := range []string{
		`data-tab="pipeline"`, `data-target="pipeline"`, `id="panel-pipeline"`,
		"Input rejected", "Parse errors", "Correlator", "Rollup", "peer", "envelope",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("pipeline tab missing %q", want)
		}
	}
}
