package logship

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// fakeCrowdSecFetcher is a test double for crowdsecFetcher: each field is
// consulted fresh on every call, so a test can mutate it between Poll calls to
// simulate the box's state changing across polls.
type fakeCrowdSecFetcher struct {
	alerts    []opnsense.CrowdSecAlert
	alertsErr *opnsense.APICallError
	decisions []opnsense.CrowdSecDecision
	decErr    *opnsense.APICallError
}

func (f *fakeCrowdSecFetcher) FetchCrowdSecAlerts() ([]opnsense.CrowdSecAlert, *opnsense.APICallError) {
	return f.alerts, f.alertsErr
}

func (f *fakeCrowdSecFetcher) FetchCrowdSecDecisions() ([]opnsense.CrowdSecDecision, *opnsense.APICallError) {
	return f.decisions, f.decErr
}

func TestCrowdSecSource_Name(t *testing.T) {
	s := newCrowdSecSource(&fakeCrowdSecFetcher{})
	if s.Name() != "crowdsec" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "crowdsec")
	}
}

func TestCrowdSecSource_MinInterval(t *testing.T) {
	s := newCrowdSecSource(&fakeCrowdSecFetcher{})
	if s.MinInterval() != 60*time.Second {
		t.Fatalf("MinInterval() = %s, want 60s", s.MinInterval())
	}
}

func TestCrowdSecSource_FirstPoll_ShipsCurrentState(t *testing.T) {
	created := time.Date(2026, 7, 12, 17, 9, 28, 0, time.UTC)
	fake := &fakeCrowdSecFetcher{
		alerts: []opnsense.CrowdSecAlert{
			{ID: 1, ScopeValue: "Ip:192.0.2.66", Scenario: "synthetic ban", DecisionsSummary: "ban:1", CreatedRaw: "2026-07-12T17:09:28Z", CreatedAt: created, HasCreatedAt: true},
		},
		decisions: []opnsense.CrowdSecDecision{
			{ID: 1, Origin: "cscli", ScopeValue: "Ip:192.0.2.66", Scenario: "synthetic ban", Action: "ban", Expiration: "693h46m29s", AlertID: 1, EventsCount: 1},
		},
	}
	s := newCrowdSecSource(fake)

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records on first poll (1 alert + 1 decision), got %d: %+v", len(records), records)
	}

	// Alert record.
	alertRec := records[0]
	if alertRec.Attributes["scenario"] != "synthetic ban" {
		t.Errorf("alert scenario attr = %q", alertRec.Attributes["scenario"])
	}
	if alertRec.Attributes["value"] != "Ip:192.0.2.66" {
		t.Errorf("alert value attr = %q", alertRec.Attributes["value"])
	}
	if alertRec.Attributes["decisions"] != "ban:1" {
		t.Errorf("alert decisions attr = %q", alertRec.Attributes["decisions"])
	}
	if !alertRec.Timestamp.Equal(created) {
		t.Errorf("alert timestamp = %v, want %v", alertRec.Timestamp, created)
	}
	var alertBody crowdsecAlertBody
	if jerr := json.Unmarshal([]byte(alertRec.Body), &alertBody); jerr != nil {
		t.Fatalf("alert body not valid JSON: %v", jerr)
	}
	if alertBody.Kind != "alert" || alertBody.ID != 1 {
		t.Errorf("alert body = %+v", alertBody)
	}

	// Decision record.
	decRec := records[1]
	if decRec.Attributes["decision_type"] != "ban" {
		t.Errorf("decision_type attr = %q", decRec.Attributes["decision_type"])
	}
	if decRec.Attributes["duration"] != "693h46m29s" {
		t.Errorf("duration attr = %q", decRec.Attributes["duration"])
	}
	if decRec.Attributes["value"] != "Ip:192.0.2.66" {
		t.Errorf("decision value attr = %q", decRec.Attributes["value"])
	}
	if !decRec.Timestamp.IsZero() {
		t.Errorf("expected zero decision timestamp (stamped at emit time), got %v", decRec.Timestamp)
	}
	var decBody crowdsecDecisionBody
	if jerr := json.Unmarshal([]byte(decRec.Body), &decBody); jerr != nil {
		t.Fatalf("decision body not valid JSON: %v", jerr)
	}
	if decBody.Kind != "decision" || decBody.ID != 1 || decBody.AlertID != 1 {
		t.Errorf("decision body = %+v", decBody)
	}
}

func TestCrowdSecSource_IncrementalDedupByID(t *testing.T) {
	fake := &fakeCrowdSecFetcher{
		alerts:    []opnsense.CrowdSecAlert{{ID: 1, Scenario: "first"}},
		decisions: []opnsense.CrowdSecDecision{{ID: 1, Scenario: "first"}},
	}
	s := newCrowdSecSource(fake)

	first, err := s.Poll(context.Background())
	if err != nil || len(first) != 2 {
		t.Fatalf("first poll: records=%d err=%v", len(first), err)
	}

	// Second poll: same rows still present (bootgrid re-dumps everything), plus
	// one genuinely new alert and decision. Only the new ones should ship.
	fake.alerts = append(fake.alerts, opnsense.CrowdSecAlert{ID: 2, Scenario: "second"})
	fake.decisions = append(fake.decisions, opnsense.CrowdSecDecision{ID: 2, Scenario: "second"})

	second, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if len(second) != 2 {
		t.Fatalf("expected 2 new records (1 alert + 1 decision) on second poll, got %d: %+v", len(second), second)
	}
	for _, r := range second {
		var body crowdsecAlertBody // id field name/position is shared with decision body
		_ = json.Unmarshal([]byte(r.Body), &body)
		if body.ID != 2 {
			t.Errorf("expected only id=2 to ship on second poll, got body=%+v", body)
		}
	}

	// Third poll: nothing new at all.
	third, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("third poll: %v", err)
	}
	if len(third) != 0 {
		t.Fatalf("expected 0 records when nothing changed, got %d", len(third))
	}
}

func TestCrowdSecSource_Empty(t *testing.T) {
	s := newCrowdSecSource(&fakeCrowdSecFetcher{})
	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
}

func TestCrowdSecSource_PluginAbsent_DegradesSilently(t *testing.T) {
	// FetchCrowdSecAlerts/FetchCrowdSecDecisions already fold a 404 (plugin
	// absent) into (nil, nil) at the opnsense layer — Poll must not error or
	// panic when both come back empty-with-no-error.
	s := newCrowdSecSource(&fakeCrowdSecFetcher{alerts: nil, decisions: nil})
	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("expected nil error when plugin absent, got: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected no records when plugin absent, got %d", len(records))
	}
}

func TestCrowdSecSource_PollError_Alerts(t *testing.T) {
	fake := &fakeCrowdSecFetcher{alertsErr: &opnsense.APICallError{Message: "boom", StatusCode: 500}}
	s := newCrowdSecSource(fake)
	_, err := s.Poll(context.Background())
	if err == nil {
		t.Fatal("expected a non-nil error when the alerts fetch fails")
	}
}

func TestCrowdSecSource_PollError_Decisions(t *testing.T) {
	fake := &fakeCrowdSecFetcher{decErr: &opnsense.APICallError{Message: "boom", StatusCode: 500}}
	s := newCrowdSecSource(fake)
	_, err := s.Poll(context.Background())
	if err == nil {
		t.Fatal("expected a non-nil error when the decisions fetch fails")
	}
}

func TestCrowdSecSource_SaveLoadState(t *testing.T) {
	fake := &fakeCrowdSecFetcher{
		alerts:    []opnsense.CrowdSecAlert{{ID: 5}},
		decisions: []opnsense.CrowdSecDecision{{ID: 7}},
	}
	s := newCrowdSecSource(fake)
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	data, ok := s.SaveState()
	if !ok {
		t.Fatal("expected SaveState to report ok=true once a cursor has advanced")
	}

	restored := newCrowdSecSource(&fakeCrowdSecFetcher{})
	restored.LoadState(data)
	restored.mu.Lock()
	gotAlert, gotDec := restored.lastAlertID, restored.lastDecisionID
	restored.mu.Unlock()
	if gotAlert != 5 || gotDec != 7 {
		t.Fatalf("restored cursor = (%d, %d), want (5, 7)", gotAlert, gotDec)
	}

	// A fresh source with nothing observed yet must skip the write.
	fresh := newCrowdSecSource(&fakeCrowdSecFetcher{})
	if _, ok := fresh.SaveState(); ok {
		t.Fatal("expected SaveState to report ok=false when no cursor has advanced")
	}
}

func TestCrowdSecSource_LoadState_CorruptDataIgnored(t *testing.T) {
	s := newCrowdSecSource(&fakeCrowdSecFetcher{})
	s.LoadState([]byte("not json"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastAlertID != 0 || s.lastDecisionID != 0 {
		t.Fatalf("corrupt state should be ignored, got (%d, %d)", s.lastAlertID, s.lastDecisionID)
	}
}

// Compile-time interface assertions.
var (
	_ Source         = (*crowdsecSource)(nil)
	_ StatefulSource = (*crowdsecSource)(nil)
	_ IntervalSource = (*crowdsecSource)(nil)
)
