package logship

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// crowdsecMinInterval is the poll floor for the crowdsec source. Each poll is a
// full cscli alerts/decisions dump (one configd exec each, per the OPNsense
// CrowdSec plugin controllers), so polling faster than this buys nothing at
// homelab/SMB event volumes — matching the metrics-side CrowdSec collector's
// cadence expectations.
const crowdsecMinInterval = 60 * time.Second

func init() {
	RegisterSource(func(deps Deps) (Source, error) {
		if !options.LogsCrowdSecEnabled() {
			return nil, nil
		}
		return newCrowdSecSource(deps.Client), nil
	})
}

// crowdsecFetcher is the subset of *opnsense.Client the crowdsec source needs.
// Narrowed to an interface so tests can inject a fake without a live client.
type crowdsecFetcher interface {
	FetchCrowdSecAlerts() ([]opnsense.CrowdSecAlert, *opnsense.APICallError)
	FetchCrowdSecDecisions() ([]opnsense.CrowdSecDecision, *opnsense.APICallError)
}

// crowdsecState is the persisted cursor shape for LoadState/SaveState.
type crowdsecState struct {
	LastAlertID    int `json:"last_alert_id"`
	LastDecisionID int `json:"last_decision_id"`
}

// crowdsecSource ships CrowdSec alert and decision records — there is no
// native syslog path for these (the plugin registers no syslog scope; alerts
// live only in the LAPI), so this pipeline is the only way to get them to
// Loki.
//
// Cursor: alert ids and decision ids are each a separate, server-side
// monotonic counter (confirmed against a live OPNsense 26.7 box 2026-07-13:
// a synthetic cscli-created ban had alert id 1 and decision id 1, independent
// namespaces). The source tracks the highest id shipped per record kind and
// ships only rows whose id is greater than that cursor next poll — a plain
// id-diff, no timestamp windowing or content hashing required. On a cold
// start (cursor 0) every currently-active alert/decision is shipped once:
// enabling the source surfaces current state rather than silently starting
// from a blank slate.
//
// Plugin-absent / daemon-not-running degrade silently by construction: both
// FetchCrowdSecAlerts and FetchCrowdSecDecisions already return (nil, nil) on
// a 404 (plugin absent) or the cscli "unable to retrieve data" message
// envelope (daemon not running), so Poll simply ships nothing for that call
// without erroring — no extra handling needed at this layer.
type crowdsecSource struct {
	client crowdsecFetcher

	mu             sync.Mutex
	lastAlertID    int
	lastDecisionID int
}

func newCrowdSecSource(client crowdsecFetcher) *crowdsecSource {
	return &crowdsecSource{client: client}
}

func (s *crowdsecSource) Name() string { return "crowdsec" }

// MinInterval implements IntervalSource.
func (s *crowdsecSource) MinInterval() time.Duration { return crowdsecMinInterval }

// Poll implements Source.
func (s *crowdsecSource) Poll(_ context.Context) ([]Record, error) {
	alerts, err := s.client.FetchCrowdSecAlerts()
	if err != nil {
		return nil, err
	}
	decisions, err := s.client.FetchCrowdSecDecisions()
	if err != nil {
		return nil, err
	}

	// Sort ascending by id so the cursor advances deterministically regardless
	// of the order the bootgrid rows arrive in.
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].ID < alerts[j].ID })
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].ID < decisions[j].ID })

	s.mu.Lock()
	defer s.mu.Unlock()

	records := make([]Record, 0, len(alerts)+len(decisions))

	for _, a := range alerts {
		if a.ID > s.lastAlertID {
			records = append(records, buildCrowdSecAlertRecord(a))
		}
	}
	if n := len(alerts); n > 0 && alerts[n-1].ID > s.lastAlertID {
		s.lastAlertID = alerts[n-1].ID
	}

	for _, d := range decisions {
		if d.ID > s.lastDecisionID {
			records = append(records, buildCrowdSecDecisionRecord(d))
		}
	}
	if n := len(decisions); n > 0 && decisions[n-1].ID > s.lastDecisionID {
		s.lastDecisionID = decisions[n-1].ID
	}

	return records, nil
}

// LoadState implements StatefulSource.
func (s *crowdsecSource) LoadState(data []byte) {
	var st crowdsecState
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAlertID = st.LastAlertID
	s.lastDecisionID = st.LastDecisionID
}

// SaveState implements StatefulSource.
func (s *crowdsecSource) SaveState() ([]byte, bool) {
	s.mu.Lock()
	lastAlertID, lastDecisionID := s.lastAlertID, s.lastDecisionID
	s.mu.Unlock()

	if lastAlertID == 0 && lastDecisionID == 0 {
		// Nothing observed yet — skip the write (per StatefulSource's contract).
		return nil, false
	}
	data, err := json.Marshal(crowdsecState{LastAlertID: lastAlertID, LastDecisionID: lastDecisionID})
	if err != nil {
		return nil, false
	}
	return data, true
}

// crowdsecAlertBody is the compact-JSON Record.Body for an alert.
type crowdsecAlertBody struct {
	Kind       string `json:"kind"`
	ID         int    `json:"id"`
	ScopeValue string `json:"scope_value"`
	Scenario   string `json:"scenario"`
	Country    string `json:"country,omitempty"`
	AS         string `json:"as,omitempty"`
	Decisions  string `json:"decisions,omitempty"`
	Created    string `json:"created,omitempty"`
}

// buildCrowdSecAlertRecord converts a fetched alert into a log Record. Body is
// the compact JSON encoding; Attributes are the bounded set named in
// docs/log-shipping.md's CrowdSec section (scenario, value, country, as,
// decisions) — high-cardinality data (the scope:ip value) travels as
// structured metadata here, never as a label (record.go's Attributes doc).
func buildCrowdSecAlertRecord(a opnsense.CrowdSecAlert) Record {
	body, _ := json.Marshal(crowdsecAlertBody{
		Kind:       "alert",
		ID:         a.ID,
		ScopeValue: a.ScopeValue,
		Scenario:   a.Scenario,
		Country:    a.Country,
		AS:         a.AS,
		Decisions:  a.DecisionsSummary,
		Created:    a.CreatedRaw,
	})

	attrs := map[string]string{
		"scenario": a.Scenario,
		"value":    a.ScopeValue,
	}
	if a.Country != "" {
		attrs["country"] = a.Country
	}
	if a.AS != "" {
		attrs["as"] = a.AS
	}
	if a.DecisionsSummary != "" {
		attrs["decisions"] = a.DecisionsSummary
	}

	r := Record{
		Body:       string(body),
		Attributes: attrs,
	}
	if a.HasCreatedAt {
		r.Timestamp = a.CreatedAt
	}
	return r
}

// crowdsecDecisionBody is the compact-JSON Record.Body for a decision.
type crowdsecDecisionBody struct {
	Kind        string `json:"kind"`
	ID          int    `json:"id"`
	AlertID     int    `json:"alert_id"`
	Origin      string `json:"origin,omitempty"`
	ScopeValue  string `json:"scope_value"`
	Scenario    string `json:"scenario"`
	Action      string `json:"action"`
	Country     string `json:"country,omitempty"`
	AS          string `json:"as,omitempty"`
	EventsCount int    `json:"events_count,omitempty"`
	Expiration  string `json:"expiration,omitempty"`
}

// buildCrowdSecDecisionRecord converts a fetched decision into a log Record.
// Timestamp is left zero (stamped at emit time): the decisions/search row has
// no absolute timestamp field, only "expiration" — a remaining-duration
// string, not a point in time (confirmed against the live dev-box capture and
// the OPNsense DecisionsController source).
func buildCrowdSecDecisionRecord(d opnsense.CrowdSecDecision) Record {
	body, _ := json.Marshal(crowdsecDecisionBody{
		Kind:        "decision",
		ID:          d.ID,
		AlertID:     d.AlertID,
		Origin:      d.Origin,
		ScopeValue:  d.ScopeValue,
		Scenario:    d.Scenario,
		Action:      d.Action,
		Country:     d.Country,
		AS:          d.AS,
		EventsCount: d.EventsCount,
		Expiration:  d.Expiration,
	})

	attrs := map[string]string{
		"scenario":      d.Scenario,
		"value":         d.ScopeValue,
		"decision_type": d.Action,
	}
	if d.Country != "" {
		attrs["country"] = d.Country
	}
	if d.AS != "" {
		attrs["as"] = d.AS
	}
	if d.Expiration != "" {
		attrs["duration"] = d.Expiration
	}

	return Record{
		Body:       string(body),
		Attributes: attrs,
	}
}
