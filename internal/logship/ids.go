package logship

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/options"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// idsSourceName is the Source.Name() value: the --logs.ids.enabled flag stem,
// the Loki `source` attribute value, and the self-metrics label value.
const idsSourceName = "ids"

// idsMinInterval floors the IDS source's poll cadence above the pipeline
// global (--logs.poll-interval, floor 5s). query_alerts triggers a reverse
// read of eve.json on the box — the same call the opt-in metrics
// alert-activity series uses (see opnsense.FetchIDSRecentAlerts) — so it is
// not free to run on every 5s tick.
const idsMinInterval = 30 * time.Second

// idsGapEvent marks a synthetic gap record — never a real Suricata alert — so
// it is distinguishable in Loki, e.g. `{source="ids"} | json | event="gap_detected"`.
const idsGapEvent = "gap_detected"

func init() {
	RegisterSource(func(deps Deps) (Source, error) {
		if !options.LogsIDSEnabled() {
			return nil, nil
		}
		return newIDSSource(deps.Client, deps.Logger), nil
	})
}

// idsFetcher is the subset of *opnsense.Client the source needs, narrowed for
// testability.
type idsFetcher interface {
	FetchIDSAlertRecords() ([]opnsense.IDSAlertRecord, *opnsense.APICallError)
}

// idsSource polls Suricata EVE alert records via query_alerts and ships full
// records (Body = compact eve JSON) to Loki.
//
// Cursor design (per issue #231): (fileid, filepos) is fragile across log
// rotation — a rotation/rename shifts fileids, so it cannot anchor resume
// across restarts or even across polls reliably. The record's own timestamp
// is the true cursor instead, with a flow_id+alert_sid dedupe ring scoped to
// records sharing the cursor's exact timestamp (µs-precision collisions are
// possible when several alerts fire in the same tick). filepos/fileid are
// never consulted; only Timestamp and the two id fields matter.
//
// Gap accounting: query_alerts is a windowed, saturating backend capped at
// opnsense.IDSAlertRowCap rows per read (see FetchIDSRecentAlerts's doc
// comment). If a poll returns a full window whose OLDEST row is still newer
// than the prior cursor, the read could not reach back far enough to cover
// everything since the last poll — some alerts in that gap were never
// observed. This is accepted, bounded loss (the issue's "accepted-loss
// design"): rather than fail or silently drop it, the source emits one
// synthetic gap Record (Severity=Warn, Attributes["event"]=idsGapEvent)
// describing the bounds, so the loss is visible and queryable in Loki instead
// of silent.
type idsSource struct {
	client idsFetcher
	log    *slog.Logger

	mu            sync.Mutex
	cursorSet     bool
	lastTimestamp time.Time
	dedupe        map[string]struct{}
}

func newIDSSource(client idsFetcher, log *slog.Logger) *idsSource {
	if log == nil {
		log = slog.Default()
	}
	return &idsSource{client: client, log: log, dedupe: map[string]struct{}{}}
}

func (s *idsSource) Name() string { return idsSourceName }

// MinInterval implements IntervalSource.
func (s *idsSource) MinInterval() time.Duration { return idsMinInterval }

// Poll fetches the newest alert window and returns every record not yet
// observed by the cursor, plus a synthetic gap record when the window
// saturated before reaching the prior cursor position (see the type doc
// comment). The very first poll (no cursor yet, whether fresh-start or a
// corrupt/missing persisted state) has nothing to diff against, so it emits
// the whole initial window as a startup catch-up and seeds the cursor from it
// — it is never treated as a gap.
func (s *idsSource) Poll(_ context.Context) ([]Record, error) {
	records, err := s.client.FetchIDSAlertRecords()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}

	ordered := append([]opnsense.IDSAlertRecord(nil), records...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Record, 0, len(ordered)+1)
	if s.cursorSet {
		if len(records) >= opnsense.IDSAlertRowCap && ordered[0].Timestamp.After(s.lastTimestamp) {
			out = append(out, s.gapRecord(s.lastTimestamp, ordered[0].Timestamp))
		}
		for _, r := range ordered {
			if r.Timestamp.Before(s.lastTimestamp) {
				continue
			}
			if r.Timestamp.Equal(s.lastTimestamp) {
				if _, seen := s.dedupe[idsDedupeKey(r)]; seen {
					continue
				}
			}
			out = append(out, idsRecordFromAlert(r))
		}
	} else {
		for _, r := range ordered {
			out = append(out, idsRecordFromAlert(r))
		}
	}

	s.advanceCursor(ordered)
	return out, nil
}

// advanceCursor moves the cursor to the newest timestamp in ordered (which
// must be sorted ascending) and rebuilds the dedupe ring to hold only the keys
// of records sharing that exact newest timestamp — bounded memory that never
// grows with alert volume.
func (s *idsSource) advanceCursor(ordered []opnsense.IDSAlertRecord) {
	newest := ordered[len(ordered)-1].Timestamp
	next := make(map[string]struct{})
	for _, r := range ordered {
		if r.Timestamp.Equal(newest) {
			next[idsDedupeKey(r)] = struct{}{}
		}
	}
	s.lastTimestamp = newest
	s.dedupe = next
	s.cursorSet = true
}

// gapRecord builds the synthetic record describing a detected window-overflow
// gap and logs it once at Warn level via the source's own logger (independent
// of whether the record itself successfully ships).
func (s *idsSource) gapRecord(from, to time.Time) Record {
	s.log.Warn("ids log source: possible gap in alert coverage (query_alerts window saturated)",
		"gap_start", from, "gap_end", to, "row_cap", opnsense.IDSAlertRowCap)
	body, err := json.Marshal(map[string]any{
		"event":     idsGapEvent,
		"gap_start": from.Format(time.RFC3339Nano),
		"gap_end":   to.Format(time.RFC3339Nano),
		"row_cap":   opnsense.IDSAlertRowCap,
		"note": "query_alerts window saturated before reaching the prior cursor; alerts in " +
			"this range were not observed (accepted, bounded loss - see docs/log-shipping.md)",
	})
	if err != nil {
		body = []byte(`{"event":"` + idsGapEvent + `"}`)
	}
	return Record{
		Timestamp:  to,
		Body:       string(body),
		Severity:   SeverityWarn,
		Attributes: map[string]string{"event": idsGapEvent},
	}
}

// idsRecordFromAlert maps one full alert record onto the pipeline's Record
// shape. Attributes are exactly the bounded set from the issue's Loki mapping:
// alert_sid, alert_action, src_ip, dest_ip, in_iface, proto, signature — never
// a label, always structured metadata. Body is the compact JSON of the full
// raw eve record (set by opnsense.FetchIDSAlertRecords), not a reconstruction.
func idsRecordFromAlert(r opnsense.IDSAlertRecord) Record {
	attrs := map[string]string{
		"alert_sid":    strconv.Itoa(r.AlertSID),
		"alert_action": r.AlertAction,
		"src_ip":       r.SrcIP,
		"dest_ip":      r.DestIP,
		"in_iface":     r.InIface,
		"proto":        r.Proto,
		"signature":    r.Signature,
	}
	// Normalised disposition, same EVE vocabulary as the syslog suricata parser, so
	// the same mapper. This lane is easy to forget — it is mutually exclusive with
	// the syslog receiver (options/logs_syslog.go refuses both), so it looks like
	// dead ground. It is not: --logs.ids.enabled + --logs.zenarmor.enabled is a
	// legal pair, and without this the IDS lane's blocks would be missing from
	// {opnsense_action="block"} while zenarmor's were present.
	if a := MapSuricataAction(r.AlertAction); a != "" {
		attrs[AttrAction] = a
	}
	return Record{
		Timestamp:  r.Timestamp,
		Body:       r.Body,
		Severity:   idsSeverity(r.AlertAction),
		Attributes: attrs,
	}
}

// idsSeverity maps the bounded alert_action to a Record severity: a "blocked"
// alert (Suricata/the firewall acted on it) is a warning, everything else
// (typically "allowed") is informational.
func idsSeverity(action string) Severity {
	if action == "blocked" {
		return SeverityWarn
	}
	return SeverityInfo
}

// idsDedupeKey is the composite dedupe key for one alert record: flow_id and
// alert_sid together identify a specific alert instance (a single flow can
// trigger several distinct signatures, and the same signature can fire on
// several flows in the same tick).
func idsDedupeKey(r opnsense.IDSAlertRecord) string {
	return strconv.FormatInt(r.FlowID, 10) + ":" + strconv.Itoa(r.AlertSID)
}

// idsCursorState is the JSON shape persisted via StatefulSource when
// --logs.state-file is set.
type idsCursorState struct {
	LastTimestamp time.Time `json:"last_timestamp"`
	Dedupe        []string  `json:"dedupe,omitempty"`
}

// LoadState implements StatefulSource. A missing, empty or corrupt blob is not
// fatal: the source simply resumes as a fresh (uncursored) start, per Poll's
// first-poll behaviour.
func (s *idsSource) LoadState(data []byte) {
	if len(data) == 0 {
		return
	}
	var st idsCursorState
	if err := json.Unmarshal(data, &st); err != nil {
		s.log.Warn("ids log source: state is corrupt; resuming from now", "err", err)
		return
	}
	if st.LastTimestamp.IsZero() {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTimestamp = st.LastTimestamp
	s.dedupe = make(map[string]struct{}, len(st.Dedupe))
	for _, k := range st.Dedupe {
		s.dedupe[k] = struct{}{}
	}
	s.cursorSet = true
}

// SaveState implements StatefulSource. Returns ok=false before the first
// successful Poll (nothing to persist yet).
func (s *idsSource) SaveState() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cursorSet {
		return nil, false
	}

	dedupe := make([]string, 0, len(s.dedupe))
	for k := range s.dedupe {
		dedupe = append(dedupe, k)
	}
	sort.Strings(dedupe)

	data, err := json.Marshal(idsCursorState{LastTimestamp: s.lastTimestamp, Dedupe: dedupe})
	if err != nil {
		return nil, false
	}
	return data, true
}
