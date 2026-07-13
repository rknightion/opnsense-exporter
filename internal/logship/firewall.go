package logship

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

func init() {
	RegisterSource(func(d Deps) (Source, error) {
		if !*options.LogsFirewallEnabled {
			return nil, nil
		}
		return newFirewallSource(d.Client, d.Logger), nil
	})
}

const (
	// firewallSourceName is the stable source identifier; it becomes the
	// `source` attribute value and keys this source's state-file entry and
	// self-metrics.
	firewallSourceName = "firewall"

	// firewallLogLimit is the per-poll row cap sent as ?limit=. 1000 matches the
	// endpoint's own default and the issue's recommendation: at homelab/SMB
	// volumes with a 10s+ poll this is far more headroom than a poll interval
	// ever produces, so the digest cursor is hit on every poll and tailing is
	// lossless. Sustained volumes that fill this cap between polls are exactly
	// the enterprise class the docs steer to native syslog instead.
	firewallLogLimit = 1000

	// firewallMinInterval is the source's poll floor, raised above the pipeline
	// global (5s). Each poll spawns configd and re-parses /tmp/rules.debug on the
	// box, so 10s keeps that cost modest while staying well inside the digest
	// window at any realistic event rate.
	firewallMinInterval = 10 * time.Second

	// firewallDedupCapacity bounds the recently-shipped digest ring. It only has
	// to cover rotation-overlap re-reads within a single poll window, so a couple
	// of poll-caps' worth is ample.
	firewallDedupCapacity = 4 * firewallLogLimit

	// firewallGapLogInterval rate-limits the gap warning so a box that
	// legitimately exceeds the row cap every poll cannot flood the log.
	firewallGapLogInterval = 30 * time.Second
)

// firewallSource tails api/diagnostics/firewall/log with its md5-digest cursor.
//
// Cursor lifecycle:
//   - First poll (no cursor, not resumed from state): fetch the newest rows,
//     adopt the newest digest as the cursor, ship NOTHING. This is the honest
//     "resume from now" start — a fresh process does not dump the box's whole
//     log backlog into Loki.
//   - Steady poll: fetch with ?digest=<cursor>. The backend returns every newer
//     row plus the cursor row itself (oldest element); drop the cursor row,
//     dedup the rest against the recently-shipped ring, ship them oldest-first,
//     and advance the cursor to the newest digest.
//   - Gap / rotation: if the cursor is not present in the returned batch, the
//     cursor rotated out of the window or more than firewallLogLimit rows
//     arrived since the last poll. Rows between the oldest returned row and the
//     cursor are unrecoverable; ship what came back, resume from the newest
//     digest, and log a rate-limited warning. This is the bounded, visible loss
//     the pipeline's at-least-once-within-a-run contract permits.
type firewallSource struct {
	client *opnsense.Client
	log    *slog.Logger
	limit  int

	mu          sync.Mutex
	cursor      string // newest shipped digest; "" until primed
	primed      bool   // first poll has established the cursor
	seen        *digestRing
	lastGapWarn time.Time
}

func newFirewallSource(client *opnsense.Client, logger *slog.Logger) *firewallSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &firewallSource{
		client: client,
		log:    logger.With("source", firewallSourceName),
		limit:  firewallLogLimit,
		seen:   newDigestRing(firewallDedupCapacity),
	}
}

// Name implements Source.
func (s *firewallSource) Name() string { return firewallSourceName }

// MinInterval implements IntervalSource: the firewall source polls no faster
// than firewallMinInterval regardless of the global --logs.poll-interval.
func (s *firewallSource) MinInterval() time.Duration { return firewallMinInterval }

// Poll implements Source. It returns the events observed since the previous
// call, oldest-first.
func (s *firewallSource) Poll(ctx context.Context) ([]Record, error) {
	s.mu.Lock()
	cursor := s.cursor
	primed := s.primed
	s.mu.Unlock()

	rows, apiErr := s.client.WithContext(ctx).FetchFirewallLog(s.limit, cursor)
	if apiErr != nil {
		return nil, apiErr
	}

	// First poll: prime the cursor at the newest row and ship nothing. Seed the
	// dedup ring with the primed rows so a rotation re-read on the next poll
	// cannot resurface a row we intentionally skipped.
	if !primed {
		s.mu.Lock()
		if len(rows) > 0 {
			s.cursor = rows[0].Digest
		}
		for i := range rows {
			s.seen.add(rows[i].Digest)
		}
		s.primed = true
		s.mu.Unlock()
		return nil, nil
	}

	if len(rows) == 0 {
		return nil, nil
	}

	// rows are newest-first. rows[0] is the newest digest we advance to.
	newestDigest := rows[0].Digest
	cursorFound := false

	// Collect new rows newest-first, then reverse to ship oldest-first so the
	// bounded queue drains chronologically (and drops the oldest under overflow).
	newest := make([]*opnsense.FirewallLogRecord, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if r.Digest == cursor {
			cursorFound = true
			continue // the cursor row was shipped on the previous poll
		}
		if s.seen.contains(r.Digest) {
			continue // rotation-overlap re-read of an already-shipped line
		}
		newest = append(newest, r)
	}

	if cursor != "" && !cursorFound {
		s.warnGap(len(rows), newestDigest)
	}

	records := make([]Record, 0, len(newest))
	s.mu.Lock()
	// oldest-first: iterate the newest-first slice in reverse.
	for i := len(newest) - 1; i >= 0; i-- {
		r := newest[i]
		s.seen.add(r.Digest)
		records = append(records, recordFromFirewallRow(r, s.log))
	}
	s.cursor = newestDigest
	s.mu.Unlock()

	return records, nil
}

// warnGap logs a rate-limited warning that the digest cursor was not found in a
// returned batch (rotation-out or > limit rows/poll). Caller must NOT hold s.mu.
func (s *firewallSource) warnGap(rowCount int, newestDigest string) {
	s.mu.Lock()
	now := time.Now()
	quiet := !s.lastGapWarn.IsZero() && now.Sub(s.lastGapWarn) < firewallGapLogInterval
	if !quiet {
		s.lastGapWarn = now
	}
	s.mu.Unlock()
	if quiet {
		return
	}
	s.log.Warn("firewall log digest cursor not found in batch; some events may be lost "+
		"(rotation, or more than the row cap arrived between polls)",
		"row_cap", s.limit, "returned", rowCount, "resume_digest", newestDigest)
}

// LoadState implements StatefulSource: restore the digest cursor so a restart
// with --logs.state-file resumes from the persisted position instead of now.
func (s *firewallSource) LoadState(data []byte) {
	var st firewallState
	if err := json.Unmarshal(data, &st); err != nil {
		s.log.Warn("firewall log state is corrupt; resuming from now", "err", err)
		return
	}
	if st.Digest == "" {
		return
	}
	s.mu.Lock()
	s.cursor = st.Digest
	s.primed = true // resume from the persisted cursor, not from-now
	s.mu.Unlock()
}

// SaveState implements StatefulSource: persist the digest cursor. Returns false
// before the first poll establishes a cursor, so no empty state is written.
func (s *firewallSource) SaveState() ([]byte, bool) {
	s.mu.Lock()
	cursor := s.cursor
	s.mu.Unlock()
	if cursor == "" {
		return nil, false
	}
	data, err := json.Marshal(firewallState{Digest: cursor})
	if err != nil {
		return nil, false
	}
	return data, true
}

// firewallState is the persisted cursor blob. Versioned by shape: a future field
// addition stays backward-compatible because unknown fields are ignored and a
// missing digest resumes from now.
type firewallState struct {
	Digest string `json:"digest"`
}

// recordFromFirewallRow maps a parsed filterlog row onto a log Record. IP
// addresses and ports travel as structured-metadata attributes (never labels,
// per the pipeline's cardinality contract); the reserved `source` /
// `service.*` keys are stripped by the pipeline, so they are never set here.
func recordFromFirewallRow(r *opnsense.FirewallLogRecord, log *slog.Logger) Record {
	attrs := make(map[string]string, 16)
	setAttr := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	setAttr("action", r.Action)
	setAttr("interface", r.Interface)
	setAttr("dir", r.Dir)
	setAttr("reason", r.Reason)
	setAttr("ipversion", r.IPVersion)
	setAttr("proto", r.ProtoName)
	setAttr("protonum", r.ProtoNum)
	setAttr("src", r.Src)
	setAttr("dst", r.Dst)
	setAttr("srcport", r.SrcPort)
	setAttr("dstport", r.DstPort)
	setAttr("length", r.Length)
	setAttr("tcpflags", r.TCPFlags)
	setAttr("rid", r.RID)
	setAttr("rulenr", r.RuleNr)
	setAttr("subrulenr", r.SubRuleNr)
	setAttr("anchorname", r.AnchorName)
	// The label is the reason to use this endpoint over syslog — carry it when
	// the rule has one (automatic/default rules and unlabelled rules have none).
	setAttr("label", r.Label)
	setAttr("digest", r.Digest)

	return Record{
		Timestamp:  parseFirewallTimestamp(r.Timestamp, log),
		Body:       firewallBody(r),
		Attributes: attrs,
		Severity:   firewallSeverity(r.Action),
	}
}

// firewallBody renders a compact, single-line JSON encoding of the event as the
// log body. read_log.py already parses the raw pf CSV line and does not return
// it, so there is no verbatim "raw line" to ship; a compact JSON of the parsed
// fields is the faithful, greppable substitute (record.go documents this
// body-is-compact-JSON option). Empty fields are omitted.
func firewallBody(r *opnsense.FirewallLogRecord) string {
	// omitempty on every field keeps the line tight and per-protocol-correct.
	type body struct {
		Time      string `json:"time,omitempty"`
		Action    string `json:"action,omitempty"`
		Interface string `json:"interface,omitempty"`
		Dir       string `json:"dir,omitempty"`
		Reason    string `json:"reason,omitempty"`
		IPVersion string `json:"ipversion,omitempty"`
		Proto     string `json:"proto,omitempty"`
		Src       string `json:"src,omitempty"`
		Dst       string `json:"dst,omitempty"`
		SrcPort   string `json:"srcport,omitempty"`
		DstPort   string `json:"dstport,omitempty"`
		TCPFlags  string `json:"tcpflags,omitempty"`
		Rid       string `json:"rid,omitempty"`
		RuleNr    string `json:"rulenr,omitempty"`
		Label     string `json:"label,omitempty"`
	}
	b, err := json.Marshal(body{
		Time:      r.Timestamp,
		Action:    r.Action,
		Interface: r.Interface,
		Dir:       r.Dir,
		Reason:    r.Reason,
		IPVersion: r.IPVersion,
		Proto:     r.ProtoName,
		Src:       r.Src,
		Dst:       r.Dst,
		SrcPort:   r.SrcPort,
		DstPort:   r.DstPort,
		TCPFlags:  r.TCPFlags,
		Rid:       r.RID,
		RuleNr:    r.RuleNr,
		Label:     r.Label,
	})
	if err != nil {
		return ""
	}
	return string(b)
}

// firewallSeverity maps a filterlog action to a log severity: a blocked packet
// is a Warn, everything else (pass/rdr/nat/binat) is Info.
func firewallSeverity(action string) Severity {
	if action == "block" {
		return SeverityWarn
	}
	return SeverityInfo
}

// firewallTimeLayout is read_log.py's __timestamp__ format: local time, second
// resolution, no zone suffix.
const firewallTimeLayout = "2006-01-02T15:04:05"

// parseFirewallTimestamp parses __timestamp__ in the exporter's local timezone
// (the payload carries no zone; homelab/SMB deployments run the exporter and the
// firewall in the same zone). An unparseable value falls back to a zero time,
// which the pipeline stamps with emit time.
func parseFirewallTimestamp(ts string, log *slog.Logger) time.Time {
	if ts == "" {
		return time.Time{}
	}
	t, err := time.ParseInLocation(firewallTimeLayout, ts, time.Local)
	if err != nil {
		log.Debug("could not parse firewall log timestamp; using emit time", "value", ts, "err", err)
		return time.Time{}
	}
	return t
}

// digestRing is a fixed-capacity set of the most recently shipped digests, used
// to suppress duplicates from rotation-overlap re-reads within a run. It is a
// ring: adding beyond capacity evicts the oldest digest. Not safe for concurrent
// use — the firewall source guards it with its own mutex.
type digestRing struct {
	set   map[string]struct{}
	order []string
	next  int
	cap   int
}

func newDigestRing(capacity int) *digestRing {
	if capacity < 1 {
		capacity = 1
	}
	return &digestRing{
		set:   make(map[string]struct{}, capacity),
		order: make([]string, 0, capacity),
		cap:   capacity,
	}
}

func (r *digestRing) contains(digest string) bool {
	_, ok := r.set[digest]
	return ok
}

func (r *digestRing) add(digest string) {
	if digest == "" {
		return
	}
	if _, ok := r.set[digest]; ok {
		return
	}
	if len(r.order) < r.cap {
		r.order = append(r.order, digest)
	} else {
		// evict the oldest at the ring position, then overwrite it.
		delete(r.set, r.order[r.next])
		r.order[r.next] = digest
	}
	r.set[digest] = struct{}{}
	r.next = (r.next + 1) % r.cap
}
