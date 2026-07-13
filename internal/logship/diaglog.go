package logship

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

func init() {
	RegisterSource(newDiagLogSource)
}

// diagLogSourceName is the stable Source.Name(): one poller multiplexes every
// configured module/scope pair (#230), so all of them share this single
// `source` attribute / metrics label / state-file key rather than one per
// scope. Each Record carries its own module/scope attributes instead.
const diagLogSourceName = "diaglog"

// diagLogPageSize always requests the server's hard maximum page size (see
// OPNsense's LogController, which clamps rowCount to 9999) to minimize the
// number of round trips needed to drain a scope's backlog.
const diagLogPageSize = 9999

// diagLogMaxPagesPerScope bounds how many pages one scope's poll will fetch in
// a single tick. At the default poll interval this is far more headroom than
// any real event volume needs (9999*5 = ~50k rows); it exists purely as a hard
// backstop against a genuine log storm — or a long gap since the last poll —
// turning one Poll call into an unbounded number of round trips. If a scope's
// true backlog exceeds this cap, the oldest rows in that backlog are skipped
// for this run: a bounded, logged loss consistent with the pipeline's own
// documented drop-oldest queue policy (record.go), not a hang.
const diagLogMaxPagesPerScope = 5

// diagLogAuditConfigChange matches Config::auditLogChange()'s config-change
// line, e.g.:
//
//	" user root@127.0.0.1 changed configuration to /conf/backup/config-....xml in /api/relayd/settings/set/virtualserver ..."
//	" user (root) changed configuration to /conf/backup/config-....xml in /tmp/fix_dup_opt4.php ..."
//
// (verified live against an OPNsense 26.7 devel box). It captures the actor
// (a bare username, "user@remote-ip", or "(user)" for CLI-invoked scripts), the
// backup revision path, and the URI/script that made the change; the line
// repeats the URI a second time ("... made changes"), which this regex does
// not need to capture.
var diagLogAuditConfigChange = regexp.MustCompile(`^\s*user (\S+) changed configuration to (\S+) in (\S+)`)

// diagLogSeverityMap maps OPNsense's syslog severity names (RFC 5424 levels
// 0-7, rendered by NewBaseLogFormat.severity_str) onto the pipeline's Severity
// enum, which has fewer levels than syslog. Emergency/Alert/Critical all
// collapse to SeverityFatal; Notice (between Warning and Informational in
// syslog) has no direct analogue and is treated as informational. Anything
// absent from this map (including the empty string OPNsense sends for
// unparsed lines) falls through to the zero value, SeverityInfo.
var diagLogSeverityMap = map[string]Severity{
	"Emergency":     SeverityFatal,
	"Alert":         SeverityFatal,
	"Critical":      SeverityFatal,
	"Error":         SeverityError,
	"Warning":       SeverityWarn,
	"Notice":        SeverityInfo,
	"Informational": SeverityInfo,
	"Debug":         SeverityDebug,
}

// newDiagLogSource is the SourceFactory registered in init(). It returns
// (nil, nil) when --logs.diaglog.enabled is false or --logs.scopes resolves to
// no scopes, per the SourceFactory contract.
func newDiagLogSource(deps Deps) (Source, error) {
	cfg, enabled, err := options.DiagLog()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}
	return &diagLogSource{
		client:  deps.Client,
		log:     log,
		scopes:  cfg.Scopes,
		cursors: make(map[string]*diagLogCursor),
		now:     time.Now,
	}, nil
}

// diagLogCursor is one scope's polling position.
type diagLogCursor struct {
	// LastEpoch is the Unix-seconds cursor sent as validFrom on the next poll,
	// parsed (as UTC — see opnsense.FetchDiagLog's doc comment on the known
	// timezone caveat) from the newest row's timestamp seen so far. Zero means
	// "not yet bootstrapped".
	LastEpoch int64
	// seenAtCursor dedupes OPNsense's inclusive validFrom boundary: the row
	// exactly at LastEpoch is returned again on the next poll, so rows whose
	// parsed epoch equals LastEpoch are checked against this set before being
	// emitted a second time. It is rebuilt from scratch whenever LastEpoch
	// advances, so it never grows past one wall-clock second's worth of lines.
	seenAtCursor map[string]struct{}
}

// diagLogSource is the generic diagnostics-log Source (#230): it polls
// api/diagnostics/log/<module>/<scope> for every configured scope and emits
// one Record per parsed line, tagging module/scope/process/pid attributes.
type diagLogSource struct {
	client *opnsense.Client
	log    *slog.Logger
	scopes []options.DiagLogScope

	mu      sync.Mutex
	cursors map[string]*diagLogCursor

	// now is time.Now, overridable in tests for deterministic bootstrap epochs.
	now func() time.Time
}

func (s *diagLogSource) Name() string { return diagLogSourceName }

// Poll fetches every configured scope in turn. A single scope's fetch failure
// is logged and skipped rather than discarding every OTHER scope's records —
// the pipeline drops the whole batch when Poll returns an error (see
// pipeline.go's pollOnce), so a partial failure must not propagate as a
// wholesale error while any scope still produced records. Only a poll where
// EVERY configured scope failed surfaces as an error (for the pipeline's
// logs_poll_errors_total{source} visibility).
func (s *diagLogSource) Poll(ctx context.Context) ([]Record, error) {
	var records []Record
	var failures int
	for _, scope := range s.scopes {
		if err := ctx.Err(); err != nil {
			return records, err
		}
		recs, err := s.pollScope(ctx, scope)
		if err != nil {
			failures++
			s.log.Warn("diaglog: scope poll failed", "module", scope.Module, "scope", scope.Scope, "err", err)
			continue
		}
		records = append(records, recs...)
	}
	if len(records) == 0 && failures > 0 {
		return nil, fmt.Errorf("diaglog: all %d configured scope(s) failed to poll", failures)
	}
	return records, nil
}

// pollScope fetches and emits the new rows for one module/scope pair since its
// cursor, paging up to diagLogMaxPagesPerScope times.
func (s *diagLogSource) pollScope(ctx context.Context, scope options.DiagLogScope) ([]Record, error) {
	key := scope.Key()

	s.mu.Lock()
	cur, ok := s.cursors[key]
	if !ok {
		cur = &diagLogCursor{}
		s.cursors[key] = cur
	}
	bootstrapping := cur.LastEpoch == 0
	if bootstrapping {
		// A scope with no prior cursor starts "from now" rather than replaying
		// the box's full retained log (which can be large, and for chatty
		// scopes like audit/configd would flood the pipeline with historical
		// noise on every restart without --logs.state-file). This mirrors the
		// pipeline's own documented "restart resumes from now" default
		// (record.go).
		cur.LastEpoch = s.now().Unix()
	}
	validFrom := cur.LastEpoch
	s.mu.Unlock()
	if bootstrapping {
		return nil, nil
	}

	var allRows []diagLogRowRef
	truncated := false
	for page := 1; page <= diagLogMaxPagesPerScope; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, apiErr := s.client.FetchDiagLog(scope.Module, scope.Scope, validFrom, diagLogPageSize, page)
		if apiErr != nil {
			return nil, apiErr
		}
		for _, row := range resp.Rows {
			allRows = append(allRows, diagLogRowRef{
				Timestamp:   row.Timestamp,
				Facility:    row.Facility.Int(),
				Severity:    row.Severity,
				ProcessName: row.ProcessName,
				Pid:         row.Pid.String(),
				Line:        row.Line,
			})
		}
		fetched := page * diagLogPageSize
		if resp.TotalRows <= fetched || len(resp.Rows) == 0 {
			break
		}
		if page == diagLogMaxPagesPerScope && resp.TotalRows > fetched {
			truncated = true
		}
	}
	if truncated {
		s.log.Warn("diaglog: scope backlog exceeds the per-poll page cap; oldest rows in this window were skipped",
			"module", scope.Module, "scope", scope.Scope, "cap_rows", diagLogMaxPagesPerScope*diagLogPageSize)
	}

	return s.emitNewRows(scope, cur, allRows), nil
}

// diagLogRowRef is a package-local copy of the fields pollScope needs from
// opnsense's unexported diagLogRow, so the rest of this file never has to name
// that type.
type diagLogRowRef struct {
	Timestamp   string
	Facility    int
	Severity    string
	ProcessName string
	Pid         string
	Line        string
}

// emitNewRows walks rows (newest-first, as the server returns them), builds a
// Record for every row newer than cur's cursor or matching-but-undeduped at
// the boundary, and advances cur to the newest epoch seen. Must be called with
// s.mu unlocked; it takes the lock itself around cursor reads/writes.
func (s *diagLogSource) emitNewRows(scope options.DiagLogScope, cur *diagLogCursor, rows []diagLogRowRef) []Record {
	if len(rows) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	records := make([]Record, 0, len(rows))
	var newestEpoch = cur.LastEpoch
	newestKeys := map[string]struct{}{}

	// Rows arrive newest-first; walk oldest-first instead so the emitted
	// stream (and the eventual Loki view) reads chronologically, and so ties
	// at the same epoch are processed in the order the box reported them.
	for i := len(rows) - 1; i >= 0; i-- {
		row := rows[i]
		epoch, ok := parseDiagLogTimestamp(row.Timestamp)
		if !ok {
			s.log.Debug("diaglog: unparseable row timestamp; skipping", "module", scope.Module, "scope", scope.Scope, "timestamp", row.Timestamp)
			continue
		}
		if epoch < cur.LastEpoch {
			continue // older than the cursor; the inclusive bound can still return trailing rows like this
		}
		dk := diagLogDedupeKey(row)
		if epoch == cur.LastEpoch {
			if _, seen := cur.seenAtCursor[dk]; seen {
				continue
			}
		}
		records = append(records, s.buildRecord(scope, row, epoch))

		if epoch > newestEpoch {
			newestEpoch = epoch
			newestKeys = map[string]struct{}{dk: {}}
		} else if epoch == newestEpoch {
			newestKeys[dk] = struct{}{}
		}
	}

	if newestEpoch > cur.LastEpoch {
		cur.LastEpoch = newestEpoch
		cur.seenAtCursor = newestKeys
	} else if newestEpoch == cur.LastEpoch && len(newestKeys) > 0 {
		if cur.seenAtCursor == nil {
			cur.seenAtCursor = map[string]struct{}{}
		}
		for k := range newestKeys {
			cur.seenAtCursor[k] = struct{}{}
		}
	}

	return records
}

// buildRecord converts one row into a Record, tagging module/scope/process/pid
// attributes and, for the audit scope's config-change lines, structured
// user/revision/uri fields.
func (s *diagLogSource) buildRecord(scope options.DiagLogScope, row diagLogRowRef, epoch int64) Record {
	attrs := map[string]string{
		"module": scope.Module,
		"scope":  scope.Scope,
	}
	if row.ProcessName != "" {
		attrs["process_name"] = row.ProcessName
	}
	if row.Pid != "" {
		attrs["pid"] = row.Pid
	}
	attrs["facility"] = fmt.Sprintf("%d", row.Facility)

	if scope.Scope == "audit" {
		if m := diagLogAuditConfigChange.FindStringSubmatch(row.Line); m != nil {
			attrs["config_user"] = m[1]
			attrs["config_revision"] = m[2]
			attrs["config_uri"] = m[3]
		}
	}

	return Record{
		Timestamp:  time.Unix(epoch, 0).UTC(),
		Body:       strings.TrimSpace(row.Line),
		Attributes: attrs,
		Severity:   diagLogSeverityMap[row.Severity],
	}
}

// parseDiagLogTimestamp parses the diagnostics-log naive wall-clock timestamp
// ("2026-07-13T20:22:11") as UTC — see opnsense.FetchDiagLog's doc comment on
// why (mirrors the box's own naive parsing) and its known limitation on a
// non-UTC box.
func parseDiagLogTimestamp(ts string) (int64, bool) {
	t, err := time.Parse("2006-01-02T15:04:05", ts)
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

// diagLogDedupeKey identifies one row for boundary-second dedup. Rnum is
// deliberately excluded: OPNsense's own row-number counter is a per-request
// ordinal over every line scanned (matching or not), not a stable id, so the
// same historical line gets a different rnum on every poll.
func diagLogDedupeKey(row diagLogRowRef) string {
	return row.Timestamp + "|" + row.ProcessName + "|" + row.Pid + "|" + row.Line
}

// LoadState restores every scope's cursor from a previously persisted blob.
// Unknown/missing scopes (a fresh install, or a scope added to --logs.scopes
// since the state file was written) simply bootstrap on their first Poll, per
// the usual "not yet bootstrapped" path.
func (s *diagLogSource) LoadState(data []byte) {
	if len(data) == 0 {
		return
	}
	var blob map[string]int64
	if err := json.Unmarshal(data, &blob); err != nil {
		s.log.Warn("diaglog: state blob is corrupt; every scope resumes from now", "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, epoch := range blob {
		s.cursors[key] = &diagLogCursor{LastEpoch: epoch}
	}
}

// SaveState snapshots every scope's cursor (LastEpoch only; the boundary dedup
// set is intentionally not persisted — a restart already accepts at-most-once
// semantics, so a handful of possible boundary-second duplicates right after a
// restart is an acceptable, documented tradeoff, not a bug).
func (s *diagLogSource) SaveState() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cursors) == 0 {
		return nil, false
	}
	blob := make(map[string]int64, len(s.cursors))
	for key, cur := range s.cursors {
		if cur.LastEpoch == 0 {
			continue
		}
		blob[key] = cur.LastEpoch
	}
	if len(blob) == 0 {
		return nil, false
	}
	data, err := json.Marshal(blob)
	if err != nil {
		return nil, false
	}
	return data, true
}
