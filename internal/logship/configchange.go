package logship

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// configChangeSourceName is the stable source identity used for the persisted
// cursor and the OTLP resource's opnsense.source attribute.
const configChangeSourceName = "configchange"

// configChangeMaxBodyBytes leaves a deliberately source-specific bound below
// the pipeline-wide record limit. A configuration diff is useful evidence, but
// one unexpectedly broad change must not consume the whole bounded queue.
const configChangeMaxBodyBytes = 192 * 1024

// configChangeTruncationMarker is included in the cap, so an operator can tell
// a deliberately shortened diff from an upstream diff that happened to end.
const configChangeTruncationMarker = "\n[config diff truncated at 192 KiB]"

// ConfigChangeRevision is the subset of one backup-history row needed by the
// source. The application wiring adapts opnsense.ConfigBackupRevision to this
// type so logship does not make opnsense depend on an internal package.
type ConfigChangeRevision struct {
	ID        string
	Timestamp time.Time
	User      string
	// Description is the backup revision's human-readable context. OPNsense
	// writes the request URI as its first whitespace-delimited token, followed
	// by a localized "made changes" phrase; URI is preferred when an adapter
	// can supply it directly.
	Description string
	URI         string
}

// ConfigChangeFetcher is the narrow API seam for the config-change source.
// FetchConfigChangeRevisions returns the current retained backup history; its
// order is immaterial because the source orders it by timestamp and ID. The
// diff route's host argument is always "this", the local firewall provider.
type ConfigChangeFetcher interface {
	FetchConfigChangeRevisions(context.Context) ([]ConfigChangeRevision, error)
	FetchConfigChangeDiff(ctx context.Context, host, oldRevision, newRevision string) (string, error)
}

type opnsenseConfigChangeFetcher struct{ client *opnsense.Client }

func (f opnsenseConfigChangeFetcher) FetchConfigChangeRevisions(ctx context.Context) ([]ConfigChangeRevision, error) {
	revisions, apiErr := f.client.WithContext(ctx).FetchConfigBackupRevisions()
	if apiErr != nil {
		return nil, apiErr
	}
	result := make([]ConfigChangeRevision, 0, len(revisions))
	for _, revision := range revisions {
		result = append(result, ConfigChangeRevision{
			ID:          revision.ID,
			Timestamp:   revision.Timestamp,
			User:        revision.User,
			Description: revision.Description,
		})
	}
	return result, nil
}

func (f opnsenseConfigChangeFetcher) FetchConfigChangeDiff(ctx context.Context, host, oldRevision, newRevision string) (string, error) {
	diff, apiErr := f.client.WithContext(ctx).FetchConfigBackupDiff(host, oldRevision, newRevision)
	if apiErr != nil {
		return "", apiErr
	}
	return diff, nil
}

func init() {
	RegisterSource(func(deps Deps) (Source, error) {
		if !options.LogsConfigChangeEnabled() {
			return nil, nil
		}
		return NewConfigChangeSource(opnsenseConfigChangeFetcher{client: deps.Client}, deps.Logger), nil
	})
}

// configChangeCursor is persisted under the configchange StatefulSource key.
// A revision filename is the route's stable identity; timestamps are not used as
// the cursor because backup files can share a whole-second revision timestamp.
type configChangeCursor struct {
	LastRevision string `json:"last_revision"`
}

// ConfigChangeSource emits one Record for each revision added after its cursor.
// It has intentionally conservative bootstrap and retention behaviour: a fresh
// source seeds itself from the latest retained revision, and a persisted cursor
// no longer present in the bounded history is likewise advanced to latest.
// Neither case replays historical configuration content. This is at-most-once
// across restarts when --logs.state-file is usable; as with every logship source,
// a cursor can be persisted after queue admission but before sink acknowledgement,
// so delivery is never claimed to be exactly-once.
type ConfigChangeSource struct {
	client ConfigChangeFetcher
	log    *slog.Logger

	mu           sync.Mutex
	lastRevision string
}

// NewConfigChangeSource exposes the source for tests and alternate embeddings.
// The package's init registration adapts the public OPNsense client to this
// narrow fetcher interface without creating an import cycle.
func NewConfigChangeSource(client ConfigChangeFetcher, log *slog.Logger) *ConfigChangeSource {
	if log == nil {
		log = slog.Default()
	}
	return &ConfigChangeSource{client: client, log: log}
}

// Name implements Source.
func (s *ConfigChangeSource) Name() string { return configChangeSourceName }

// Poll implements Source. A baseline does not emit a diff because the endpoint
// needs a predecessor and replaying the retained backup window on enablement
// would turn old changes into new events.
func (s *ConfigChangeSource) Poll(ctx context.Context) ([]Record, error) {
	revisions, err := s.client.FetchConfigChangeRevisions(ctx)
	if err != nil {
		return nil, err
	}
	if len(revisions) == 0 {
		return nil, nil
	}

	ordered := append([]ConfigChangeRevision(nil), revisions...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Timestamp.Equal(ordered[j].Timestamp) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Timestamp.Before(ordered[j].Timestamp)
	})

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastRevision == "" {
		s.lastRevision = ordered[len(ordered)-1].ID
		return nil, nil
	}

	previousIndex := -1
	for i, revision := range ordered {
		if revision.ID == s.lastRevision {
			previousIndex = i
			break
		}
	}
	if previousIndex == -1 {
		// History has a retention bound. Without the prior revision the first
		// unified diff cannot be reconstructed, and emitting retained rows risks
		// replaying old changes after a restore, so safely re-baseline instead.
		s.log.Warn("config-change log source cursor is no longer in backup history; re-baselining without replay",
			"last_revision", s.lastRevision, "latest_revision", ordered[len(ordered)-1].ID)
		s.lastRevision = ordered[len(ordered)-1].ID
		return nil, nil
	}

	records := make([]Record, 0, len(ordered)-previousIndex-1)
	for i := previousIndex + 1; i < len(ordered); i++ {
		previous, current := ordered[i-1], ordered[i]
		diff, err := s.client.FetchConfigChangeDiff(ctx, "this", previous.ID, current.ID)
		if err != nil {
			// Do not advance the cursor after a partial batch. Retrying the same
			// sequence next poll preserves one record per observed revision.
			return nil, fmt.Errorf("fetch config diff %q to %q: %w", previous.ID, current.ID, err)
		}
		records = append(records, configChangeRecord(current, diff))
	}

	// Advance only once every diff is available. The pipeline owns delivery and
	// persistence; this cursor means this source will not fetch the same diff on
	// a later successful poll.
	s.lastRevision = ordered[len(ordered)-1].ID
	return records, nil
}

// LoadState implements StatefulSource. Corrupt, empty and incomplete state is
// intentionally a fresh baseline rather than a history replay.
func (s *ConfigChangeSource) LoadState(data []byte) {
	var state configChangeCursor
	if len(data) == 0 || json.Unmarshal(data, &state) != nil || state.LastRevision == "" {
		return
	}
	s.mu.Lock()
	s.lastRevision = state.LastRevision
	s.mu.Unlock()
}

// SaveState implements StatefulSource. The pipeline atomically flushes this
// cursor every 30 seconds and on shutdown when --logs.state-file is configured.
func (s *ConfigChangeSource) SaveState() ([]byte, bool) {
	s.mu.Lock()
	lastRevision := s.lastRevision
	s.mu.Unlock()
	if lastRevision == "" {
		return nil, false
	}
	data, err := json.Marshal(configChangeCursor{LastRevision: lastRevision})
	if err != nil {
		return nil, false
	}
	return data, true
}

func configChangeRecord(revision ConfigChangeRevision, diff string) Record {
	return Record{
		Timestamp: revision.Timestamp,
		Body:      truncateConfigChangeDiff(redactConfigChangeDiff(html.UnescapeString(diff))),
		Attributes: map[string]string{
			"revision": revision.ID,
			"user":     revision.User,
			"uri":      configChangeURI(revision),
		},
	}
}

func configChangeURI(revision ConfigChangeRevision) string {
	if revision.URI != "" {
		return revision.URI
	}
	for _, field := range strings.Fields(revision.Description) {
		if strings.HasPrefix(field, "/") {
			return field
		}
	}
	return ""
}

func truncateConfigChangeDiff(diff string) string {
	if len(diff) <= configChangeMaxBodyBytes {
		return diff
	}
	prefixEnd := configChangeMaxBodyBytes - len(configChangeTruncationMarker)
	// html.UnescapeString returns valid UTF-8 for valid input. Preserve that
	// property when the byte budget happens to bisect a multibyte rune.
	for prefixEnd > 0 && !utf8.RuneStart(diff[prefixEnd]) {
		prefixEnd--
	}
	return diff[:prefixEnd] + configChangeTruncationMarker
}

var _ Source = (*ConfigChangeSource)(nil)
var _ StatefulSource = (*ConfigChangeSource)(nil)

// configChangeRedactionMarker replaces the value of any config.xml element whose
// name names a credential. The element itself is kept: an operator reading the
// diff still needs to see THAT a WireGuard key or a RADIUS secret changed, and
// on which revision, without the value leaving the firewall.
const configChangeRedactionMarker = "[redacted]"

// redactConfigChangeDiff strips credential values out of an upstream config.xml
// unified diff before it becomes a shipped log body.
//
// The diff is the whole point of this source, and a config.xml diff carries user
// password hashes, API keys and secrets, WireGuard and IPsec private keys, RADIUS
// shared secrets and certificate private halves whenever those sections change.
// Shipping it verbatim would hand every credential on the firewall to whoever can
// read the log backend, so the element vocabulary is shared with the config
// snapshot path via opnsense.SensitiveConfigKey rather than duplicated.
//
// Redaction runs BEFORE truncation so a body that is later cut short has already
// had its secrets removed, and so the truncation bound is measured against what
// is actually shipped.
//
// The scanner tracks an element left open at the end of a line to handle
// multiline XML values. Diff prefixes may change while the element remains
// open. Each side has its own state: a removed closing tag does not close the
// added value. Context lines are scrubbed against both sides, and a hunk header
// clears both. Over-redaction is the safe direction here.
func redactConfigChangeDiff(diff string) string {
	lines := strings.Split(diff, "\n")
	var (
		b              strings.Builder
		oldTag, newTag string
	)
	b.Grow(len(diff))
	for i, line := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		if strings.HasPrefix(line, "@@") {
			oldTag, newTag = "", ""
			b.WriteString(line)
			continue
		}
		var prefix byte
		body := line
		if len(line) > 0 && (line[0] == '+' || line[0] == '-' || line[0] == ' ') {
			prefix, body = line[0], line[1:]
		}
		var redacted string
		switch prefix {
		case '-':
			redacted, oldTag = redactConfigDiffBody(body, oldTag)
		case '+':
			redacted, newTag = redactConfigDiffBody(body, newTag)
		default:
			var oldBody, newBody string
			oldBody, oldTag = redactConfigDiffBody(body, oldTag)
			newBody, newTag = redactConfigDiffBody(body, newTag)
			switch {
			case oldBody == newBody, newBody == body:
				redacted = oldBody
			case oldBody == body:
				redacted = newBody
			default:
				// Both sides removed different spans. Their intersection is not
				// safe to infer from rewritten offsets, so suppress this line.
				redacted = configChangeRedactionMarker
			}
		}
		if prefix != 0 {
			b.WriteByte(prefix)
		}
		b.WriteString(redacted)
	}
	return b.String()
}

// redactConfigDiffBody redacts one diff line's content, carrying in and out the
// name of a sensitive element left unterminated by the previous line.
func redactConfigDiffBody(body, openTag string) (string, string) {
	var b strings.Builder
	for i := 0; i < len(body); {
		if openTag != "" {
			closing := "</" + openTag + ">"
			idx := strings.Index(body[i:], closing)
			if idx < 0 {
				b.WriteString(configChangeRedactionMarker)
				return b.String(), openTag
			}
			b.WriteString(configChangeRedactionMarker)
			b.WriteString(closing)
			i += idx + len(closing)
			openTag = ""
			continue
		}
		lt := strings.IndexByte(body[i:], '<')
		if lt < 0 {
			b.WriteString(body[i:])
			break
		}
		b.WriteString(body[i : i+lt])
		i += lt
		gt := strings.IndexByte(body[i:], '>')
		if gt < 0 {
			b.WriteString(body[i:])
			break
		}
		tag := body[i : i+gt+1]
		b.WriteString(tag)
		i += gt + 1

		name := strings.TrimSuffix(strings.TrimPrefix(tag, "<"), ">")
		// A closing, self-closing, comment or processing-instruction tag opens
		// nothing, so none of them can start a sensitive element.
		if name == "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "!") ||
			strings.HasPrefix(name, "?") || strings.HasSuffix(name, "/") {
			continue
		}
		if cut := strings.IndexAny(name, " \t"); cut >= 0 {
			name = name[:cut]
		}
		if opnsense.SensitiveConfigKey(name) {
			openTag = name
		}
	}
	return b.String(), openTag
}
