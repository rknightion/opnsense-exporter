package geoip

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// checkStateFile is the per-edition "when did we last ask MaxMind?" record, kept in
// the download directory beside the databases it describes.
//
// It exists because the installed file's mtime cannot answer that question: Fetch
// deliberately stamps it with the server's Last-Modified, so the mtime is MaxMind's
// BUILD time. A database built on Tuesday and checked five minutes ago has a
// three-day-old mtime, and reusing it here would re-download on every start — which
// is the quota exhaustion this file prevents.
//
// A ".json" name beside "<Edition>.mmdb" files cannot be mistaken for a database, and
// a hand-replaced database is handled sensibly by construction: the record only ever
// defers a network check, never a load, and the reload tick picks the new file up
// regardless of what this file says.
const checkStateFile = "download-state.json"

// The recorded outcome of a check. Only these three defer the next one: all three
// mean MaxMind answered, so asking again before the interval is pure waste (or, for a
// 429, waste that cannot succeed). A transport error, a 401 or a 5xx records nothing,
// so the next start retries — none of those consume download quota.
const (
	checkResultUpdated     = "updated"
	checkResultUnmodified  = "unmodified"
	checkResultRateLimited = "rate_limited"
)

// checkRecord is one edition's last answered check.
type checkRecord struct {
	CheckedAt time.Time `json:"checked_at"`
	Result    string    `json:"result"`
}

// checkState is the on-disk document. Schema is written for a future reader; an
// unrecognised value is treated as no state at all, which costs one extra fetch.
type checkState struct {
	Schema   int                    `json:"schema"`
	Editions map[string]checkRecord `json:"editions"`
}

const checkStateSchema = 1

func checkStatePath(dir string) string { return filepath.Join(dir, checkStateFile) }

// loadCheckState reads the state document. Every failure — absent, unreadable,
// truncated, a schema from the future — returns empty state rather than an error:
// not knowing when we last checked must cost a download, never a startup failure.
func loadCheckState(dir string) checkState {
	empty := checkState{Schema: checkStateSchema, Editions: map[string]checkRecord{}}
	if dir == "" {
		return empty
	}
	raw, err := os.ReadFile(checkStatePath(dir)) //nolint:gosec // dir is operator-configured, like every other path here
	if err != nil {
		return empty
	}
	var st checkState
	if err := json.Unmarshal(raw, &st); err != nil || st.Schema != checkStateSchema {
		return empty
	}
	if st.Editions == nil {
		st.Editions = map[string]checkRecord{}
	}
	return st
}

// recordCheck stores one edition's outcome, preserving the other editions' records.
// Written to a temporary file and renamed, so a crash mid-write cannot leave a
// half-written document that reads as "never checked" for every edition.
func recordCheck(dir, edition, result string, at time.Time) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create geoip database directory %s: %w", dir, err)
	}
	st := loadCheckState(dir)
	st.Editions[edition] = checkRecord{CheckedAt: at.UTC().Truncate(time.Second), Result: result}

	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode geoip download state: %w", err)
	}
	raw = append(raw, '\n')

	f, err := os.CreateTemp(dir, ".download-state-*.json")
	if err != nil {
		return fmt.Errorf("create temporary geoip download state file: %w", err)
	}
	tmp := f.Name()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write geoip download state: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("set permissions on geoip download state: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close geoip download state: %w", err)
	}
	if err := os.Rename(tmp, checkStatePath(dir)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install geoip download state: %w", err)
	}
	return nil
}
