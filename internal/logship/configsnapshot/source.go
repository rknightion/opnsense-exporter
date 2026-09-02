// Package configsnapshot ships opt-in, per-family configuration snapshots as
// compact JSON records. It is intentionally a sibling of logship: the root
// imports it for registration, while it reuses logship's source/persistence
// contracts rather than creating a competing poller.
package configsnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

const (
	sourceName   = "configstate"
	subsystem    = "config"
	schema       = "opnsense.config.snapshot.v1"
	heartbeat    = 6 * time.Hour
	maxBodyBytes = 196608
	stateSchema  = 1
)

// Entity is one stable member of a configuration family. Value must be JSON
// marshalable; providers keep it to the upstream-produced shape they support.
type Entity struct {
	ID    string
	Value any
}

// Provider returns the full present state of one independently deduplicated
// family. Family names are closed by the source constructors, not user input.
type Provider interface {
	Family() string
	Snapshot(context.Context) ([]Entity, error)
}

// heartbeatProvider is an optional future-family override. Most families use
// the frozen six-hour cadence; the security-posture family has a separately
// decided seven-day cadence without duplicating this framework.
type heartbeatProvider interface {
	Heartbeat() time.Duration
}

type familyState struct {
	Hash          string    `json:"hash"`
	LastEmittedAt time.Time `json:"last_emitted_at"`
}

type persistedState struct {
	Schema   int                    `json:"schema"`
	Families map[string]familyState `json:"families"`
}

type source struct {
	providers []Provider
	now       func() time.Time
	newID     func() string

	mu       sync.Mutex
	families map[string]familyState
}

func newSource(providers []Provider, now func() time.Time, newID func() string) *source {
	return &source{
		providers: providers,
		now:       now,
		newID:     newID,
		families:  make(map[string]familyState),
	}
}

func (s *source) Name() string { return sourceName }

// Poll canonicalises each family before deciding whether to emit. A successful
// poll is committed to the cursor only after every record body is built, so an
// oversized entity cannot leave a half-advanced hash behind.
func (s *source) Poll(ctx context.Context) ([]logship.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	var records []logship.Record
	nextFamilies := make(map[string]familyState, len(s.families)+len(s.providers))
	for family, state := range s.families {
		nextFamilies[family] = state
	}
	for _, provider := range s.providers {
		entities, err := provider.Snapshot(ctx)
		if err != nil {
			return nil, err
		}
		ordered, canonical, err := canonicalEntities(provider.Family(), entities)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(canonical)
		hash := hex.EncodeToString(digest[:])
		previous, seen := nextFamilies[provider.Family()]
		reason := "change"
		if seen && previous.Hash == hash {
			if now.Sub(previous.LastEmittedAt) < providerHeartbeat(provider) {
				continue
			}
			reason = "heartbeat"
		}

		batchID := s.newID()
		batch := make([]logship.Record, 0, len(ordered))
		for i, entity := range ordered {
			body, truncated, err := recordBody(provider.Family(), entity)
			if err != nil {
				return nil, err
			}
			attrs := map[string]string{
				logship.AttrSubsystem: subsystem,
				"snapshot.id":         batchID,
				"snapshot.seq":        strconv.Itoa(i + 1),
				"snapshot.total":      strconv.Itoa(len(ordered)),
				"snapshot.family":     provider.Family(),
				"snapshot.reason":     reason,
				"snapshot.entity_id":  entity.ID,
			}
			if truncated {
				attrs["snapshot.truncated"] = "true"
			}
			batch = append(batch, logship.Record{Body: string(body), Attributes: attrs})
		}
		// Empty family state still advances. An empty configuration is meaningful:
		// it must suppress repeated empty batches while retaining its hash.
		nextFamilies[provider.Family()] = familyState{Hash: hash, LastEmittedAt: now}
		records = append(records, batch...)
	}
	s.families = nextFamilies
	return records, nil
}

func providerHeartbeat(provider Provider) time.Duration {
	if override, ok := provider.(heartbeatProvider); ok && override.Heartbeat() > 0 {
		return override.Heartbeat()
	}
	return heartbeat
}

func canonicalEntities(family string, entities []Entity) ([]Entity, []byte, error) {
	ordered := append([]Entity(nil), entities...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	// The length delimiter makes a canonical stream unambiguous even where two
	// adjacent valid JSON values would otherwise concatenate to the same bytes.
	var stream []byte
	for i, entity := range ordered {
		if i > 0 && ordered[i-1].ID == entity.ID {
			return nil, nil, fmt.Errorf("%s snapshot contains duplicate entity id %q", family, entity.ID)
		}
		body, err := normalBody(family, entity)
		if err != nil {
			return nil, nil, err
		}
		stream = strconv.AppendInt(stream, int64(len(body)), 10)
		stream = append(stream, ':')
		stream = append(stream, body...)
	}
	return ordered, stream, nil
}

type normalEnvelope struct {
	Schema    string `json:"schema"`
	Family    string `json:"family"`
	EntityID  string `json:"entity_id"`
	Entity    any    `json:"entity"`
	Truncated bool   `json:"truncated"`
}

type truncatedEnvelope struct {
	Schema        string `json:"schema"`
	Family        string `json:"family"`
	EntityID      string `json:"entity_id"`
	Entity        any    `json:"entity"`
	Truncated     bool   `json:"truncated"`
	OriginalBytes int    `json:"original_bytes"`
	ContentSHA256 string `json:"content_sha256"`
}

func normalBody(family string, entity Entity) ([]byte, error) {
	return json.Marshal(normalEnvelope{
		Schema: schema, Family: family, EntityID: entity.ID, Entity: entity.Value,
	})
}

func recordBody(family string, entity Entity) ([]byte, bool, error) {
	body, err := normalBody(family, entity)
	if err != nil || len(body) <= maxBodyBytes {
		return body, false, err
	}
	digest := sha256.Sum256(body)
	fallback, err := json.Marshal(truncatedEnvelope{
		Schema:        schema,
		Family:        family,
		EntityID:      entity.ID,
		Entity:        nil,
		Truncated:     true,
		OriginalBytes: len(body),
		ContentSHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return nil, false, err
	}
	return fallback, true, nil
}

// LoadState restores only a complete current-version state blob. A malformed
// file intentionally behaves like no file, matching the other StatefulSource
// implementations: the next successful poll publishes a fresh snapshot.
func (s *source) LoadState(data []byte) {
	var persisted persistedState
	if json.Unmarshal(data, &persisted) != nil || persisted.Schema != stateSchema || persisted.Families == nil {
		return
	}
	s.mu.Lock()
	s.families = persisted.Families
	s.mu.Unlock()
}

func (s *source) SaveState() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.families) == 0 {
		return nil, false
	}
	data, err := json.Marshal(persistedState{Schema: stateSchema, Families: s.families})
	if err != nil {
		return nil, false
	}
	return data, true
}

var _ logship.Source = (*source)(nil)
var _ logship.StatefulSource = (*source)(nil)
