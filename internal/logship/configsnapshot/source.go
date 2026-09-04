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
	// Provider state is an optional extension to schema 1. Keeping the version
	// unchanged lets older binaries continue to restore the family cursor when
	// a state file written by a newer binary is encountered.
	stateSchema = 1
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

// snapshotCommitter lets a provider defer observation-only cursor changes until
// every provider and record body in the source poll has succeeded. Providers that
// do not carry their own cursor need not implement it.
type snapshotCommitter interface {
	CommitSnapshot()
}

// providerStateful is an optional persistence seam for providers with
// observation-only state in addition to the source's family cursor. The source
// calls these methods while holding its poll/state mutex, so the provider state
// and family state are saved and restored as one source-state operation.
type providerStateful interface {
	Provider
	LoadState([]byte)
	SaveState() ([]byte, bool)
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
	// Providers is decoded separately so a malformed optional provider entry
	// cannot invalidate an otherwise usable family cursor.
	Providers json.RawMessage `json:"providers,omitempty"`
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
	for _, provider := range s.providers {
		if committer, ok := provider.(snapshotCommitter); ok {
			committer.CommitSnapshot()
		}
	}
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
		body, err := canonicalBody(family, entity)
		if err != nil {
			return nil, nil, err
		}
		stream = strconv.AppendInt(stream, int64(len(body)), 10)
		stream = append(stream, ':')
		stream = append(stream, body...)
	}
	return ordered, stream, nil
}

// canonicalBody permits a family to mark emission-only fields that must not
// turn a stable snapshot into a synthetic content change. The normal record
// body remains untouched, so the field is still available to downstream
// consumers on the first emitted entity.
func canonicalBody(family string, entity Entity) ([]byte, error) {
	value := entity.Value
	if canonicalizer, ok := value.(interface{ snapshotCanonicalValue() any }); ok {
		value = canonicalizer.snapshotCanonicalValue()
	}
	return normalBody(family, Entity{ID: entity.ID, Value: value})
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

// LoadState restores a complete state blob from the current schema, including
// the family-only form written before provider state was added.
// A malformed file intentionally behaves like no file, matching the other
// StatefulSource implementations: the next successful poll publishes a fresh
// snapshot. The optional provider envelope is decoded independently so a bad
// provider cursor cannot discard a valid family cursor.
func (s *source) LoadState(data []byte) {
	var persisted persistedState
	if json.Unmarshal(data, &persisted) != nil || persisted.Schema != stateSchema || persisted.Families == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.families = persisted.Families
	loadProviderStates(s.providers, persisted.Providers)
}

func (s *source) SaveState() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.families) == 0 {
		return nil, false
	}
	persisted := persistedState{Schema: stateSchema, Families: s.families}
	providerStates := make(map[string]json.RawMessage)
	for _, provider := range s.providers {
		stateful, ok := provider.(providerStateful)
		if !ok {
			continue
		}
		data, ok := stateful.SaveState()
		if !ok {
			continue
		}
		if !json.Valid(data) {
			// Provider state is part of this source's one state blob. Do not
			// persist a family cursor without it, because that would restore
			// an incomplete restart baseline.
			return nil, false
		}
		providerStates[provider.Family()] = json.RawMessage(append([]byte(nil), data...))
	}
	if len(providerStates) > 0 {
		data, err := json.Marshal(providerStates)
		if err != nil {
			return nil, false
		}
		persisted.Providers = data
	}
	data, err := json.Marshal(persisted)
	if err != nil {
		return nil, false
	}
	return data, true
}

// loadProviderStates treats the optional provider envelope independently from
// the family cursor. A malformed provider entry therefore has the same safe
// fallback as a malformed provider's own state: that provider starts fresh,
// while a valid family hash and timestamp remain usable.
func loadProviderStates(providers []Provider, data json.RawMessage) {
	if len(data) == 0 {
		return
	}
	var states map[string]json.RawMessage
	if json.Unmarshal(data, &states) != nil || states == nil {
		return
	}
	for _, provider := range providers {
		stateful, ok := provider.(providerStateful)
		if !ok {
			continue
		}
		state, ok := states[provider.Family()]
		if !ok {
			continue
		}
		stateful.LoadState(append([]byte(nil), state...))
	}
}

var _ logship.Source = (*source)(nil)
var _ logship.StatefulSource = (*source)(nil)
