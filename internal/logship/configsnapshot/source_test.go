package configsnapshot

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

type fakeProvider struct {
	family   string
	entities []Entity
	err      error
}

type sequenceProvider struct {
	family string
	values [][]Entity
	index  int
}

func (p *sequenceProvider) Family() string { return p.family }

func (p *sequenceProvider) Snapshot(context.Context) ([]Entity, error) {
	if len(p.values) == 0 {
		return nil, nil
	}
	index := p.index
	if index >= len(p.values) {
		index = len(p.values) - 1
	}
	p.index++
	return p.values[index], nil
}

func (p *fakeProvider) Family() string { return p.family }

func (p *fakeProvider) Snapshot(context.Context) ([]Entity, error) {
	return p.entities, p.err
}

func TestSourceChangeDedupHeartbeatAndStableBatchMetadata(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	p := &fakeProvider{family: "firewall", entities: []Entity{
		{ID: "filter_rule:b", Value: map[string]any{"kind": "filter_rule", "description": "B"}},
		{ID: "filter_rule:a", Value: map[string]any{"kind": "filter_rule", "description": "A"}},
	}}
	batch := 0
	s := newSource([]Provider{p}, func() time.Time { return now }, func() string {
		batch++
		return "snapshot-" + string(rune('0'+batch))
	})
	if got := s.Name(); got != sourceName {
		t.Fatalf("Name() = %q, want %q", got, sourceName)
	}

	first, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first Poll emitted %d records, want 2", len(first))
	}
	assertBatch(t, first, "snapshot-1", "change", []string{"filter_rule:a", "filter_rule:b"})

	now = now.Add(time.Hour)
	second, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("unchanged Poll: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("unchanged Poll emitted %d records, want 0", len(second))
	}

	now = now.Add(5 * time.Hour)
	heartbeat, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("heartbeat Poll: %v", err)
	}
	if len(heartbeat) != 2 {
		t.Fatalf("heartbeat Poll emitted %d records, want 2", len(heartbeat))
	}
	assertBatch(t, heartbeat, "snapshot-2", "heartbeat", []string{"filter_rule:a", "filter_rule:b"})

	p.entities[0].Value = map[string]any{"kind": "filter_rule", "description": "changed"}
	now = now.Add(time.Minute)
	changed, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("changed Poll: %v", err)
	}
	if len(changed) != 2 {
		t.Fatalf("changed Poll emitted %d records, want 2", len(changed))
	}
	assertBatch(t, changed, "snapshot-3", "change", []string{"filter_rule:a", "filter_rule:b"})
}

func TestSourceIgnoresDeviceInventoryNewMarkerForContentHash(t *testing.T) {
	provider := &sequenceProvider{
		family: "device_inventory",
		values: [][]Entity{
			{{ID: "mac:aa:bb:cc:dd:ee:01", Value: DeviceInventoryRecord{
				MAC: "aa:bb:cc:dd:ee:01", IPs: []string{"192.0.2.10"}, NewDevice: true,
			}}},
			{{ID: "mac:aa:bb:cc:dd:ee:01", Value: DeviceInventoryRecord{
				MAC: "aa:bb:cc:dd:ee:01", IPs: []string{"192.0.2.10"}, NewDevice: false,
			}}},
		},
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	source := newSource([]Provider{provider}, func() time.Time { return now }, func() string { return "batch" })

	first, err := source.Poll(context.Background())
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("first Poll emitted %d records, want 1", len(first))
	}
	var envelope struct {
		Entity DeviceInventoryRecord `json:"entity"`
	}
	if err := json.Unmarshal([]byte(first[0].Body), &envelope); err != nil {
		t.Fatalf("first body is invalid JSON: %v", err)
	}
	if !envelope.Entity.NewDevice {
		t.Fatal("first body lost new_device=true marker")
	}

	second, err := source.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if len(second) != 0 {
		t.Fatalf("second Poll emitted %d records for marker-only change, want 0", len(second))
	}
}

func TestSourceDoesNotConsumeNewDeviceMarkerWhenLaterProviderFails(t *testing.T) {
	device := newDeviceInventoryProviderWithFetcher(&fakeDeviceInventoryFetcher{
		observations: []DeviceInventoryObservation{{
			Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10",
		}},
	})
	later := &fakeProvider{family: "later", err: errors.New("later provider failed")}
	source := newSource([]Provider{device, later}, time.Now, func() string { return "batch" })

	if _, err := source.Poll(context.Background()); err == nil {
		t.Fatal("first Poll succeeded despite later provider failure")
	}
	later.err = nil
	later.entities = []Entity{{ID: "later", Value: map[string]any{"ok": true}}}
	records, err := source.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	var found bool
	for _, record := range records {
		if record.Attributes["snapshot.family"] != deviceInventoryFamily {
			continue
		}
		found = true
		var envelope struct {
			Entity DeviceInventoryRecord `json:"entity"`
		}
		if err := json.Unmarshal([]byte(record.Body), &envelope); err != nil {
			t.Fatalf("device body is invalid JSON: %v", err)
		}
		if !envelope.Entity.NewDevice {
			t.Fatal("failed poll consumed the new_device marker")
		}
	}
	if !found {
		t.Fatal("successful retry emitted no device-inventory record")
	}
}

func TestSourceStateRoundTripSuppressesUnchangedFamily(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	p := &fakeProvider{family: "firewall", entities: []Entity{{ID: "filter_rule:a", Value: map[string]any{"kind": "filter_rule"}}}}
	s := newSource([]Provider{p}, func() time.Time { return now }, func() string { return "snapshot-1" })
	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	state, ok := s.SaveState()
	if !ok {
		t.Fatal("SaveState returned ok=false after a successful snapshot")
	}

	restored := newSource([]Provider{p}, func() time.Time { return now.Add(time.Hour) }, func() string { return "snapshot-2" })
	restored.LoadState(state)
	records, err := restored.Poll(context.Background())
	if err != nil {
		t.Fatalf("restored Poll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("restored unchanged Poll emitted %d records, want 0", len(records))
	}
}

func TestSourceStateRoundTripRestoresDeviceInventorySeenIdentities(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	initialFetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"},
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:02", IP: "192.0.2.11"},
	}}
	initialProvider := newDeviceInventoryProviderWithFetcher(initialFetcher)
	initial := newSource([]Provider{initialProvider}, func() time.Time { return now }, func() string { return "snapshot-1" })
	if _, err := initial.Poll(context.Background()); err != nil {
		t.Fatalf("initial Poll: %v", err)
	}
	state, ok := initial.SaveState()
	if !ok {
		t.Fatal("SaveState returned ok=false after the initial device snapshot")
	}

	restartedFetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"},
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:02", IP: "192.0.2.11"},
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:03", IP: "192.0.2.12"},
	}}
	restartedProvider := newDeviceInventoryProviderWithFetcher(restartedFetcher)
	restarted := newSource([]Provider{restartedProvider}, func() time.Time { return now.Add(time.Minute) }, func() string { return "snapshot-2" })
	restarted.LoadState(state)

	records, err := restarted.Poll(context.Background())
	if err != nil {
		t.Fatalf("restarted Poll: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("restarted Poll emitted %d records, want 3 for the one-device change", len(records))
	}
	for _, record := range records {
		var envelope struct {
			Entity DeviceInventoryRecord `json:"entity"`
		}
		if err := json.Unmarshal([]byte(record.Body), &envelope); err != nil {
			t.Fatalf("device body is invalid JSON: %v", err)
		}
		wantNew := record.Attributes["snapshot.entity_id"] == "mac:aa:bb:cc:dd:ee:03"
		if envelope.Entity.NewDevice != wantNew {
			t.Errorf("entity %q new_device = %v, want %v", record.Attributes["snapshot.entity_id"], envelope.Entity.NewDevice, wantNew)
		}
	}
}

func TestSourceStateDoesNotPersistPendingDeviceInventoryIdentities(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	fetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"},
	}}
	device := newDeviceInventoryProviderWithFetcher(fetcher)
	later := &fakeProvider{family: "later", entities: []Entity{{ID: "later", Value: map[string]any{"ok": true}}}}
	source := newSource([]Provider{device, later}, func() time.Time { return now }, func() string { return "batch" })
	if _, err := source.Poll(context.Background()); err != nil {
		t.Fatalf("initial Poll: %v", err)
	}
	committed, ok := source.SaveState()
	if !ok {
		t.Fatal("SaveState returned ok=false after the initial successful poll")
	}

	fetcher.observations = append(fetcher.observations, DeviceInventoryObservation{
		Source: "arp", MAC: "aa:bb:cc:dd:ee:02", IP: "192.0.2.11",
	})
	later.err = errors.New("later provider failed")
	if _, err := source.Poll(context.Background()); err == nil {
		t.Fatal("changed Poll succeeded despite a later provider failure")
	}
	current, ok := source.SaveState()
	if !ok {
		t.Fatal("SaveState returned ok=false after the failed poll")
	}
	if string(current) != string(committed) {
		t.Fatalf("failed poll changed persisted state:\n got %s\nwant %s", current, committed)
	}
}

func TestSourceLoadStateIgnoresMalformedProviderStateWithoutDroppingFamilies(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	initialFetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"},
	}}
	initial := newSource([]Provider{newDeviceInventoryProviderWithFetcher(initialFetcher)}, func() time.Time { return now }, func() string { return "batch-1" })
	if _, err := initial.Poll(context.Background()); err != nil {
		t.Fatalf("initial Poll: %v", err)
	}
	state, ok := initial.SaveState()
	if !ok {
		t.Fatal("SaveState returned ok=false after the initial device snapshot")
	}
	var persisted persistedState
	if err := json.Unmarshal(state, &persisted); err != nil {
		t.Fatalf("saved state is invalid JSON: %v", err)
	}
	persisted.Providers = json.RawMessage(`{"device_inventory":{"seen":"not-an-array"}}`)
	malformedProviderState, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal malformed provider state: %v", err)
	}

	restartedFetcher := &fakeDeviceInventoryFetcher{observations: []DeviceInventoryObservation{
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:01", IP: "192.0.2.10"},
		{Source: "arp", MAC: "aa:bb:cc:dd:ee:02", IP: "192.0.2.11"},
	}}
	restartedProvider := newDeviceInventoryProviderWithFetcher(restartedFetcher)
	restarted := newSource([]Provider{restartedProvider}, func() time.Time { return now.Add(time.Minute) }, func() string { return "batch-2" })
	restarted.LoadState(malformedProviderState)
	if got, want := restarted.families[deviceInventoryFamily], initial.families[deviceInventoryFamily]; got != want {
		t.Fatalf("malformed provider state dropped family cursor: got %+v, want %+v", got, want)
	}

	records, err := restarted.Poll(context.Background())
	if err != nil {
		t.Fatalf("restarted Poll: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("restarted Poll emitted %d records, want 2 for the changed inventory", len(records))
	}
	for _, record := range records {
		var envelope struct {
			Entity DeviceInventoryRecord `json:"entity"`
		}
		if err := json.Unmarshal([]byte(record.Body), &envelope); err != nil {
			t.Fatalf("device body is invalid JSON: %v", err)
		}
		if !envelope.Entity.NewDevice {
			t.Errorf("malformed provider state restored identity %q", record.Attributes["snapshot.entity_id"])
		}
	}
}

func TestSourceLoadStateAcceptsFamilyStateWithoutProviderState(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	p := &fakeProvider{family: "firewall", entities: []Entity{{ID: "filter_rule:a", Value: map[string]any{"kind": "filter_rule"}}}}
	initial := newSource([]Provider{p}, func() time.Time { return now }, func() string { return "batch-1" })
	if _, err := initial.Poll(context.Background()); err != nil {
		t.Fatalf("initial Poll: %v", err)
	}
	familyOnly, err := json.Marshal(persistedState{Schema: stateSchema, Families: initial.families})
	if err != nil {
		t.Fatalf("marshal family-only state: %v", err)
	}

	restarted := newSource([]Provider{p}, func() time.Time { return now.Add(time.Hour) }, func() string { return "batch-2" })
	restarted.LoadState(familyOnly)
	records, err := restarted.Poll(context.Background())
	if err != nil {
		t.Fatalf("restarted Poll: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("family-only unchanged Poll emitted %d records, want 0", len(records))
	}
}

func TestSourceOversizeEntityFallsBackToBoundedValidJSON(t *testing.T) {
	p := &fakeProvider{family: "firewall", entities: []Entity{{
		ID:    "filter_rule:large",
		Value: map[string]any{"kind": "filter_rule", "description": strings.Repeat("x", maxBodyBytes)},
	}}}
	s := newSource([]Provider{p}, time.Now, func() string { return "snapshot-1" })
	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Poll emitted %d records, want 1", len(records))
	}
	if len(records[0].Body) > maxBodyBytes {
		t.Fatalf("fallback body has %d bytes, cap is %d", len(records[0].Body), maxBodyBytes)
	}
	var body struct {
		Entity        any    `json:"entity"`
		Truncated     bool   `json:"truncated"`
		OriginalBytes int    `json:"original_bytes"`
		ContentSHA256 string `json:"content_sha256"`
	}
	if err := json.Unmarshal([]byte(records[0].Body), &body); err != nil {
		t.Fatalf("fallback body is invalid JSON: %v", err)
	}
	if body.Entity != nil || !body.Truncated || body.OriginalBytes <= maxBodyBytes || len(body.ContentSHA256) != 64 {
		t.Fatalf("fallback body = %+v, want null entity, truncated metadata and digest", body)
	}
	if got := records[0].Attributes["snapshot.truncated"]; got != "true" {
		t.Fatalf("snapshot.truncated = %q, want true", got)
	}
}

func TestSourceDoesNotAdvanceAnyFamilyStateAfterLaterProviderFailure(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	first := &fakeProvider{family: "firewall", entities: []Entity{{ID: "filter_rule:a", Value: map[string]any{"kind": "filter_rule"}}}}
	second := &fakeProvider{family: "interfaces", err: errors.New("upstream unavailable")}
	s := newSource([]Provider{first, second}, func() time.Time { return now }, func() string { return "snapshot" })

	if _, err := s.Poll(context.Background()); err == nil {
		t.Fatal("Poll succeeded despite a later provider failure")
	}

	second.err = nil
	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("retry Poll: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("retry Poll emitted %d records, want the first family's initial snapshot", len(records))
	}
}

func TestCanonicalEntitiesRejectsDuplicateIDs(t *testing.T) {
	_, _, err := canonicalEntities("firewall", []Entity{
		{ID: "filter_rule:a", Value: map[string]any{"description": "first"}},
		{ID: "filter_rule:a", Value: map[string]any{"description": "second"}},
	})
	if err == nil {
		t.Fatal("canonicalEntities accepted duplicate entity IDs")
	}
}

func assertBatch(t *testing.T, records []logship.Record, id, reason string, ids []string) {
	t.Helper()
	for i, wantEntityID := range ids {
		r := records[i]
		if got := r.Attributes["snapshot.id"]; got != id {
			t.Errorf("record %d snapshot.id = %q, want %q", i, got, id)
		}
		if got := r.Attributes["snapshot.seq"]; got != string(rune('1'+i)) {
			t.Errorf("record %d snapshot.seq = %q, want %d", i, got, i+1)
		}
		if got := r.Attributes["snapshot.total"]; got != "2" {
			t.Errorf("record %d snapshot.total = %q, want 2", i, got)
		}
		if got := r.Attributes["snapshot.reason"]; got != reason {
			t.Errorf("record %d snapshot.reason = %q, want %q", i, got, reason)
		}
		if got := r.Attributes["snapshot.entity_id"]; got != wantEntityID {
			t.Errorf("record %d entity id = %q, want %q", i, got, wantEntityID)
		}
		if got := r.Attributes["opnsense.subsystem"]; got != "config" {
			t.Errorf("record %d subsystem = %q, want config", i, got)
		}
	}
}
