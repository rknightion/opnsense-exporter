package logship

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type fakeRoutingChangeFetcher struct {
	snapshots []RoutingSnapshot
	index     int
}

func (f *fakeRoutingChangeFetcher) FetchRoutingSnapshot(context.Context) (RoutingSnapshot, error) {
	if f.index >= len(f.snapshots) {
		return f.snapshots[len(f.snapshots)-1], nil
	}
	snapshot := f.snapshots[f.index]
	f.index++
	return snapshot, nil
}

func TestRoutingChangeSource_NoChangeAndGatewayHealthOnlyChangeAreSilent(t *testing.T) {
	t0 := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	now := t0
	base := routingSnapshot("198.51.100.1", opnsense.GatewayStatusOnline)
	healthOnly := routingSnapshot("198.51.100.1", opnsense.GatewayStatusOffline)
	fetcher := &fakeRoutingChangeFetcher{snapshots: []RoutingSnapshot{base, base, healthOnly}}
	source := newRoutingChangeSource(fetcher, nil, func() time.Time { return now }, time.Minute)

	if records, err := source.Poll(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("baseline poll = (%d records, %v), want no event", len(records), err)
	}
	now = now.Add(10 * time.Second)
	if records, err := source.Poll(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("unchanged poll = (%d records, %v), want no event", len(records), err)
	}
	now = now.Add(10 * time.Second)
	if records, err := source.Poll(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("dpinger-only status poll = (%d records, %v), want no event", len(records), err)
	}
}

func TestRoutingChangeSource_EmitsOneBeforeAfterDefaultRouteEvent(t *testing.T) {
	t0 := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	now := t0
	base := routingSnapshot("198.51.100.1", opnsense.GatewayStatusOnline)
	moved := routingSnapshot("198.51.100.2", opnsense.GatewayStatusOnline)
	fetcher := &fakeRoutingChangeFetcher{snapshots: []RoutingSnapshot{base, moved, moved}}
	source := newRoutingChangeSource(fetcher, nil, func() time.Time { return now }, time.Minute)

	if _, err := source.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	records, err := source.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("moved poll emitted %d records, want 1", len(records))
	}
	var event routingChangeEventBody
	if err := json.Unmarshal([]byte(records[0].Body), &event); err != nil {
		t.Fatalf("event body is not JSON: %v", err)
	}
	if event.Schema != routingChangeSchema || event.Event != routingChangeEvent || event.Family != "default_route" {
		t.Fatalf("event envelope = %#v, want routing default-route event", event)
	}
	if got := event.Before.RoutingTable.DefaultRoutes[0].Gateway; got != "198.51.100.1" {
		t.Errorf("before gateway = %q, want 198.51.100.1", got)
	}
	if got := event.After.RoutingTable.DefaultRoutes[0].Gateway; got != "198.51.100.2" {
		t.Errorf("after gateway = %q, want 198.51.100.2", got)
	}
	if event.Flap != nil {
		t.Errorf("first route movement has flap detail %#v", event.Flap)
	}
	if records[0].Attributes[AttrSubsystem] != routingChangeSubsystem {
		t.Errorf("subsystem = %q, want %q", records[0].Attributes[AttrSubsystem], routingChangeSubsystem)
	}
	if records[0].Attributes["change_kind"] != "move" {
		t.Errorf("change_kind = %q, want move", records[0].Attributes["change_kind"])
	}

	now = now.Add(10 * time.Second)
	if records, err := source.Poll(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("same moved snapshot = (%d records, %v), want no duplicate", len(records), err)
	}
}

func TestRoutingChangeSource_FlappingIsCoalescedAndRateBounded(t *testing.T) {
	t0 := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	now := t0
	// The source sees four movements after the first event, but only the
	// cooldown-expired aggregate may be emitted. The final quiet poll verifies
	// that a flap which returns to a stable route is still reported once.
	fetcher := &fakeRoutingChangeFetcher{snapshots: []RoutingSnapshot{
		routingSnapshot("198.51.100.1", opnsense.GatewayStatusOnline),
		routingSnapshot("198.51.100.2", opnsense.GatewayStatusOnline),
		routingSnapshot("198.51.100.1", opnsense.GatewayStatusOnline),
		routingSnapshot("198.51.100.2", opnsense.GatewayStatusOnline),
		routingSnapshot("198.51.100.3", opnsense.GatewayStatusOnline),
		routingSnapshot("198.51.100.3", opnsense.GatewayStatusOnline),
	}}
	source := newRoutingChangeSource(fetcher, nil, func() time.Time { return now }, time.Minute)

	var emitted []Record
	for i := 0; i < 5; i++ {
		if i > 0 {
			now = now.Add(10 * time.Second)
		}
		records, err := source.Poll(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		emitted = append(emitted, records...)
	}
	if len(emitted) != 1 {
		t.Fatalf("flapping polls emitted %d records before cooldown, want 1", len(emitted))
	}

	// At t=1m10s, the latest snapshot is unchanged but the pending flap is
	// flushed as one detail event. It is the second event, not a per-transition
	// storm.
	now = t0.Add(70 * time.Second)
	records, err := source.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("cooldown flush emitted %d records, want 1", len(records))
	}
	var event routingChangeEventBody
	if err := json.Unmarshal([]byte(records[0].Body), &event); err != nil {
		t.Fatalf("flap body is not JSON: %v", err)
	}
	if event.Flap == nil || event.Flap.SuppressedChanges != 3 {
		t.Fatalf("flap detail = %#v, want three suppressed changes", event.Flap)
	}
	if records[0].Attributes["change_kind"] != "flap" || records[0].Attributes["flap_suppressed"] != "3" {
		t.Fatalf("flap attributes = %#v, want kind=flap suppressed=3", records[0].Attributes)
	}
}

func TestRoutingChangeSource_StateRoundTripSuppressesDuplicateAndPreservesBaseline(t *testing.T) {
	t0 := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	now := t0
	base := routingSnapshot("198.51.100.1", opnsense.GatewayStatusOnline)
	moved := routingSnapshot("198.51.100.2", opnsense.GatewayStatusOnline)
	fetcher := &fakeRoutingChangeFetcher{snapshots: []RoutingSnapshot{base, moved}}
	first := newRoutingChangeSource(fetcher, nil, func() time.Time { return now }, time.Minute)
	if _, err := first.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	if records, err := first.Poll(context.Background()); err != nil || len(records) != 1 {
		t.Fatalf("first source move = (%d records, %v), want one event", len(records), err)
	}
	state, ok := first.SaveState()
	if !ok {
		t.Fatal("SaveState returned no state after baseline and event")
	}

	changedAgain := routingSnapshot("198.51.100.3", opnsense.GatewayStatusOnline)
	restartedFetcher := &fakeRoutingChangeFetcher{snapshots: []RoutingSnapshot{moved, changedAgain}}
	restarted := newRoutingChangeSource(restartedFetcher, nil, func() time.Time { return now }, time.Minute)
	restarted.LoadState(state)
	if records, err := restarted.Poll(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("restored unchanged snapshot = (%d records, %v), want no replay", len(records), err)
	}

	now = now.Add(time.Minute)
	if records, err := restarted.Poll(context.Background()); err != nil || len(records) != 1 {
		t.Fatalf("restored next movement = (%d records, %v), want one event", len(records), err)
	}
}

func TestRoutingChangeRedactionUsesSharedSensitiveKeyVocabulary(t *testing.T) {
	value := map[string]any{
		"routingTable": map[string]any{
			"gateway": "198.51.100.1",
			"apiKey":  "do-not-ship",
			"nested":  []any{map[string]any{"pre-shared-key": "also-do-not-ship"}},
		},
		"description": "ordinary context remains",
	}
	redactRoutingChangeValue(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	got := string(encoded)
	for _, secret := range []string{"do-not-ship", "also-do-not-ship"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sensitive value %q survived routing redaction: %s", secret, got)
		}
	}
	if !strings.Contains(got, "ordinary context remains") || !strings.Contains(got, "198.51.100.1") {
		t.Fatalf("redaction removed ordinary route context: %s", got)
	}
}

func routingSnapshot(gateway string, status opnsense.GatewayStatusType) RoutingSnapshot {
	return RoutingSnapshot{
		DefaultRoutes: []opnsense.DefaultRoute{{
			Proto: "ipv4", Device: "wan0", Interface: "WAN", Gateway: gateway,
		}},
		Gateways: []opnsense.Gateway{{
			UUID: "gateway-wan", Name: "WAN_GW", Description: "WAN",
			HardwareInterface: "wan0", IPProtocol: "inet", Gateway: gateway,
			DefaultGateway: true, Enabled: true, Interface: "wan",
			InterfaceDescription: "WAN", Upstream: true, Status: status,
		}},
	}
}
