package configsnapshot

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type blockingFirewallSnapshotFetcher struct{ started chan struct{} }

func (f *blockingFirewallSnapshotFetcher) FetchFirewallConfigSnapshots(ctx context.Context) ([]opnsense.ConfigSnapshotEntity, *opnsense.APICallError) {
	close(f.started)
	<-ctx.Done()
	return nil, &opnsense.APICallError{Message: ctx.Err().Error()}
}

func TestEnabledProvidersComposesIndependentSnapshotFamilies(t *testing.T) {
	providers := enabledProviders(logship.Deps{}, true, true, true)
	if len(providers) != 3 {
		t.Fatalf("enabledProviders returned %d providers, want 3", len(providers))
	}
	want := []string{"firewall", "device_inventory", "security_posture"}
	for i, provider := range providers {
		if got := provider.Family(); got != want[i] {
			t.Errorf("provider %d family = %q, want %q", i, got, want[i])
		}
	}

	if got := enabledProviders(logship.Deps{}, false, false, false); len(got) != 0 {
		t.Fatalf("disabled providers = %d, want 0", len(got))
	}
}

func TestFirewallProvider_SnapshotHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fetcher := &blockingFirewallSnapshotFetcher{started: make(chan struct{})}
	provider := firewallProvider{client: fetcher}
	done := make(chan error, 1)
	go func() {
		_, err := provider.Snapshot(ctx)
		done <- err
	}()

	select {
	case <-fetcher.started:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("Snapshot did not start the firewall fetch")
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Snapshot returned nil error after context cancellation")
		}
		// Asserting on ctx.Err() here would pass without Snapshot doing
		// anything: the test cancelled that context itself. The claim under
		// test is that Snapshot propagates the cancellation to its caller, and
		// the client surfaces it as an *opnsense.APICallError carrying the
		// context error's message rather than a wrapped context.Canceled.
		if !strings.Contains(err.Error(), context.Canceled.Error()) {
			t.Fatalf("Snapshot error = %v, want one reporting %v", err, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("Snapshot did not return after context cancellation")
	}
}
