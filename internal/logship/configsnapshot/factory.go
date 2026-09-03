package configsnapshot

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rknightion/opnsense2otel/v4/internal/logship"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

func init() {
	logship.RegisterSource(func(deps logship.Deps) (logship.Source, error) {
		providers := enabledProviders(
			deps,
			options.LogsConfigSnapshotFirewallEnabled(),
			options.LogsConfigSnapshotDevicesEnabled(),
		)
		if len(providers) == 0 {
			return nil, nil
		}
		return newSource(providers, nowUTC, uuid.NewString), nil
	})
}

func enabledProviders(deps logship.Deps, firewall, devices bool) []Provider {
	providers := make([]Provider, 0, 2)
	if firewall {
		providers = append(providers, firewallProvider{
			client: opnsenseFirewallSnapshotFetcher{client: deps.Client},
		})
	}
	if devices {
		providers = append(providers, newDeviceInventoryProvider(deps.Client))
	}
	return providers
}

func nowUTC() time.Time { return time.Now().UTC() }

type firewallSnapshotFetcher interface {
	FetchFirewallConfigSnapshots(context.Context) ([]opnsense.ConfigSnapshotEntity, *opnsense.APICallError)
}

type opnsenseFirewallSnapshotFetcher struct{ client *opnsense.Client }

func (f opnsenseFirewallSnapshotFetcher) FetchFirewallConfigSnapshots(ctx context.Context) ([]opnsense.ConfigSnapshotEntity, *opnsense.APICallError) {
	return f.client.WithContext(ctx).FetchFirewallConfigSnapshots()
}

// firewallProvider exposes one logical family, while preserving the five
// upstream rule classes as the entity kind within that family.
type firewallProvider struct{ client firewallSnapshotFetcher }

func (firewallProvider) Family() string { return "firewall" }

func (p firewallProvider) Snapshot(ctx context.Context) ([]Entity, error) {
	entities, err := p.client.FetchFirewallConfigSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Entity, 0, len(entities))
	for _, entity := range entities {
		out = append(out, Entity{
			ID: entity.Kind + ":" + entity.ID,
			Value: map[string]any{
				"kind":   entity.Kind,
				"config": entity.Config,
			},
		})
	}
	return out, nil
}
