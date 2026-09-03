package options

import "testing"

func TestLogsConfigSnapshotRoutingChangesEnabledDefaultFalse(t *testing.T) {
	if LogsConfigSnapshotRoutingChangesEnabled() {
		t.Fatal("expected --logs.config-snapshot.routing-changes.enabled to default to false")
	}
}
