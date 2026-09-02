package options

import "testing"

func TestLogsConfigSnapshotFirewallEnabledDefaultFalse(t *testing.T) {
	if LogsConfigSnapshotFirewallEnabled() {
		t.Fatal("expected --logs.config-snapshot.firewall.enabled to default to false")
	}
}
