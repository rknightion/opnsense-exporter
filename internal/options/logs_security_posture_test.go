package options

import "testing"

func TestLogsConfigSnapshotSecurityPostureEnabledDefaultFalse(t *testing.T) {
	if LogsConfigSnapshotSecurityPostureEnabled() {
		t.Fatal("expected --logs.config-snapshot.security-posture.enabled to default to false")
	}
}
