package options

import "testing"

func TestLogsConfigSnapshotDeviceInventoryEnabledDefaultFalse(t *testing.T) {
	if LogsConfigSnapshotDevicesEnabled() {
		t.Fatal("expected devices config snapshot flag to default to false")
	}
}
