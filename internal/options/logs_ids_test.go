package options

import "testing"

// TestLogsIDSEnabledDefault proves --logs.ids.enabled defaults to false, like
// every log source (opt-in on top of opt-in --logs.enabled).
func TestLogsIDSEnabledDefault(t *testing.T) {
	if LogsIDSEnabled() {
		t.Fatal("expected --logs.ids.enabled to default to false")
	}
}
