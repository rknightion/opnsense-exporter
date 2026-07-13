package options

import (
	"testing"
	"time"
)

func TestLogsUnboundEnabled_DefaultFalse(t *testing.T) {
	if LogsUnboundEnabled() {
		t.Fatal("expected --logs.unbound.enabled to default to false")
	}
}

func TestLogsUnboundMinInterval_Is15Seconds(t *testing.T) {
	if LogsUnboundMinInterval() != 15*time.Second {
		t.Fatalf("unbound log poll floor drifted: %s", LogsUnboundMinInterval())
	}
}
