package options

import (
	"strings"
	"testing"
)

// withNetflowDebugCapture sets the flag for one test and restores it.
func withNetflowDebugCapture(t *testing.T, mode string) {
	t.Helper()
	prev := *flowNetflowDebugCapture
	t.Cleanup(func() { *flowNetflowDebugCapture = prev })
	*flowNetflowDebugCapture = mode
}

// withNetflowEnabled turns the receiver on for one test and restores it. The
// receiver requires --flow.enabled and a listen address, so this sets the whole
// coherent trio rather than one field the validator will reject for another reason.
func withNetflowEnabled(t *testing.T, on bool) {
	t.Helper()
	prevNF, prevFlow, prevListen := *flowNetflowEnabled, *flowEnabled, *flowNetflowListen
	t.Cleanup(func() {
		*flowNetflowEnabled, *flowEnabled, *flowNetflowListen = prevNF, prevFlow, prevListen
	})
	*flowNetflowEnabled = on
	*flowEnabled = true
	*flowNetflowListen = ":2055"
}

func TestNetflowDebugCaptureIsOffByDefault(t *testing.T) {
	cfg, err := Flow()
	if err != nil {
		t.Fatalf("Flow: %v", err)
	}
	if cfg.NetflowDebugCapture != "off" {
		t.Fatalf("NetflowDebugCapture = %q by default, want \"off\" - a debug capture that is on "+
			"by default writes real network data to disk on every deployment", cfg.NetflowDebugCapture)
	}
}

// The same "quiet no-op" rule the rest of this package enforces: an operator who
// asked for a capture and got none must be told, not left to discover it when they
// go looking for the samples.
func TestNetflowDebugCaptureRequiresTheSharedDir(t *testing.T) {
	withDebugCaptureDir(t, "")
	withNetflowEnabled(t, true)
	withNetflowDebugCapture(t, "unidentified")

	_, err := Flow()
	if err == nil || !strings.Contains(err.Error(), "logs.debug-capture.dir") {
		t.Fatalf("expected a debug-capture-needs-dir error, got: %v", err)
	}
}

func TestNetflowDebugCaptureRequiresTheReceiver(t *testing.T) {
	withDebugCaptureDir(t, "/var/capture")
	withNetflowEnabled(t, false)
	withNetflowDebugCapture(t, "all")

	_, err := Flow()
	if err == nil || !strings.Contains(err.Error(), "flow.netflow.enabled") {
		t.Fatalf("expected a capture-needs-the-receiver error, got: %v", err)
	}
}

func TestNetflowDebugCaptureResolvesWhenBothAreSet(t *testing.T) {
	withDebugCaptureDir(t, "/var/capture")
	withNetflowEnabled(t, true)
	withNetflowDebugCapture(t, "all")

	cfg, err := Flow()
	if err != nil {
		t.Fatalf("Flow: %v", err)
	}
	if cfg.NetflowDebugCapture != "all" {
		t.Fatalf("NetflowDebugCapture = %q, want \"all\"", cfg.NetflowDebugCapture)
	}
}

// Off must stay valid with neither the dir nor the receiver, or the default
// configuration would fail to start.
func TestNetflowDebugCaptureOffNeedsNothing(t *testing.T) {
	withDebugCaptureDir(t, "")
	withNetflowEnabled(t, false)
	withNetflowDebugCapture(t, "off")

	if _, err := Flow(); err != nil {
		t.Fatalf("off must validate with nothing else configured: %v", err)
	}
}
