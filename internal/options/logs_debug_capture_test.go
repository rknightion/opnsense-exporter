package options

import (
	"strings"
	"testing"
)

// withDebugCaptureDir sets the shared capture dir for one test and restores it.
func withDebugCaptureDir(t *testing.T, dir string) {
	t.Helper()
	prev := *logsDebugCaptureDir
	t.Cleanup(func() { *logsDebugCaptureDir = prev })
	*logsDebugCaptureDir = dir
}

func TestLogsDebugCaptureAccessors(t *testing.T) {
	withDebugCaptureDir(t, "  /var/capture  ")
	if got := LogsDebugCaptureDir(); got != "/var/capture" {
		t.Fatalf("dir = %q, want trimmed", got)
	}
	if !LogsDebugCaptureEnabled() {
		t.Fatal("enabled should be true when a dir is set")
	}
	// The default (256MiB) resolves to a positive byte count.
	if LogsDebugCaptureMaxBytes() <= 0 {
		t.Fatalf("max-bytes = %d, want > 0", LogsDebugCaptureMaxBytes())
	}
}

func TestLogsDebugCaptureDisabledByDefault(t *testing.T) {
	withDebugCaptureDir(t, "")
	if LogsDebugCaptureEnabled() {
		t.Fatal("capture should be disabled with an empty dir")
	}
}

// A per-receiver toggle with no capture dir is a startup error: it reads as "on" but
// would write nowhere.
func TestZenarmorDebugCaptureRequiresDir(t *testing.T) {
	withZenarmorFlags(t, func() {
		withDebugCaptureDir(t, "")
		prev := *logsZenarmorDebugCapture
		t.Cleanup(func() { *logsZenarmorDebugCapture = prev })

		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorDebugCapture = true

		_, _, err := LogsZenarmor()
		if err == nil || !strings.Contains(err.Error(), "debug-capture") {
			t.Fatalf("expected a debug-capture-needs-dir error, got: %v", err)
		}
	})
}

func TestSyslogDebugCaptureRequiresDir(t *testing.T) {
	enabled, udp, conns, toggle := *logsSyslogEnabled, *logsSyslogListenUDP, *logsSyslogMaxConns, *logsSyslogDebugCapture
	t.Cleanup(func() {
		*logsSyslogEnabled, *logsSyslogListenUDP, *logsSyslogMaxConns, *logsSyslogDebugCapture = enabled, udp, conns, toggle
	})
	withDebugCaptureDir(t, "")

	*logsSyslogEnabled = true
	*logsSyslogListenUDP = ":5514"
	*logsSyslogMaxConns = 10
	*logsSyslogDebugCapture = true

	_, _, err := LogsSyslog()
	if err == nil || !strings.Contains(err.Error(), "debug-capture") {
		t.Fatalf("expected a debug-capture-needs-dir error, got: %v", err)
	}
}

func TestZenarmorDebugCaptureOKWithDir(t *testing.T) {
	withZenarmorFlags(t, func() {
		withDebugCaptureDir(t, "/var/capture")
		prev := *logsZenarmorDebugCapture
		t.Cleanup(func() { *logsZenarmorDebugCapture = prev })

		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorDebugCapture = true

		cfg, enabled, err := LogsZenarmor()
		if err != nil || !enabled {
			t.Fatalf("got (%v, %v), want a valid enabled config", enabled, err)
		}
		if !cfg.DebugCapture {
			t.Fatal("DebugCapture not carried into the resolved config")
		}
	})
}
