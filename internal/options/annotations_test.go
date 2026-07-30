package options

import (
	"strings"
	"testing"
	"time"
)

func validAnnotationsConfig() AnnotationsConfig {
	return AnnotationsConfig{
		GrafanaURL:  "https://stack.grafana.net",
		Token:       "token",
		Interval:    time.Minute,
		Lookback:    24 * time.Hour,
		Timeout:     10 * time.Second,
		MaxPerCycle: 20,
	}
}

// An unknown kind is silent at runtime — it matches no watch, so the exporter
// writes nothing for it and every self-metric looks healthy. Startup is the only
// place it can be caught (#540).
func TestAnnotationsRejectsAnUnknownKind(t *testing.T) {
	cfg := validAnnotationsConfig()
	cfg.Kinds = []string{"reboot", "threat-feed-updates"}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected a misspelled event kind to be rejected")
	}
	if !strings.Contains(err.Error(), "threat-feed-updates") {
		t.Errorf("error should name the offending kind, got %q", err)
	}
	if !strings.Contains(err.Error(), "threat-feed-update") {
		t.Errorf("error should list the known kinds so the typo is obvious, got %q", err)
	}
}

func TestAnnotationsAcceptsKnownKinds(t *testing.T) {
	cfg := validAnnotationsConfig()
	cfg.Kinds = []string{"reboot", "config-change", "threat-feed-update"}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("known kinds rejected: %v", err)
	}
}

func TestAnnotationsAcceptsAnUnsetKindList(t *testing.T) {
	cfg := validAnnotationsConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty Kinds must mean the defaults, not an error: %v", err)
	}
}
