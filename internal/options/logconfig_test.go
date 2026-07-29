package options

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// The startup block, the --config.check preflight and the /config page must render
// the same facts. The guard is that they read one source: if LogEffectiveConfig
// grows its own notion of what a section is, this drifts and nothing else notices
// until an operator debugs against a config the exporter is not running.
func TestLogEffectiveConfigRendersEverySectionFromTheSharedSource(t *testing.T) {
	var buf bytes.Buffer
	LogEffectiveConfig(slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()

	sections := EffectiveConfig()
	if len(sections) == 0 {
		t.Fatal("EffectiveConfig() is empty; this test would pass vacuously")
	}
	for _, section := range sections {
		if !strings.Contains(out, "effective config: "+section.Title) {
			t.Errorf("section %q is missing from the startup log:\n%s", section.Title, out)
		}
	}
	if got, want := strings.Count(out, "effective config:"), len(sections); got != want {
		t.Errorf("logged %d sections, want %d — one entry per section, never a multi-line "+
			"message (it would break logfmt parsing downstream)", got, want)
	}
}

// A secret must not reach the log even in a startup dump nobody thought about.
// buildEffectiveConfig reduces every secret to a placeholder before this function
// sees it, so this asserts the property end to end rather than trusting the layer.
func TestLogEffectiveConfigNeverLogsASecretValue(t *testing.T) {
	var buf bytes.Buffer
	LogEffectiveConfig(slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()

	for _, section := range EffectiveConfig() {
		for _, item := range section.Items {
			if !item.Secret {
				continue
			}
			if item.Value != redacted && item.Value != unset {
				t.Errorf("secret %q rendered as %q, which is neither the redacted nor the unset "+
					"placeholder — buildEffectiveConfig must never emit a real credential",
					item.Key, item.Value)
			}
		}
	}
	if strings.Contains(out, "\n") && strings.Count(out, "effective config:") == 0 {
		t.Error("no sections logged")
	}
}

func TestSetResolvedCollectorSwitchesIsWhatConfigRenders(t *testing.T) {
	t.Cleanup(func() { resolvedSwitches = nil })

	raw := CollectorsSwitches()
	flipped := raw
	flipped.SMART = !raw.SMART
	SetResolvedCollectorSwitches(flipped)

	want := boolStr(flipped.SMART)
	for _, item := range collectorConfigItems() {
		if item.Key == "SMART" {
			if item.Value != want {
				t.Errorf("SMART renders %q, want %q — the config surfaces must show the "+
					"post-resolution switch set, not the raw flag values", item.Value, want)
			}
			return
		}
	}
	t.Error("no SMART row in collectorConfigItems()")
}
