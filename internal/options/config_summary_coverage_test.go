package options

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

// configFamilySections maps a registered flag's family — the first dot-segment
// of its name — to the /config + --config.check summary section it must
// render under. #518: annotations/logs/flow flags existed and were fully
// wired, validated and started, but printed NOTHING in the summary; this map
// plus TestConfigSummaryCoversEveryFlagFamily is what makes that recur loudly
// (a failing test) instead of silently (a section nobody notices is missing).
//
// "exporter." is deliberately absent here: exporter.disable-*/exporter.enable-*
// are the collector switches (-> "Collectors") while every other exporter.*
// flag is server config (-> "Exporter / Server") — see the split in the test
// loop below, since a single family->section entry can't express that.
var configFamilySections = map[string]string{
	"opnsense":    "Connection",
	"otlp":        "Telemetry (OTLP)",
	"pyroscope":   "Pyroscope",
	"annotations": "Annotations",
	"logs":        "Log shipping",
	"flow":        "Flow",
	"geoip":       "GeoIP",
}

// configFamilyExemptions lists flag families deliberately left off the
// effective-config summary, each with the reason a reader needs to trust the
// omission is intentional rather than the #518 gap recurring. Add a family
// here only when it is genuinely out of scope for this summary — never to
// silence this test.
var configFamilyExemptions = map[string]string{
	"help":                   "kingpin's own help flag, not a configuration value",
	"help-long":              "kingpin's own help flag, not a configuration value",
	"help-man":               "kingpin's own help flag, not a configuration value",
	"completion-bash":        "kingpin's own shell-completion flag",
	"completion-script-bash": "kingpin's own shell-completion flag",
	"completion-script-zsh":  "kingpin's own shell-completion flag",
	"config":                 "--config.check is the preflight switch itself, not a value it reports on",
	"log":                    "promslog process-logging flags (log.level/log.format), not exporter configuration",
	"collector":              "poll-scheduler tuning (collector.poll-interval*); a pre-existing gap outside #518's scope",
	"web": "toolkit server flags (listen address, TLS config file) and the operator-console UI toggles " +
		"render on their own surfaces, not this summary; a pre-existing gap outside #518's scope",
}

// TestConfigSummaryCoversEveryFlagFamily walks the real kingpin flag model
// (the same approach TestCollectorFlagsCoverAllSwitchFlags in docmeta_test.go
// uses for CollectorFlags) and fails on any flag family that is neither mapped
// to a section above nor explicitly exempted. A new configuration family
// (a new "--foo.*" flag group) must consciously pick one or the other.
func TestConfigSummaryCoversEveryFlagFamily(t *testing.T) {
	RegisterAllFlags()
	model := kingpin.CommandLine.Model()

	sectionTitles := map[string]bool{}
	for _, sec := range buildEffectiveConfig(configInputs{}) {
		sectionTitles[sec.Title] = true
	}

	for _, f := range model.Flags {
		// The collector switches are exporter.disable-*/exporter.enable-*; every
		// other exporter.* flag is server config. This has to be checked before
		// the generic family split below, since both share the "exporter" family.
		if strings.HasPrefix(f.Name, "exporter.disable-") || strings.HasPrefix(f.Name, "exporter.enable-") {
			if !sectionTitles["Collectors"] {
				t.Errorf("flag --%s maps to section %q, but buildEffectiveConfig has no such section", f.Name, "Collectors")
			}
			continue
		}
		if strings.HasPrefix(f.Name, "exporter.") {
			if !sectionTitles["Exporter / Server"] {
				t.Errorf("flag --%s maps to section %q, but buildEffectiveConfig has no such section",
					f.Name, "Exporter / Server")
			}
			continue
		}

		family := f.Name
		if i := strings.Index(family, "."); i >= 0 {
			family = family[:i]
		}
		if reason, exempt := configFamilyExemptions[family]; exempt {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("flag family %q exempted with no reason in configFamilyExemptions", family)
			}
			continue
		}
		section, ok := configFamilySections[family]
		if !ok {
			t.Errorf("flag --%s (family %q) has no config-summary section mapping and no exemption; "+
				"add it to configFamilySections or configFamilyExemptions in config_summary_coverage_test.go",
				f.Name, family)
			continue
		}
		if !sectionTitles[section] {
			t.Errorf("flag family %q maps to section %q, but buildEffectiveConfig has no such section", family, section)
		}
	}
}
