package options

import "log/slog"

// resolvedSwitches, when set, is the collector switch set AFTER every startup
// resolution step (--exporter.enable-all-available, and the availability probe
// behind it). Nil until main sets it.
//
// It exists because the rendered config must show what is IN FORCE, not what was
// typed. collectorConfigItems reads the raw flag values, so with the blanket
// switch set every collector it turned on rendered as disabled — the /config page
// and the preflight both understated the running exporter.
var resolvedSwitches *CollectorsDisableSwitch

// SetResolvedCollectorSwitches records the post-resolution switch set as the one
// every config surface renders. Call it once, after all resolution.
func SetResolvedCollectorSwitches(sw CollectorsDisableSwitch) {
	resolvedSwitches = &sw
}

// LogEffectiveConfig writes the whole resolved configuration to the log, one
// entry per section, at Info.
//
// It renders from EffectiveConfig() — the same source as the --config.check
// preflight and the operator console's /config page. That is the point: a
// separate startup formatter would be a fourth rendering of the same facts, would
// drift from the other three, and would reopen the secret-handling question that
// is currently answered in exactly one place. Secrets arrive here already reduced
// to "set"/"unset" by buildEffectiveConfig, so this function cannot leak one even
// if it tried.
//
// One entry PER SECTION rather than one per setting, or one giant multi-line
// message: a multi-line message breaks logfmt parsing downstream, and a line per
// setting would be a hundred lines competing with the rest of startup. A section
// is a valid logfmt record whose attributes are its settings, so it stays
// greppable and queryable.
func LogEffectiveConfig(log *slog.Logger) {
	if log == nil {
		return
	}
	for _, section := range EffectiveConfig() {
		attrs := make([]any, 0, len(section.Items)*2+2)
		attrs = append(attrs, "component", "startup")
		for _, item := range section.Items {
			key := item.Key
			if item.Display != "" {
				key = item.Display
			}
			attrs = append(attrs, key, item.Value)
		}
		log.Info("effective config: "+section.Title, attrs...)
	}
}
