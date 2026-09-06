package main

import (
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense2otel/v5/internal/collector"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

// FlagDoc is documentation metadata for one CLI flag, read from the kingpin
// model — the single source of truth for flags, env vars, defaults and help.
type FlagDoc struct {
	Name     string // without leading --
	Help     string
	Envar    string
	Default  string
	Required bool
}

// builtinFlags are kingpin built-ins excluded from documentation.
var builtinFlags = map[string]bool{
	"help": true, "help-long": true, "help-man": true,
	"completion-bash": true, "completion-script-bash": true, "completion-script-zsh": true,
	"version": true,
}

// collectAllFlags registers every exporter flag on the global kingpin app
// (package init of internal/options registers most; RegisterAllFlags adds
// the promslog --log.* flags) and walks the application model.
func collectAllFlags() []FlagDoc {
	options.RegisterAllFlags()
	model := kingpin.CommandLine.Model()
	var out []FlagDoc
	for _, f := range model.Flags {
		if builtinFlags[f.Name] || f.Hidden {
			continue
		}
		out = append(out, FlagDoc{
			Name:     f.Name,
			Help:     f.Help,
			Envar:    f.Envar,
			Default:  strings.Join(f.Default, ","),
			Required: f.Required,
		})
	}
	if len(out) < 50 {
		fatal("kingpin model returned only %d flags; expected the full exporter flag set", len(out))
	}
	// --web.systemd-socket used to be synthesized here when absent, because
	// exporter-toolkit registers it only when GOOS=linux and generated docs must
	// not depend on the platform docgen runs on. That patched presence only, and
	// two renderers reading the live kingpin model still diverged by platform
	// (#532). internal/options now hides the flag instead, so the Hidden skip
	// above drops it on Linux and it is simply absent everywhere else — one
	// documented flag set on every platform, with nothing to synthesize.
	return out
}

// collectorFlagInfo derives the per-subsystem switch-flag info (used in the
// metrics/collector reference tables) from the kingpin model joined with
// options.CollectorFlags. Detail flags are skipped: they modify a collector,
// they do not enable/disable it. Always-on collectors (no switch flag) get an
// empty-flag entry so tables render "---" as before.
func collectorFlagInfo(flags []FlagDoc) map[string]FlagInfo {
	byName := map[string]FlagDoc{}
	for _, f := range flags {
		byName[f.Name] = f
	}

	result := map[string]FlagInfo{}
	for _, cf := range options.CollectorFlags {
		if cf.Detail {
			continue
		}
		fd, ok := byName[cf.Flag]
		if !ok {
			fatal("CollectorFlags entry %q not found in kingpin model", cf.Flag)
		}
		isEnable := strings.HasPrefix(cf.Flag, "exporter.enable-")
		def := "Enabled"
		if isEnable && fd.Default == "false" {
			def = "Disabled"
		} else if !isEnable && fd.Default != "false" {
			def = "Disabled"
		}
		result[cf.Subsystem] = FlagInfo{
			FlagName: "--" + cf.Flag,
			EnvVar:   fd.Envar,
			Default:  def,
		}
	}

	// Always-enabled collectors without a switch flag.
	for _, inst := range collector.AllCollectors() {
		if _, exists := result[inst.Name()]; !exists {
			result[inst.Name()] = FlagInfo{Default: "Enabled"}
		}
	}
	return result
}
