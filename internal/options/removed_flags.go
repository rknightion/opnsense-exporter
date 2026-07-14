package options

import (
	"fmt"
	"os"
	"strings"
)

// removedSetting is a flag/env var that no longer exists, paired with what to do
// instead. A user upgrading with one of these still in their compose file or unit
// must get an actionable error, not silence.
type removedSetting struct {
	Flag string
	Env  string
	Why  string
}

// removedSettings are the log-source settings retired by the syslog receiver
// (#248). The firewall and diaglog poll lanes polled API endpoints that merely
// re-read log files OPNsense will push over syslog; the receiver supersedes both.
//
// --logs.unbound.enabled is deliberately NOT here: it ships Unbound's per-query DNS
// log from OPNsense's reporting database, which has no syslog equivalent.
var removedSettings = []removedSetting{
	{
		Flag: "logs.firewall.enabled",
		Env:  "OPNSENSE_EXPORTER_LOGS_FIREWALL_ENABLED",
		Why:  "the syslog receiver now ships firewall (filterlog) records, enriched with rule descriptions",
	},
	{
		Flag: "logs.diaglog.enabled",
		Env:  "OPNSENSE_EXPORTER_LOGS_DIAGLOG_ENABLED",
		Why:  "the syslog receiver now ships the audit/configd/gateway/portal logs this polled",
	},
	{
		Flag: "logs.scopes",
		Env:  "OPNSENSE_EXPORTER_LOGS_SCOPES",
		Why:  "scope selection is now done on the firewall, in the syslog target's Applications/Facilities filters",
	},
}

// CheckRemovedFlags fails fast when a retired setting is still configured.
//
// kingpin already rejects an unknown --flag, so the case that genuinely needs this
// guard is the ENVIRONMENT VARIABLE path: once the flag is gone, its Envar binding
// goes with it, and a stale OPNSENSE_EXPORTER_LOGS_DIAGLOG_ENABLED would otherwise
// be read by nothing and silently ignored — leaving a user who thought they were
// shipping logs with an empty log stream and no error. Call before kingpin.Parse.
func CheckRemovedFlags(args []string, env []string) error {
	for _, r := range removedSettings {
		for _, a := range args {
			if a == "--"+r.Flag || strings.HasPrefix(a, "--"+r.Flag+"=") ||
				a == "--no-"+r.Flag {
				return removedErr(r)
			}
		}
		for _, e := range env {
			if strings.HasPrefix(e, r.Env+"=") {
				return removedErr(r)
			}
		}
	}
	return nil
}

func removedErr(r removedSetting) error {
	return fmt.Errorf(
		"--%s (%s) has been removed: %s.\n"+
			"Set --logs.syslog.enabled instead, and configure a syslog target on the firewall "+
			"(System > Settings > Logging > Targets) pointing at this exporter on port 5514. "+
			"See docs/syslog-receiver.md",
		r.Flag, r.Env, r.Why)
}

// CheckRemovedFlagsFromProcess is the production entry point: it inspects the real
// process arguments and environment.
func CheckRemovedFlagsFromProcess() error {
	return CheckRemovedFlags(os.Args[1:], os.Environ())
}
