package options

import (
	"strings"
	"testing"
)

// The env-var path is the one that actually matters: kingpin already rejects an
// unknown --flag, but once a flag is deleted its Envar binding goes too, so a stale
// OPNSENSE_EXPORTER_LOGS_DIAGLOG_ENABLED would be read by nothing and silently
// ignored — leaving the user with an empty log stream and no error to explain it.
func TestCheckRemovedFlags_EnvVarPath(t *testing.T) {
	for _, env := range []string{
		"OPNSENSE_EXPORTER_LOGS_FIREWALL_ENABLED=true",
		"OPNSENSE_EXPORTER_LOGS_DIAGLOG_ENABLED=true",
		"OPNSENSE_EXPORTER_LOGS_SCOPES=core/audit",
	} {
		err := CheckRemovedFlags(nil, []string{"PATH=/usr/bin", env})
		if err == nil {
			t.Errorf("stale env var %q was silently ignored; it must fail fast", env)
			continue
		}
		if !strings.Contains(err.Error(), "logs.syslog.enabled") {
			t.Errorf("error for %q must name the replacement, got: %v", env, err)
		}
	}
}

func TestCheckRemovedFlags_FlagPath(t *testing.T) {
	for _, arg := range []string{
		"--logs.firewall.enabled",
		"--logs.diaglog.enabled=true",
		"--no-logs.diaglog.enabled",
		"--logs.scopes=core/audit",
	} {
		err := CheckRemovedFlags([]string{arg}, nil)
		if err == nil {
			t.Errorf("removed flag %q did not error", arg)
			continue
		}
		if !strings.Contains(err.Error(), "logs.syslog.enabled") {
			t.Errorf("error for %q must name the replacement, got: %v", arg, err)
		}
	}
}

// The unbound lane SURVIVES the syslog receiver: it ships Unbound's per-query DNS
// log from OPNsense's reporting DB, which has no syslog equivalent. Guard against a
// future edit sweeping it into the removed list.
func TestCheckRemovedFlags_UnboundIsNotRemoved(t *testing.T) {
	if err := CheckRemovedFlags(
		[]string{"--logs.unbound.enabled"},
		[]string{"OPNSENSE_EXPORTER_LOGS_UNBOUND_ENABLED=true"},
	); err != nil {
		t.Fatalf("--logs.unbound.enabled must still be supported (per-query DNS has no syslog path), got: %v", err)
	}
}

func TestCheckRemovedFlags_CleanConfigPasses(t *testing.T) {
	if err := CheckRemovedFlags(
		[]string{"--logs.enabled", "--logs.syslog.enabled"},
		[]string{"PATH=/usr/bin", "OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED=true"},
	); err != nil {
		t.Fatalf("a valid configuration must not error: %v", err)
	}
}
