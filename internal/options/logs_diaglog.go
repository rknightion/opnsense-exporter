package options

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

// defaultDiagLogScopes are the high-signal event scopes enabled out of the box:
// config-change audit trail, dpinger/gateway state, CARP + other kernel events,
// captive-portal connect/disconnect, and configd service-lifecycle events. All
// five are core module/scope pairs, so they exist on every OPNsense install
// regardless of installed plugins (#230).
const defaultDiagLogScopes = "core/audit,core/gateways,core/portalauth,core/system,core/configd"

var (
	diagLogEnabled = kingpin.Flag(
		"logs.diaglog.enabled",
		"Enable the generic diagnostics-log source (api/diagnostics/log/<module>/<scope>): audit/config-change, "+
			"gateway (dpinger), CARP, captive-portal auth, and DHCP/service events. Only takes effect when "+
			"--logs.enabled is also set. Which module/scope pairs are polled is controlled by --logs.scopes.",
	).Envar("OPNSENSE_EXPORTER_LOGS_DIAGLOG_ENABLED").Default("true").Bool()

	diagLogScopesRaw = kingpin.Flag(
		"logs.scopes",
		"Comma-separated module/scope pairs polled by the diagnostics-log source "+
			"(api/diagnostics/log/<module>/<scope>), e.g. core/audit,core/gateways. See docs/log-shipping.md "+
			"for the scope registry. Only used when --logs.diaglog.enabled is set.",
	).Envar("OPNSENSE_EXPORTER_LOGS_SCOPES").Default(defaultDiagLogScopes).String()
)

// DiagLogScope is one module/scope pair polled by the diagnostics-log source.
type DiagLogScope struct {
	Module string
	Scope  string
}

// Key returns the "module/scope" identity used as the cursor-state map key and
// the Record module/scope attributes.
func (s DiagLogScope) Key() string { return s.Module + "/" + s.Scope }

// DiagLogConfig is the resolved configuration for the diagnostics-log source.
type DiagLogConfig struct {
	Scopes []DiagLogScope
}

// DiagLog assembles the diagnostics-log source configuration from flags/env.
// The returned bool reports whether the source should run: true only when
// --logs.diaglog.enabled is set AND at least one scope is configured (an
// explicitly emptied --logs.scopes disables the source rather than erroring,
// since "poll nothing" is a valid way to turn it off without touching the
// enabled flag).
func DiagLog() (*DiagLogConfig, bool, error) {
	if !*diagLogEnabled {
		return nil, false, nil
	}
	scopes, err := ParseDiagLogScopes(*diagLogScopesRaw)
	if err != nil {
		return nil, false, err
	}
	if len(scopes) == 0 {
		return nil, false, nil
	}
	return &DiagLogConfig{Scopes: scopes}, true, nil
}

// ParseDiagLogScopes parses a comma-separated "module/scope,module/scope,..."
// list. Blank entries (from stray commas or trailing whitespace) are skipped
// silently; a segment that doesn't split into exactly two non-empty
// slash-separated parts is a hard configuration error.
func ParseDiagLogScopes(raw string) ([]DiagLogScope, error) {
	var out []DiagLogScope
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		segs := strings.SplitN(part, "/", 2)
		if len(segs) != 2 || segs[0] == "" || segs[1] == "" {
			return nil, fmt.Errorf("logs.scopes: invalid module/scope pair %q (want module/scope)", part)
		}
		out = append(out, DiagLogScope{Module: segs[0], Scope: segs[1]})
	}
	return out, nil
}
