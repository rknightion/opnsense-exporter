package opnsense

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
)

// This file is the exporter's endpoint→collector→OPNsense-privilege map (#442).
//
// WHY IT IS A STATIC TABLE. OPNsense authorises an API key as the user it belongs
// to, and authorisation is a URI match: ACL units ("privileges") each carry a list
// of URI patterns, and ApiControllerBase compares the RAW request URI against every
// pattern of every privilege the user holds, before dispatch. Nothing in the API
// reports which privilege covers which route, so the mapping can only be derived
// from OPNsense's own ACL.xml files. That derivation is done offline, against the
// releases named below, and its result is committed here so it is reviewable,
// diffable, and usable at runtime to explain a 403.
//
// HOW IT WAS DERIVED. Every ACL.xml in OPNsense core (both supported releases) and
// in the plugins tree was parsed, and each endpoint's registered path was matched
// against every pattern using OPNsense's own matching rule (Core\ACL::urlMatch: "."
// and "?" are literals, "*" is a wildcard, a pattern ending in "/​*" also matches the
// bare prefix, anchored at both ends and case-sensitive).
//
// THE THREE STATES ARE NOT INTERCHANGEABLE. ACLStatusUnknown means no pattern in the
// audited sources covers the URL — it is a recorded negative result, not a gap to be
// filled with a plausible guess. Those rows keep a Note saying exactly what was
// checked and why nothing matched.
const (
	// ACLCoreCurrentRelease and ACLCorePreviousRelease are the OPNsense core tags the
	// core rows were derived from — the support window (current + previous stable).
	ACLCoreCurrentRelease  = "26.7.1"
	ACLCorePreviousRelease = "26.1.11"

	// ACLPluginsSource is the plugins tree the plugin rows were derived from. Plugin
	// ACL files live outside core and are released on their own cadence, so they are
	// pinned by commit, not by an OPNsense version.
	ACLPluginsSource = "github.com/opnsense/plugins @ b59cf8e (2026-07-12)"

	// ACLDataRevised is when this table was last re-derived from those sources.
	ACLDataRevised = "2026-07-25"
)

// ACLStatus classifies how well an endpoint's required OPNsense privilege is known.
type ACLStatus string

const (
	// ACLStatusKnown: a core ACL privilege covers this URL, identically in both
	// releases in the support window.
	ACLStatusKnown ACLStatus = "known"

	// ACLStatusPluginDependent: the covering privilege comes from a plugin's own
	// ACL.xml (which drifts independently of core), or it differs between the two
	// supported core releases. Either way the grant is not stable across the
	// support window and the Note says how it varies.
	ACLStatusPluginDependent ACLStatus = "plugin-dependent"

	// ACLStatusUnknown: nothing in the audited core or plugin ACLs covers this URL.
	// Only page-all ("All pages") reaches it. Never used to mean "not looked at".
	ACLStatusUnknown ACLStatus = "unknown"
)

// ACLScope describes how broad a privilege's API grant is.
type ACLScope string

const (
	// ACLScopeExact: every api/ pattern the privilege carries is a literal route,
	// so holding it grants those named actions and nothing else.
	ACLScopeExact ACLScope = "exact"

	// ACLScopeWildcard: at least one of the privilege's api/ patterns contains a
	// wildcard, so holding it grants every action under that prefix — including any
	// mutating action the same controller exposes. This is a property of OPNsense's
	// ACL granularity, not of what the exporter calls: the exporter only ever issues
	// reads, but the operator has to grant the whole unit.
	//
	// Conservative by construction: a wildcard grant MAY include writes. Verified
	// examples that do — Status: Services grants api/core/service/* which includes
	// start/stop/restart; System: Firmware grants api/core/firmware/* which includes
	// update/upgrade/install/remove/reboot/poweroff; System: Gateways grants
	// api/routing/settings/* which includes addGateway/setGateway/delGateway.
	ACLScopeWildcard ACLScope = "wildcard"
)

// ACLPrivilege is one OPNsense ACL unit that covers an endpoint's URL.
type ACLPrivilege struct {
	// Key is the ACL key as it appears in ACL.xml (e.g. "page-status-services").
	// This is what goes in a user's or group's privilege list.
	Key string
	// Name is the label the OPNsense GUI shows for that key.
	Name string
	// Origin is "core" or the plugin's ports path (e.g. "sysutils/smart").
	Origin string
	// Pattern is the URI pattern that matched this endpoint's path.
	Pattern string
	// Scope reports whether the privilege's api/ grant is limited to literal
	// routes or opens a whole prefix. See ACLScopeWildcard.
	Scope ACLScope
}

// aclEntry is the stored classification for one endpoint.
type aclEntry struct {
	// Consumer is the collector subsystem that calls this endpoint, or a
	// parenthesised non-collector consumer ("(log shipping)", "(health probe)")
	// for the endpoints that are not driven by a collector at all.
	Consumer string
	// Component is "core" or the plugin's ports path.
	Component string
	Status    ACLStatus
	// Privileges is every ACL unit that covers the URL. Any ONE of them is
	// sufficient; they are alternatives, not a required set.
	Privileges []ACLPrivilege
	// Note records version drift, or — for ACLStatusUnknown — what was checked
	// and why nothing matched.
	Note string
}

// EndpointACL is one row of the published matrix: the stored classification joined
// with the endpoint's path/method from the live contract manifest.
type EndpointACL struct {
	Endpoint    EndpointName
	Path        EndpointPath
	Method      string
	Consumer    string
	Component   string
	Status      ACLStatus
	Privileges  []ACLPrivilege
	Note        string
	PluginGated bool
}

// WildcardAPIScope reports whether ANY covering privilege opens a whole api/
// prefix rather than named routes. When true, the operator cannot grant this
// endpoint without also granting every other action that prefix exposes.
func (e EndpointACL) WildcardAPIScope() bool {
	for _, p := range e.Privileges {
		if p.Scope == ACLScopeWildcard {
			return true
		}
	}
	return false
}

// PrivilegeKeys returns the covering ACL keys, sorted. Any one of them suffices.
func (e EndpointACL) PrivilegeKeys() []string {
	out := make([]string, 0, len(e.Privileges))
	for _, p := range e.Privileges {
		out = append(out, p.Key)
	}
	sort.Strings(out)
	return out
}

// EndpointACLs returns the full matrix, sorted by endpoint name.
func EndpointACLs() []EndpointACL {
	manifest := ContractManifest()
	gated := pluginGatedSet()
	out := make([]EndpointACL, 0, len(endpointACL))
	for name, entry := range endpointACL {
		c := manifest[name]
		out = append(out, EndpointACL{
			Endpoint:    name,
			Path:        c.Path,
			Method:      c.Method,
			Consumer:    entry.Consumer,
			Component:   entry.Component,
			Status:      entry.Status,
			Privileges:  entry.Privileges,
			Note:        entry.Note,
			PluginGated: gated[name],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

// ACLForEndpoint returns the row for an endpoint name.
func ACLForEndpoint(name EndpointName) (EndpointACL, bool) {
	entry, ok := endpointACL[name]
	if !ok {
		return EndpointACL{}, false
	}
	c := ContractManifest()[name]
	return EndpointACL{
		Endpoint:    name,
		Path:        c.Path,
		Method:      c.Method,
		Consumer:    entry.Consumer,
		Component:   entry.Component,
		Status:      entry.Status,
		Privileges:  entry.Privileges,
		Note:        entry.Note,
		PluginGated: pluginGatedSet()[name],
	}, true
}

// ACLForPath resolves a row from whatever APICallError.Endpoint happens to carry.
// That is the api/* path on every real HTTP failure, but a handful of client error
// paths populate it with the endpoint NAME instead, so both are accepted. A path
// carrying a query string resolves on its path part.
func ACLForPath(pathOrName string) (EndpointACL, bool) {
	if i := strings.IndexAny(pathOrName, "?#"); i >= 0 {
		pathOrName = pathOrName[:i]
	}
	pathOrName = strings.TrimPrefix(pathOrName, "/")
	if row, ok := ACLForEndpoint(EndpointName(pathOrName)); ok {
		return row, true
	}
	for name, path := range defaultEndpoints() {
		if string(path) == pathOrName {
			return ACLForEndpoint(name)
		}
	}
	return EndpointACL{}, false
}

func pluginGatedSet() map[EndpointName]bool {
	gated := make(map[EndpointName]bool, len(PluginGatedEndpoints()))
	for _, n := range PluginGatedEndpoints() {
		gated[n] = true
	}
	return gated
}

// isAuthzStatus reports whether a status code is OPNsense refusing on identity or
// privilege rather than on the request itself.
func isAuthzStatus(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusForbidden
}

// AuthzHint returns operator-facing remediation text for a 401/403, naming the
// collector, the endpoint and the privilege to grant. It returns "" for every
// other status.
//
// It is built only from this file's static table plus the endpoint the request was
// aimed at. It never reads the API key, the secret, the Authorization header or the
// response body, so it is always safe to log and to render in the operator console.
func (e APICallError) AuthzHint() string {
	if !isAuthzStatus(e.StatusCode) {
		return ""
	}

	row, ok := ACLForPath(e.Endpoint)
	if !ok {
		return fmt.Sprintf(
			"HTTP %d from %s: the OPNsense API user is not authorised for this endpoint, and the endpoint is not in the exporter's ACL matrix. Check the API key's user under System > Access > Users > Effective Privileges.",
			e.StatusCode, e.Endpoint)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d on %s (%s, consumed by %s)", e.StatusCode, row.Path, row.Component, row.Consumer)

	switch row.Status {
	case ACLStatusUnknown:
		fmt.Fprintf(&b, ": no OPNsense ACL privilege covers this URL in %s / %s or %s, so only page-all (\"All pages\") grants it. %s",
			ACLCoreCurrentRelease, ACLCorePreviousRelease, ACLPluginsSource, strings.TrimSuffix(row.Note, "."))
	default:
		keys := row.PrivilegeKeys()
		names := make([]string, 0, len(row.Privileges))
		for _, p := range row.Privileges {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		plural := "privilege"
		if len(keys) > 1 {
			plural = "any one of these privileges"
		}
		fmt.Fprintf(&b, ": grant the API key's user %s — %s (%s)",
			plural, strings.Join(names, ", "), strings.Join(keys, ", "))
		if row.Status == ACLStatusPluginDependent {
			b.WriteString(". This privilege is plugin- or release-dependent")
			if row.Note != "" {
				fmt.Fprintf(&b, ": %s", row.Note)
			}
		}
		if row.WildcardAPIScope() {
			b.WriteString(". Note this privilege grants a whole api/ prefix, so it also covers that controller's write actions")
		}
	}
	b.WriteString(". Verify with System > Access > Users > Effective Privileges.")
	return b.String()
}

// LogValue implements slog.LogValuer so a 401/403 logs the collector, endpoint and
// the privilege to grant instead of a bare "Forbidden" body (#442).
//
// Every other error renders exactly as it always has — the plain Error() string —
// so the log format only changes for the case that needs explaining. Credentials
// are never included: the group is built from AuthzHint and the static ACL table.
func (e *APICallError) LogValue() slog.Value {
	if e == nil {
		return slog.StringValue("<nil>")
	}
	if !isAuthzStatus(e.StatusCode) {
		return slog.StringValue(e.Error())
	}

	attrs := []slog.Attr{
		slog.String("error", e.Error()),
		slog.String("endpoint", e.Endpoint),
		slog.Int("code", e.StatusCode),
	}
	if row, ok := ACLForPath(e.Endpoint); ok {
		// An unknown classification still names a grant that works — page-all — so
		// the field is never empty and never a guess at a narrower privilege.
		privilege := strings.Join(row.PrivilegeKeys(), ",")
		if row.Status == ACLStatusUnknown {
			privilege = "page-all"
		}
		attrs = append(attrs,
			slog.String("collector", row.Consumer),
			slog.String("acl_status", string(row.Status)),
			slog.String("acl_privilege", privilege),
		)
	}
	attrs = append(attrs, slog.String("acl_hint", e.AuthzHint()))
	return slog.GroupValue(attrs...)
}

// endpointACL is the classification table. Every endpoint in defaultEndpoints()
// must appear here — TestEndpointACLCoversEveryEndpoint fails otherwise, which is
// what stops a new collector shipping with no ACL guidance.
var endpointACL = map[EndpointName]aclEntry{
	"acmeCertificates": {
		Consumer:  "acme",
		Component: "security/acme-client",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-acmeclient", Name: "Services: ACME Client", Origin: "security/acme-client", Pattern: "api/acmeclient/*", Scope: ACLScopeWildcard},
		},
	},
	"aliasTableSize": {
		Consumer:  "alias",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-firewall-alias-edit", Name: "Firewall: Alias: Edit", Origin: "core", Pattern: "api/firewall/alias/*", Scope: ACLScopeWildcard},
			{Key: "page-firewall-aliases", Name: "Firewall: Aliases", Origin: "core", Pattern: "api/firewall/alias/get*", Scope: ACLScopeWildcard},
		},
	},
	"apcupsdServiceStatus": {
		Consumer:  "apcupsd",
		Component: "sysutils/apcupsd",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-apcupsd", Name: "Services: Apcupsd System Monitoring page", Origin: "sysutils/apcupsd", Pattern: "api/apcupsd/service/*", Scope: ACLScopeWildcard},
		},
	},
	"apcupsdUpsStatus": {
		Consumer:  "apcupsd",
		Component: "sysutils/apcupsd",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-apcupsd", Name: "Services: Apcupsd System Monitoring page", Origin: "sysutils/apcupsd", Pattern: "api/apcupsd/service/*", Scope: ACLScopeWildcard},
		},
	},
	"arp": {
		Consumer:  "arp_table",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-arptable", Name: "Diagnostics: ARP Table", Origin: "core", Pattern: "api/diagnostics/interface/search_arp*", Scope: ACLScopeWildcard},
		},
	},
	"authAPIKeys": {
		Consumer:  "auth",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-usermanager", Name: "System: Access: Management", Origin: "core", Pattern: "api/auth/user/*", Scope: ACLScopeWildcard},
		},
	},
	"authGroups": {
		Consumer:  "auth",
		Component: "core",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-system-usermanager", Name: "System: Access: Management", Origin: "core", Pattern: "api/auth/group/*", Scope: ACLScopeWildcard},
		},
		Note: "granted by page-system-groupmanager on 26.1.11 and page-system-usermanager on 26.7.1",
	},
	"authUsers": {
		Consumer:  "auth",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-usermanager", Name: "System: Access: Management", Origin: "core", Pattern: "api/auth/user/*", Scope: ACLScopeWildcard},
		},
	},
	"backupHistory": {
		Consumer:  "backup",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-configurationhistory", Name: "Diagnostics: Configuration History", Origin: "core", Pattern: "api/core/backup/*", Scope: ACLScopeWildcard},
		},
	},
	"backupDiff": {
		Consumer:  "configchange",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-configurationhistory", Name: "Diagnostics: Configuration History", Origin: "core", Pattern: "api/core/backup/*", Scope: ACLScopeWildcard},
		},
	},
	"bpfStatistics": {
		Consumer:  "bpf",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netstat", Name: "Diagnostics: Netstat", Origin: "core", Pattern: "api/diagnostics/interface/get_bpf_statistics*", Scope: ACLScopeWildcard},
		},
	},
	"caCertificates": {
		Consumer:  "certificate",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-camanager", Name: "System: CA Manager", Origin: "core", Pattern: "api/trust/ca/*", Scope: ACLScopeWildcard},
		},
	},
	"captivePortalServiceStatus": {
		Consumer:  "captiveportal",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-captiveportal", Name: "Services: Captive Portal", Origin: "core", Pattern: "api/captiveportal/*", Scope: ACLScopeWildcard},
		},
	},
	"captivePortalSessions": {
		Consumer:  "captiveportal",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-captiveportal", Name: "Services: Captive Portal", Origin: "core", Pattern: "api/captiveportal/*", Scope: ACLScopeWildcard},
		},
	},
	"captivePortalVoucherGroups": {
		Consumer:  "captiveportal",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-captiveportal", Name: "Services: Captive Portal", Origin: "core", Pattern: "api/captiveportal/*", Scope: ACLScopeWildcard},
		},
	},
	"captivePortalVoucherProviders": {
		Consumer:  "captiveportal",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-captiveportal", Name: "Services: Captive Portal", Origin: "core", Pattern: "api/captiveportal/*", Scope: ACLScopeWildcard},
		},
	},
	"captivePortalVouchers": {
		Consumer:  "captiveportal",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-captiveportal", Name: "Services: Captive Portal", Origin: "core", Pattern: "api/captiveportal/*", Scope: ACLScopeWildcard},
		},
	},
	"captivePortalZones": {
		Consumer:  "captiveportal",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-captiveportal", Name: "Services: Captive Portal", Origin: "core", Pattern: "api/captiveportal/*", Scope: ACLScopeWildcard},
		},
	},
	"carpStatus": {
		Consumer:  "carp",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-carp", Name: "Interfaces: Virtual IPs: Status", Origin: "core", Pattern: "api/diagnostics/interface/get_vip_status", Scope: ACLScopeWildcard},
		},
	},
	"certificates": {
		Consumer:  "certificate",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-certmanager", Name: "System: Certificate Manager", Origin: "core", Pattern: "api/trust/cert/*", Scope: ACLScopeWildcard},
		},
	},
	"chronyServiceStatus": {
		Consumer:  "chrony",
		Component: "net/chrony",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-chrony", Name: "Services: Chrony", Origin: "net/chrony", Pattern: "api/chrony/*", Scope: ACLScopeWildcard},
		},
	},
	"chronySourceStats": {
		Consumer:  "chrony",
		Component: "net/chrony",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-chrony", Name: "Services: Chrony", Origin: "net/chrony", Pattern: "api/chrony/*", Scope: ACLScopeWildcard},
		},
	},
	"chronySources": {
		Consumer:  "chrony",
		Component: "net/chrony",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-chrony", Name: "Services: Chrony", Origin: "net/chrony", Pattern: "api/chrony/*", Scope: ACLScopeWildcard},
		},
	},
	"chronyTracking": {
		Consumer:  "chrony",
		Component: "net/chrony",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-chrony", Name: "Services: Chrony", Origin: "net/chrony", Pattern: "api/chrony/*", Scope: ACLScopeWildcard},
		},
	},
	"clamavVersion": {
		Consumer:  "clamav",
		Component: "security/clamav",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-clamav", Name: "Services: ClamAV", Origin: "security/clamav", Pattern: "api/clamav/*", Scope: ACLScopeWildcard},
		},
	},
	"cpuType": {
		Consumer:  "system",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-login-logout", Name: "Lobby: Dashboard", Origin: "core", Pattern: "api/diagnostics/cpu_usage/*", Scope: ACLScopeWildcard},
		},
	},
	"cpuUsageStream": {
		Consumer:  "cpu",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-login-logout", Name: "Lobby: Dashboard", Origin: "core", Pattern: "api/diagnostics/cpu_usage/*", Scope: ACLScopeWildcard},
		},
	},
	"cronJobs": {
		Consumer:  "cron",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-cron", Name: "System: Settings: Cron", Origin: "core", Pattern: "api/cron/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecAlerts": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecAppsecConfigs": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecAppsecRules": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecBouncers": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecCollections": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecDecisions": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecMachines": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecParsers": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecPostoverflows": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecScenarios": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecServiceStatus": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"crowdsecVersion": {
		Consumer:  "crowdsec",
		Component: "security/crowdsec",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-user-crowdsec", Name: "CrowdSec", Origin: "security/crowdsec", Pattern: "api/crowdsec/*", Scope: ACLScopeWildcard},
		},
	},
	"dechwPowerStatus": {
		Consumer:  "hardware",
		Component: "sysutils/dec-hw",
		Status:    ACLStatusUnknown,
		Note:      "the dec-hw plugin grants api/dechw/info/powerstatus; the exporter registers the underscored spelling power_status, which routes to the same action but matches no privilege except page-all.",
	},
	"dhcpv4": {
		Consumer:  "dhcpv4",
		Component: "net/isc-dhcp",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-status-dhcpleases", Name: "Services: ISC DHCPv4: Leases", Origin: "net/isc-dhcp", Pattern: "api/dhcpv4/leases/*", Scope: ACLScopeWildcard},
		},
	},
	"dhcpv6Leases": {
		Consumer:  "dhcpv6",
		Component: "net/isc-dhcp",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-status-dhcpv6leases", Name: "Status: ISC DHCPv6: Leases", Origin: "net/isc-dhcp", Pattern: "api/dhcpv6/leases/*", Scope: ACLScopeWildcard},
		},
	},
	"dhcpv6Prefixes": {
		Consumer:  "dhcpv6",
		Component: "net/isc-dhcp",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-status-dhcpv6leases", Name: "Status: ISC DHCPv6: Leases", Origin: "net/isc-dhcp", Pattern: "api/dhcpv6/leases/*", Scope: ACLScopeWildcard},
		},
	},
	"dmidecodeInfo": {
		Consumer:  "hardware",
		Component: "sysutils/dmidecode",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-service-dmidecode", Name: "Service: DMI Data Widget", Origin: "sysutils/dmidecode", Pattern: "api/dmidecode/service/get", Scope: ACLScopeExact},
		},
	},
	"dnsmasqLeases": {
		Consumer:  "dnsmasq",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-dnsforwarder", Name: "Services: Dnsmasq DNS/DHCP: Settings", Origin: "core", Pattern: "api/dnsmasq/*", Scope: ACLScopeWildcard},
		},
	},
	"dnsmasqRanges": {
		Consumer:  "dnsmasq",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-dnsforwarder", Name: "Services: Dnsmasq DNS/DHCP: Settings", Origin: "core", Pattern: "api/dnsmasq/*", Scope: ACLScopeWildcard},
		},
	},
	"dnsmasqServiceStatus": {
		Consumer:  "dnsmasq",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-dnsforwarder", Name: "Services: Dnsmasq DNS/DHCP: Settings", Origin: "core", Pattern: "api/dnsmasq/*", Scope: ACLScopeWildcard},
		},
	},
	"dyndnsAccounts": {
		Consumer:  "dyndns",
		Component: "dns/ddclient",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-dyndns", Name: "Services: Dynamic DNS", Origin: "dns/ddclient", Pattern: "api/dyndns/accounts/*", Scope: ACLScopeWildcard},
		},
	},
	"dyndnsServiceStatus": {
		Consumer:  "dyndns",
		Component: "dns/ddclient",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-dyndns", Name: "Services: Dynamic DNS", Origin: "dns/ddclient", Pattern: "api/dyndns/service/*", Scope: ACLScopeWildcard},
		},
	},
	"firewallGeoIP": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-firewall-alias-edit", Name: "Firewall: Alias: Edit", Origin: "core", Pattern: "api/firewall/alias/*", Scope: ACLScopeWildcard},
			{Key: "page-firewall-aliases", Name: "Firewall: Aliases", Origin: "core", Pattern: "api/firewall/alias/get*", Scope: ACLScopeWildcard},
		},
	},
	"firewallRuleIDs": {
		Consumer:  "(log shipping)",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-system-pftop", Name: "Diagnostics: Firewall sessions", Origin: "core", Pattern: "api/diagnostics/firewall/list_rule_ids", Scope: ACLScopeExact},
		},
	},
	"firewallRuleStats": {
		Consumer:  "firewall_rule",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-firewall-rules", Name: "Firewall: Rules", Origin: "core", Pattern: "api/firewall/filter_util/rule_stats*", Scope: ACLScopeWildcard},
		},
	},
	"firewallRules": {
		Consumer:  "firewall_rule",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-filter-api", Name: "Firewall: Rules [new]", Origin: "core", Pattern: "api/firewall/filter/*", Scope: ACLScopeWildcard},
		},
	},
	"firewallStates": {
		Consumer:  "flow",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-showstates", Name: "Diagnostics: Show States", Origin: "core", Pattern: "api/diagnostics/firewall/query_states*", Scope: ACLScopeWildcard},
		},
	},
	"firewallStats": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-logs-firewall-summary", Name: "Diagnostics: Logs: Firewall: Summary View", Origin: "core", Pattern: "api/diagnostics/firewall/stats*", Scope: ACLScopeWildcard},
		},
	},
	"firmware": {
		Consumer:  "firmware",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-firmware-manualupdate", Name: "System: Firmware", Origin: "core", Pattern: "api/core/firmware/*", Scope: ACLScopeWildcard},
		},
	},
	"firmwareInfo": {
		Consumer:  "firmware",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-firmware-manualupdate", Name: "System: Firmware", Origin: "core", Pattern: "api/core/firmware/*", Scope: ACLScopeWildcard},
		},
	},
	"gatewaysStatus": {
		Consumer:  "gateways",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-gateways", Name: "System: Gateways", Origin: "core", Pattern: "api/routing/settings/*", Scope: ACLScopeWildcard},
		},
	},
	"gatewayGroups": {
		Consumer:  "gateway_groups",
		Component: "core",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-system-gateways", Name: "System: Gateways", Origin: "core", Pattern: "api/routing/group_settings/*", Scope: ACLScopeWildcard},
		},
	},
	"firewallMigrationRules": {
		Consumer:  "firewall_migration",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "no ACL pattern in either supported core release covers api/firewall/migration/countRules; only page-all is known to reach it.",
	},
	"firewallMigrationOutbound": {
		Consumer:  "firewall_migration",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "no ACL pattern in either supported core release covers api/firewall/migration/countOutbound; only page-all is known to reach it.",
	},
	"haproxyCounters": {
		Consumer:  "haproxy",
		Component: "net/haproxy",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-haproxy", Name: "Services: HAProxy", Origin: "net/haproxy", Pattern: "api/haproxy/*", Scope: ACLScopeWildcard},
		},
	},
	"haproxyInfo": {
		Consumer:  "haproxy",
		Component: "net/haproxy",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-haproxy", Name: "Services: HAProxy", Origin: "net/haproxy", Pattern: "api/haproxy/*", Scope: ACLScopeWildcard},
		},
	},
	"haproxyServiceStatus": {
		Consumer:  "haproxy",
		Component: "net/haproxy",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-haproxy", Name: "Services: HAProxy", Origin: "net/haproxy", Pattern: "api/haproxy/*", Scope: ACLScopeWildcard},
		},
	},
	"haproxyTables": {
		Consumer:  "haproxy",
		Component: "net/haproxy",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-haproxy", Name: "Services: HAProxy", Origin: "net/haproxy", Pattern: "api/haproxy/*", Scope: ACLScopeWildcard},
		},
	},
	"hasyncServices": {
		Consumer:  "hasync",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-habackup", Name: "Status: HA backup", Origin: "core", Pattern: "api/core/hasync_status/*", Scope: ACLScopeWildcard},
		},
	},
	"hasyncVersion": {
		Consumer:  "hasync",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-habackup", Name: "Status: HA backup", Origin: "core", Pattern: "api/core/hasync_status/*", Scope: ACLScopeWildcard},
		},
	},
	"healthCheck": {
		Consumer:  "(health probe)",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-status", Name: "System: Status", Origin: "core", Pattern: "api/core/system/status*", Scope: ACLScopeWildcard},
		},
	},
	"hostdiscoverySearch": {
		Consumer:  "hostdiscovery",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-hostdiscovery", Name: "Interfaces: Neighbors: Automatic discovery", Origin: "core", Pattern: "api/hostdiscovery/service/*", Scope: ACLScopeWildcard},
		},
	},
	"idsAlertLogs": {
		Consumer:  "ids",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-ids", Name: "Services: Intrusion Detection", Origin: "core", Pattern: "api/ids/*", Scope: ACLScopeWildcard},
		},
	},
	"idsQueryAlerts": {
		Consumer:  "ids",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-ids", Name: "Services: Intrusion Detection", Origin: "core", Pattern: "api/ids/*", Scope: ACLScopeWildcard},
		},
	},
	"idsRulesets": {
		Consumer:  "ids",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-ids", Name: "Services: Intrusion Detection", Origin: "core", Pattern: "api/ids/*", Scope: ACLScopeWildcard},
		},
	},
	"idsSearchInstalledRules": {
		Consumer:  "ids",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-ids", Name: "Services: Intrusion Detection", Origin: "core", Pattern: "api/ids/*", Scope: ACLScopeWildcard},
		},
	},
	"idsSettings": {
		Consumer:  "ids",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-ids", Name: "Services: Intrusion Detection", Origin: "core", Pattern: "api/ids/*", Scope: ACLScopeWildcard},
		},
	},
	"idsStatus": {
		Consumer:  "ids",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-ids", Name: "Services: Intrusion Detection", Origin: "core", Pattern: "api/ids/*", Scope: ACLScopeWildcard},
		},
	},
	"interfaceConfig": {
		Consumer:  "(log shipping)",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "no core ACL pattern covers api/diagnostics/interface/get_interface_config at all in either supported release; only page-all reaches it.",
	},
	"interfaceStatistics": {
		Consumer:  "(log shipping)",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netstat", Name: "Diagnostics: Netstat", Origin: "core", Pattern: "api/diagnostics/interface/get_interface_statistics*", Scope: ACLScopeWildcard},
		},
	},
	"interfaces": {
		Consumer:  "interfaces",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-trafficgraph", Name: "Reporting: Traffic", Origin: "core", Pattern: "api/diagnostics/traffic/*", Scope: ACLScopeWildcard},
		},
	},
	"interfacesOverview": {
		Consumer:  "interfaces",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-interfaces", Name: "Status: Interfaces", Origin: "core", Pattern: "api/interfaces/overview/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecLegacyStatus": {
		Consumer:  "ipsec",
		Component: "security/strongswan-legacy",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-vpn-ipsec", Name: "VPN: IPsec: Tunnels [legacy]", Origin: "security/strongswan-legacy", Pattern: "api/ipsec/legacy_subsystem/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecPhase1": {
		Consumer:  "ipsec",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ipsec", Name: "Status: IPsec", Origin: "core", Pattern: "api/ipsec/sessions/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecPhase2": {
		Consumer:  "ipsec",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ipsec", Name: "Status: IPsec", Origin: "core", Pattern: "api/ipsec/sessions/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecPools": {
		Consumer:  "ipsec",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ipsec-leases", Name: "Status: IPsec: Leasespage", Origin: "core", Pattern: "api/ipsec/leases/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecSad": {
		Consumer:  "ipsec",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ipsec-sad", Name: "Status: IPsec: SAD", Origin: "core", Pattern: "api/ipsec/sad/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecServiceStatus": {
		Consumer:  "ipsec",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ipsec-spd", Name: "Status: IPsec: SPD", Origin: "core", Pattern: "api/ipsec/service/*", Scope: ACLScopeWildcard},
			{Key: "page-vpn-ipsec-connections", Name: "VPN: IPsec: Connections", Origin: "core", Pattern: "api/ipsec/service/*", Scope: ACLScopeWildcard},
			{Key: "page-vpn-ipsec-editkeys", Name: "VPN: IPsec: Edit Pre-Shared Keys", Origin: "core", Pattern: "api/ipsec/service/*", Scope: ACLScopeWildcard},
			{Key: "page-vpn-ipsec-keypairs", Name: "VPN: IPsec: Key Pairs", Origin: "core", Pattern: "api/ipsec/service/*", Scope: ACLScopeWildcard},
		},
	},
	"ipsecSpd": {
		Consumer:  "ipsec",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ipsec-spd", Name: "Status: IPsec: SPD", Origin: "core", Pattern: "api/ipsec/spd/*", Scope: ACLScopeWildcard},
		},
	},
	"keaLeases4": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v4", Name: "Services: DHCP: Kea(v4)", Origin: "core", Pattern: "api/kea/leases4/*", Scope: ACLScopeWildcard},
		},
	},
	"keaLeases6": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v6", Name: "Services: DHCP: Kea(v6)", Origin: "core", Pattern: "api/kea/leases6/*", Scope: ACLScopeWildcard},
		},
	},
	"keaReservations4": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v4", Name: "Services: DHCP: Kea(v4)", Origin: "core", Pattern: "api/kea/dhcpv4/*", Scope: ACLScopeWildcard},
		},
	},
	"keaReservations6": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v6", Name: "Services: DHCP: Kea(v6)", Origin: "core", Pattern: "api/kea/dhcpv6/*", Scope: ACLScopeWildcard},
		},
	},
	"keaPdPools6": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v6", Name: "Services: DHCP: Kea(v6)", Origin: "core", Pattern: "api/kea/dhcpv6/*", Scope: ACLScopeWildcard},
		},
	},
	"keaServiceStatus": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-ctrl-agent", Name: "Services: DHCP: Kea Ctrl Agent", Origin: "core", Pattern: "api/kea/service/*", Scope: ACLScopeWildcard},
			{Key: "page-dhcp-kea-ddns", Name: "Services: DHCP: Kea DDNS Agent", Origin: "core", Pattern: "api/kea/service/*", Scope: ACLScopeWildcard},
			{Key: "page-dhcp-kea-v4", Name: "Services: DHCP: Kea(v4)", Origin: "core", Pattern: "api/kea/service/*", Scope: ACLScopeWildcard},
			{Key: "page-dhcp-kea-v6", Name: "Services: DHCP: Kea(v6)", Origin: "core", Pattern: "api/kea/service/*", Scope: ACLScopeWildcard},
		},
	},
	"keaSubnets4": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v4", Name: "Services: DHCP: Kea(v4)", Origin: "core", Pattern: "api/kea/dhcpv4/*", Scope: ACLScopeWildcard},
		},
	},
	"keaSubnets6": {
		Consumer:  "kea",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-dhcp-kea-v6", Name: "Services: DHCP: Kea(v6)", Origin: "core", Pattern: "api/kea/dhcpv6/*", Scope: ACLScopeWildcard},
		},
	},
	"lldpdNeighbors": {
		Consumer:  "lldp",
		Component: "net-mgmt/lldpd",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-lldpd", Name: "Services: Lldpd", Origin: "net-mgmt/lldpd", Pattern: "api/lldpd/*", Scope: ACLScopeWildcard},
		},
	},
	"memoryStatistics": {
		Consumer:  "mbuf",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netstat", Name: "Diagnostics: Netstat", Origin: "core", Pattern: "api/diagnostics/interface/get_memory_statistics*", Scope: ACLScopeWildcard},
		},
	},
	"monitServiceStatus": {
		Consumer:  "monit",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-monit", Name: "WebCfg - Services: Monit System Monitoring page", Origin: "core", Pattern: "api/monit/service/*", Scope: ACLScopeWildcard},
		},
	},
	"monitStatus": {
		Consumer:  "monit",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-monit", Name: "WebCfg - Services: Monit System Monitoring page", Origin: "core", Pattern: "api/monit/status/*", Scope: ACLScopeWildcard},
		},
	},
	"natDNATRules": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-firewall-nat-portforward-edit", Name: "Firewall: NAT: Destination NAT", Origin: "core", Pattern: "api/firewall/d_nat/*", Scope: ACLScopeWildcard},
		},
	},
	"natNPTRules": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-firewall-nat-npt", Name: "Firewall: NAT: NPTv6", Origin: "core", Pattern: "api/firewall/npt/*", Scope: ACLScopeWildcard},
		},
	},
	"natOneToOneRules": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-firewall-nat-1-1-edit", Name: "Firewall: NAT: 1:1", Origin: "core", Pattern: "api/firewall/one_to_one/*", Scope: ACLScopeWildcard},
		},
	},
	"natSourceNATRules": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-filter-snat-api", Name: "Firewall: NAT: Source NAT", Origin: "core", Pattern: "api/firewall/source_nat/*", Scope: ACLScopeWildcard},
		},
	},
	"ndpTable": {
		Consumer:  "ndp",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-ndptable", Name: "Diagnostics: NDP Table", Origin: "core", Pattern: "api/diagnostics/interface/get_ndp*", Scope: ACLScopeWildcard},
		},
	},
	"netbirdServiceStatus": {
		Consumer:  "netbird",
		Component: "security/netbird",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-vpn-netbird", Name: "VPN: NetBird", Origin: "security/netbird", Pattern: "api/netbird/*", Scope: ACLScopeWildcard},
		},
	},
	"netbirdStatus": {
		Consumer:  "netbird",
		Component: "security/netbird",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-vpn-netbird", Name: "VPN: NetBird", Origin: "security/netbird", Pattern: "api/netbird/*", Scope: ACLScopeWildcard},
		},
	},
	"zerotierNetworkInfo": {
		Consumer:  "zerotier",
		Component: "net/zerotier",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-vpn-zerotier", Name: "VPN: Zerotier", Origin: "net/zerotier", Pattern: "api/zerotier/*", Scope: ACLScopeWildcard},
		},
	},
	"zerotierNetworks": {
		Consumer:  "zerotier",
		Component: "net/zerotier",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-vpn-zerotier", Name: "VPN: Zerotier", Origin: "net/zerotier", Pattern: "api/zerotier/*", Scope: ACLScopeWildcard},
		},
	},
	"netflowCacheStats": {
		Consumer:  "netflow",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netflow", Name: "Diagnostics: Netflow configuration", Origin: "core", Pattern: "api/diagnostics/netflow/*", Scope: ACLScopeWildcard},
		},
	},
	"netflowGetConfig": {
		Consumer:  "netflow",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netflow", Name: "Diagnostics: Netflow configuration", Origin: "core", Pattern: "api/diagnostics/netflow/*", Scope: ACLScopeWildcard},
		},
	},
	"netflowIsEnabled": {
		Consumer:  "netflow",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netflow", Name: "Diagnostics: Netflow configuration", Origin: "core", Pattern: "api/diagnostics/netflow/*", Scope: ACLScopeWildcard},
		},
	},
	"netflowStatus": {
		Consumer:  "netflow",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netflow", Name: "Diagnostics: Netflow configuration", Origin: "core", Pattern: "api/diagnostics/netflow/*", Scope: ACLScopeWildcard},
		},
	},
	"netisrStatistics": {
		Consumer:  "network_diag",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netstat", Name: "Diagnostics: Netstat", Origin: "core", Pattern: "api/diagnostics/interface/get_netisr_statistics*", Scope: ACLScopeWildcard},
		},
	},
	"nginxBans": {
		Consumer:  "nginx",
		Component: "www/nginx",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-Nginx", Name: "nginx", Origin: "www/nginx", Pattern: "api/nginx/*", Scope: ACLScopeWildcard},
		},
	},
	"nginxServiceStatus": {
		Consumer:  "nginx",
		Component: "www/nginx",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-Nginx", Name: "nginx", Origin: "www/nginx", Pattern: "api/nginx/*", Scope: ACLScopeWildcard},
		},
	},
	"nginxVts": {
		Consumer:  "nginx",
		Component: "www/nginx",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-Nginx", Name: "nginx", Origin: "www/nginx", Pattern: "api/nginx/*", Scope: ACLScopeWildcard},
		},
	},
	"ntpGPS": {
		Consumer:  "ntp",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "Status: NTP grants only the exact route api/ntpd/service/status; nothing grants api/ntpd/service/gps except page-all.",
	},
	"ntpStatus": {
		Consumer:  "ntp",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-ntp", Name: "Status: NTP", Origin: "core", Pattern: "api/ntpd/service/status", Scope: ACLScopeExact},
		},
	},
	"nutServiceStatus": {
		Consumer:  "nut",
		Component: "sysutils/nut",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-nut", Name: "Nut", Origin: "sysutils/nut", Pattern: "api/nut/*", Scope: ACLScopeWildcard},
		},
	},
	"nutUpsStatus": {
		Consumer:  "nut",
		Component: "sysutils/nut",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-nut", Name: "Nut", Origin: "sysutils/nut", Pattern: "api/nut/*", Scope: ACLScopeWildcard},
		},
	},
	"openVPNInstances": {
		Consumer:  "openvpn",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-openvpn-instances", Name: "VPN: OpenVPN: Instances", Origin: "core", Pattern: "api/openvpn/instances/*", Scope: ACLScopeWildcard},
		},
	},
	"openVPNSessions": {
		Consumer:  "openvpn",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-openvpn", Name: "Status: OpenVPN", Origin: "core", Pattern: "api/openvpn/service/*", Scope: ACLScopeWildcard},
		},
	},
	"pfStates": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "Lobby: Dashboard grants the exact route api/diagnostics/firewall/pf_states with no trailing wildcard; the exporter appends the /1 parameter, so the request URI matches no privilege except page-all.",
	},
	"pfStatisticsByInterface": {
		Consumer:  "firewall",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-pf-info", Name: "Diagnostics: Firewall statistics", Origin: "core", Pattern: "api/diagnostics/firewall/pf_statistics/*", Scope: ACLScopeWildcard},
		},
	},
	"pfStatsInfo": {
		Consumer:  "pf_stats",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-pf-info", Name: "Diagnostics: Firewall statistics", Origin: "core", Pattern: "api/diagnostics/firewall/pf_statistics/*", Scope: ACLScopeWildcard},
		},
	},
	"pfStatsMemory": {
		Consumer:  "pf_stats",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-pf-info", Name: "Diagnostics: Firewall statistics", Origin: "core", Pattern: "api/diagnostics/firewall/pf_statistics/*", Scope: ACLScopeWildcard},
		},
	},
	"pfStatsTimeouts": {
		Consumer:  "pf_stats",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-pf-info", Name: "Diagnostics: Firewall statistics", Origin: "core", Pattern: "api/diagnostics/firewall/pf_statistics/*", Scope: ACLScopeWildcard},
		},
	},
	"pfsyncNodes": {
		Consumer:  "network_diag",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-carp", Name: "Interfaces: Virtual IPs: Status", Origin: "core", Pattern: "api/diagnostics/interface/get_pfsync_nodes", Scope: ACLScopeWildcard},
		},
	},
	"protocolStatistics": {
		Consumer:  "protocol",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netstat", Name: "Diagnostics: Netstat", Origin: "core", Pattern: "api/diagnostics/interface/get_protocol_statistics*", Scope: ACLScopeWildcard},
		},
	},
	"qfeedsStats": {
		Consumer:  "qfeeds",
		Component: "security/q-feeds-connector",
		Status:    ACLStatusUnknown,
		Note:      "the q-feeds-connector plugin grants api/q_feeds/*; the exporter registers api/qfeeds/..., which routes to the same controller but matches no privilege except page-all.",
	},
	"quaggaBfdCounters": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaBfdNeighbors": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaBfdSummary": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaBgpNeighbors": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaBgpSummary": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaBgpRoute4": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaBgpRoute6": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaGeneralRoute4": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaGeneralRoute6": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfDatabase": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfInterface": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfNeighbors": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfOverview": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfRoute": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfv3Database": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfv3Interface": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfv3Overview": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaOspfv3Route": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"quaggaServiceStatus": {
		Consumer:  "frr",
		Component: "net/frr",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-routing", Name: "Routing", Origin: "net/frr", Pattern: "api/quagga/*", Scope: ACLScopeWildcard},
		},
	},
	"relaydStatusSum": {
		Consumer:  "relayd",
		Component: "net/relayd",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-relayd", Name: "Services: Relayd", Origin: "net/relayd", Pattern: "api/relayd/*", Scope: ACLScopeWildcard},
		},
	},
	"routingTable": {
		Consumer:  "network_diag",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-routingtables", Name: "Diagnostics: Routing tables", Origin: "core", Pattern: "api/diagnostics/interface/get_routes*", Scope: ACLScopeWildcard},
		},
	},
	"services": {
		Consumer:  "services",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-status-services", Name: "Status: Services", Origin: "core", Pattern: "api/core/service/*", Scope: ACLScopeWildcard},
		},
	},
	"siproxdRegistrations": {
		Consumer:  "siproxd",
		Component: "net/siproxd",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-siproxd", Name: "Services: Siproxd", Origin: "net/siproxd", Pattern: "api/siproxd/*", Scope: ACLScopeWildcard},
		},
	},
	"smartInfo": {
		Consumer:  "smart",
		Component: "sysutils/smart",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-smart", Name: "Services: SMART", Origin: "sysutils/smart", Pattern: "api/smart/service/*", Scope: ACLScopeWildcard},
		},
	},
	"smartList": {
		Consumer:  "smart",
		Component: "sysutils/smart",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-smart", Name: "Services: SMART", Origin: "sysutils/smart", Pattern: "api/smart/service/*", Scope: ACLScopeWildcard},
		},
	},
	"snapshotsIsSupported": {
		Consumer:  "snapshots",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-snapshots", Name: "System: Snapshots", Origin: "core", Pattern: "api/core/snapshots/*", Scope: ACLScopeWildcard},
		},
	},
	"snapshotsSearch": {
		Consumer:  "snapshots",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-snapshots", Name: "System: Snapshots", Origin: "core", Pattern: "api/core/snapshots/*", Scope: ACLScopeWildcard},
		},
	},
	"socketStatistics": {
		Consumer:  "network_diag",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-netstat", Name: "Diagnostics: Netstat", Origin: "core", Pattern: "api/diagnostics/interface/get_socket_statistics*", Scope: ACLScopeWildcard},
		},
	},
	"syslogServiceStatus": {
		Consumer:  "syslog",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-logs-settings-targets", Name: "System: Settings: Logging", Origin: "core", Pattern: "api/syslog/*", Scope: ACLScopeWildcard},
		},
	},
	"syslogStats": {
		Consumer:  "syslog",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-logs-settings-targets", Name: "System: Settings: Logging", Origin: "core", Pattern: "api/syslog/*", Scope: ACLScopeWildcard},
		},
	},
	"systemActivity": {
		Consumer:  "activity",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-system-activity", Name: "Diagnostics: System Activity", Origin: "core", Pattern: "api/diagnostics/activity/*", Scope: ACLScopeWildcard},
		},
	},
	"systemDisk": {
		Consumer:  "system",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL grants the snake_case spelling api/diagnostics/system/system_disk (Lobby: Dashboard). OPNsense routes both spellings to the same action but matches the ACL against the raw request URI, so the camelCase URL the exporter registers is covered by no privilege except page-all.",
	},
	"systemInformation": {
		Consumer:  "system",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-system-login-logout", Name: "Lobby: Dashboard", Origin: "core", Pattern: "api/diagnostics/system/system_information", Scope: ACLScopeWildcard},
		},
	},
	"systemMemory": {
		Consumer:  "kernel_memory",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL's Lobby: Dashboard privilege lists the seven api/diagnostics/system/system_* URLs individually and carries no wildcard; api/diagnostics/system/memory (SystemController::memoryAction) appears in no pattern in either audited core release, so it is covered by no privilege except page-all. Re-checked against core stable/26.7 and master on 2026-07-30.",
	},
	"systemMbuf": {
		Consumer:  "mbuf",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL grants api/diagnostics/system/system_mbuf (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all.",
	},
	"systemResources": {
		Consumer:  "system",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL grants api/diagnostics/system/system_resources (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all.",
	},
	"systemSwap": {
		Consumer:  "system",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL grants api/diagnostics/system/system_swap (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all.",
	},
	"systemTemperature": {
		Consumer:  "temperature",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL grants api/diagnostics/system/system_temperature (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all.",
	},
	"systemTime": {
		Consumer:  "system",
		Component: "core",
		Status:    ACLStatusUnknown,
		Note:      "the Core ACL grants api/diagnostics/system/system_time (Lobby: Dashboard); the camelCase URL the exporter registers matches no privilege except page-all.",
	},
	"tailscaleServiceStatus": {
		Consumer:  "tailscale",
		Component: "security/tailscale",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-tailscale-config", Name: "Tailscale", Origin: "security/tailscale", Pattern: "api/tailscale/service/*", Scope: ACLScopeWildcard},
		},
	},
	"tailscaleStatus": {
		Consumer:  "tailscale",
		Component: "security/tailscale",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-tailscale-config", Name: "Tailscale", Origin: "security/tailscale", Pattern: "api/tailscale/status/*", Scope: ACLScopeWildcard},
		},
	},
	"torCircuits": {
		Consumer:  "tor",
		Component: "security/tor",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-tor", Name: "tor", Origin: "security/tor", Pattern: "api/tor/*", Scope: ACLScopeWildcard},
		},
	},
	"torHiddenServices": {
		Consumer:  "tor",
		Component: "security/tor",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-tor", Name: "tor", Origin: "security/tor", Pattern: "api/tor/*", Scope: ACLScopeWildcard},
		},
	},
	"torStreams": {
		Consumer:  "tor",
		Component: "security/tor",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-tor", Name: "tor", Origin: "security/tor", Pattern: "api/tor/*", Scope: ACLScopeWildcard},
		},
	},
	"trafficShaperStatistics": {
		Consumer:  "trafficshaper",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-diagnostics-limiter-info", Name: "Diagnostics: Shaper status", Origin: "core", Pattern: "api/trafficshaper/service/statistics/*", Scope: ACLScopeWildcard},
			{Key: "page-firewall-trafficshaper", Name: "Firewall: Shaper", Origin: "core", Pattern: "api/trafficshaper/*", Scope: ACLScopeWildcard},
		},
	},
	"unboundBlocklistPolicies": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
			{Key: "page-status-dnsoverview", Name: "Status: DNS Overview", Origin: "core", Pattern: "api/unbound/overview*", Scope: ACLScopeWildcard},
		},
	},
	"unboundDNSStatus": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
		},
	},
	"unboundInfra": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
		},
	},
	"unboundInsecureDomains": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
		},
	},
	"unboundLocalData": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
		},
	},
	"unboundLocalZones": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
		},
	},
	"unboundQueryStatsEnabled": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
			{Key: "page-status-dnsoverview", Name: "Status: DNS Overview", Origin: "core", Pattern: "api/unbound/overview*", Scope: ACLScopeWildcard},
		},
	},
	"unboundQueryStatsTotals": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
			{Key: "page-status-dnsoverview", Name: "Status: DNS Overview", Origin: "core", Pattern: "api/unbound/overview*", Scope: ACLScopeWildcard},
		},
	},
	"unboundSearchQueries": {
		Consumer:  "(log shipping)",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
			{Key: "page-status-dnsoverview", Name: "Status: DNS Overview", Origin: "core", Pattern: "api/unbound/overview*", Scope: ACLScopeWildcard},
		},
	},
	"unboundServiceStatus": {
		Consumer:  "unbound_dns",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-services-unbound", Name: "Services: Unbound", Origin: "core", Pattern: "api/unbound/*", Scope: ACLScopeWildcard},
		},
	},
	"vnstatGetJsonData": {
		Consumer:  "vnstat",
		Component: "net/vnstat",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-vnstat", Name: "Services: Vnstat", Origin: "net/vnstat", Pattern: "api/vnstat/*", Scope: ACLScopeWildcard},
		},
	},
	"vnstatInterfaceList": {
		Consumer:  "vnstat",
		Component: "net/vnstat",
		Status:    ACLStatusPluginDependent,
		Privileges: []ACLPrivilege{
			{Key: "page-services-vnstat", Name: "Services: Vnstat", Origin: "net/vnstat", Pattern: "api/vnstat/*", Scope: ACLScopeWildcard},
		},
	},
	"wireguardClients": {
		Consumer:  "wireguard",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-wireguard-config", Name: "VPN: WireGuard: Configuration", Origin: "core", Pattern: "api/wireguard/service/*", Scope: ACLScopeWildcard},
			{Key: "page-wireguard-diagnostics", Name: "VPN: WireGuard: Status", Origin: "core", Pattern: "api/wireguard/service/*", Scope: ACLScopeWildcard},
		},
	},
	"wireguardServiceStatus": {
		Consumer:  "wireguard",
		Component: "core",
		Status:    ACLStatusKnown,
		Privileges: []ACLPrivilege{
			{Key: "page-wireguard-config", Name: "VPN: WireGuard: Configuration", Origin: "core", Pattern: "api/wireguard/service/*", Scope: ACLScopeWildcard},
			{Key: "page-wireguard-diagnostics", Name: "VPN: WireGuard: Status", Origin: "core", Pattern: "api/wireguard/service/*", Scope: ACLScopeWildcard},
		},
	},
}
