package opnsense

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// TestEndpointACLCoversEveryEndpoint is the completeness gate demanded by #442:
// a new endpoint added to defaultEndpoints() without an ACL classification fails
// here, and a classification left behind by a removed endpoint fails here too.
func TestEndpointACLCoversEveryEndpoint(t *testing.T) {
	endpoints := defaultEndpoints()

	for name := range endpoints {
		if _, ok := endpointACL[name]; !ok {
			t.Errorf("endpoint %q has no ACL classification; add it to endpointACL in opnsense/acl.go "+
				"(use ACLStatusUnknown with a Note rather than guessing a privilege)", name)
		}
	}
	for name := range endpointACL {
		if _, ok := endpoints[name]; !ok {
			t.Errorf("endpointACL carries %q, which is not in defaultEndpoints(); remove the stale entry", name)
		}
	}
}

// TestEndpointACLEntriesAreWellFormed enforces the three-state contract: an entry
// is either a known privilege, plugin/version-dependent, or explicitly unknown —
// and an unknown one must say why rather than silently claiming nothing.
func TestEndpointACLEntriesAreWellFormed(t *testing.T) {
	for name, entry := range endpointACL {
		switch entry.Status {
		case ACLStatusKnown, ACLStatusPluginDependent:
			if len(entry.Privileges) == 0 {
				t.Errorf("%s: status %q with no privileges; use ACLStatusUnknown instead", name, entry.Status)
			}
		case ACLStatusUnknown:
			if len(entry.Privileges) != 0 {
				t.Errorf("%s: status unknown but carries %d privileges", name, len(entry.Privileges))
			}
			if entry.Note == "" {
				t.Errorf("%s: status unknown with no Note; an unknown mapping must state what was checked", name)
			}
		default:
			t.Errorf("%s: unrecognised ACL status %q", name, entry.Status)
		}

		if entry.Consumer == "" {
			t.Errorf("%s: no Consumer (collector subsystem or non-collector consumer) recorded", name)
		}
		if entry.Component == "" {
			t.Errorf("%s: no Component (core or plugin port) recorded", name)
		}
		for _, p := range entry.Privileges {
			if p.Key == "" || p.Name == "" || p.Pattern == "" || p.Origin == "" {
				t.Errorf("%s: incomplete privilege %+v", name, p)
			}
			if p.Scope != ACLScopeExact && p.Scope != ACLScopeWildcard {
				t.Errorf("%s: privilege %s has invalid scope %q", name, p.Key, p.Scope)
			}
		}
	}
}

// TestEndpointACLsResolveByNameAndPath covers both public lookups.
func TestEndpointACLsResolveByNameAndPath(t *testing.T) {
	all := EndpointACLs()
	if len(all) != len(defaultEndpoints()) {
		t.Fatalf("EndpointACLs() returned %d rows, want %d", len(all), len(defaultEndpoints()))
	}

	byName, ok := ACLForEndpoint("arp")
	if !ok {
		t.Fatal("ACLForEndpoint(arp) not found")
	}
	if byName.Path != "api/diagnostics/interface/search_arp" {
		t.Errorf("arp path = %q", byName.Path)
	}
	if byName.Method != "POST" {
		t.Errorf("arp method = %q, want POST (it is in postEndpoints)", byName.Method)
	}
	if byName.Consumer != "arp_table" {
		t.Errorf("arp consumer = %q, want arp_table", byName.Consumer)
	}

	byPath, ok := ACLForPath("api/diagnostics/interface/search_arp")
	if !ok {
		t.Fatal("ACLForPath did not resolve the arp path")
	}
	if byPath.Endpoint != "arp" {
		t.Errorf("ACLForPath resolved to %q, want arp", byPath.Endpoint)
	}

	// The lookup must also accept an endpoint NAME, because a handful of client
	// error paths populate APICallError.Endpoint with the name, not the path.
	byNameViaPath, ok := ACLForPath("arp")
	if !ok || byNameViaPath.Endpoint != "arp" {
		t.Errorf("ACLForPath(%q) = %+v, %v; want the arp row", "arp", byNameViaPath, ok)
	}

	if _, ok := ACLForPath("api/does/not/exist"); ok {
		t.Error("ACLForPath resolved an unknown path")
	}
}

// TestEndpointACLPrivilegeScopeIsHonest guards the security claim the docs make:
// a wildcard api/ pattern grants every action under that prefix, writes included.
func TestEndpointACLPrivilegeScopeIsHonest(t *testing.T) {
	entry, ok := ACLForEndpoint("ntpStatus")
	if !ok {
		t.Fatal("ntpStatus missing")
	}
	if entry.WildcardAPIScope() {
		t.Errorf("ntpStatus: page-status-ntp grants only the exact api/ntpd/service/status route; WildcardAPIScope() must be false")
	}

	entry, ok = ACLForEndpoint("services")
	if !ok {
		t.Fatal("services missing")
	}
	if !entry.WildcardAPIScope() {
		t.Errorf("services: Status: Services grants api/core/service/* including restart/start/stop; WildcardAPIScope() must be true")
	}
}

// TestAuthzHintNamesCollectorEndpointAndPrivilege is the #442 acceptance check for
// actionable 403s.
func TestAuthzHintNamesCollectorEndpointAndPrivilege(t *testing.T) {
	err := &APICallError{
		Endpoint:   "api/core/service/search",
		Message:    `{"status":403,"message":"Forbidden"}`,
		StatusCode: http.StatusForbidden,
	}
	hint := err.AuthzHint()
	if hint == "" {
		t.Fatal("AuthzHint() empty for a 403")
	}
	for _, want := range []string{"services", "api/core/service/search", "page-status-services", "Status: Services"} {
		if !strings.Contains(hint, want) {
			t.Errorf("AuthzHint() = %q, missing %q", hint, want)
		}
	}
	if strings.Contains(hint, err.Message) {
		t.Errorf("AuthzHint() must not echo the response body: %q", hint)
	}
}

func TestAuthzHintOnlyForAuthzStatuses(t *testing.T) {
	for _, code := range []int{200, 404, 500, 0} {
		err := &APICallError{Endpoint: "api/core/service/search", StatusCode: code}
		if got := err.AuthzHint(); got != "" {
			t.Errorf("status %d: AuthzHint() = %q, want empty", code, got)
		}
	}
}

func TestAuthzHintForUnknownClassification(t *testing.T) {
	err := &APICallError{Endpoint: "api/diagnostics/system/systemDisk", StatusCode: http.StatusForbidden}
	hint := err.AuthzHint()
	if !strings.Contains(hint, "no OPNsense ACL") {
		t.Errorf("AuthzHint() for an unknown-classification endpoint = %q; it must say the mapping is unknown", hint)
	}
	if !strings.Contains(hint, "page-all") {
		t.Errorf("AuthzHint() = %q; it must name page-all as the only grant that covers it", hint)
	}
}

// TestLogValueLeavesNonAuthErrorsUnchanged pins the log-shape promise: only 401/403
// lines gain the ACL annotation, every other error still renders exactly as before.
func TestLogValueLeavesNonAuthErrorsUnchanged(t *testing.T) {
	err := &APICallError{Endpoint: "api/core/service/search", Message: "boom", StatusCode: 500}
	v := err.LogValue()
	if v.Kind() != slog.KindString || v.String() != err.Error() {
		t.Errorf("LogValue() = %v (kind %v), want the plain Error() string", v, v.Kind())
	}
}

func TestLogValueAnnotatesAuthzErrors(t *testing.T) {
	err := &APICallError{Endpoint: "api/core/service/search", Message: `{"status":403}`, StatusCode: http.StatusForbidden}
	v := err.LogValue()
	if v.Kind() != slog.KindGroup {
		t.Fatalf("LogValue() kind = %v, want a group for a 403", v.Kind())
	}
	got := map[string]string{}
	for _, a := range v.Group() {
		got[a.Key] = a.Value.String()
	}
	for _, key := range []string{"error", "endpoint", "collector", "acl_status", "acl_privilege", "acl_hint"} {
		if got[key] == "" {
			t.Errorf("LogValue() group missing %q; got %v", key, got)
		}
	}
	if got["endpoint"] != "api/core/service/search" {
		t.Errorf("endpoint = %q", got["endpoint"])
	}
}

// TestACLDataProvenanceRecorded keeps the support window visible: the generated
// docs quote these, so an un-versioned table cannot ship.
func TestACLDataProvenanceRecorded(t *testing.T) {
	if ACLCoreCurrentRelease == "" || ACLCorePreviousRelease == "" {
		t.Error("core release provenance not recorded")
	}
	if ACLPluginsSource == "" || ACLDataRevised == "" {
		t.Error("plugin ACL source / revision date not recorded")
	}
}
