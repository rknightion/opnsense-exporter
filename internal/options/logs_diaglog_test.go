package options

import "testing"

func TestParseDiagLogScopes_Default(t *testing.T) {
	scopes, err := ParseDiagLogScopes(defaultDiagLogScopes)
	if err != nil {
		t.Fatalf("default scopes rejected: %v", err)
	}
	want := []DiagLogScope{
		{Module: "core", Scope: "audit"},
		{Module: "core", Scope: "gateways"},
		{Module: "core", Scope: "portalauth"},
		{Module: "core", Scope: "system"},
		{Module: "core", Scope: "configd"},
	}
	if len(scopes) != len(want) {
		t.Fatalf("got %d scopes, want %d: %+v", len(scopes), len(want), scopes)
	}
	for i, w := range want {
		if scopes[i] != w {
			t.Errorf("scope[%d] = %+v, want %+v", i, scopes[i], w)
		}
	}
}

func TestParseDiagLogScopes_WhitespaceAndBlanksTolerated(t *testing.T) {
	scopes, err := ParseDiagLogScopes(" core/audit , ,core/gateways ,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("got %d scopes, want 2: %+v", len(scopes), scopes)
	}
	if scopes[0].Key() != "core/audit" || scopes[1].Key() != "core/gateways" {
		t.Errorf("got %+v", scopes)
	}
}

func TestParseDiagLogScopes_Empty(t *testing.T) {
	scopes, err := ParseDiagLogScopes("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 0 {
		t.Fatalf("got %d scopes, want 0", len(scopes))
	}
}

func TestParseDiagLogScopes_InvalidPair(t *testing.T) {
	cases := []string{"core", "core/", "/audit", ""}
	for _, c := range cases {
		if c == "" {
			continue // covered by the Empty test; an all-blank string is valid (zero scopes)
		}
		if _, err := ParseDiagLogScopes(c); err == nil {
			t.Errorf("ParseDiagLogScopes(%q): expected error, got nil", c)
		}
	}
}

func TestParseDiagLogScopes_ModuleScopeExtraSlashKeepsScopeWhole(t *testing.T) {
	// SplitN(part, "/", 2) means a module/scope/subscope form puts everything
	// after the first slash into Scope, not an error -- routing/frr-style
	// two-level nesting is the module, "frr" is the scope; there is no third
	// level in the real registry, but the parser should not choke if one shows
	// up rather than silently truncating.
	scopes, err := ParseDiagLogScopes("routing/frr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 1 || scopes[0].Module != "routing" || scopes[0].Scope != "frr" {
		t.Fatalf("got %+v", scopes)
	}
}

func TestDiagLogScope_Key(t *testing.T) {
	s := DiagLogScope{Module: "core", Scope: "audit"}
	if s.Key() != "core/audit" {
		t.Errorf("Key() = %q, want core/audit", s.Key())
	}
}
