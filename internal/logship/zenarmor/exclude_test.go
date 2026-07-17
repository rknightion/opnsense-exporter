package zenarmor

import (
	"strings"
	"testing"
)

func TestParseExcludeRules_Valid(t *testing.T) {
	rules, err := parseExcludeRules([]string{
		`server_name=~.*\.grafana\.net`,
		`query=~^example\.com$`,
	})
	if err != nil {
		t.Fatalf("parseExcludeRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Field != "server_name" {
		t.Errorf("Field = %q, want server_name", rules[0].Field)
	}
	// Raw is the `rule` label value, so it must survive verbatim.
	if rules[0].Raw != `server_name=~.*\.grafana\.net` {
		t.Errorf("Raw = %q, want the rule exactly as written", rules[0].Raw)
	}
	if !rules[0].Re.MatchString("otlp-gateway-prod-gb-south-1.grafana.net") {
		t.Error("rule should match the Grafana Cloud endpoint it was written for")
	}
	if rules[0].Re.MatchString("example.com") {
		t.Error("rule should not match an unrelated host")
	}
}

// A typo'd field name must be a startup error, not a filter that silently matches
// nothing — the same reasoning as the strict --logs.zenarmor.families validation. A
// filter that quietly does nothing looks exactly like a quiet network.
func TestParseExcludeRules_UnknownFieldIsAnError(t *testing.T) {
	_, err := parseExcludeRules([]string{`servername=~.*\.grafana\.net`})
	if err == nil {
		t.Fatal("a typo'd field name must fail startup, not silently match nothing")
	}
	// The message has to name the offender and point somewhere useful.
	if !strings.Contains(err.Error(), "servername") {
		t.Errorf("error must name the unknown field, got: %v", err)
	}
	if !strings.Contains(err.Error(), "server_name") {
		t.Errorf("error should suggest the near-miss it was probably meant to be, got: %v", err)
	}
}

func TestParseExcludeRules_MalformedRules(t *testing.T) {
	for _, tc := range []struct{ name, rule, wantIn string }{
		{"no operator", `server_name`, "=~"},
		{"exact-match operator is not supported", `server_name=x`, "=~"},
		{"empty field", `=~.*`, "field"},
		{"empty regex", `server_name=~`, "regex"},
		{"bad regex", `server_name=~*broken`, "regex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExcludeRules([]string{tc.rule})
			if err == nil {
				t.Fatalf("rule %q must be rejected", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q should mention %q", err, tc.wantIn)
			}
		})
	}
}

// The regex is matched against the field's VALUE, so a rule may legitimately contain
// characters (commas, equals) that a naive splitter would mangle.
func TestParseExcludeRules_RegexKeepsItsOwnPunctuation(t *testing.T) {
	rules, err := parseExcludeRules([]string{`uri=~^/a{1,3}=b$`})
	if err != nil {
		t.Fatalf("parseExcludeRules: %v", err)
	}
	if !rules[0].Re.MatchString("/aa=b") {
		t.Error("regex containing a comma and an equals must survive parsing intact")
	}
}

func TestExcludedBy(t *testing.T) {
	rules, err := parseExcludeRules([]string{
		`server_name=~.*\.grafana\.net`,
		`query=~.*\.grafana\.net`,
	})
	if err != nil {
		t.Fatalf("parseExcludeRules: %v", err)
	}

	t.Run("matches on the named field only", func(t *testing.T) {
		attrs := map[string]string{"server_name": "profiles-prod-023.grafana.net"}
		rule, ok := excludedBy(rules, attrs)
		if !ok {
			t.Fatal("record should be excluded")
		}
		if rule.Field != "server_name" {
			t.Errorf("matched rule Field = %q, want server_name", rule.Field)
		}
	})

	t.Run("a value under a different key does not match", func(t *testing.T) {
		// The same string under `host` must NOT trip a server_name rule: a field-scoped
		// rule that matched any field would be a silent over-drop.
		attrs := map[string]string{"host": "profiles-prod-023.grafana.net"}
		if _, ok := excludedBy(rules, attrs); ok {
			t.Error("a server_name rule must not match the value of another field")
		}
	})

	t.Run("absent field does not match", func(t *testing.T) {
		attrs := map[string]string{"src_hostname": "camden"}
		if _, ok := excludedBy(rules, attrs); ok {
			t.Error("a record without the field must not be excluded")
		}
	})

	t.Run("no rules excludes nothing", func(t *testing.T) {
		attrs := map[string]string{"server_name": "profiles-prod-023.grafana.net"}
		if _, ok := excludedBy(nil, attrs); ok {
			t.Error("default off: no rules must exclude nothing")
		}
	})

	t.Run("reports the rule that matched", func(t *testing.T) {
		attrs := map[string]string{"query": "otlp-gateway-prod-gb-south-1.grafana.net"}
		rule, ok := excludedBy(rules, attrs)
		if !ok {
			t.Fatal("record should be excluded")
		}
		if rule.Raw != `query=~.*\.grafana\.net` {
			t.Errorf("matched rule = %q, want the query rule; the rule label must identify which rule dropped it", rule.Raw)
		}
	})
}

// Every field a rule may name must be one the parser can actually produce. This is
// the vocabulary the startup validation checks against, so a key missing from it
// would make a legitimate rule fail to start.
func TestKnownAttributeKeysCoverEveryKeyTheParserSets(t *testing.T) {
	produced := attributeKeysSetByParser(t)
	known := map[string]bool{}
	for _, k := range KnownAttributeKeys {
		known[k] = true
	}
	for key, where := range produced {
		if !known[key] {
			t.Errorf("parse.go sets attribute %q at %s but it is not in KnownAttributeKeys, so "+
				"--logs.zenarmor.exclude=%s=~... would be rejected at startup as an unknown field", key, where, key)
		}
	}
	for _, k := range KnownAttributeKeys {
		if _, ok := produced[k]; !ok {
			t.Errorf("KnownAttributeKeys lists %q but the parser never sets it; a rule naming it "+
				"would be accepted at startup and then silently match nothing", k)
		}
	}
}
