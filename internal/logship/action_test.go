package logship

import "testing"

func TestMapFilterlogAction(t *testing.T) {
	cases := map[string]string{
		"pass":   ActionPass,
		"block":  ActionBlock,
		"reject": ActionBlock,

		// filterlog's action is a RAW WIRE PASSTHROUGH (`action := f[fAction]`,
		// syslog/filterlog.go:89) — the parser does not constrain the vocabulary, and
		// NAT/rdr rules can put verbs there that are neither a pass nor a deny. An
		// unrecognised verb MUST leave the label unset rather than be guessed into
		// "block": a wrong security label is worse than an absent one.
		"rdr":   "",
		"nat":   "",
		"binat": "",
		"":      "",
		"PASS":  "", // case-sensitive on purpose; pf writes lowercase
	}
	for in, want := range cases {
		if got := MapFilterlogAction(in); got != want {
			t.Errorf("MapFilterlogAction(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapUnboundAction(t *testing.T) {
	// Capitalised in the unbound reporting DB — see opnsense/unbound_search_queries.go:39.
	cases := map[string]string{
		"Pass":  ActionPass,
		"Block": ActionBlock,
		"Drop":  ActionBlock,

		"pass":  "", // wrong case is not a match
		"Cache": "", // that is the `source` field's vocabulary, not action's
		"":      "",
	}
	for in, want := range cases {
		if got := MapUnboundAction(in); got != want {
			t.Errorf("MapUnboundAction(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapSuricataAction(t *testing.T) {
	cases := map[string]string{
		"allowed": ActionPass,
		"blocked": ActionBlock,

		"dropped": "", // not an EVE action value; do not guess
		"":        "",
	}
	for in, want := range cases {
		if got := MapSuricataAction(in); got != want {
			t.Errorf("MapSuricataAction(%q) = %q, want %q", in, got, want)
		}
	}
}

// The vocabulary is binary and closed. If someone adds a third value they must
// re-check the sink's maxLogResources budget, because action multiplies the
// resource-key count.
func TestActionVocabularyIsBinary(t *testing.T) {
	if ActionPass != "pass" || ActionBlock != "block" {
		t.Fatalf("vocabulary changed: %q/%q", ActionPass, ActionBlock)
	}
}
