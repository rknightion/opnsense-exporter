package main

import "testing"

func TestVerifyAcceptsRedactedConfigChangeAndCleanSnapshot(t *testing.T) {
	result := verify(request{
		ConfigChange: []string{"--- old\n+++ new\n+<password>[redacted]</password>\n+<description>safe</description>"},
		ConfigState:  []string{`{"rule":{"description":"safe"}}`},
	})
	if !result.ConfigChangeBodiesRedacted || !result.ConfigStateBodiesRedacted {
		t.Fatalf("result = %+v, want both body families clean", result)
	}
	if result.ConfigChangeSensitiveElements != 1 || result.ConfigStateSensitiveKeys != 0 {
		t.Fatalf("coverage = %+v, want one redacted config-change element and no configstate keys", result)
	}
}

func TestVerifyRejectsUnredactedOrMalformedBodies(t *testing.T) {
	tests := []struct {
		name string
		in   request
	}{
		{
			name: "unredacted config change",
			in:   request{ConfigChange: []string{"+<api_key>not-safe</api_key>"}, ConfigState: []string{`{"safe":true}`}},
		},
		{
			name: "sensitive configstate key",
			in:   request{ConfigChange: []string{"+<description>safe</description>"}, ConfigState: []string{`{"nested":{"wg_private_key":"not-safe"}}`}},
		},
		{
			name: "malformed configstate JSON",
			in:   request{ConfigChange: []string{"+<description>safe</description>"}, ConfigState: []string{"{"}},
		},
		{
			name: "malformed config change XML",
			in:   request{ConfigChange: []string{"+<description"}, ConfigState: []string{`{"safe":true}`}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := verify(test.in)
			if result.ConfigChangeBodiesRedacted && result.ConfigStateBodiesRedacted {
				t.Fatalf("result = %+v, want at least one failing family", result)
			}
		})
	}
}

func TestVerifyUsesTheSharedSensitiveVocabulary(t *testing.T) {
	result := verify(request{
		ConfigChange: []string{"+<ldap_bindpw>[redacted]</ldap_bindpw>"},
		ConfigState:  []string{`{"community":"must-not-ship"}`},
	})
	if !result.ConfigChangeBodiesRedacted || result.ConfigStateBodiesRedacted {
		t.Fatalf("result = %+v, want shared-vocabulary handling", result)
	}
}

func TestVerifyRejectsHiddenSensitiveSnapshotAndNonSnapshotValues(t *testing.T) {
	for _, body := range []string{`{"rule":{"password":"synthetic-secret"},"rule":{}}`, `null`, `"not a snapshot"`} {
		clean, _ := verifyConfigState(body)
		if clean {
			t.Fatal("invalid or duplicate-key snapshot passed verification")
		}
	}
}

func TestVerifyAcceptsWrappedRedactedDiff(t *testing.T) {
	// The source preserves an opening tag on its own line, then replaces each
	// following value line. This is deliberately synthetic parser tolerance.
	clean, count := verifyConfigChange("+<password>\n+[redacted]\n+[redacted]</password>")
	if !clean || count != 1 {
		t.Fatalf("clean=%t count=%d, want true/1", clean, count)
	}
}

func TestVerifyDoesNotHideSensitivePayloadBehindDiffHeaderPrefix(t *testing.T) {
	clean, _ := verifyConfigChange("+<description>safe</description>\n+++<password>synthetic-secret</password>")
	if clean {
		t.Fatal("payload beginning with plus signs bypassed sensitive-element inspection")
	}
}
