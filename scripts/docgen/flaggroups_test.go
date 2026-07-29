package main

import "testing"

// Every flag must land in exactly one group. A flag no rule claims is a flag
// missing from all three generated example configs — the silent omission those
// artifacts exist to prevent — so it fails the build here rather than shipping.
func TestGroupFlagsCoversEveryFlag(t *testing.T) {
	flags := collectAllFlags()
	if unmatched := groupFlagsUnmatched(flags); len(unmatched) > 0 {
		t.Fatalf("flags matched by no group rule (add a prefix to groupRules in flaggroups.go): %v",
			unmatched)
	}
	total := 0
	for _, g := range groupFlags(flags) {
		if len(g.Flags) == 0 {
			t.Errorf("group %q has no flags; drop the rule or fix its prefixes", g.Key)
		}
		total += len(g.Flags)
	}
	if total != len(flags) {
		t.Fatalf("grouped %d flags, model has %d: a flag is in two groups or none", total, len(flags))
	}
}

// The narrow prefixes must be tried before the broad ones they sit under, or
// every syslog flag lands in the generic logs section.
func TestGroupFlagsPrefixPrecedence(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{
		{"logs.syslog.enabled", "logs-syslog"},
		{"logs.zenarmor.enabled", "logs-zenarmor"},
		{"logs.debug-capture.dir", "logs-debug-capture"},
		{"logs.sink", "logs"},
		{"flow.netflow.enabled", "flow-netflow"},
		{"flow.correlate", "flow"},
		{"web.ui-enabled", "webui"},
		{"web.listen-address", "server"},
		{"exporter.enable-smart", "collectors-opt-in"},
		{"exporter.disable-carp", "collectors-default-on"},
		{"exporter.instance-label", "exporter"},
	} {
		r, ok := ruleFor(FlagDoc{Name: tc.flag})
		if !ok {
			t.Errorf("%s: matched no rule", tc.flag)
			continue
		}
		if r.key != tc.want {
			t.Errorf("%s: grouped as %q, want %q", tc.flag, r.key, tc.want)
		}
	}
}
