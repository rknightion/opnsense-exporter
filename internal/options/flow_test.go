package options

import (
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

// A flag that quietly does nothing looks exactly like a quiet network, so every
// incoherent combination is a startup error rather than a silent no-op — the same
// rule --logs.zenarmor.families validation already follows.
func TestFlowConfig_RejectsNetflowWithoutFlowEnabled(t *testing.T) {
	c := FlowConfig{Enabled: false, NetflowEnabled: true, TopN: 1000, MaxKeys: 2500}
	if err := c.Validate(); err == nil {
		t.Fatal("--flow.netflow.enabled without --flow.enabled must be a startup error")
	}
}

func TestFlowConfig_RejectsNegativeBounds(t *testing.T) {
	for _, c := range []FlowConfig{
		{Enabled: true, TopN: -1, MaxKeys: 2500},
		{Enabled: true, TopN: 1000, MaxKeys: -1},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("negative bound accepted: %+v", c)
		}
	}
}

// top-n above max-keys is incoherent rather than merely odd: the emit cap can never
// bind above the insert cap, so the operator asked for something that cannot
// happen and should be told rather than left believing it took effect.
func TestFlowConfig_RejectsTopNAboveMaxKeys(t *testing.T) {
	if err := (FlowConfig{Enabled: true, TopN: 5000, MaxKeys: 2500}).Validate(); err == nil {
		t.Fatal("--flow.top-n above --flow.max-keys must be rejected")
	}
	// Zero means unbounded on either side, so neither combination is incoherent.
	for _, c := range []FlowConfig{
		{Enabled: true, TopN: 5000, MaxKeys: 0},
		{Enabled: true, TopN: 0, MaxKeys: 2500},
		{Enabled: true, TopN: 0, MaxKeys: 0},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("unbounded config rejected: %+v: %v", c, err)
		}
	}
}

// The shipped defaults are read from the flag model rather than from the parsed
// values: this package's tests must never call kingpin.Parse, which would os.Exit
// on the required connection flags (see webui_test.go:8).
func TestFlowConfig_ShippedDefaults(t *testing.T) {
	defaults := map[string]string{}
	for _, f := range kingpin.CommandLine.Model().Flags {
		if strings.HasPrefix(f.Name, "flow.") {
			defaults[f.Name] = strings.Join(f.Default, ",")
		}
	}
	for name, want := range map[string]string{
		// On by default: phase 1 opens no socket and derives from documents the
		// exporter already parses, so defaulting it off would ship a metric family
		// absent on every deployment.
		"flow.enabled":  "true",
		"flow.zenarmor": "true",
		"flow.top-n":    "10000",
		"flow.max-keys": "100000",
		// The NetFlow receiver is OFF by default and stays that way: unlike the
		// Zenarmor lane it opens an unauthenticated UDP socket, and NetFlow has no
		// authentication of any kind, so switching it on is a deliberate act.
		"flow.netflow.enabled": "false",
		"flow.netflow.listen":  ":2055",
	} {
		if got, ok := defaults[name]; !ok {
			t.Errorf("--%s is not registered", name)
		} else if got != want {
			t.Errorf("--%s default = %q, want %q", name, got, want)
		}
	}
	// And those defaults must actually validate as a config.
	if err := (FlowConfig{Enabled: true, Zenarmor: true, TopN: 1000, MaxKeys: 2500}).Validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
}

func TestFlowConfig_RejectsNetflowWithNoListenAddress(t *testing.T) {
	c := FlowConfig{Enabled: true, NetflowEnabled: true, NetflowListen: "", TopN: 1000, MaxKeys: 2500}
	if err := c.Validate(); err == nil {
		t.Fatal("--flow.netflow.enabled with an empty listen address must be a startup error")
	}
}

func TestParseAllowedPeers(t *testing.T) {
	got, err := parseAllowedPeers([]string{"10.0.0.0/8", "192.0.2.1/32", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d prefixes, want 3", len(got))
	}
	// A bare address is the overwhelmingly likely operator typo, and silently
	// ignoring it would leave the listener wide open while looking configured.
	if _, err := parseAllowedPeers([]string{"10.0.0.1"}); err == nil {
		t.Fatal("a bare address (no prefix length) must be rejected, not ignored")
	}
	if _, err := parseAllowedPeers([]string{"not-a-cidr"}); err == nil {
		t.Fatal("malformed CIDR must be rejected")
	}
}

func TestParseIfIndexMap(t *testing.T) {
	// The live production mapping (#346): these ordinals are ng_netflow's ifinfo
	// enumeration, not OS or SNMP indices.
	got, err := parseIfIndexMap("1=ixl0,5=igb0,13=ixl0_vlan50,14=pppoe0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[uint32]string{1: "ixl0", 5: "igb0", 13: "ixl0_vlan50", 14: "pppoe0"}
	if len(got) != len(want) {
		t.Fatalf("parsed %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("index %d = %q, want %q", k, got[k], v)
		}
	}
	if m, err := parseIfIndexMap(""); err != nil || m != nil {
		t.Errorf("empty override must yield a nil map and no error, got %v / %v", m, err)
	}
	for _, bad := range []string{"ixl0", "1=", "=ixl0", "x=ixl0", "-1=ixl0", "1=ixl0,1=igb0"} {
		if _, err := parseIfIndexMap(bad); err == nil {
			t.Errorf("malformed override %q accepted", bad)
		}
	}
}
