package main

import (
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
)

// TestDocumentedFlagsAreNotPlatformDependent pins the one flag whose presence in
// the kingpin model depends on GOOS: exporter-toolkit registers
// --web.systemd-socket only when GOOS=linux. While it was documented, docs
// regenerated on macOS failed `make docs-check` on a Linux CI runner, red-ing
// main for a day (#532) — every generated artifact renders from the flag set, so
// a platform-dependent entry makes the artifacts platform-dependent too.
//
// internal/options hides it, and this asserts BOTH halves: that docgen does not
// document it, and that hiding is the reason. The second half is what catches a
// future edit removing the Hidden() call — without it, this test still passes on
// macOS (where the flag was never registered) and fails only in CI.
func TestDocumentedFlagsAreNotPlatformDependent(t *testing.T) {
	for _, f := range collectAllFlags() {
		if f.Name == "web.systemd-socket" {
			t.Error("web.systemd-socket is documented but registers only on GOOS=linux: " +
				"generated docs would differ by platform (#532). It must stay hidden in " +
				"internal/options, not be re-synthesized here.")
		}
	}

	// GetFlag returns nil on non-Linux, where the flag is never registered.
	options.RegisterAllFlags()
	if f := kingpin.CommandLine.GetFlag("web.systemd-socket"); f != nil {
		if !f.Model().Hidden {
			t.Error("web.systemd-socket is registered but not hidden: restore the " +
				"Hidden() call in internal/options/exporter.go (#532)")
		}
	}
}

func TestCollectAllFlagsFindsKnownFlags(t *testing.T) {
	flags := collectAllFlags()
	if len(flags) < 50 {
		t.Fatalf("expected >=50 flags from kingpin model, got %d", len(flags))
	}
	byName := map[string]FlagDoc{}
	for _, f := range flags {
		byName[f.Name] = f
	}
	arp, ok := byName["exporter.disable-arp-table"]
	if !ok {
		t.Fatal("exporter.disable-arp-table not in model")
	}
	if arp.Envar != "OPN2OTEL_DISABLE_ARP_TABLE" || arp.Default != "false" {
		t.Errorf("unexpected arp flag metadata: %+v", arp)
	}
	if _, ok := byName["log.level"]; !ok {
		t.Error("log.level missing — RegisterAllFlags not called?")
	}
	if _, ok := byName["web.listen-address"]; !ok {
		t.Error("web.listen-address missing from model")
	}
	if _, ok := byName["help"]; ok {
		t.Error("built-in help flag should be excluded")
	}
}

func TestCollectorFlagInfo(t *testing.T) {
	info := collectorFlagInfo(collectAllFlags())
	arp, ok := info["arp_table"]
	if !ok {
		t.Fatal("no flag info for arp_table")
	}
	if arp.FlagName != "--exporter.disable-arp-table" || arp.Default != "Enabled" {
		t.Errorf("unexpected arp_table info: %+v", arp)
	}
	nd, ok := info["network_diag"]
	if !ok || nd.Default != "Disabled" {
		t.Errorf("network_diag should be Disabled by default, got %+v", nd)
	}
	// interfaces/services/protocol gained default-on disable switches (#143): they now
	// have a --exporter.disable-* flag and are Enabled by default.
	for _, s := range []string{"interfaces", "services", "protocol"} {
		fi, ok := info[s]
		if !ok || fi.FlagName != "--exporter.disable-"+s || fi.Default != "Enabled" {
			t.Errorf("subsystem %s should have a default-on disable flag: got %+v ok=%v", s, fi, ok)
		}
	}
}
