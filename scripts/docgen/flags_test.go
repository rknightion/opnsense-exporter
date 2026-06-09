package main

import "testing"

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
	if arp.Envar != "OPNSENSE_EXPORTER_DISABLE_ARP_TABLE" || arp.Default != "false" {
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
	// always-on collectors get empty-flag entries
	for _, s := range []string{"interfaces", "services", "protocol"} {
		fi, ok := info[s]
		if !ok || fi.FlagName != "" || fi.Default != "Enabled" {
			t.Errorf("always-on subsystem %s: got %+v ok=%v", s, fi, ok)
		}
	}
}
