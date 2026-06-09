package main

import (
	"strings"
	"testing"
)

func TestRenderGroupedTables(t *testing.T) {
	flags := collectAllFlags()
	tables := renderFlagTables(flags)

	required := []string{
		"flags-connection", "flags-exporter", "flags-pyroscope", "flags-otlp",
		"flags-collectors-default-on", "flags-collectors-opt-in",
		"flags-collectors-details", "flags-full-reference",
	}
	for _, name := range required {
		if tables[name] == "" {
			t.Errorf("no table rendered for region %q", name)
		}
	}
	if !strings.Contains(tables["flags-connection"], "`--opnsense.protocol`") {
		t.Error("connection table missing opnsense.protocol")
	}
	if !strings.Contains(tables["flags-collectors-default-on"], "ARP Table") {
		t.Error("default-on table missing ARP Table display name")
	}
	if !strings.Contains(tables["flags-collectors-opt-in"], "`--exporter.enable-netflow`") {
		t.Error("opt-in table missing netflow")
	}
	if !strings.Contains(tables["flags-collectors-details"], "`--exporter.enable-openvpn-details`") {
		t.Error("details table missing openvpn-details")
	}
	if !strings.Contains(tables["flags-full-reference"], "`--web.listen-address`") {
		t.Error("full reference missing web.listen-address")
	}
	if strings.Contains(tables["flags-exporter"], "exporter.disable-arp-table") {
		t.Error("collector switch leaked into exporter settings table")
	}
}
