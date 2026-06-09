package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

func mdCell(s string) string {
	if s == "" {
		return "--"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

func mdCode(s string) string {
	if s == "" {
		return "--"
	}
	return "`" + s + "`"
}

// renderFlagTables renders every docgen region for docs/configuration.md,
// keyed by region name.
func renderFlagTables(flags []FlagDoc) map[string]string {
	byName := map[string]FlagDoc{}
	var connection, exporter, pyroscope, otlp []FlagDoc
	for _, f := range flags {
		byName[f.Name] = f
		switch {
		case strings.HasPrefix(f.Name, "opnsense."):
			connection = append(connection, f)
		case strings.HasPrefix(f.Name, "pyroscope."):
			pyroscope = append(pyroscope, f)
		case strings.HasPrefix(f.Name, "otlp."):
			otlp = append(otlp, f)
		case strings.HasPrefix(f.Name, "exporter.disable-"), strings.HasPrefix(f.Name, "exporter.enable-"):
			// collector switches rendered from options.CollectorFlags below
		default:
			exporter = append(exporter, f) // web.*, log.*, exporter.instance-label
		}
	}

	std := func(group []FlagDoc) string {
		var b strings.Builder
		b.WriteString("| Flag | Env Var | Default | Description |\n")
		b.WriteString("|------|---------|---------|-------------|\n")
		for _, f := range group {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				mdCode("--"+f.Name), mdCode(f.Envar), mdCode(f.Default), flagDescription(f))
		}
		return b.String()
	}

	type switchRow struct{ flag, envar, name, help string }
	var defaultOn, optIn, details []switchRow
	for _, cf := range options.CollectorFlags {
		f, ok := byName[cf.Flag]
		if !ok {
			fatal("CollectorFlags entry %q not in kingpin model", cf.Flag)
		}
		row := switchRow{flag: cf.Flag, envar: f.Envar, name: collector.SubsystemDisplayNames[cf.Subsystem], help: f.Help}
		switch {
		case cf.Detail:
			details = append(details, row)
		case strings.HasPrefix(cf.Flag, "exporter.enable-"):
			optIn = append(optIn, row)
		default:
			defaultOn = append(defaultOn, row)
		}
	}
	sortRows := func(rows []switchRow) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	}
	sortRows(defaultOn)
	sortRows(optIn)
	sortRows(details)
	switchTable := func(rows []switchRow) string {
		var b strings.Builder
		b.WriteString("| Flag | Env Var | Collector | Description |\n")
		b.WriteString("|------|---------|-----------|-------------|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				mdCode("--"+r.flag), mdCode(r.envar), mdCell(r.name), mdCell(r.help))
		}
		return b.String()
	}

	full := append([]FlagDoc(nil), flags...)
	sort.Slice(full, func(i, j int) bool { return full[i].Name < full[j].Name })

	return map[string]string{
		"flags-connection":            std(connection),
		"flags-exporter":              std(exporter),
		"flags-pyroscope":             std(pyroscope),
		"flags-otlp":                  std(otlp),
		"flags-collectors-default-on": switchTable(defaultOn),
		"flags-collectors-opt-in":     switchTable(optIn),
		"flags-collectors-details":    switchTable(details),
		"flags-full-reference":        std(full),
	}
}

func flagDescription(f FlagDoc) string {
	desc := mdCell(f.Help)
	if f.Required {
		desc = "**Required.** " + desc
	}
	return desc
}
