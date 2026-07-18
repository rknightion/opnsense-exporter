package webui

import (
	_ "embed"
	"strings"
)

//go:embed oui_data.txt
var ouiData string

// ouiTable maps a normalised 6-hex uppercase MAC prefix to a short vendor name.
// It is parsed once at init from the embedded IEEE-derived table (see
// scripts/gen_oui.sh for provenance and regeneration).
var ouiTable = parseOUI(ouiData)

// parseOUI reads the embedded "PREFIX\tVendor" table into a lookup map. Blank
// lines and comment lines (starting with '#') are ignored.
func parseOUI(data string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, vendor, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		prefix = strings.ToUpper(strings.TrimSpace(prefix))
		vendor = strings.TrimSpace(vendor)
		if len(prefix) != 6 || vendor == "" {
			continue
		}
		m[prefix] = vendor
	}
	return m
}

// LookupOUI returns the vendor name for a MAC address, or "" when the address
// is too short or its prefix is not in the embedded table. It normalises the
// input by stripping ':', '.' and '-', upper-casing, and taking the first six
// hex digits (the OUI).
func LookupOUI(mac string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ':', '.', '-', ' ':
			return -1
		default:
			return r
		}
	}, mac)
	cleaned = strings.ToUpper(cleaned)
	if len(cleaned) < 6 {
		return ""
	}
	return ouiTable[cleaned[:6]]
}
