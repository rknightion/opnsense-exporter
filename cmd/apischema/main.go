// Command apischema writes the committed golden schema files derived from the
// exporter's response structs (opnsense/schema.go + schema_registry.go) into
// opnsense/testdata/schemas/. The schemas are structure-only (key paths + JSON
// types, no values) and are what the live canary (cmd/apidrift) validates a
// real box's payloads against.
//
// Run via `make schemas` after changing any response struct;
// opnsense.TestSchemasUpToDate fails CI when the committed files are stale.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

func main() {
	out := flag.String("out", "opnsense/testdata/schemas", "directory to write golden schema files into")
	flag.Parse()

	schemas, err := opnsense.AllEndpointSchemas()
	if err != nil {
		fmt.Fprintf(os.Stderr, "deriving schemas: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", *out, err)
		os.Exit(1)
	}

	// Committed non-golden files in the same directory: the compat ledger and
	// the live-coverage ledger (#377). They are hand-maintained, so the orphan
	// sweep below must never delete them.
	valid := map[string]bool{"exemptions.json": true, "coverage.json": true}
	for _, s := range schemas {
		name := s.Endpoint + ".json"
		valid[name] = true
		raw, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal %s: %v\n", s.Endpoint, err)
			os.Exit(1)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(*out, name), raw, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", name, err)
			os.Exit(1)
		}
	}

	// Remove orphans from endpoints that no longer exist.
	entries, err := os.ReadDir(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *out, err)
		os.Exit(1)
	}
	var removed int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || valid[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(*out, e.Name())); err != nil {
			fmt.Fprintf(os.Stderr, "remove orphan %s: %v\n", e.Name(), err)
			os.Exit(1)
		}
		removed++
	}

	fmt.Printf("wrote %d golden schemas to %s (%d orphans removed)\n", len(schemas), *out, removed)
}
