// Command apicontract diffs the exporter's endpoint manifest against OPNsense
// source endpoint lists (one JSON file per ref, produced by extract.py).
//
// Usage:
//
//	apicontract --ref master=upstream-master.json --ref stable/26.1=upstream-stable.json [--out report.md]
//
// Exit code 0 = no missing endpoints; 1 = drift (missing endpoints) found;
// 2 = usage/IO error. Verb drift is reported but does not change the exit code.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rknightion/opnsense-exporter/opnsense"
)

// exemptEndpoints are never flagged as missing. OPNsense's parser skips
// FirmwareController (EXCLUDE_CONTROLLERS), so our firmware endpoints would
// otherwise always read as "missing".
var exemptEndpoints = map[string]bool{
	"firmware":     true,
	"firmwareInfo": true,
}

type refFlag struct {
	pairs []struct{ name, path string }
}

func (r *refFlag) String() string { return "" }
func (r *refFlag) Set(v string) error {
	name, path, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("expected name=path, got %q", v)
	}
	r.pairs = append(r.pairs, struct{ name, path string }{name, path})
	return nil
}

func manifestEndpoints() []Endpoint {
	manifest := opnsense.ContractManifest()
	out := make([]Endpoint, 0, len(manifest))
	for name, ec := range manifest {
		out = append(out, Endpoint{Name: string(name), Path: string(ec.Path), Method: ec.Method})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func main() {
	var refs refFlag
	out := flag.String("out", "", "write the markdown report to this file as well as stdout")
	flag.Var(&refs, "ref", "name=path-to-upstream.json (repeatable)")
	flag.Parse()

	if len(refs.pairs) == 0 {
		fmt.Fprintln(os.Stderr, "at least one --ref name=path is required")
		os.Exit(2)
	}

	ours := manifestEndpoints()
	var reports []Report
	for _, p := range refs.pairs {
		ups, err := loadUpstream(p.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ref %s: %v\n", p.name, err)
			os.Exit(2)
		}
		rep := Diff(ours, ups, exemptEndpoints)
		rep.Ref = p.name
		reports = append(reports, rep)
	}

	md := RenderMarkdown(reports)
	fmt.Print(md)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(md), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(2)
		}
	}

	if HasErrors(reports) {
		os.Exit(1)
	}
}
