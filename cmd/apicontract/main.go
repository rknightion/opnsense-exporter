// Command apicontract diffs the exporter's endpoint manifest against OPNsense
// source endpoint lists (one JSON file per ref, produced by extract.py).
//
// Usage:
//
//	apicontract --ref master=upstream-master.json --ref stable/26.1=upstream-stable.json [--out report.md]
//
// Exit code 0 = no missing endpoints; 1 = drift (missing endpoints) found;
// 2 = usage/IO error. Verb drift is reported but does not change the exit code; it is
// surfaced to CI via the `warnings` step output (see GitHubOutputs) so a warnings-only
// run still files/updates the api-drift issue instead of finishing silently green.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// exemptEndpoints are never flagged as missing because OPNsense's source parser
// structurally cannot see them — they are parser blind spots, not drift:
//
//   - firmware/firmwareInfo: OPNsense's docs parser hard-excludes
//     Core/Api/FirmwareController.php (EXCLUDE_CONTROLLERS), so these never appear.
//   - keaLeases4/keaLeases6: the real routes are served by Kea\Api\Leases4Controller
//     and Leases6Controller, which add no methods of their own — they inherit
//     searchAction() from the abstract LeasesController base. The parser only reads
//     methods literally defined in each file, so it sees searchAction only on the
//     abstract base and nothing for the concrete leases4/leases6 routes. extract.py now
//     filters abstract controllers (#146), so the base no longer appears as a phantom
//     kea/leases/search either — but the concrete routes still aren't emitted, so these
//     two exemptions remain necessary. Verified against a live 26.1 box: kea/leases4/search
//     and kea/leases6/search return 200 while kea/leases/search returns 404.
//
// Coverage gap (acknowledged): these four endpoints have NO automated drift detection.
// The source-diff canary is exempt for them by design, and there is no automated
// live-box stage that re-validates them — the only live-box tooling (cmd/apicapture,
// `just capture`) is a manual, local action that captures response contracts
// (opnsense/response_contract.go), not these manifest endpoints. A future OPNsense
// rename/removal of firmware/status, firmware/info, or the Kea leases4/leases6 search
// routes would surface only as broken collectors on user installs, not as a CI signal.
var exemptEndpoints = map[string]bool{
	"firmware":     true,
	"firmwareInfo": true,
	"keaLeases4":   true,
	"keaLeases6":   true,
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

	// Emit drift/warnings step outputs so the workflow can act on verb-drift warnings
	// (file/update the api-drift issue) without them forcing a hard CI failure — the
	// exit code below is still gated on errors only (#93). GITHUB_OUTPUT is a file the
	// runner reads back as this step's outputs; appending is how Actions sets them.
	if gho := os.Getenv("GITHUB_OUTPUT"); gho != "" {
		f, err := os.OpenFile(gho, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open GITHUB_OUTPUT: %v\n", err)
			os.Exit(2)
		}
		if _, err := f.WriteString(GitHubOutputs(reports)); err != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "write GITHUB_OUTPUT: %v\n", err)
			os.Exit(2)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close GITHUB_OUTPUT: %v\n", err)
			os.Exit(2)
		}
	}

	if HasErrors(reports) {
		os.Exit(1)
	}
}
