package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/collector"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// renderACLMatrix renders every live endpoint's ACL classification. The endpoint
// table is deliberately the input, rather than a curated list of GUI privileges:
// EndpointACLs is completeness-checked against defaultEndpoints in opnsense.
func renderACLMatrix() string {
	flags := map[string]FlagDoc{}
	for _, flag := range collectAllFlags() {
		flags[flag.Name] = flag
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Generated from the endpoint ACL map, OPNsense core %s and %s, and %s (re-derived %s).\n\n",
		opnsense.ACLCoreCurrentRelease, opnsense.ACLCorePreviousRelease, opnsense.ACLPluginsSource, opnsense.ACLDataRevised)
	b.WriteString("Status is **known**, **plugin-dependent**, or **unknown**. Unknown is an audited result, not an omitted recommendation. `plugin-gated` means this endpoint is treated as absent when its plugin route returns 404.\n\n")
	b.WriteString("| Collector | Collection mode | Plugin gate | Endpoint | ACL status | Likely privilege (any one) | Scope | Evidence / caveat |\n")
	b.WriteString("|-----------|-----------------|-------------|----------|------------|----------------------------|-------|-------------------|\n")

	for _, row := range opnsense.EndpointACLs() {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			mdCell(aclCollectorName(row.Consumer)),
			mdCell(aclCollectionMode(row.Consumer, flags)),
			aclPluginGate(row.PluginGated),
			mdCode(string(row.Endpoint))+"<br>"+mdCode(row.Method+" "+string(row.Path)),
			mdCode(string(row.Status)),
			aclPrivileges(row),
			aclScope(row),
			mdCell(row.Note),
		)
	}
	return b.String()
}

func aclCollectorName(consumer string) string {
	if display, ok := collector.SubsystemDisplayNames[consumer]; ok {
		return display
	}
	return consumer
}

func aclCollectionMode(consumer string, flags map[string]FlagDoc) string {
	if strings.HasPrefix(consumer, "(") {
		return "non-collector endpoint"
	}

	var base string
	var highCardinality []string
	for _, cf := range options.CollectorFlags {
		if cf.Subsystem != consumer {
			continue
		}
		if cf.Detail {
			if fd, ok := flags[cf.Flag]; ok && strings.Contains(strings.ToLower(fd.Help), "cardinality") {
				highCardinality = append(highCardinality, "`--"+cf.Flag+"`")
			}
			continue
		}
		switch {
		case strings.HasPrefix(cf.Flag, "exporter.disable-"):
			base = "default-on (`--" + cf.Flag + "` disables)"
		case strings.HasPrefix(cf.Flag, "exporter.enable-"):
			base = "opt-in (`--" + cf.Flag + "`)"
		}
	}
	if base == "" {
		return "collector switch not recorded"
	}
	if len(highCardinality) == 0 {
		return base
	}
	sort.Strings(highCardinality)
	return base + "; high-cardinality opt-in (" + strings.Join(highCardinality, ", ") + ")"
}

func aclPluginGate(pluginGated bool) string {
	if pluginGated {
		return "plugin-gated"
	}
	return "--"
}

func aclPrivileges(row opnsense.EndpointACL) string {
	if row.Status == opnsense.ACLStatusUnknown {
		return "No matched ACL; only `page-all`"
	}
	privileges := append([]opnsense.ACLPrivilege(nil), row.Privileges...)
	sort.Slice(privileges, func(i, j int) bool { return privileges[i].Key < privileges[j].Key })
	parts := make([]string, 0, len(privileges))
	for _, privilege := range privileges {
		parts = append(parts, mdCell(privilege.Name)+" (`"+privilege.Key+"`)")
	}
	return strings.Join(parts, "; ")
}

func aclScope(row opnsense.EndpointACL) string {
	if row.WildcardAPIScope() {
		return "wildcard; may include writes"
	}
	return "exact"
}

// injectSecurityDoc fills the ACL matrix region in docs/security.md.
func injectSecurityDoc(out *output) {
	path := filepath.Join(out.repoRoot, "docs", "security.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("reading %s: %v", path, err)
	}
	doc, err := injectRegion(string(raw), "acl-matrix", renderACLMatrix())
	if err != nil {
		fatal("%s: %v", path, err)
	}
	out.write(path, []byte(doc))
}
