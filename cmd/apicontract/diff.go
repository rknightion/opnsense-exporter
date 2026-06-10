package main

import (
	"fmt"
	"sort"
	"strings"
)

// Endpoint is one endpoint the exporter calls (adapted from opnsense.ContractManifest).
type Endpoint struct {
	Name   string
	Path   string
	Method string
}

// FindingKind distinguishes hard errors from soft warnings.
type FindingKind int

const (
	KindMissing FindingKind = iota // endpoint absent from source -> error
	KindVerb                       // method not advertised by source -> warning
)

// Finding is a single drift observation.
type Finding struct {
	Endpoint  string
	OurPath   string
	OurMethod string
	Kind      FindingKind
	Detail    string
}

// Report groups findings for one ref.
type Report struct {
	Ref      string
	Errors   []Finding // missing paths
	Warnings []Finding // verb drift
}

// normalize canonicalises a path for comparison. OPNsense's parser snake_cases
// action-method names (searchGateway -> search_gateway, systemDisk -> system_disk),
// while our endpoint map keeps the original camelCase. Lowercasing and removing
// underscores collapses both spellings so they compare equal. Path "/" separators
// are preserved so the prefix logic in match() still respects command boundaries.
func normalize(p string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(p, "api/")), "_", "")
}

// match returns the most specific upstream endpoint whose path equals our path
// or is a "/"-bounded prefix of it (our path may carry positional args).
func match(ourPath string, ups []UpstreamEndpoint) (UpstreamEndpoint, bool) {
	np := normalize(ourPath)
	var best UpstreamEndpoint
	found := false
	for _, e := range ups {
		ep := normalize(e.Path)
		if np == ep || strings.HasPrefix(np, ep+"/") {
			if !found || len(ep) > len(normalize(best.Path)) {
				best = e
				found = true
			}
		}
	}
	return best, found
}

func methodAllowed(our string, advertised []string) bool {
	for _, m := range advertised {
		if strings.EqualFold(m, our) {
			return true
		}
	}
	return false
}

// Diff compares our endpoints against the upstream list. exempt endpoint names
// are never reported as missing (e.g. firmware, which OPNsense's parser skips).
func Diff(ours []Endpoint, ups []UpstreamEndpoint, exempt map[string]bool) Report {
	var rep Report
	for _, o := range ours {
		if exempt[o.Name] {
			continue
		}
		e, ok := match(o.Path, ups)
		if !ok {
			rep.Errors = append(rep.Errors, Finding{
				Endpoint: o.Name, OurPath: o.Path, OurMethod: o.Method,
				Kind: KindMissing, Detail: "no matching controller/command in OPNsense source",
			})
			continue
		}
		// Verb drift is reported in one direction only: we issue a GET but the
		// source no longer advertises GET (the CVE-2026-30868 GET->POST tightening
		// class). The reverse — we POST to an endpoint the parser labels GET — is
		// pervasive noise: OPNsense's parser infers methods heuristically and
		// under-reports POST for model "search" endpoints that in fact accept both,
		// so flagging it would warn on many endpoints we call successfully.
		if strings.EqualFold(o.Method, "GET") && len(e.Methods) > 0 && !methodAllowed("GET", e.Methods) {
			rep.Warnings = append(rep.Warnings, Finding{
				Endpoint: o.Name, OurPath: o.Path, OurMethod: o.Method,
				Kind:   KindVerb,
				Detail: fmt.Sprintf("exporter uses GET; source advertises %v (endpoint may now require POST)", e.Methods),
			})
		}
	}
	sort.Slice(rep.Errors, func(i, j int) bool { return rep.Errors[i].Endpoint < rep.Errors[j].Endpoint })
	sort.Slice(rep.Warnings, func(i, j int) bool { return rep.Warnings[i].Endpoint < rep.Warnings[j].Endpoint })
	return rep
}
