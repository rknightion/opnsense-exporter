package main

import (
	"sort"
	"strings"
)

// FlagGroup is one ordered section of the exporter's configuration surface.
//
// Every generated example config (the .env reference, the Compose reference and
// the Helm values file) renders from this one grouping, so the three artifacts
// cannot drift into three different section layouts as flags are added.
type FlagGroup struct {
	Key   string // stable slug, safe for anchors and YAML keys
	Title string // heading shown to operators
	Blurb string // one line on what the section governs
	Flags []FlagDoc
}

// groupRule assigns flags to a group by name prefix. Order matters: the first
// matching rule wins, so the narrow prefixes (logs.syslog.) must precede the
// broad ones (logs.).
type groupRule struct {
	key, title, blurb string
	prefixes          []string
	// match is an optional extra predicate, for the groups a prefix alone
	// cannot express (the collector switches share the exporter. prefix).
	match func(FlagDoc) bool
}

var groupRules = []groupRule{
	{
		key: "connection", title: "OPNsense connection",
		blurb:    "How to reach the firewall API. Address and protocol are required; everything else tunes the client.",
		prefixes: []string{"opnsense."},
	},
	{
		key: "collectors-opt-in", title: "Opt-in collectors",
		blurb:    "Off by default, each for a stated reason: extra per-poll API cost, high cardinality, or a live call to a third party.",
		prefixes: []string{"exporter.enable-"},
	},
	{
		key: "collectors-default-on", title: "Default-on collectors",
		blurb:    "On unless disabled. Each is silent when the subsystem or plugin it reads is absent, so leaving one on costs nothing on a box without it.",
		prefixes: []string{"exporter.disable-"},
	},
	{
		key: "webui", title: "Operator console",
		blurb:    "The web UI served at /. Reads a passive snapshot of the last scrape; it never gathers on its own.",
		prefixes: []string{"web.ui-"},
	},
	{
		key: "server", title: "HTTP server and logging",
		blurb:    "The metrics listener and process logging.",
		prefixes: []string{"web.", "log."},
	},
	{
		key: "exporter", title: "Exporter behaviour",
		blurb:    "Poll scheduling, caching, instance identity and the cardinality budget.",
		prefixes: []string{"exporter.", "collector.", "config."},
	},
	{
		key: "otlp", title: "OTLP metrics export",
		blurb:    "Push metrics to an OTLP endpoint instead of, or alongside, being scraped.",
		prefixes: []string{"otlp."},
	},
	{
		key: "pyroscope", title: "Continuous profiling (Pyroscope)",
		blurb:    "Off until a server address is set. All profile types are pushed by default.",
		prefixes: []string{"pyroscope."},
	},
	{
		key: "annotations", title: "Grafana annotations",
		blurb:    "The exporter's only outbound write: firewall change events written into Grafana's annotation store.",
		prefixes: []string{"annotations."},
	},
	{
		key: "logs-syslog", title: "Log shipping: syslog receiver",
		blurb:    "Push-based. The firewall sends syslog here; the exporter parses, enriches and ships it. UNAUTHENTICATED unless TLS client certs are configured.",
		prefixes: []string{"logs.syslog."},
	},
	{
		key: "logs-zenarmor", title: "Log shipping: Zenarmor receiver",
		blurb:    "The exporter poses as an Elasticsearch node so Zenarmor streams its reporting data here. High volume: trim at source with Zenarmor's own indexes setting.",
		prefixes: []string{"logs.zenarmor."},
	},
	{
		key: "logs-lanes", title: "Log shipping: polled lanes",
		blurb:    "Lanes that poll the firewall API rather than receiving a push.",
		prefixes: []string{"logs.crowdsec.", "logs.ids.", "logs.unbound."},
	},
	{
		key: "logs-debug-capture", title: "Log shipping: debug capture",
		blurb:    "Writes UNMODELLED receiver signals to disk so unknown payloads can be modelled without a packet capture. An investigation tool for a window, not a running mode.",
		prefixes: []string{"logs.debug-capture."},
	},
	{
		key: "logs", title: "Log shipping: pipeline",
		blurb:    "The shared sink, buffer and delivery settings every log lane feeds.",
		prefixes: []string{"logs."},
	},
	{
		key: "flow-netflow", title: "Flow: NetFlow receiver",
		blurb:    "Opens an UNAUTHENTICATED UDP socket. NetFlow has no authentication of any kind, so restrict it with an allowlist or by firewalling the port.",
		prefixes: []string{"flow.netflow."},
	},
	{
		key: "flow", title: "Flow: rollups and correlation",
		blurb:    "Volume counters derived from flow records, and the correlator that joins NetFlow fragments with Zenarmor conn documents.",
		prefixes: []string{"flow."},
	},
	{
		// Listed after "flow" on purpose: --flow.geoip.metric-dims is a flow-family
		// flag and belongs in the flow section beside the other cardinality controls,
		// while the "geoip." family is the database configuration itself. Rules are
		// matched in order, so the flow prefix claims that one first.
		key: "geoip", title: "GeoIP enrichment",
		blurb: "Local MaxMind lookups that give every flow record a country, continent and ASN, " +
			"whether or not Zenarmor saw the connection. Purely local - no lookup touches the " +
			"network. Fail-open: a missing database means the attributes are absent, never a " +
			"failed start.",
		prefixes: []string{"geoip."},
	},
}

// groupFlags partitions the kingpin model into ordered sections. Every flag
// lands in exactly one group; groupFlagsCoverage is the test hook that proves
// it, so a new flag whose prefix matches no rule fails the build rather than
// vanishing from every generated example config.
func groupFlags(flags []FlagDoc) []FlagGroup {
	groups := make([]FlagGroup, 0, len(groupRules))
	byKey := map[string]int{}
	for i, r := range groupRules {
		groups = append(groups, FlagGroup{Key: r.key, Title: r.title, Blurb: r.blurb})
		byKey[r.key] = i
	}
	for _, f := range flags {
		r, ok := ruleFor(f)
		if !ok {
			continue // reported by groupFlagsUnmatched, not silently dropped
		}
		i := byKey[r.key]
		groups[i].Flags = append(groups[i].Flags, f)
	}
	for i := range groups {
		sort.Slice(groups[i].Flags, func(a, b int) bool {
			return groups[i].Flags[a].Name < groups[i].Flags[b].Name
		})
	}
	return groups
}

// ruleFor returns the first rule matching a flag.
func ruleFor(f FlagDoc) (groupRule, bool) {
	for _, r := range groupRules {
		if r.match != nil && r.match(f) {
			return r, true
		}
		for _, p := range r.prefixes {
			if strings.HasPrefix(f.Name, p) {
				return r, true
			}
		}
	}
	return groupRule{}, false
}

// groupFlagsUnmatched lists flags no rule claims. Callers fail the build on a
// non-empty result: a flag absent from the grouping is a flag absent from every
// generated example config, which is exactly the silent-omission failure these
// artifacts exist to prevent.
func groupFlagsUnmatched(flags []FlagDoc) []string {
	var out []string
	for _, f := range flags {
		if _, ok := ruleFor(f); !ok {
			out = append(out, f.Name)
		}
	}
	sort.Strings(out)
	return out
}
