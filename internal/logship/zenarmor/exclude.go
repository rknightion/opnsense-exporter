package zenarmor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// excludeOp is the only operator --logs.zenarmor.exclude accepts.
//
// Regex-only, deliberately. An exact-match `=` would be a second thing to explain
// for no expressive gain (`^x$` says it), and reserving `=` now leaves room to add
// it — or `!=` — later without redefining what a bare `=` already meant.
const excludeOp = "=~"

// ExcludeRule is one parsed --logs.zenarmor.exclude entry: drop the record when
// Field's value matches Re.
//
// EXCLUSION IS LOSSY, and not in the way --logs.syslog.sample is. Sampling only ever
// removes the redundant raw copy of something a counter already captured, because
// opnsense_log_events_firewall_total carries action, interface and rule — most of the
// line's value survives in the counter. opnsense_log_events_zenarmor_total carries
// only family / action / category / interface / rcode / severity / status_class,
// deliberately, for cardinality. It has no server_name, no query, no device_name. So
// dropping a Zenarmor record after counting it still destroys the thing the SIEM
// view exists to show, and unlike a query-time filter that decision cannot be undone
// after the fact. Hence: default off, counted per rule, and documented as lossy.
type ExcludeRule struct {
	// Raw is the rule exactly as the operator wrote it. It is the `rule` label value
	// on logs_zenarmor_excluded_total, so the blind spot is visible on a dashboard
	// rather than inferred from a config file.
	Raw string
	// Field is the record attribute to test. Validated against KnownAttributeKeys.
	Field string
	// Re is matched against the field's value.
	Re *regexp.Regexp
}

// KnownAttributeKeys is every attribute the parser can put on a Zenarmor record, and
// therefore every field an exclude rule may name. It is enforced against parse.go's
// actual set()/setInt() calls by TestKnownAttributeKeysCoverEveryKeyTheParserSets,
// in both directions: a key the parser sets but this list omits would make a
// legitimate rule fail at startup, and a key listed here that the parser never sets
// would let a rule start up and then silently match nothing.
//
// Keys are family-dependent — server_name only exists on tls, query only on dns —
// and that is fine. A rule naming a field this record does not carry simply does not
// match it; the field only has to be one SOME family can produce.
//
// The numeric fields (ip_src_port, src_nbytes, ...) are matchable because the
// receiver stores every attribute as a string; the regex sees "443", not 443. There
// is no range operator, so they are of limited use — but rejecting them would be a
// special case with no upside.
//
// opnsense.subsystem and opnsense.action are the pipeline's own attributes, present
// on the record at exclusion time and so genuinely matchable. Excluding on either is
// a bad idea (families already restricts subsystem, and dropping by action would
// blind the SIEM view to exactly the records worth keeping), but that is the
// operator's call to make explicitly, not something to hide by pretending the field
// does not exist.
var KnownAttributeKeys = []string{
	"alertinfo.action",
	"alertinfo.category",
	"alertinfo.severity",
	"alertinfo.sid",
	"alertinfo.signature",
	"alert_category",
	"alert_severity",
	"answers",
	"app_category",
	"app_name",
	"app_proto",
	"community_id",
	"conn_uuid",
	"device.category",
	"device.id",
	"device.name",
	"device.os",
	"device.osver",
	"device.vendor",
	"direction",
	"domain_category",
	"dst.scope",
	"dst.service",
	"dst_hostname",
	"dst_hwaddr",
	"dst_nbytes",
	"dst_npackets",
	"dst_pbytes",
	"dst_username",
	"encryption",
	"host",
	"http.status_code",
	"http.version",
	"interface",
	"interface.name",
	"ip_dst_port",
	"ip_dst_saddr",
	"ip_src_port",
	"ip_src_saddr",
	"ja3",
	"method",
	"opnsense.action",
	"opnsense.device_category",
	"opnsense.interface",
	"opnsense.subsystem",
	"organization",
	"policyid",
	"qclass",
	"qtype",
	"query",
	"rcode",
	"referrer",
	"req_body_len",
	"rsp_body_len",
	"server_name",
	"sip_method",
	"sip_status",
	"sip_uri",
	"src.scope",
	"src_hostname",
	"src_hwaddr",
	"src_nbytes",
	"src_npackets",
	"src_pbytes",
	"src_username",
	"total_answers",
	"transport_proto",
	"uri",
	"user_agent",
	"vlanid",
}

// parseExcludeRules parses, validates and compiles the raw --logs.zenarmor.exclude
// entries. It refuses ambiguity rather than guessing: an unknown field name is an
// error, not a rule that matches nothing, because a filter that silently does
// nothing looks exactly like a quiet network — the same reasoning that makes
// --logs.zenarmor.families validation strict.
func parseExcludeRules(raw []string) ([]ExcludeRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	known := make(map[string]bool, len(KnownAttributeKeys))
	for _, k := range KnownAttributeKeys {
		known[k] = true
	}

	rules := make([]ExcludeRule, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		field, expr, found := strings.Cut(entry, excludeOp)
		if !found {
			return nil, fmt.Errorf(
				"logs.zenarmor.exclude: %q is not a rule; expected FIELD=~REGEX (e.g. "+
					`server_name=~.*\.grafana\.net). Only the =~ (regex) operator is supported — `+
					"use ^value$ for an exact match", entry)
		}
		field = strings.TrimSpace(field)
		if field == "" {
			return nil, fmt.Errorf("logs.zenarmor.exclude: %q has an empty field name before =~", entry)
		}
		if expr == "" {
			return nil, fmt.Errorf("logs.zenarmor.exclude: %q has an empty regex after =~; to match "+
				"any value use %s=~.+", entry, field)
		}
		if !known[field] {
			return nil, fmt.Errorf(
				"logs.zenarmor.exclude: unknown field %q in rule %q%s. A rule naming a field the "+
					"receiver never sets would silently match nothing, so this is refused at startup. "+
					"Valid fields: %s",
				field, entry, suggest(field, KnownAttributeKeys), strings.Join(KnownAttributeKeys, ", "))
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("logs.zenarmor.exclude: rule %q has an invalid regex: %w", entry, err)
		}
		rules = append(rules, ExcludeRule{Raw: entry, Field: field, Re: re})
	}
	return rules, nil
}

// excludedBy returns the first rule matching attrs, if any. Rules are OR-ed: any one
// match drops the record.
//
// Matching is FIELD-SCOPED — a server_name rule never tests the value of `host`.
// A rule that matched any field would over-drop silently, which is the one failure
// mode an exclusion feature must not have.
func excludedBy(rules []ExcludeRule, attrs map[string]string) (ExcludeRule, bool) {
	for _, r := range rules {
		v, ok := attrs[r.Field]
		if !ok {
			continue // this family does not carry the field; not a match
		}
		if r.Re.MatchString(v) {
			return r, true
		}
	}
	return ExcludeRule{}, false
}

// suggest names the closest known key when a field looks like a typo of one, so the
// error points at the fix rather than only at the mistake.
func suggest(field string, known []string) string {
	var near []string
	for _, k := range known {
		if editDistanceWithin(field, k, 2) {
			near = append(near, k)
		}
	}
	if len(near) == 0 {
		return ""
	}
	sort.Strings(near)
	return fmt.Sprintf(" (did you mean %s?)", strings.Join(near, " or "))
}

// editDistanceWithin reports whether a and b are within max edits of each other. A
// full Levenshtein table is overkill for two short keys, but it is 20 lines and the
// alternative is an error message that only says "unknown".
func editDistanceWithin(a, b string, max int) bool {
	if a == b {
		return true
	}
	if len(a)-len(b) > max || len(b)-len(a) > max {
		return false
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = minOf(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)] <= max
}

func minOf(vals ...int) int {
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}
