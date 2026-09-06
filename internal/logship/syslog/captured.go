package syslog

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// Captured extensions run only after the program's existing parser declined a
// line. These are log-only observations: syslog.event deliberately does not feed
// the existing derived metric families. A DHCP diagnostic is not a lease event,
// and three daemons reporting a link change must not create three link counters.
// Rules are program-scoped, anchored and compiled at startup. Adding a grammar
// does not require widening the existing parser's vocabulary or opt-in gates.
type capturedRule struct {
	pattern *regexp.Regexp
	event   string
	fields  []string
}

var capturedRules = map[string][]capturedRule{}

func capturedEvent(program, event, pattern string, fields ...string) {
	re := regexp.MustCompile("^(?:" + pattern + ")[ \t]*$")
	if re.NumSubexp() != len(fields) {
		panic("syslog: captured event field count mismatch: " + event)
	}
	capturedRules[program] = append(capturedRules[program], capturedRule{re, event, fields})
}

func parseCapturedRecord(env Envelope, snap *enrich.Snapshot) (logship.Record, bool) {
	for _, rule := range capturedRules[env.Program] {
		m := rule.pattern.FindStringSubmatch(env.Message)
		if m == nil {
			continue
		}
		// Reject malformed positional addresses rather than emitting invalid IP
		// attributes or letting a future hostname spelling silently change the type.
		valid := true
		for i, key := range rule.fields {
			if !validCapturedField(key, m[i+1]) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		rec, set := newRecord(env)
		set("syslog.event", rule.event)
		for i, key := range rule.fields {
			if key != "" {
				set(key, m[i+1])
			}
		}
		for _, prefix := range []string{"src", "dst"} {
			if ip := rec.Attributes[prefix+".ip"]; ip != "" {
				enrichEndpoint(set, snap, prefix, ip, "", "")
			}
		}
		// Preserve the generic body enrichment these formerly unparsed lines had.
		// Positional endpoint enrichment above is separate from the peer.* body scan.
		addCommon(&rec, env, snap, true)
		return rec, true
	}
	return logship.Record{}, false
}

// Validate typed wire values before a grammar is claimed. Other captures remain
// strings because their daemon-defined vocabulary is intentionally preserved.
func validCapturedField(key, value string) bool {
	switch {
	case strings.HasSuffix(key, ".ip"):
		_, err := netip.ParseAddr(value)
		return err == nil
	case strings.HasSuffix(key, ".port"):
		_, err := strconv.ParseUint(value, 10, 16)
		return err == nil
	case key == "dhcp6c.prefix":
		prefix, err := netip.ParsePrefix(value)
		return err == nil && prefix.Addr().Is6()
	default:
		return true
	}
}
