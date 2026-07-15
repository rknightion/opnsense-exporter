package syslog

import (
	"strconv"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// family is the derived metric family a syslog program belongs to (#258).
// familyUnknown is the zero value: a program not in programFamily below.
type family int

const (
	familyUnknown family = iota
	familyFirewall
	familyHAProxy
	familySSHD
	familyDHCP
	familyAudit
	familyIDS
)

// programFamily maps every program name a parser in this package registers
// (see the RegisterParser calls in filterlog.go, haproxy.go, sshd.go, dhcp.go,
// audit.go, suricata.go) onto its derived metric family. It is built from
// explicit program lists mirroring those calls, on purpose, so it stays in
// lockstep with the parsers: a program registered there without a matching
// entry here just falls through to familyUnknown, never a mis-derived metric.
var programFamily = map[string]family{
	"filterlog": familyFirewall,

	"haproxy": familyHAProxy,

	"sshd":         familySSHD,
	"sshd-session": familySSHD,

	"dhcpd":     familyDHCP,
	"dnsmasq":   familyDHCP,
	"kea-dhcp4": familyDHCP,
	"kea-dhcp6": familyDHCP,
	"dhcrelay":  familyDHCP,

	"audit":      familyAudit,
	"configd.py": familyAudit,

	"suricata": familyIDS,
}

// deriveFamily reports the derived metric family for a syslog program name.
// ok is false for anything outside the six derived families.
func deriveFamily(program string) (family, bool) {
	f, ok := programFamily[program]
	return f, ok
}

// observeDerived counts one record's attributes against sink, if program
// belongs to a derived family. counted reports whether a call actually
// happened: a derived program whose key attribute is missing (e.g. a
// filterlog line that failed structured parsing and carries no "action")
// returns false rather than counting a blank label value, so the caller never
// treats an uncounted line as handled — see sampleKeep, which never drops a
// line observeDerived did not count.
func observeDerived(sink logship.MetricSink, program string, attrs map[string]string) (counted bool) {
	fam, ok := deriveFamily(program)
	if !ok {
		return false
	}

	switch fam {
	case familyFirewall:
		action := attrs["action"]
		if action == "" {
			return false
		}
		iface := firstNonEmpty(attrs["interface.name"], attrs["interface"])
		ruleID := firstNonEmpty(attrs["rule.id"], attrs["rule.ref"])
		sink.ObserveFirewall(action, iface, ruleID, attrs["rule.description"], attrs["src.scope"])
		return true

	case familyHAProxy:
		event := attrs["haproxy.event"]
		if event == "" {
			return false
		}
		sink.ObserveHAProxy(event, attrs["haproxy.backend"], attrs["haproxy.server"], attrs["haproxy.state"], statusClass(attrs["http.status_code"]))
		return true

	case familySSHD:
		result := attrs["auth.result"]
		if result == "" {
			return false
		}
		sink.ObserveSSHD(result, attrs["auth.method"], attrs["src.scope"])
		return true

	case familyDHCP:
		action := attrs["dhcp.action"]
		if action == "" {
			return false
		}
		iface := firstNonEmpty(attrs["interface.name"], attrs["interface"])
		sink.ObserveDHCP(action, iface, attrs["dhcp.server_ip"])
		return true

	case familyAudit:
		event := attrs["event"]
		if event == "" {
			return false
		}
		sink.ObserveAudit(event, attrs["audit.result"])
		return true

	case familyIDS:
		eventType := attrs["event_type"]
		if eventType == "" {
			return false
		}
		sink.ObserveIDS(eventType, attrs["alert_action"], attrs["alert_category"], attrs["alert_severity"])
		return true
	}

	return false
}

// firstNonEmpty returns a, falling back to b when a is empty.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// statusClass buckets an HTTP status code string into "2xx".."5xx". Empty or
// unparseable input (including anything outside 100-599) yields "".
func statusClass(status string) string {
	if status == "" {
		return ""
	}
	code, err := strconv.Atoi(status)
	if err != nil || code < 100 || code > 599 {
		return ""
	}
	return strconv.Itoa(code/100) + "xx"
}
