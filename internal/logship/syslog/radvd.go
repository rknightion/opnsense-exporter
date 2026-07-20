package syslog

import (
	"regexp"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// radvd's IPv6 router-advertisement daemon chatter. Only two shapes are worth
// structuring — the periodic poll and the per-interface timer tick — both
// captured verbatim from the live box:
//
//	polling for 27.344 second(s), next iface is ixl0_vlan100
//	polling for 51.757 second(s), next iface is ixl0
//	timer_handler called for ixl0_vlan100
//	timer_handler called for ixl0
//
// Attributes emitted:
//
//	radvd.event             polling | timer
//	interface                the raw device (e.g. ixl0_vlan100)
//	interface.name           resolved friendly name, when known
//	radvd.interval_seconds   the poll interval, polling lines only, kept as the
//	                         exact string from the line
//
// Anything else radvd logs returns ok=false and degrades to a generic record.
var (
	reRadvdPolling = regexp.MustCompile(`^polling for (\S+) second\(s\), next iface is (\S+)$`)
	reRadvdTimer   = regexp.MustCompile(`^timer_handler called for (\S+)$`)
)

func init() {
	RegisterParser(parseRadvd, "radvd")
}

func parseRadvd(env Envelope, snap *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reRadvdPolling.FindStringSubmatch(env.Message); m != nil {
		interval, dev := m[1], m[2]
		rec, set := newRecord(env)
		set("radvd.event", "polling")
		set("interface", dev)
		if name, ok := ifaceName(snap, dev); ok {
			set("interface.name", name)
		}
		set("radvd.interval_seconds", interval)
		return rec, true
	}

	if m := reRadvdTimer.FindStringSubmatch(env.Message); m != nil {
		dev := m[1]
		rec, set := newRecord(env)
		set("radvd.event", "timer")
		set("interface", dev)
		if name, ok := ifaceName(snap, dev); ok {
			set("interface.name", name)
		}
		return rec, true
	}

	return logship.Record{}, false
}
