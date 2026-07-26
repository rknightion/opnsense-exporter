package syslog

import (
	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

func init() {
	RegisterParser(parseFreeRADIUS, "radiusd")
}

// parseFreeRADIUS consumes only the fixed messages produced by
// sanitizeFreeRADIUS. It never sees a username, password, client identity,
// address, reply text, or arbitrary daemon error, so none can accidentally
// become record attributes or metric labels.
func parseFreeRADIUS(
	env Envelope,
	_ *enrich.Snapshot,
	_ func(table string),
) (logship.Record, bool) {
	result := ""
	switch env.Message {
	case freeRADIUSAccessAcceptedMessage:
		result = "accepted"
	case freeRADIUSAccessRejectedMessage:
		result = "rejected"
	default:
		return logship.Record{}, false
	}

	rec, set := newRecord(env)
	set("radius.event", "access")
	set("radius.result", result)
	set("radius.client_scope", "configured")
	return rec, true
}
