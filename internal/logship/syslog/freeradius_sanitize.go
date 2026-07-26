package syslog

import (
	"fmt"
	"regexp"
	"time"
)

const (
	freeRADIUSAccessAcceptedMessage = "FreeRADIUS access request accepted"
	freeRADIUSAccessRejectedMessage = "FreeRADIUS access request rejected"
	freeRADIUSGenericMessage        = "FreeRADIUS message redacted"
)

var (
	// Captured on OPNsense 27.1.a_40 with os-freeradius 1.10.2 while both
	// password logging options were disabled (#407). Everything after the stable
	// event prefix is identity-bearing and is discarded rather than parsed.
	reFreeRADIUSAccessAccepted = regexp.MustCompile(
		`^(?:\(\d+\) )?Login OK:`,
	)
	reFreeRADIUSAccessRejected = regexp.MustCompile(
		`^(?:\(\d+\) )?Login incorrect(?: \([^)]*\))?:`,
	)

	// These recognizers are deliberately narrower than a substring search. They
	// are used only when the ordinary envelope parser failed, so the program
	// cannot be trusted through Envelope.Program. A radiusd token in an unrelated
	// message body must not cause that line to be replaced.
	reMalformedFreeRADIUS5424 = regexp.MustCompile(
		`^1 \S+ \S+ radiusd(?: |$)`,
	)
	reMalformedFreeRADIUS3164 = regexp.MustCompile(
		`^[A-Z][a-z]{2} [ 0-9][0-9] \d{2}:\d{2}:\d{2} \S+ radiusd(?:\[\d+\])?:`,
	)
)

// sanitizeFreeRADIUS is the confidentiality boundary for a successfully parsed
// radiusd envelope. It runs before filtering, parser dispatch, generic
// enrichment, debug capture, shape normalization, metric derivation, sampling,
// queueing, or logging.
//
// The safe representation deliberately discards every wire-derived identity
// field except the code-defined program name and the transport priority/time.
// This includes RFC5424 structured data, which ParseEnvelope does not retain in
// Envelope but debug capture otherwise would preserve through raw.
func sanitizeFreeRADIUS(
	env Envelope,
	raw []byte,
) (safeEnv Envelope, safeRaw []byte, recognized bool) {
	if env.Program != "radiusd" {
		return env, raw, false
	}

	safeMessage := freeRADIUSGenericMessage
	switch {
	case env.Message == freeRADIUSAccessAcceptedMessage,
		env.Message == freeRADIUSAccessRejectedMessage,
		env.Message == freeRADIUSGenericMessage:
		safeMessage = env.Message
	case reFreeRADIUSAccessAccepted.MatchString(env.Message):
		safeMessage = freeRADIUSAccessAcceptedMessage
	case reFreeRADIUSAccessRejected.MatchString(env.Message):
		safeMessage = freeRADIUSAccessRejectedMessage
	}

	safeEnv = Envelope{
		Timestamp: env.Timestamp,
		Program:   "radiusd",
		Facility:  env.Facility,
		Severity:  env.Severity,
		Message:   safeMessage,
	}
	return safeEnv, renderSafeFreeRADIUS(safeEnv), true
}

// sanitizeMalformedFreeRADIUS fails closed when the ordinary envelope parser
// rejects a line whose header still has an unambiguous radiusd program token.
// The caller records the original parse failure, then uses only this safe
// envelope/frame for every downstream operation.
func sanitizeMalformedFreeRADIUS(
	line []byte,
	now time.Time,
) (safeEnv Envelope, safeRaw []byte, recognized bool) {
	if len(line) == 0 {
		return Envelope{}, line, false
	}
	rest, pri, err := parsePRI(line)
	if err != nil {
		return Envelope{}, line, false
	}
	if !reMalformedFreeRADIUS5424.Match(rest) &&
		!reMalformedFreeRADIUS3164.Match(rest) {
		return Envelope{}, line, false
	}

	safeEnv = Envelope{
		Timestamp: now,
		Program:   "radiusd",
		Facility:  pri / 8,
		Severity:  pri % 8,
		Message:   freeRADIUSGenericMessage,
	}
	return safeEnv, renderSafeFreeRADIUS(safeEnv), true
}

func renderSafeFreeRADIUS(env Envelope) []byte {
	timestamp := "-"
	if !env.Timestamp.IsZero() {
		timestamp = env.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	priority := env.Facility*8 + env.Severity
	return fmt.Appendf(
		nil,
		"<%d>1 %s - radiusd - - - %s",
		priority,
		timestamp,
		env.Message,
	)
}
