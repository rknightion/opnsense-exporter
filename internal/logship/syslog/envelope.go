// Package syslog implements the exporter's syslog receiver: RFC6587/newline
// framing, RFC5424 + RFC3164 envelope parsing, hardened UDP/TCP listeners and the
// record builders that turn OPNsense log lines into logship records.
package syslog

import (
	"errors"
	"strconv"
	"time"
)

// Envelope is the transport-level syslog header plus the message body. Program is
// the dispatch key (RFC5424 APP-NAME / RFC3164 TAG).
type Envelope struct {
	Timestamp time.Time
	Hostname  string
	Program   string
	PID       string
	Facility  int
	Severity  int
	Message   string
}

var (
	errEmpty     = errors.New("syslog: empty line")
	errNoPRI     = errors.New("syslog: missing or malformed <PRI>")
	errBadPRI    = errors.New("syslog: PRI out of range")
	errTruncated = errors.New("syslog: truncated envelope")
	errBadTime   = errors.New("syslog: malformed timestamp")
)

// ParseEnvelope parses one syslog line in either RFC5424 or RFC3164 (legacy BSD)
// format. OPNsense's syslog destination defaults its rfc5424 flag to 0, so the
// legacy format is the common case, not an edge case.
//
// now supplies the year for the BSD timestamp, which carries none. It never
// panics: every malformed input returns an error, and the caller ships the raw
// line rather than dropping it.
func ParseEnvelope(line []byte, now time.Time) (Envelope, error) {
	var env Envelope
	if len(line) == 0 {
		return env, errEmpty
	}
	rest, pri, err := parsePRI(line)
	if err != nil {
		return env, err
	}
	env.Facility = pri / 8
	env.Severity = pri % 8

	// "1 " => RFC5424 VERSION. Anything else is legacy BSD.
	if len(rest) >= 2 && rest[0] == '1' && rest[1] == ' ' {
		return parse5424(rest[2:], env)
	}
	return parse3164(rest, env, now)
}

// parsePRI consumes the leading "<N>" and returns the remainder plus N.
func parsePRI(line []byte) (rest []byte, pri int, err error) {
	if line[0] != '<' {
		return nil, 0, errNoPRI
	}
	end := -1
	// A PRI is at most three digits.
	for i := 1; i < len(line) && i <= 4; i++ {
		if line[i] == '>' {
			end = i
			break
		}
		if line[i] < '0' || line[i] > '9' {
			return nil, 0, errNoPRI
		}
	}
	if end < 2 { // "<>" has no digits
		return nil, 0, errNoPRI
	}
	pri, convErr := strconv.Atoi(string(line[1:end]))
	if convErr != nil {
		return nil, 0, errNoPRI
	}
	if pri < 0 || pri > 191 {
		return nil, 0, errBadPRI
	}
	return line[end+1:], pri, nil
}

// nilStr maps the RFC5424 nil value "-" to the empty string.
func nilStr(b []byte) string {
	if len(b) == 1 && b[0] == '-' {
		return ""
	}
	return string(b)
}

// field splits off the next space-delimited field. ok is false when the input is
// exhausted (i.e. the envelope is truncated).
func field(b []byte) (tok, rest []byte, ok bool) {
	if len(b) == 0 {
		return nil, nil, false
	}
	for i := 0; i < len(b); i++ {
		if b[i] == ' ' {
			return b[:i], b[i+1:], true
		}
	}
	return nil, nil, false // no trailing SP: another field was expected
}

// parse5424 parses TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG.
func parse5424(b []byte, env Envelope) (Envelope, error) {
	ts, b, ok := field(b)
	if !ok {
		return env, errTruncated
	}
	if len(ts) == 1 && ts[0] == '-' {
		env.Timestamp = time.Time{}
	} else {
		t, err := time.Parse(time.RFC3339Nano, string(ts))
		if err != nil {
			return env, errBadTime
		}
		env.Timestamp = t
	}

	host, b, ok := field(b)
	if !ok {
		return env, errTruncated
	}
	env.Hostname = nilStr(host)

	app, b, ok := field(b)
	if !ok {
		return env, errTruncated
	}
	env.Program = nilStr(app)

	procid, b, ok := field(b)
	if !ok {
		return env, errTruncated
	}
	env.PID = nilStr(procid)

	// MSGID is parsed and discarded.
	if _, b, ok = field(b); !ok {
		return env, errTruncated
	}

	msg, err := skipStructuredData(b)
	if err != nil {
		return env, err
	}
	env.Message = string(msg)
	return env, nil
}

// skipStructuredData consumes the STRUCTURED-DATA element ("-" or one or more
// bracketed elements) and returns the MSG that follows it.
func skipStructuredData(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errTruncated
	}
	if b[0] == '-' {
		if len(b) == 1 {
			return nil, nil
		}
		if b[1] != ' ' {
			return nil, errTruncated
		}
		return b[2:], nil
	}
	if b[0] != '[' {
		return nil, errTruncated
	}
	i := 0
	for i < len(b) && b[i] == '[' {
		i++
		for i < len(b) {
			if b[i] == '\\' { // escaped char inside a param value: \] \" \\
				i += 2
				continue
			}
			if b[i] == ']' {
				i++
				break
			}
			i++
		}
		if i > len(b) {
			return nil, errTruncated
		}
	}
	if i >= len(b) {
		return nil, nil // SD only, no MSG
	}
	if b[i] != ' ' {
		return nil, errTruncated
	}
	return b[i+1:], nil
}

var bsdMonths = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// parse3164 parses the legacy BSD envelope: MMM DD HH:MM:SS SP HOST SP TAG[PID]: SP MSG.
func parse3164(b []byte, env Envelope, now time.Time) (Envelope, error) {
	// "Jul 14 19:50:01" is exactly 15 bytes; the day may be space-padded ("Jul  4").
	const stampLen = 15
	if len(b) < stampLen+1 || b[stampLen] != ' ' {
		return env, errTruncated
	}
	ts, err := parseBSDTime(b[:stampLen], now)
	if err != nil {
		return env, err
	}
	env.Timestamp = ts
	b = b[stampLen+1:]

	host, b, ok := field(b)
	if !ok {
		return env, errTruncated
	}
	env.Hostname = string(host)

	tag, b, ok := field(b)
	if !ok {
		return env, errTruncated
	}
	// TAG is "prog:", "prog[pid]:" or a bare "prog".
	if n := len(tag); n > 0 && tag[n-1] == ':' {
		tag = tag[:n-1]
	}
	env.Program, env.PID = splitTagPID(tag)
	env.Message = string(b)
	return env, nil
}

// splitTagPID splits "filterlog[19325]" into ("filterlog", "19325").
func splitTagPID(tag []byte) (prog, pid string) {
	n := len(tag)
	if n > 2 && tag[n-1] == ']' {
		for i := n - 2; i > 0; i-- {
			if tag[i] == '[' {
				return string(tag[:i]), string(tag[i+1 : n-1])
			}
		}
	}
	return string(tag), ""
}

// parseBSDTime resolves the year-less BSD stamp against now. A stamp that lands
// more than 24h in the future belongs to the previous year — the New Year's Eve
// case, where a 31 Dec line is parsed on 1 Jan.
func parseBSDTime(b []byte, now time.Time) (time.Time, error) {
	if len(b) < 15 {
		return time.Time{}, errBadTime
	}
	mon, ok := bsdMonths[string(b[0:3])]
	if !ok {
		return time.Time{}, errBadTime
	}
	day, err := atoiSpace(b[4:6])
	if err != nil || day < 1 || day > 31 {
		return time.Time{}, errBadTime
	}
	// "Jul 14 19:50:01": 0-2 mon, 3 SP, 4-5 day, 6 SP, 7-8 hh, 9 ':', 10-11 mm, 12 ':', 13-14 ss.
	if b[3] != ' ' || b[6] != ' ' || b[9] != ':' || b[12] != ':' {
		return time.Time{}, errBadTime
	}
	hh, err1 := atoiSpace(b[7:9])
	mm, err2 := atoiSpace(b[10:12])
	ss, err3 := atoiSpace(b[13:15])
	if err1 != nil || err2 != nil || err3 != nil {
		return time.Time{}, errBadTime
	}
	if hh > 23 || mm > 59 || ss > 60 {
		return time.Time{}, errBadTime
	}
	loc := now.Location()
	if loc == nil {
		loc = time.UTC
	}
	t := time.Date(now.Year(), mon, day, hh, mm, ss, 0, loc)
	if t.Sub(now) > 24*time.Hour {
		t = t.AddDate(-1, 0, 0)
	}
	return t, nil
}

// atoiSpace parses a 2-digit field that may be space-padded ("Jul  4").
func atoiSpace(b []byte) (int, error) {
	n := 0
	seen := false
	for _, c := range b {
		if c == ' ' && !seen {
			continue
		}
		if c < '0' || c > '9' {
			return 0, errBadTime
		}
		n = n*10 + int(c-'0')
		seen = true
	}
	if !seen {
		return 0, errBadTime
	}
	return n, nil
}
