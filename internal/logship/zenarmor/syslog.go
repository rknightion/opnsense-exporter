package zenarmor

import (
	"net/netip"
	"strings"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/syslog"
)

// parseSyslogPayload extracts the family token and raw data JSON from a Zenarmor
// syslog message body of the form:
//
//	daemon=zenarmor, index=<family>, data=<JSON>
//
// The data JSON is taken as everything after the first "data=" verbatim: it holds
// commas and braces, so it must never be tokenised. ok is false for any body that is
// not this shape, so the receiver ships it raw rather than manufacture a record.
func parseSyslogPayload(msg string) (family, data string, ok bool) {
	const idxKey, dataKey = "index=", "data="
	i := strings.Index(msg, idxKey)
	d := strings.Index(msg, dataKey)
	if i < 0 || d < 0 || d < i {
		return "", "", false
	}
	// family is index= up to the next comma (before data=).
	fam := msg[i+len(idxKey):]
	if c := strings.IndexByte(fam, ','); c >= 0 {
		fam = fam[:c]
	}
	fam = strings.TrimSpace(fam)
	data = strings.TrimSpace(msg[d+len(dataKey):])
	if fam == "" || data == "" || data[0] != '{' {
		return "", "", false
	}
	return fam, data, true
}

// syslogProcessor adapts the shared docProcessor to the syslog receiver's
// ProgramProcessor interface, so a Zenarmor line arriving over syslog runs
// through the exact same pipeline (enrichment, self-traffic filtering, derived
// metrics, exclusion) as one arriving over the Elasticsearch bulk endpoint.
type syslogProcessor struct{ proc *docProcessor }

// Handles reports whether program is the Zenarmor daemon name.
func (s *syslogProcessor) Handles(program string) bool { return program == sourceName }

// Process delegates a Zenarmor syslog line to the shared docProcessor. It returns
// false (ship generic) when the body is not the Zenarmor shape or names a family we
// do not model — never a silent drop.
func (s *syslogProcessor) Process(env syslog.Envelope, peer netip.Addr, ports []int, emit func(logship.Record)) bool {
	fam, data, ok := parseSyslogPayload(env.Message)
	if !ok {
		return false // not a Zenarmor daemon line; let the generic path ship it raw
	}
	family := indexFamilies[fam]
	if family == "" {
		s.proc.m.reject("unknown_family")
		return true // recognised as Zenarmor, but a family we don't model — counted, dropped
	}
	// Self-traffic over syslog is the box->exporter:syslogport flow Zenarmor reports,
	// the exact analogue of the ES _bulk link. The box streams to one syslog endpoint,
	// so the first bound port is it; 0 (no ports) disables the filter. listenPort is
	// passed as an argument — never stored — because Process runs concurrently on many
	// listener goroutines.
	port := 0
	if len(ports) > 0 {
		port = ports[0]
	}
	s.proc.process(family, []byte(data), peer, port, emit)
	return true
}
