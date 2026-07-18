package zenarmor

import "strings"

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
