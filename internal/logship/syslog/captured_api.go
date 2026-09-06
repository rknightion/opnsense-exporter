package syslog

import "strings"

// OPNsense logs the supplied API key after this diagnostic marker. It can be
// arbitrary input, including a PEM block or embedded newline. Remove the entire
// suffix before parsing the envelope: malformed envelopes and unknown programs
// otherwise bypass body parsers and enter raw debug capture. Keeping the marker
// makes the diagnostic useful without retaining any of the credential bytes.
// This is a redaction boundary, not a parser claim: an unfamiliar surrounding
// grammar still ships and is captured as unknown, using only the safe bytes.
func redactAPIAuthFailure(text string) string {
	const marker = "authentication failed for api key"
	i := strings.Index(text, marker)
	if i < 0 {
		return text
	}
	return text[:i+len(marker)] + " [REDACTED]"
}

func init() {
	capturedEvent("api", "api_authentication_failed", `uri (/api/[\w/-]+) authentication failed for api key \[REDACTED\]`, "url.path")
}
