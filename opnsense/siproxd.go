package opnsense

import (
	"net/http"
	"strings"
)

// siproxdRegistrationsResponse mirrors api/siproxd/service/showregistrations
// (os-siproxd plugin's ServiceController::showregistrationsAction, which
// wraps `configdRun('siproxd registrations')` — literally `/bin/cat
// /var/lib/siproxd/siproxd_registrations`, per actions_siproxd.conf — in
// {"response": "..."}).
//
// VERIFICATION: the os-siproxd plugin is not installed on the 26.7-devel test
// box (GET returns 404 "Endpoint not found"), so no live populated capture
// exists (#224). The file format is derived instead from siproxd's own
// registration_file writer and the pfSense package that parses the identical
// file (pfsense/FreeBSD-ports net/pfSense-pkg-siproxd
// siproxd_registered_phones.php): plain text, four lines per registration
// entry — a "stars:active:expires" header, then real/nat/registered
// "type:user@host:port;tags" legs — never binary. Re-validate against a live
// populated file if the plugin ever becomes installable on a test box.
type siproxdRegistrationsResponse struct {
	Response flexString `json:"response"`
}

// SiproxdRegistrations is the normalised, PII-free view of
// api/siproxd/service/showregistrations. Present is false when the os-siproxd
// plugin is absent (404). No per-registration user/host labels are exposed
// (SIP AORs and their real IPs are PII) — only a total active count.
type SiproxdRegistrations struct {
	Present bool
	Active  int64
}

// FetchSiproxdRegistrations counts active SIP registrations from the raw
// siproxd_registrations text file. Every registration occupies exactly 4
// lines; the header line's second colon-delimited field is "1" for an active
// registration, "0" otherwise. Parsing is deliberately defensive: a header
// line that doesn't split into at least 2 colon-delimited fields is skipped
// rather than counted, so unexpected/binary-ish content degrades to an
// undercount instead of a crashed scrape or a bogus number (#224 — this
// format has never been validated against a live populated file).
func (c *Client) FetchSiproxdRegistrations() (SiproxdRegistrations, *APICallError) {
	var data SiproxdRegistrations

	url, ok := c.endpoints["siproxdRegistrations"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "siproxdRegistrations",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	var resp siproxdRegistrationsResponse
	if err := c.do("GET", url, nil, &resp); err != nil {
		if err.StatusCode == http.StatusNotFound {
			return data, nil // feature absent
		}
		return data, err
	}

	data.Present = true

	raw := strings.TrimRight(resp.Response.String(), "\r\n")
	if raw == "" {
		return data, nil
	}

	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i += 4 {
		header := lines[i]
		fields := strings.SplitN(header, ":", 3)
		if len(fields) < 2 {
			// Not the expected "stars:active:expires" shape; skip this block
			// rather than mis-parsing content that doesn't look like ours.
			continue
		}
		if fields[1] == "1" {
			data.Active++
		}
	}

	return data, nil
}
