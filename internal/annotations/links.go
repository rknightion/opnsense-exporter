package annotations

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DashboardUID is the operational dashboard's frozen UID. It is the same value as
// `MAIN_UID` in grafana/uids.py, and grafana/tests/test_annotations.py reads this
// constant out of the Go source and compares the two — a divergence here has no
// symptom, because a link to a nonexistent dashboard 404s only for the operator who
// clicks it, months later, during an incident (#419).
const DashboardUID = "opnsense-exporter"

// InstanceVar is the dashboard's instance picker, spelled as its URL parameter. The
// dashboard side builds this through `${opnsense_instance:queryparam}`; there is no
// such interpolation available here, so the name is written once and pinned by test.
const InstanceVar = "var-opnsense_instance"

// linkWindow brackets the event rather than starting at it. A link that opens at
// exactly the event instant shows the aftermath and none of the run-up, which is the
// comparison the annotation exists to support.
const linkWindow = 15 * time.Minute

// contextLink builds an absolute dashboard URL for one event, or "" when it could
// not resolve to something worth clicking.
//
// Absolute rather than relative, because unlike the dashboard's own generated links
// this URL is read outside any dashboard: it lands in an annotation body that shows
// in Explore, beside alerts, and in the annotation list. The base is the operator's
// own `--annotations.url`, so nothing stack-specific is compiled in.
//
// The instant is written as concrete epoch milliseconds, NOT as Grafana's
// `${__url_time_range}` token: annotation text is not interpolated against dashboard
// variables, so a token here would render literally and produce a dead link.
func contextLink(base, instance string, at time.Time) string {
	if instance == "" {
		return ""
	}
	parsed, err := url.Parse(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(base), "/")))
	if err != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	query := url.Values{}
	query.Set("from", strconv.FormatInt(at.Add(-linkWindow).UnixMilli(), 10))
	query.Set("to", strconv.FormatInt(at.Add(linkWindow).UnixMilli(), 10))
	query.Set(InstanceVar, instance)
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/d/" + DashboardUID
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// withLink returns the annotation body: the event text, plus a markdown link back to
// the dashboard at this event's instance and window when one can be built.
//
// The instance comes from the event's own `instance:<name>` tag rather than from
// configuration, so the link follows the box the event happened on even when one
// exporter serves several appliances.
func withLink(event Event, base string) string {
	_, instance, _ := decodeTags(event.Tags)
	link := contextLink(base, instance, event.At)
	if link == "" {
		return event.Text
	}
	return event.Text + " — [view on the OPNsense dashboard](" + link + ")"
}
