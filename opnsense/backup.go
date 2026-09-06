package opnsense

import (
	"math"
	"net/url"
	"strings"
	"time"
)

// configBackupItem mirrors one entry of the api/core/backup/backups/this
// bootgrid response — the on-box history of automatic config backups written
// by OPNsense's own BackupController (globbed from /conf/backup/config-*.xml).
//
// Field shapes confirmed against a live OPNsense 26.7 box (2026-07-13):
//   - time     is an epoch-seconds value with a fractional component; observed
//     on the wire as a quoted decimal string ("1783886416.55"). flexString
//     tolerates either that or a bare JSON number, so a future release that
//     switches representation (per the AGENTS.md "absorb" triage) does not
//     need a struct change.
//   - filesize is a JSON int on the wire; flexString is still used so a
//     string-typed filesize on some release doesn't break decoding.
type configBackupItem struct {
	ID          flexString `json:"id"`
	Time        flexString `json:"time"`
	Username    flexString `json:"username"`
	Description flexString `json:"description"`
	Filesize    flexString `json:"filesize"`
}

// configBackupResponse is the top-level api/core/backup/backups/this payload.
type configBackupResponse struct {
	Items []configBackupItem `json:"items"`
}

type configBackupDiffResponse struct {
	Items []string `json:"items"`
}

// ConfigBackupDiffMaxInputBytes bounds the diff FetchConfigBackupDiff will join
// and return. Upstream can return a diff of roughly 64 MiB for a pathological
// revision pair; the log-shipping pipeline unescapes and redacts that whole
// string before its own 192 KiB output truncation (internal/logship/configchange.go),
// so an unbounded input costs about three times its size in transient
// allocation. This bound is applied here, at the client, before any of that
// unescape/redact work runs.
const ConfigBackupDiffMaxInputBytes = 4 << 20

// configBackupDiffTruncationMarker is appended as a final line whenever
// boundConfigBackupDiffLines drops one or more trailing lines to stay under
// ConfigBackupDiffMaxInputBytes.
const configBackupDiffTruncationMarker = "[diff truncated at 4 MiB by opnsense2otel before redaction]"

// configBackupDiffMaxResponseBytes caps the raw JSON body FetchConfigBackupDiff
// will read at all, before it is decoded. The line bound above only trims what
// is retained after decoding, so without this the client would still buffer and
// decode a 64 MiB body to keep 4 MiB of it. Four times the input bound leaves
// generous room for JSON quoting and escaping of a diff that fits the bound; a
// body beyond it is refused as an API error, which the configchange source
// reports as a poll error.
const configBackupDiffMaxResponseBytes = 4 * ConfigBackupDiffMaxInputBytes

// boundConfigBackupDiffLines joins items with "\n", stopping at a line
// boundary once including the next whole line would exceed max. It never cuts
// inside a line: a credential element on one diff line is either kept whole
// (and later redacted by the log-shipping pipeline) or dropped whole, never
// left half-included in clear text. It reports whether any line was dropped.
func boundConfigBackupDiffLines(items []string, max int) (string, bool) {
	var b strings.Builder
	total := 0
	truncated := false
	// Reserve room for the marker and its separator so the returned string,
	// marker included, never exceeds max.
	budget := max - len(configBackupDiffTruncationMarker) - 1
	for i, line := range items {
		sep := 0
		if i > 0 {
			sep = 1
		}
		if total+sep+len(line) > budget {
			truncated = true
			break
		}
		if i > 0 {
			b.WriteByte('\n')
			total++
		}
		b.WriteString(line)
		total += len(line)
	}
	if truncated {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(configBackupDiffTruncationMarker)
	}
	return b.String(), truncated
}

// requestObserverAtPath retains the client's per-request instrumentation while
// collapsing a parameterized route onto its registered endpoint path. In
// particular, a config-revision filename is a fresh value on every write and
// must never become a Prometheus endpoint-label value.
type requestObserverAtPath struct {
	observer RequestObserver
	path     string
}

func (o requestObserverAtPath) ObserveAPIRequest(_ string, statusCode int, duration time.Duration) {
	o.observer.ObserveAPIRequest(o.path, statusCode, duration)
}

func (o requestObserverAtPath) ObserveAPIRequestResult(_ string, statusCode int, duration time.Duration, apiErr *APICallError) {
	if rich, ok := o.observer.(RequestResultObserver); ok {
		rich.ObserveAPIRequestResult(o.path, statusCode, duration, apiErr)
		return
	}
	o.observer.ObserveAPIRequest(o.path, statusCode, duration)
}

// ConfigBackupRevision is the public, identity-bearing view of a retained
// configuration-history row used by the opt-in config-change log source. These
// fields are deliberately not metric labels; user and description may contain
// operator identity or free text and belong only on the emitted log record.
type ConfigBackupRevision struct {
	ID          string
	Timestamp   time.Time
	User        string
	Description string
}

// ConfigBackupHistory is the normalised config-backup freshness summary: is the
// firewall's own config actually being backed up, and how stale is the newest
// copy. No per-backup metrics are derived — descriptions/usernames can carry
// hostnames or admin identity, so only the aggregate counts/timestamp are
// surfaced.
type ConfigBackupHistory struct {
	// Count is the number of backups OPNsense currently retains (bounded by
	// the box's retention setting; observed as high as 100 on a live box).
	Count int
	// LastTimestamp is the Unix-seconds time of the newest backup, or 0 if
	// Count is 0.
	LastTimestamp float64
	// LastSizeBytes is the file size of the newest backup, or 0 if Count is 0.
	LastSizeBytes float64
}

// FetchConfigBackupHistory retrieves the on-box config backup history and
// summarises it into freshness/count/size signals. This is a core endpoint —
// it is never plugin-gated and never answers 404.
func (c *Client) FetchConfigBackupHistory() (ConfigBackupHistory, *APICallError) {
	var resp configBackupResponse
	var data ConfigBackupHistory

	path, ok := c.endpoints["backupHistory"]
	if !ok {
		return data, &APICallError{
			Endpoint:   "backupHistory",
			Message:    "endpoint not found in client endpoints",
			StatusCode: 0,
		}
	}

	if err := c.do("GET", path, nil, &resp); err != nil {
		return data, err
	}

	data.Count = len(resp.Items)
	if data.Count == 0 {
		return data, nil
	}

	// OPNsense's BackupController documents items[] as newest-first, but the
	// newest entry is derived explicitly by max(time) rather than trusting
	// index 0, so a reordered or paginated response can't silently misreport
	// the newest backup.
	newestIdx := 0
	newestTime := safeParseFloat(resp.Items[0].Time.String())
	for i := 1; i < len(resp.Items); i++ {
		t := safeParseFloat(resp.Items[i].Time.String())
		if t > newestTime {
			newestTime = t
			newestIdx = i
		}
	}

	data.LastTimestamp = newestTime
	data.LastSizeBytes = safeParseFloat(resp.Items[newestIdx].Filesize.String())

	return data, nil
}

// FetchConfigBackupRevisions returns the retained configuration-history rows.
// The response order is preserved; consumers that need chronology must sort by
// Timestamp and ID because the upstream grid is normally newest-first.
func (c *Client) FetchConfigBackupRevisions() ([]ConfigBackupRevision, *APICallError) {
	var resp configBackupResponse
	path, ok := c.endpoints["backupHistory"]
	if !ok {
		return nil, &APICallError{Endpoint: "backupHistory", Message: "endpoint not found in client endpoints"}
	}
	if err := c.do("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	revisions := make([]ConfigBackupRevision, 0, len(resp.Items))
	for _, item := range resp.Items {
		revisions = append(revisions, ConfigBackupRevision{
			ID:          item.ID.String(),
			Timestamp:   configBackupTime(item.Time.String()),
			User:        item.Username.String(),
			Description: item.Description.String(),
		})
	}
	return revisions, nil
}

// FetchConfigBackupDiff fetches the upstream-produced unified diff between two
// retained revisions. It intentionally returns the raw HTML-escaped lines: the
// log source owns presentation unescaping immediately before emission.
func (c *Client) FetchConfigBackupDiff(host, oldRevision, newRevision string) (string, *APICallError) {
	base, ok := c.endpoints["backupDiff"]
	if !ok {
		return "", &APICallError{Endpoint: "backupDiff", Message: "endpoint not found in client endpoints"}
	}
	// BackupController::diffAction runs diff(backup2, backup1), so the newer
	// revision must be the first route argument to produce old-to-new changes.
	path := EndpointPath(strings.Join([]string{
		string(base), url.PathEscape(host), url.PathEscape(newRevision), url.PathEscape(oldRevision),
	}, "/"))
	// The request path embeds revision names. Keep the operational request and
	// duration metrics keyed by the static registered route, rather than growing
	// a new time series for every configuration write.
	requestClient := *c
	requestClient.maxResponseBody = configBackupDiffMaxResponseBytes
	if c.observer != nil {
		requestClient.observer = requestObserverAtPath{observer: c.observer, path: string(base)}
	}
	var resp configBackupDiffResponse
	if err := requestClient.do("GET", path, nil, &resp); err != nil {
		return "", err
	}
	diff, _ := boundConfigBackupDiffLines(resp.Items, ConfigBackupDiffMaxInputBytes)
	return diff, nil
}

func configBackupTime(raw string) time.Time {
	seconds := safeParseFloat(raw)
	if seconds <= 0 {
		return time.Time{}
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*1e9)).UTC()
}
