package annotations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved `--annotations.*` configuration.
type Config struct {
	// URL is the Grafana base URL (https://<stack>.grafana.net). The API path is
	// appended, so a trailing slash is tolerated.
	URL string
	// Token authenticates as a service account. It needs only the annotation
	// write permission; nothing here reads dashboards or datasources.
	Token string
	// Interval is how often the watched metrics are diffed. It bounds how late an
	// annotation can be POSTED, never where it is PLACED — the annotation carries
	// the event's own instant.
	Interval time.Duration
	Timeout  time.Duration
	// Lookback bounds two things at once: how far back the startup reconciliation
	// looks for annotations this exporter has already written, and therefore how
	// old an event may be and still be worth posting. An instant older than this
	// is treated as history, not news.
	Lookback time.Duration
	// ExtraTags are added to every annotation, for deployments that want to
	// separate environments or overlay these on an existing tag scheme.
	ExtraTags []string
	// Kinds is the exact set of event kinds to write. Empty means DefaultKinds()
	// — the catalogue minus its DefaultOff entries — and a non-empty list
	// overrides that in BOTH directions, so it enables a default-off kind and
	// disables a default-on one.
	Kinds []string
	// MaxPerCycle caps posts per detection pass. A guard, not a feature: without
	// it, one bad gather (every watched series appearing to change at once) would
	// write hundreds of annotations before anyone noticed.
	MaxPerCycle int
}

// Event is one annotation to write.
type Event struct {
	Kind string
	Text string
	At   time.Time
	Tags []string
}

// annotationPayload is Grafana's POST /api/annotations body. No dashboardUID is
// sent: an organisation-wide annotation is visible to ANY dashboard whose
// annotation layer queries the tag, which is the point of pushing them rather than
// deriving them on one dashboard.
type annotationPayload struct {
	Time int64    `json:"time"`
	Tags []string `json:"tags"`
	Text string   `json:"text"`
}

// existingAnnotation is the subset of Grafana's GET /api/annotations response used
// for startup reconciliation.
type existingAnnotation struct {
	Time int64    `json:"time"`
	Tags []string `json:"tags"`
}

// httpError is a non-2xx answer from Grafana, carrying the status and any
// Retry-After the server stated. Collapsing every rejection into a bare
// fmt.Errorf is what left the watcher unable to tell "you are sending too many
// requests" (back off) from "this body will never be accepted" (stop sending it)
// from "Grafana is restarting" (retry unchanged) — so it answered all three the
// same way, forever (#519).
type httpError struct {
	StatusCode int
	// RetryAfter is the parsed Retry-After header: 0 when absent or unparseable,
	// and a nanosecond when the server said "retry immediately" (a zero, negative
	// or past value). The two must stay distinguishable — treating "retry now" as
	// "no header" would substitute a 30s exponential wait the server never asked
	// for.
	RetryAfter time.Duration
	Body       string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("grafana returned %d: %s", e.StatusCode, e.Body)
}

// permanent reports whether re-sending the identical body could ever succeed. A
// 4xx other than 429/408 is a verdict on the request, not on load: it will be
// rejected identically on every subsequent interval, so retrying it is a request
// storm no operator action short of a restart can stop. 401/403 are included
// deliberately — a token without annotation:write is a config error, and the
// events lost while it is wrong are re-detected after the restart that fixes it,
// because the dedupe set lives only in memory and is re-seeded from Grafana.
func (e *httpError) permanent() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500 &&
		e.StatusCode != http.StatusTooManyRequests &&
		e.StatusCode != http.StatusRequestTimeout
}

// parseRetryAfter reads RFC 9110's Retry-After in BOTH legal forms. Grafana Cloud
// sends delta-seconds; a proxy in front of a self-hosted Grafana may send an
// HTTP-date, and parsing only the integer form silently discards the server's
// instruction and falls back to a guess. Garbage returns 0 (no usable header)
// rather than an error: a malformed header must never be able to stall or
// short-circuit the writer.
func parseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	clamp := func(d time.Duration) time.Duration {
		if d <= 0 {
			// Legal and means "retry now". Returned as a nanosecond so it stays
			// distinct from the "absent" zero.
			return time.Nanosecond
		}
		// A proxy answering 429 with a ten-day Retry-After would otherwise park the
		// writer past any plausible operator attention span.
		if d > backoffCeiling {
			return backoffCeiling
		}
		return d
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return clamp(time.Duration(seconds) * time.Second)
	}
	if at, err := http.ParseTime(header); err == nil {
		return clamp(at.Sub(now))
	}
	return 0
}

type client struct {
	cfg  Config
	http *http.Client
	// now is injectable because an HTTP-date Retry-After is only meaningful
	// against a clock, and a test that had to sleep to observe backoff would be
	// both slow and flaky. The Watcher points this at its own now.
	now func() time.Time
}

// newClient deliberately offers no TLS-verification escape hatch. This is the
// exporter's only outbound WRITE, carrying a token that can create annotations in
// the org, so an operator behind a private CA should trust the CA
// (SSL_CERT_FILE/SSL_CERT_DIR) rather than turn verification off for it.
func newClient(cfg Config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}, now: time.Now}
}

func (c *client) endpoint(path string) string {
	return strings.TrimSuffix(c.cfg.URL, "/") + path
}

func (c *client) do(ctx context.Context, method, target string, body io.Reader) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Bounded read: a misconfigured URL pointing at something that is not Grafana
	// should not stream an unbounded body into the exporter.
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &httpError{
			StatusCode: response.StatusCode,
			RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), c.now()),
			Body:       strings.TrimSpace(string(payload)),
		}
	}
	return payload, nil
}

// payloadFor renders one event into Grafana's annotation body. Separate from post()
// so the body — including the dashboard link (#419/#421) — is testable without an
// HTTP round trip.
func (c *client) payloadFor(event Event) annotationPayload {
	return annotationPayload{
		Time: event.At.UnixMilli(),
		Tags: event.Tags,
		Text: withLink(event, c.cfg.URL),
	}
}

// post writes one annotation.
func (c *client) post(ctx context.Context, event Event) error {
	body, err := json.Marshal(c.payloadFor(event))
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, c.endpoint("/api/annotations"), bytes.NewReader(body))
	return err
}

// existing lists the annotations this exporter has already written inside the
// lookback window, so a restart does not re-post events that are still on the
// timeline. Without it the choice would be between duplicating every recent event
// on every restart and silently dropping a reboot annotation for the reboot that
// caused the restart.
func (c *client) existing(ctx context.Context, now time.Time) ([]existingAnnotation, error) {
	query := url.Values{}
	query.Set("tags", BaseTag)
	query.Set("from", fmt.Sprint(now.Add(-c.cfg.Lookback).UnixMilli()))
	query.Set("to", fmt.Sprint(now.UnixMilli()))
	// Generous but bounded: the cap exists so a very old, very busy org cannot
	// return an unbounded list into memory.
	query.Set("limit", "1000")

	payload, err := c.do(ctx, http.MethodGet,
		c.endpoint("/api/annotations")+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var found []existingAnnotation
	if err := json.Unmarshal(payload, &found); err != nil {
		return nil, fmt.Errorf("decode annotation list: %w", err)
	}
	return found, nil
}
