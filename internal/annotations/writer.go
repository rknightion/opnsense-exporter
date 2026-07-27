package annotations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

type client struct {
	cfg  Config
	http *http.Client
}

// newClient deliberately offers no TLS-verification escape hatch. This is the
// exporter's only outbound WRITE, carrying a token that can create annotations in
// the org, so an operator behind a private CA should trust the CA
// (SSL_CERT_FILE/SSL_CERT_DIR) rather than turn verification off for it.
func newClient(cfg Config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}}
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
		return nil, fmt.Errorf("grafana returned %d: %s",
			response.StatusCode, strings.TrimSpace(string(payload)))
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
