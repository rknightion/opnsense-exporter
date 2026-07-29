package annotations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// fakeGrafana records every annotation POSTed to it and serves a canned list on GET.
type fakeGrafana struct {
	mu       sync.Mutex
	server   *httptest.Server
	posted   []annotationPayload
	existing []existingAnnotation
	postCode int
	listCode int
	gets     int
	// postAttempts counts every POST that reached the server, including the ones
	// rejected by postCode. posted only records successes, so it cannot see the
	// request volume a failing cycle generates - which is the thing the per-cycle
	// cap is supposed to bound.
	postAttempts int
	// postRetryAfter, when non-empty, is sent as the Retry-After header on every
	// rejected POST. Grafana Cloud sends it on a 429; a self-hosted Grafana behind
	// a proxy may not, which is why the backoff cannot depend on it.
	postRetryAfter string
}

func newFakeGrafana(t *testing.T) *fakeGrafana {
	t.Helper()
	f := &fakeGrafana{postCode: http.StatusOK, listCode: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/annotations", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			f.gets++
			if f.listCode != http.StatusOK {
				w.WriteHeader(f.listCode)
				return
			}
			_ = json.NewEncoder(w).Encode(f.existing)
		case http.MethodPost:
			f.postAttempts++
			if f.postCode != http.StatusOK {
				if f.postRetryAfter != "" {
					w.Header().Set("Retry-After", f.postRetryAfter)
				}
				w.WriteHeader(f.postCode)
				_, _ = io.WriteString(w, `{"message":"nope"}`)
				return
			}
			var payload annotationPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.posted = append(f.posted, payload)
			_, _ = io.WriteString(w, `{"id":1,"message":"Annotation added"}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGrafana) writes() []annotationPayload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]annotationPayload(nil), f.posted...)
}

// gaugeFixture builds a registry holding the named gauges, each with the given
// labels and value, mirroring what the collector registry gathers.
type series struct {
	name   string
	labels map[string]string
	value  float64
}

func fixtureRegistry(t *testing.T, all ...series) *prometheus.Registry {
	t.Helper()
	registry := prometheus.NewRegistry()
	byName := map[string]*prometheus.GaugeVec{}
	for _, s := range all {
		keys := make([]string, 0, len(s.labels))
		for key := range s.labels {
			keys = append(keys, key)
		}
		gauge, ok := byName[s.name]
		if !ok {
			gauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: s.name, Help: s.name}, keys)
			registry.MustRegister(gauge)
			byName[s.name] = gauge
		}
		gauge.With(s.labels).Set(s.value)
	}
	return registry
}

func testConfig(f *fakeGrafana) Config {
	return Config{
		URL:         f.server.URL,
		Token:       "test-token",
		Interval:    time.Hour, // never fires inside a test; tick() is called directly
		Timeout:     2 * time.Second,
		Lookback:    24 * time.Hour,
		MaxPerCycle: 20,
	}
}

func newTestWatcher(t *testing.T, f *fakeGrafana, now time.Time, all ...series) *Watcher {
	t.Helper()
	w := New(testConfig(f), fixtureRegistry(t, all...), nil, promslog.NewNopLogger())
	w.now = func() time.Time { return now }
	return w
}

func TestWatcherWritesAnEventAtTheMetricsOwnInstant(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	changed := now.Add(-90 * time.Minute).Truncate(time.Second)

	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(changed.Unix()),
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	writes := f.writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(writes))
	}
	// The whole point: the marker is placed where the CHANGE happened, not at the
	// detection pass that noticed it. On the cold poll tier those can be 15
	// minutes apart, and on a restart, days.
	if writes[0].Time != changed.UnixMilli() {
		t.Errorf("annotation time = %d, want the event instant %d", writes[0].Time, changed.UnixMilli())
	}
	if !strings.Contains(writes[0].Text, "configuration changed") {
		t.Errorf("unexpected text %q", writes[0].Text)
	}
	assertTags(t, writes[0].Tags, BaseTag, "config-change", "instance:fw-a")
}

func TestWatcherDoesNotRewriteTheSameEvent(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(now.Add(-time.Hour).Unix()),
	})
	w.reconcile(context.Background())

	for range 4 {
		w.tick(context.Background())
	}

	if got := len(f.writes()); got != 1 {
		t.Fatalf("expected 1 annotation across 4 passes, got %d", got)
	}
}

func TestWatcherSkipsEventsOlderThanTheLookback(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	// A box up for 200 days: the boot instant is real, and annotating it now would
	// put a "rebooted" marker on a timeline nobody is looking at, on every fresh
	// deployment.
	w := newTestWatcher(t, f, now, series{
		name:   BootMetric,
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(now.Add(-200 * 24 * time.Hour).Unix()),
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no annotation for a 200-day-old boot, got %d", got)
	}
}

func TestWatcherSkipsEventsFurtherAheadThanTheClockTolerance(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(now.Add(48 * time.Hour).Unix()),
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no annotation for an instant two days in the future, got %d", got)
	}
}

func TestWatcherReconcilesAgainstAnnotationsGrafanaAlreadyHas(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	rebooted := now.Add(-30 * time.Minute).Truncate(time.Second)
	f.existing = []existingAnnotation{{
		Time: rebooted.UnixMilli(),
		Tags: []string{BaseTag, "reboot", "instance:fw-a"},
	}}

	w := newTestWatcher(t, f, now, series{
		name:   BootMetric,
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(rebooted.Unix()),
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	if f.gets != 1 {
		t.Errorf("expected exactly one reconciliation read, got %d", f.gets)
	}
	// Restarting the exporter must not duplicate a reboot annotation that is still
	// on the timeline — and must not lose one either, which is why the read-back
	// exists rather than a blanket "never post on the first pass".
	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no annotation for an event Grafana already has, got %d", got)
	}
}

func TestWatcherSeedsSilentlyWhenReconciliationFails(t *testing.T) {
	f := newFakeGrafana(t)
	f.listCode = http.StatusInternalServerError
	now := time.Now()

	w := newTestWatcher(t, f, now,
		series{name: BootMetric, labels: map[string]string{instanceLabel: "fw-a"},
			value: float64(now.Add(-time.Hour).Unix())},
		series{name: "opnsense_system_config_last_change", labels: map[string]string{instanceLabel: "fw-a"},
			value: float64(now.Add(-2 * time.Hour).Unix())},
	)
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 0 {
		t.Fatalf("a failed read-back must seed silently, not post %d annotations", got)
	}

	// The next real change still gets written: seeding suppresses the backlog, not
	// the feature.
	registry := fixtureRegistry(t, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(now.Add(-5 * time.Minute).Unix()),
	})
	w.gatherer = registry
	w.tick(context.Background())

	if got := len(f.writes()); got != 1 {
		t.Fatalf("expected the post-seed change to be written once, got %d", got)
	}
}

func TestWatcherRetriesAFailedWrite(t *testing.T) {
	f := newFakeGrafana(t)
	f.postCode = http.StatusInternalServerError
	now := time.Now()

	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(now.Add(-time.Hour).Unix()),
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no successful write, got %d", got)
	}

	f.mu.Lock()
	f.postCode = http.StatusOK
	f.mu.Unlock()
	w.tick(context.Background())

	// A transient Grafana error must not consume the event: it is only marked seen
	// once it has actually been written.
	if got := len(f.writes()); got != 1 {
		t.Fatalf("expected the event to be retried and written, got %d writes", got)
	}
}

func TestWatcherAnchorsTheInterfaceResetMarkerToTheBootInstant(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	boot := now.Add(-6 * time.Hour).Truncate(time.Second)
	// The kernel reports this marker as an uptime reading, so on its own it is a
	// small number of seconds, not an instant. 3600 = one hour after boot.
	w := newTestWatcher(t, f, now,
		series{name: BootMetric, labels: map[string]string{instanceLabel: "fw-a"},
			value: float64(boot.Unix())},
		series{name: "opnsense_interfaces_attach_or_statistics_reset_uptime_seconds",
			labels: map[string]string{instanceLabel: "fw-a", "interface": "LAN"},
			value:  3600},
	)
	w.reconcile(context.Background())
	w.tick(context.Background())

	writes := f.writes()
	// Two events: the boot itself and the interface reset an hour later.
	if len(writes) != 2 {
		t.Fatalf("expected 2 annotations (reboot + interface reset), got %d", len(writes))
	}
	var reset *annotationPayload
	for i := range writes {
		if hasTag(writes[i].Tags, "interface-reset") {
			reset = &writes[i]
		}
	}
	if reset == nil {
		t.Fatal("no interface-reset annotation written")
	}
	if want := boot.Add(time.Hour).UnixMilli(); reset.Time != want {
		t.Errorf("interface reset placed at %d, want boot+3600s = %d", reset.Time, want)
	}
	assertTags(t, reset.Tags, BaseTag, "interface-reset", "instance:fw-a", "interface:LAN")
	if !strings.Contains(reset.Text, "LAN") {
		t.Errorf("text should name the interface, got %q", reset.Text)
	}
}

func TestWatcherSkipsTheResetMarkerWithNoBootAnchor(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	// systemTime failed, so there is no boot epoch. The marker is a bare uptime
	// reading; dating an annotation from it would place it in 1970.
	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_interfaces_attach_or_statistics_reset_uptime_seconds",
		labels: map[string]string{instanceLabel: "fw-a", "interface": "LAN"},
		value:  3600,
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no annotation without a boot anchor, got %d", got)
	}
}

func TestWatcherKeepsAppliancesApart(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	at := now.Add(-time.Hour).Truncate(time.Second)
	// Two firewalls whose configs changed at the SAME instant. Both must be
	// annotated: keying without the instance would silently drop the second.
	w := newTestWatcher(t, f, now,
		series{name: "opnsense_system_config_last_change",
			labels: map[string]string{instanceLabel: "fw-a"}, value: float64(at.Unix())},
		series{name: "opnsense_system_config_last_change",
			labels: map[string]string{instanceLabel: "fw-b"}, value: float64(at.Unix())},
	)
	w.reconcile(context.Background())
	w.tick(context.Background())

	writes := f.writes()
	if len(writes) != 2 {
		t.Fatalf("expected one annotation per appliance, got %d", len(writes))
	}
	seen := map[string]bool{}
	for _, write := range writes {
		for _, tag := range write.Tags {
			if strings.HasPrefix(tag, "instance:") {
				seen[tag] = true
			}
		}
	}
	if !seen["instance:fw-a"] || !seen["instance:fw-b"] {
		t.Errorf("both appliances must be tagged, got %v", seen)
	}
}

func TestWatcherCapsWritesPerCycle(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	var all []series
	for i := range 10 {
		all = append(all, series{
			name:   "opnsense_ids_ruleset_last_updated_timestamp_seconds",
			labels: map[string]string{instanceLabel: "fw-a", "ruleset": string(rune('a' + i))},
			value:  float64(now.Add(-time.Duration(i+1) * time.Minute).Unix()),
		})
	}
	w := newTestWatcher(t, f, now, all...)
	w.cfg.MaxPerCycle = 3
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 3 {
		t.Fatalf("expected the per-cycle cap to hold at 3, got %d", got)
	}
}

// A cycle whose posts all fail must still stop at the cap. Counting successes
// instead of attempts means the cap never trips while Grafana is rejecting, so
// the exporter answers a 429 by sending the whole backlog again every interval -
// sustaining the exact condition that produced the 429 (#519).
func TestWatcherCapsAttemptsWhenEveryPostFails(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	var all []series
	for i := range 10 {
		all = append(all, series{
			name:   "opnsense_ids_ruleset_last_updated_timestamp_seconds",
			labels: map[string]string{instanceLabel: "fw-a", "ruleset": string(rune('a' + i))},
			value:  float64(now.Add(-time.Duration(i+1) * time.Minute).Unix()),
		})
	}
	w := newTestWatcher(t, f, now, all...)
	w.cfg.MaxPerCycle = 3
	w.reconcile(context.Background())

	f.mu.Lock()
	f.postCode = http.StatusTooManyRequests
	f.mu.Unlock()

	w.tick(context.Background())

	f.mu.Lock()
	attempts := f.postAttempts
	f.mu.Unlock()

	if attempts != 3 {
		t.Fatalf("a fully failing cycle attempted %d posts against a cap of 3; the cap must "+
			"bound attempts, not successes, or a rate-limited exporter retries the whole "+
			"backlog every interval", attempts)
	}
	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no successful writes while the server rejects, got %d", got)
	}
}

// rulesetBacklog builds n distinct events, one per ruleset, all inside the
// lookback. This is the shape that produced #519 live: a fresh deployment with a
// 24h lookback found dozens of ids-ruleset-update events at once.
func rulesetBacklog(now time.Time, n int) []series {
	all := make([]series, 0, n)
	for i := range n {
		all = append(all, series{
			name:   "opnsense_ids_ruleset_last_updated_timestamp_seconds",
			labels: map[string]string{instanceLabel: "fw-a", "ruleset": string(rune('a' + i))},
			value:  float64(now.Add(-time.Duration(i+1) * time.Minute).Unix()),
		})
	}
	return all
}

func postAttempts(f *fakeGrafana) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.postAttempts
}

func setPostResponse(f *fakeGrafana, code int, retryAfter string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.postCode = code
	f.postRetryAfter = retryAfter
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var d dto.Metric
	if err := c.Write(&d); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return d.GetCounter().GetValue()
}

// A 429 says "you are sending too many requests". Answering it by sending the same
// cap-full of requests on the very next interval is what made #519 self-sustaining:
// bounding attempts alone turns an unbounded storm into a permanent 20-per-minute
// one. The cycle after a rate limit must post NOTHING, and must not consume the
// backlog while it waits.
func TestWatcherBacksOffAfterARateLimit(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 10)...)
	w.cfg.MaxPerCycle = 3
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusTooManyRequests, "")

	w.tick(context.Background())
	if got := postAttempts(f); got != 3 {
		t.Fatalf("first tick made %d attempts, want the cap of 3", got)
	}
	if got := counterValue(t, w.metrics.rateLimited); got != 3 {
		t.Errorf("rate_limited_total = %v, want 3", got)
	}
	if !w.backoffUntil.After(now) {
		t.Fatalf("a 429 did not arm the backoff (backoffUntil=%s, now=%s)", w.backoffUntil, now)
	}

	w.tick(context.Background())
	if got := postAttempts(f); got != 3 {
		t.Fatalf("a backed-off tick made %d further attempts; it must post nothing", got-3)
	}
	// The backlog is still owed: backing off delays the writes, it does not drop
	// them, so nothing may be marked seen while waiting.
	if len(w.seen) != 0 {
		t.Errorf("a backed-off tick consumed %d events from the backlog", len(w.seen))
	}
}

// Grafana Cloud answers a 429 with Retry-After. Guessing an exponential delay when
// the server has stated one either hammers it early or idles far longer than asked.
func TestWatcherHonoursRetryAfterInDeltaSeconds(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 2)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusTooManyRequests, "120")

	w.tick(context.Background())

	if want := now.Add(120 * time.Second); !w.backoffUntil.Equal(want) {
		t.Fatalf("backoffUntil = %s, want the server's Retry-After of %s", w.backoffUntil, want)
	}
}

// RFC 9110 allows Retry-After as an HTTP-date as well as delta-seconds, and both
// forms are seen in the wild behind proxies. Parsing only the integer form silently
// discards the header and falls back to a guess.
func TestWatcherHonoursRetryAfterAsAnHTTPDate(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 2)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusTooManyRequests,
		now.Add(90*time.Second).UTC().Format(http.TimeFormat))

	w.tick(context.Background())

	// HTTP-date has one-second granularity, so the parsed instant can sit up to a
	// second below the target.
	delay := w.backoffUntil.Sub(now)
	if delay < 89*time.Second || delay > 90*time.Second {
		t.Fatalf("backoff delay = %s, want ~90s from the HTTP-date Retry-After", delay)
	}
}

// A garbage Retry-After must not poison the backoff into 0 (an immediate retry) or
// into a bogus instant. It falls through to the exponential path.
func TestWatcherFallsBackToExponentialOnAnUnparseableRetryAfter(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 2)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusTooManyRequests, "in a bit")

	w.tick(context.Background())

	delay := w.backoffUntil.Sub(now)
	low := time.Duration(float64(backoffBase) * (1 - backoffJitter))
	high := time.Duration(float64(backoffBase) * (1 + backoffJitter))
	if delay < low || delay > high {
		t.Fatalf("backoff delay = %s, want the jittered base in [%s, %s]", delay, low, high)
	}
}

// Consecutive rate limits must widen the gap, or a persistently rate-limited org
// keeps a fixed 30s drumbeat against a limit it is already over.
func TestWatcherBackoffGrowsWithConsecutiveRateLimits(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 2)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusTooManyRequests, "")

	var previous time.Duration
	for cycle := range 4 {
		w.now = func() time.Time { return now }
		w.tick(context.Background())
		delay := w.backoffUntil.Sub(now)
		if cycle > 0 && delay <= previous {
			t.Fatalf("cycle %d backoff %s did not grow past %s", cycle, delay, previous)
		}
		previous = delay
		// Step past the wait so the next tick is allowed to attempt again.
		now = w.backoffUntil.Add(time.Second)
	}
	if previous > backoffCeiling {
		t.Fatalf("backoff %s exceeded the ceiling %s", previous, backoffCeiling)
	}
}

// A success means the limit has cleared. Leaving the streak wound up would make the
// next isolated 429 wait minutes for no reason.
func TestWatcherResetsBackoffAfterASuccess(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 2)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusTooManyRequests, "")

	w.tick(context.Background())
	if w.backoffStreak == 0 {
		t.Fatal("a 429 must record a backoff streak")
	}

	setPostResponse(f, http.StatusOK, "")
	w.now = func() time.Time { return w.backoffUntil.Add(time.Second) }
	w.tick(context.Background())

	if got := len(f.writes()); got != 2 {
		t.Fatalf("expected the backlog to drain once the limit cleared, got %d writes", got)
	}
	if w.backoffStreak != 0 || !w.backoffUntil.IsZero() {
		t.Fatalf("backoff not reset after a success: streak=%d until=%s", w.backoffStreak, w.backoffUntil)
	}
}

// A 400 is a statement about the request, not about load: the identical body will be
// rejected identically forever. Retrying it every --annotations.interval is a
// permanent request storm that no operator action short of a restart can stop, so
// the event is marked seen and counted as undeliverable instead.
func TestWatcherDoesNotRetryANonRetryable4xx(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 1)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusBadRequest, "")

	w.tick(context.Background())
	if got := postAttempts(f); got != 1 {
		t.Fatalf("first tick made %d attempts, want 1", got)
	}
	if got := counterValue(t, w.metrics.undeliverable); got != 1 {
		t.Errorf("undeliverable_total = %v, want 1", got)
	}
	if w.backoffUntil.After(now) {
		t.Error("a non-retryable 4xx must not arm the rate-limit backoff")
	}

	setPostResponse(f, http.StatusOK, "")
	w.tick(context.Background())

	if got := postAttempts(f); got != 1 {
		t.Fatalf("a permanently rejected event was retried: %d attempts", got)
	}
	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no writes, got %d", got)
	}
}

// A 5xx or a 408 is transient by definition, so the existing retry contract still
// holds for them — dropping those would lose events on a Grafana restart.
func TestWatcherStillRetriesATransientRejection(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, rulesetBacklog(now, 1)...)
	w.reconcile(context.Background())
	setPostResponse(f, http.StatusRequestTimeout, "")

	w.tick(context.Background())
	if got := counterValue(t, w.metrics.undeliverable); got != 0 {
		t.Fatalf("a 408 was treated as permanent: undeliverable_total = %v", got)
	}

	setPostResponse(f, http.StatusOK, "")
	w.tick(context.Background())
	if got := len(f.writes()); got != 1 {
		t.Fatalf("expected the 408'd event to be retried and written, got %d writes", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	base := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"absent", "", 0},
		{"delta seconds", "120", 120 * time.Second},
		{"delta seconds with padding", "  30  ", 30 * time.Second},
		// A zero or negative delta is legal and means "retry now"; it must not be
		// mistaken for "header absent", which would substitute an exponential wait.
		{"zero delta", "0", time.Nanosecond},
		{"http date", base.Add(45 * time.Second).Format(http.TimeFormat), 45 * time.Second},
		// A date already in the past means the wait is over.
		{"past http date", base.Add(-time.Hour).Format(http.TimeFormat), time.Nanosecond},
		{"garbage", "soon", 0},
		{"negative delta", "-5", time.Nanosecond},
		// Clamped: a proxy answering with a day would park the writer for a day.
		{"absurd delta", "864000", backoffCeiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.header, base); got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %s, want %s", tc.header, got, tc.want)
			}
		})
	}
}

func TestWatcherIgnoresZeroValuedTimestamps(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	// "0 = never" is an explicit convention on several of these metrics; an
	// annotation at epoch 0 would land in 1970.
	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_acme_certificate_last_update_timestamp_seconds",
		labels: map[string]string{instanceLabel: "fw-a", "name": "wildcard"},
		value:  0,
	})
	w.reconcile(context.Background())
	w.tick(context.Background())

	if got := len(f.writes()); got != 0 {
		t.Fatalf("expected no annotation for a never-updated certificate, got %d", got)
	}
}

func TestWatcherAddsConfiguredExtraTags(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(now.Add(-time.Hour).Unix()),
	})
	w.cfg.ExtraTags = []string{"env:prod"}
	w.reconcile(context.Background())
	w.tick(context.Background())

	writes := f.writes()
	if len(writes) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(writes))
	}
	if !hasTag(writes[0].Tags, "env:prod") {
		t.Errorf("configured extra tag missing from %v", writes[0].Tags)
	}
}

// TestCatalogueTagsAreClosedVocabularies guards the privacy rule from the source
// side: a label key added to the catalogue becomes an indexed, org-wide queryable
// tag, so it must name a thing, never a person or an address.
func TestCatalogueTagsAreClosedVocabularies(t *testing.T) {
	forbidden := map[string]bool{
		"host": true, "hostname": true, "user": true, "username": true,
		"real_address": true, "virtual_address": true, "peer": true,
		"address": true, "description": true, "config_user": true,
	}
	for _, watch := range Watches {
		for _, key := range watch.LabelKeys {
			if forbidden[key] {
				t.Errorf("%s tags %q, which carries an address, identity or free text",
					watch.Metric, key)
			}
		}
	}
}

// TestCatalogueTextPlaceholdersMatchLabelKeys catches the mismatch that would ship
// a literal "%!s(MISSING)" into an operator-visible annotation.
func TestCatalogueTextPlaceholdersMatchLabelKeys(t *testing.T) {
	for _, watch := range Watches {
		if got := strings.Count(watch.Text, "%s"); got != len(watch.LabelKeys) {
			t.Errorf("%s: text has %d placeholders but %d label keys",
				watch.Metric, got, len(watch.LabelKeys))
		}
	}
}

func TestCatalogueKindsAreUniqueAndTagSafe(t *testing.T) {
	seen := map[string]bool{}
	for _, watch := range Watches {
		if seen[watch.Kind] {
			t.Errorf("duplicate event kind %q: annotations would be indistinguishable by tag", watch.Kind)
		}
		seen[watch.Kind] = true
		// A kind must not contain ':' — decodeTags reads a colon-bearing tag as a
		// key:value detail, so a colon in the kind would break restart dedupe.
		if strings.Contains(watch.Kind, ":") {
			t.Errorf("event kind %q contains ':', which decodeTags reads as a key:value tag", watch.Kind)
		}
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func assertTags(t *testing.T, tags []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !hasTag(tags, w) {
			t.Errorf("tag %q missing from %v", w, tags)
		}
	}
}

// TestWatcherPrunesTheDedupeSet guards against the dedupe map growing for the life
// of the process. Pruning is safe only because detect() refuses an instant older
// than the lookback, so a pruned entry can never be proposed a second time — and
// this test asserts both halves of that: the entry goes, and no annotation follows.
func TestWatcherPrunesTheDedupeSet(t *testing.T) {
	f := newFakeGrafana(t)
	now := time.Now()
	at := now.Add(-2 * time.Hour).Truncate(time.Second)

	w := newTestWatcher(t, f, now, series{
		name:   "opnsense_system_config_last_change",
		labels: map[string]string{instanceLabel: "fw-a"},
		value:  float64(at.Unix()),
	})
	w.cfg.Lookback = 3 * time.Hour
	w.reconcile(context.Background())
	w.tick(context.Background())

	if len(w.seen) != 1 {
		t.Fatalf("expected 1 dedupe entry, got %d", len(w.seen))
	}

	// Four hours later the event is outside the lookback: the entry is dropped and
	// the event stays unwritten, because detect() no longer proposes it.
	w.now = func() time.Time { return now.Add(4 * time.Hour) }
	w.tick(context.Background())

	if len(w.seen) != 0 {
		t.Errorf("aged-out dedupe entries not pruned: %d remain", len(w.seen))
	}
	if got := len(f.writes()); got != 1 {
		t.Errorf("pruning must not let the event be rewritten: %d writes", got)
	}
}
