package collector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// intervalFake is a fakeCollectorInstance that also declares a poll tier.
type intervalFake struct {
	fakeCollectorInstance
	d time.Duration
}

func (f *intervalFake) PollInterval() time.Duration { return f.d }

// wedgedSchedulerCollector signals once it has entered Update, then holds its
// poll slot until the test cancels its context. It models a slow/cold endpoint
// whose request is still within the configured poll timeout.
type wedgedSchedulerCollector struct {
	fakeCollectorInstance
	started chan<- struct{}
}

func (f *wedgedSchedulerCollector) Update(ctx context.Context, _ *opnsense.Client, _ chan<- prometheus.Metric) *opnsense.APICallError {
	select {
	case f.started <- struct{}{}:
	case <-ctx.Done():
		return nil
	}
	<-ctx.Done()
	return nil
}

func TestPollOnceCapturesRecordsAndPropagatesCtx(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	tracker := NewStatusTracker()
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 7)}}
	c := newScrapeTestCollector(t, client, fake)
	c.statusTracker = tracker

	ctx := context.WithValue(context.Background(), scrapeCtxKey{}, "marker")
	c.pollOnce(ctx, fake)

	e := c.store.entry("fake")
	if len(e.metrics) != 1 || !e.lastOK || !e.polled {
		t.Fatalf("poll should capture 1 metric, lastOK, polled; got metrics=%d ok=%v polled=%v", len(e.metrics), e.lastOK, e.polled)
	}
	stats := tracker.Snapshot()
	if len(stats) != 1 || stats[0].Runs != 1 || !stats[0].LastOK {
		t.Fatalf("poll should record one successful run, got %+v", stats)
	}
	if got := fake.contextValue(scrapeCtxKey{}); got != "marker" {
		t.Errorf("request context must reach Update, got %v", got)
	}
}

func TestPollOnceErrorRetainsAndRecordsFailure(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 1)}}
	c := newScrapeTestCollector(t, client, fake)

	c.pollOnce(context.Background(), fake) // seed last-good
	fake.emit = nil
	fake.err = &opnsense.APICallError{Endpoint: "ep", Message: "boom"}
	c.pollOnce(context.Background(), fake)

	e := c.store.entry("fake")
	if len(e.metrics) != 1 {
		t.Errorf("error poll must retain last-good metrics, got %d", len(e.metrics))
	}
	if e.lastOK {
		t.Error("error poll must set lastOK=false")
	}
	if got := counterValue(t, c.endpointErrors.WithLabelValues("ep", "test")); got != 1 {
		t.Errorf("endpoint error should be counted, got %v", got)
	}
}

func TestPollOncePanicRecordsSentinel(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", panics: true}
	c := newScrapeTestCollector(t, client, fake)

	c.pollOnce(context.Background(), fake) // must recover, not crash the test
	if got := counterValue(t, c.endpointErrors.WithLabelValues("panic:fake", "test")); got != 1 {
		t.Errorf("panic must increment the panic:-sentinel endpoint, got %v", got)
	}
	if c.store.entry("fake").lastOK {
		t.Error("panic poll must set lastOK=false")
	}
}

func TestPollCollectorSkipsWhenUnreachable(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake"}
	c := newScrapeTestCollector(t, client, fake)
	c.pollSem = make(chan struct{}, 1)
	c.unreachable.Store(true)

	c.pollCollector(context.Background(), fake)
	if fake.callCount() != 0 {
		t.Errorf("poll must skip Update while the box is unreachable, got %d calls", fake.callCount())
	}
}

// TestFastPollKeepsReservedCapacityFromWedgedGeneralPolls pins OPN-0032. Slow
// and cold polls must be unable to occupy every global slot: otherwise the fast
// gateway poll queues behind wedged API calls exactly when failover detection is
// most important. The same eight-wedge harness proves the before/after boundary:
// the old scheduler reaches eight general polls and leaves the fast poll blocked;
// the reservation admits only seven general polls, then lets the fast poll run.
func TestFastPollKeepsReservedCapacityFromWedgedGeneralPolls(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	c := newScrapeTestCollector(t, client)
	c.pollSem = make(chan struct{}, maxPollConcurrency)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, maxPollConcurrency)
	for i := 0; i < maxPollConcurrency; i++ {
		slow := &wedgedSchedulerCollector{
			fakeCollectorInstance: fakeCollectorInstance{name: fmt.Sprintf("wedged-general-%d", i)},
			started:               started,
		}
		go c.pollCollector(ctx, slow)
	}

	// First establish the common precondition: enough slow polls have entered to
	// fill every non-reserved slot. This is channel-synchronised rather than a
	// scheduling delay, so a loaded race run cannot mistake an unstarted poll for
	// a reserved slot.
	generalStarted := 0
	for generalStarted < maxPollConcurrency-1 {
		select {
		case <-started:
			generalStarted++
		case <-time.After(time.Second):
			t.Fatalf("only %d wedged general polls entered; want at least %d", generalStarted, maxPollConcurrency-1)
		}
	}

	// On the unfixed scheduler the eighth general poll enters too. With one
	// reserved fast slot it remains queued indefinitely (until ctx is cancelled).
	select {
	case <-started:
		generalStarted++
	case <-time.After(150 * time.Millisecond):
	}

	fast := &fakeCollectorInstance{name: GatewaysSubsystem}
	fastDone := make(chan struct{})
	go func() {
		defer close(fastDone)
		c.pollCollector(ctx, fast)
	}()

	if generalStarted == maxPollConcurrency {
		select {
		case <-fastDone:
			t.Fatal("fast poll ran after slow polls occupied every slot")
		case <-time.After(150 * time.Millisecond):
			t.Fatalf("fast poll was blocked behind %d wedged general polls; reserve one fast-tier slot", generalStarted)
		}
	}
	if want := maxPollConcurrency - 1; generalStarted != want {
		t.Fatalf("wedged general polls admitted = %d, want %d with one slot reserved for fast polls", generalStarted, want)
	}

	select {
	case <-fastDone:
	case <-time.After(time.Second):
		t.Fatal("fast poll did not use its reserved slot")
	}
	if got := fast.callCount(); got != 1 {
		t.Fatalf("fast poll Update calls = %d, want 1", got)
	}
}

func TestStartPollingColdStartPolls(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", emit: []prometheus.Metric{testMetric("opnsense_x", 1)}}
	c := newScrapeTestCollector(t, client, fake)

	c.StartPolling(context.Background())
	defer c.StopPolling()

	deadline := time.Now().Add(3 * time.Second) // cold-start jitter is capped at 5s but usually far less
	for time.Now().Before(deadline) {
		if c.store.entry("fake").polled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !c.store.entry("fake").polled {
		t.Fatal("cold start should poll the collector shortly after StartPolling")
	}
}

func TestResolvePollIntervalClamp(t *testing.T) {
	fast := &intervalFake{fakeCollectorInstance: fakeCollectorInstance{name: "f"}, d: IntervalFast}
	if got := resolvePollInterval(fast, IntervalMedium); got != IntervalFast {
		t.Errorf("declared interval should win, got %v", got)
	}
	tooLow := &intervalFake{fakeCollectorInstance: fakeCollectorInstance{name: "l"}, d: time.Second}
	if got := resolvePollInterval(tooLow, IntervalMedium); got != IntervalFloor {
		t.Errorf("interval below floor should clamp to floor, got %v", got)
	}
	tooHigh := &intervalFake{fakeCollectorInstance: fakeCollectorInstance{name: "h"}, d: time.Hour}
	if got := resolvePollInterval(tooHigh, IntervalMedium); got != IntervalCeil {
		t.Errorf("interval above ceil should clamp to ceil, got %v", got)
	}
	plain := &fakeCollectorInstance{name: "p"}
	if got := resolvePollInterval(plain, IntervalSlow); got != IntervalSlow {
		t.Errorf("no declaration should use the clamped global default, got %v", got)
	}
}

func TestResolveIntervalTierTableAndOverrides(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	gw := &fakeCollectorInstance{name: GatewaysSubsystem}  // fast in the tier table
	fw := &fakeCollectorInstance{name: FirmwareSubsystem}  // cold in the tier table
	plain := &fakeCollectorInstance{name: "no_tier_plain"} // falls through to global
	c := newScrapeTestCollector(t, client, gw, fw, plain)

	if got := c.resolveInterval(gw); got != IntervalFast {
		t.Errorf("gateways should resolve to the fast tier, got %v", got)
	}
	if got := c.resolveInterval(fw); got != IntervalCold {
		t.Errorf("firmware should resolve to the cold tier, got %v", got)
	}
	if got := c.resolveInterval(plain); got != IntervalMedium {
		t.Errorf("an untiered collector should resolve to the global default, got %v", got)
	}

	// An operator override wins over the code tier, clamped.
	c.pollOverrides = map[string]time.Duration{
		GatewaysSubsystem: 10 * time.Second,
		FirmwareSubsystem: time.Hour, // above ceil -> clamp to 15m
	}
	if got := c.resolveInterval(gw); got != 10*time.Second {
		t.Errorf("override should win over the fast tier, got %v", got)
	}
	if got := c.resolveInterval(fw); got != IntervalCeil {
		t.Errorf("override above ceil should clamp to ceil, got %v", got)
	}
}

// TestSnapshotWarmNeedsHealthAndEveryCollector pins the readiness contract (#341):
// warm means the snapshot a scrape would replay is COMPLETE — the health poll plus
// every enabled collector has finished a first poll. A partially warm snapshot is
// exactly what made the live-box canary see 24 of 47 collectors and 170 of ~495
// metric names when it scraped 3s after start.
func TestSnapshotWarmNeedsHealthAndEveryCollector(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	a := &fakeCollectorInstance{name: "a"}
	b := &fakeCollectorInstance{name: "b"}
	c := newScrapeTestCollector(t, client, a, b)

	if c.SnapshotWarm() {
		t.Fatal("a never-polled exporter must not report warm")
	}
	c.pollHealth(context.Background())
	if c.SnapshotWarm() {
		t.Fatal("health alone must not report warm while collectors are unpolled")
	}
	c.pollOnce(context.Background(), a)
	if c.SnapshotWarm() {
		t.Fatal("a partially polled snapshot must not report warm")
	}
	c.pollOnce(context.Background(), b)
	if !c.SnapshotWarm() {
		t.Fatal("health + every collector polled must report warm")
	}
}

// TestSnapshotWarmCountsFailedPolls: warm is about completeness, not success. A
// collector whose first poll errored has still had its turn, so it must not hold
// readiness open forever — the failure surfaces as scrape_collector_success=0.
func TestSnapshotWarmCountsFailedPolls(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", err: &opnsense.APICallError{Endpoint: "ep", Message: "boom"}}
	c := newScrapeTestCollector(t, client, fake)

	c.pollHealth(context.Background())
	c.pollOnce(context.Background(), fake)
	if !c.SnapshotWarm() {
		t.Error("a failed first poll must still count towards warm-up")
	}
}

// TestSnapshotWarmWithNoCollectorsNeedsHealth guards the degenerate case: an
// exporter with every collector disabled is warm as soon as health has polled.
func TestSnapshotWarmWithNoCollectorsNeedsHealth(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	c := newScrapeTestCollector(t, client)

	if c.SnapshotWarm() {
		t.Error("no collectors but no health poll yet must not report warm")
	}
	c.pollHealth(context.Background())
	if !c.SnapshotWarm() {
		t.Error("no collectors + health polled must report warm")
	}
}

// TestPollCollectorRechecksUnreachableAfterAdmission pins #383: the unreachable
// check must run AGAIN after the poll-concurrency semaphore is acquired. A
// collector can pass the pre-admission check, queue behind the slot cap, and be
// admitted only after the health poller has already tripped the circuit — every
// queued caller then drains as a doomed API poll, which is exactly the dial storm
// #127 exists to prevent.
//
// The test is deterministic rather than timing-hopeful: it asserts the poll is
// still blocked BEFORE flipping the flag. A poll that had already returned (i.e.
// one whose pre-check saw unreachable=true) would have closed done by then, so
// reaching the flip proves the pre-check observed a reachable box and the
// goroutine is parked on the semaphore with nowhere else to be.
func TestPollCollectorRechecksUnreachableAfterAdmission(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake"}
	c := newScrapeTestCollector(t, client, fake)
	c.pollSem = make(chan struct{}, 1)
	c.pollSem <- struct{}{} // occupy the only slot

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.pollCollector(context.Background(), fake)
	}()

	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("poll returned while the semaphore was full; it must block on admission")
	default:
	}

	c.unreachable.Store(true) // the health poller trips the circuit mid-queue
	<-c.pollSem               // release the slot: the queued poll is admitted

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("admitted poll did not return")
	}
	if got := fake.callCount(); got != 0 {
		t.Errorf("a poll admitted after the circuit tripped must not call Update, got %d calls", got)
	}
}

// TestPollCollectorCancelledWhileQueuedLeaksNoToken pins that a poll cancelled
// while waiting for admission exits promptly and does not consume or leak a
// semaphore token (#383).
func TestPollCollectorCancelledWhileQueuedLeaksNoToken(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake"}
	c := newScrapeTestCollector(t, client, fake)
	c.pollSem = make(chan struct{}, 1)
	c.pollSem <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.pollCollector(ctx, fake)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled poll did not exit promptly while queued")
	}
	if fake.callCount() != 0 {
		t.Error("cancelled poll must not call Update")
	}
	// The occupying token is still ours to drain; a leaked/duplicated token would
	// make this second receive succeed too.
	<-c.pollSem
	select {
	case <-c.pollSem:
		t.Error("cancelled poll leaked a semaphore token")
	default:
	}
}

// TestAdvanceDeadlineFixedCadence pins the #385 schedule contract: the published
// next-poll deadline follows the FIXED ticker cadence, not poll completion time.
func TestAdvanceDeadlineFixedCadence(t *testing.T) {
	base := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	const interval = time.Minute

	// A poll shorter than one interval: the next deadline is the next tick, NOT
	// completion + interval (which would be 20s late).
	next := advanceDeadline(base.Add(interval), interval, base.Add(interval+20*time.Second))
	if want := base.Add(2 * interval); !next.Equal(want) {
		t.Errorf("slow-but-sub-interval poll: next deadline = %v, want %v", next, want)
	}

	// A poll exceeding one interval: the ticker drops the missed fires, so the
	// deadline must skip forward to the first fire that is still in the future
	// rather than landing in the past.
	// The poll started at the 12:01 tick and ran until 12:03:30 — 2.5 intervals —
	// so the 12:02 and 12:03 fires were dropped and the next real one is 12:04.
	now := base.Add(interval + 150*time.Second)
	next = advanceDeadline(base.Add(interval), interval, now)
	if want := base.Add(4 * interval); !next.Equal(want) {
		t.Errorf("overrunning poll: next deadline = %v, want %v", next, want)
	}
	if !next.After(now) {
		t.Errorf("next deadline %v must be strictly after now %v", next, now)
	}
}

// TestSchedulerPublishesRealDeadlineNotCompletionPlusInterval pins #385 end to end:
// with a poll that takes real time, the deadline the scheduler publishes must track
// the fixed ticker, so it lands EARLIER than the lastPoll+interval value the metric
// and console used to compute. Uses the 5s interval floor with a 400ms poll, so the
// two answers differ by the poll duration.
func TestSchedulerPublishesRealDeadlineNotCompletionPlusInterval(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	fake := &fakeCollectorInstance{name: "fake", delay: 400 * time.Millisecond}
	c := newScrapeTestCollector(t, client, fake)
	c.pollOverrides = map[string]time.Duration{"fake": IntervalFloor}

	c.StartPolling(context.Background())
	defer c.StopPolling()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if c.store.entry("fake").polled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	e := c.store.entry("fake")
	if !e.polled {
		t.Fatal("collector never polled")
	}
	if e.nextDeadline.IsZero() {
		t.Fatal("scheduler must publish a real next-poll deadline")
	}
	derived := e.lastPoll.Add(IntervalFloor)
	if !e.nextDeadline.Before(derived) {
		t.Errorf("published deadline %v must precede the old lastPoll+interval estimate %v (a %v poll makes them differ)",
			e.nextDeadline, derived, fake.delay)
	}
	// And it must still be a sane point in the future, close to one interval out.
	if d := time.Until(e.nextDeadline); d <= 0 || d > IntervalFloor {
		t.Errorf("published deadline is %v away, want within (0, %v]", d, IntervalFloor)
	}
}

// TestHealthPollIntervalIsIndependentOfCollectorDefault pins #386. Before it, the
// health poller — which owns the process-wide unreachable circuit — silently ran on
// --collector.poll-interval. An operator raising that to 15m for firewall load was
// also buying up to 15m of recovery latency after the box came back, and lowering it
// to 5s was quietly hammering the health endpoint. Neither is what the flag says.
func TestHealthPollIntervalIsIndependentOfCollectorDefault(t *testing.T) {
	c := &Collector{}
	if got := c.healthPollInterval(); got != IntervalMedium {
		t.Errorf("unset health interval must default to %v, got %v", IntervalMedium, got)
	}

	// The collector default must no longer move health cadence at all.
	c.pollGlobal = IntervalCold
	if got := c.healthPollInterval(); got != IntervalMedium {
		t.Errorf("--collector.poll-interval must not change health cadence, got %v", got)
	}
	if got := c.pollGlobalInterval(); got != IntervalCold {
		t.Errorf("the collector default itself must still apply, got %v", got)
	}

	// An explicit health interval is honoured and clamped like any other.
	c.healthPollGlobal = 30 * time.Second
	if got := c.healthPollInterval(); got != 30*time.Second {
		t.Errorf("explicit health interval = %v, want 30s", got)
	}
	c.healthPollGlobal = time.Millisecond
	if got := c.healthPollInterval(); got != IntervalFloor {
		t.Errorf("health interval below the floor must clamp to %v, got %v", IntervalFloor, got)
	}
	c.healthPollGlobal = 24 * time.Hour
	if got := c.healthPollInterval(); got != IntervalCeil {
		t.Errorf("health interval above the ceiling must clamp to %v, got %v", IntervalCeil, got)
	}
}

// TestHealthPollerRecoveryLatencyIgnoresCollectorDefault is the behavioural half of
// #386: with the collector default at the 15m ceiling, the health endpoint must still
// be re-polled on its own cadence, because that poll is the only thing that clears
// the unreachable circuit and lets every collector resume.
func TestHealthPollerRecoveryLatencyIgnoresCollectorDefault(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"system":{"status":"OK"}}`)
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := newScrapeTestCollector(t, client) // no collectors: only the health poller runs
	c.pollGlobal = IntervalCold            // 15m — the pathological operator setting
	c.healthPollGlobal = IntervalFloor     // 5s

	c.StartPolling(context.Background())
	defer c.StopPolling()

	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := hits.Load(); got < 2 {
		t.Errorf("health must re-poll on its own %v cadence even with a %v collector default; got %d polls",
			IntervalFloor, IntervalCold, got)
	}
}

// TestHealthSnapshotReportsUpstreamState pins the passive seam the operator console
// consumes for #384: reachability must be readable without an API call or a registry
// gather, and must distinguish "not polled yet" from "transport-unreachable" from
// "reachable but the health endpoint errored".
func TestHealthSnapshotReportsUpstreamState(t *testing.T) {
	client := newCollectorTestClient(t, healthOKServer(t))
	c := newScrapeTestCollector(t, client)

	if h := c.HealthSnapshot(); h.Polled || h.CheckOK || h.Unreachable || !h.CheckedAt.IsZero() {
		t.Errorf("before the first health poll everything must be zero, got %+v", h)
	}

	c.pollHealth(context.Background())
	h := c.HealthSnapshot()
	if !h.Polled || !h.CheckOK || h.Unreachable {
		t.Errorf("after a good health poll want polled+ok+reachable, got %+v", h)
	}
	if h.CheckedAt.IsZero() {
		t.Error("a completed health poll must stamp CheckedAt")
	}
	if h.LastError != "" {
		t.Errorf("a good health poll must clear LastError, got %q", h.LastError)
	}

	// Transport-level failure (nothing listening) => unreachable.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	c.Client = newCollectorTestClientForURL(t, deadURL)
	c.pollHealth(context.Background())
	h = c.HealthSnapshot()
	if !h.Polled || h.CheckOK || !h.Unreachable {
		t.Errorf("a transport failure must report polled+not-ok+unreachable, got %+v", h)
	}
	if h.LastError == "" {
		t.Error("a failed health poll must carry a reason")
	}

	// Reachable but erroring (HTTP 500) => not ok, but NOT transport-unreachable.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	c.Client = newCollectorTestClientForURL(t, bad.URL)
	c.pollHealth(context.Background())
	h = c.HealthSnapshot()
	if h.CheckOK {
		t.Error("an erroring health endpoint must not report ok")
	}
	if h.Unreachable {
		t.Error("a reachable box returning HTTP 500 must NOT be called transport-unreachable")
	}
}

// TestValidatePollOverrideNames pins #387: a typo in the collector name half of
// --collector.poll-interval-override was accepted at startup and silently ignored
// forever, so the operator's intended rate/cost control never applied and nothing
// said so. Unknown names now fail closed, matching how a malformed duration is
// already treated.
func TestValidatePollOverrideNames(t *testing.T) {
	// A known-but-currently-disabled collector stays valid on purpose, so one
	// declarative config can be reused across deployments with different feature
	// flags. Validation is against every collector compiled into the binary.
	valid := []string{GatewaysSubsystem, FirmwareSubsystem, SMARTSubsystem}
	if err := ValidatePollOverrideNames(valid); err != nil {
		t.Errorf("known collector names must validate, got %v", err)
	}
	if err := ValidatePollOverrideNames(nil); err != nil {
		t.Errorf("no overrides must validate, got %v", err)
	}

	err := ValidatePollOverrideNames([]string{GatewaysSubsystem, "gatways"})
	if err == nil {
		t.Fatal("a typo'd collector name must fail startup, not be silently ignored")
	}
	msg := err.Error()
	if !strings.Contains(msg, "gatways") {
		t.Errorf("the error must name the offending key, got %q", msg)
	}
	if !strings.Contains(msg, GatewaysSubsystem) {
		t.Errorf("the error must list the valid names so the typo is fixable, got %q", msg)
	}
	// Valid names are listed sorted, so the message is stable and diffable.
	all := AllRegisteredCollectorNames()
	if !sort.StringsAreSorted(all) {
		t.Error("AllRegisteredCollectorNames must be sorted")
	}
	if len(all) < 40 {
		t.Errorf("expected the full registered set (~60 collectors), got %d", len(all))
	}
}
