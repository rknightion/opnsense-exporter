package collector

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// maxPollConcurrency caps how many collectors may hit the OPNsense API at once
// across all poll goroutines (D7), so a box with many collectors isn't dialed by
// dozens of pollers simultaneously.
const maxPollConcurrency = 8

// coldStartJitterCap bounds the deterministic startup jitter so the first poll of
// every collector still lands within a few seconds (D4) while staggering the herd.
const coldStartJitterCap = 5 * time.Second

// pollConcurrency is the effective per-process poll fan-out cap: min(GOMAXPROCS, 8).
func pollConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	if n > maxPollConcurrency {
		return maxPollConcurrency
	}
	if n < 1 {
		return 1
	}
	return n
}

// pollGlobalInterval is the default interval for collectors that declare no tier.
func (c *Collector) pollGlobalInterval() time.Duration {
	if c.pollGlobal > 0 {
		return clampInterval(c.pollGlobal)
	}
	return IntervalMedium
}

// healthPollInterval is the interval at which the health poller runs, resolved
// independently of the collector default (#386). Zero means IntervalMedium (60s),
// which preserves the previous default behaviour exactly. Always clamped.
func (c *Collector) healthPollInterval() time.Duration {
	if c.healthPollGlobal > 0 {
		return clampInterval(c.healthPollGlobal)
	}
	return IntervalMedium
}

// resolveInterval returns the DECLARED poll interval for a collector: an operator
// override (--collector.poll-interval-override) wins, else its code tier / the global
// default via resolvePollInterval. Always clamped.
//
// Declared, not effective (#550). This is what OTLP fast-lane membership is derived
// from, so the export-lane clamp deliberately lives one layer above it in
// effectiveInterval — see poll_lane.go for why folding it in here fails silently.
func (c *Collector) resolveInterval(coll CollectorInstance) time.Duration {
	if d, ok := c.pollOverrides[coll.Name()]; ok {
		return clampInterval(d)
	}
	return resolvePollInterval(coll, c.pollGlobalInterval())
}

// StartPolling launches the internal poll scheduler (#336): one goroutine per
// enabled collector plus a health goroutine, each polling the OPNsense API on its
// own interval into the snapshot store that the serving path replays. It returns
// immediately; StopPolling cancels and waits. Call once, after New.
func (c *Collector) StartPolling(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	c.pollCancel = cancel
	c.pollSem = make(chan struct{}, pollConcurrency())

	c.pollWG.Add(1)
	go c.runHealthPoller(ctx, c.healthPollInterval())

	for _, w := range c.PollLaneWarnings() {
		c.log.Warn(w.String(), "component", "collector", "warning", w.Kind)
	}

	for _, coll := range c.collectors {
		interval := c.effectiveInterval(coll)
		if c.statusTracker != nil {
			c.statusTracker.SetInterval(coll.Name(), interval)
		}
		c.pollWG.Add(1)
		go c.runCollectorPoller(ctx, coll, interval)
	}
	c.log.Info("poll scheduler started",
		"component", "collector",
		"collectors", len(c.collectors),
		"default_interval", c.pollGlobalInterval().String(),
		"health_interval", c.healthPollInterval().String(),
		"concurrency", pollConcurrency(),
	)
}

// StopPolling cancels all pollers and blocks until they exit. Safe to call once
// after StartPolling; a no-op if polling was never started.
func (c *Collector) StopPolling() {
	if c.pollCancel != nil {
		c.pollCancel()
	}
	c.pollWG.Wait()
}

// SnapshotWarm reports whether the snapshot the serving path replays is COMPLETE:
// the health poller and every enabled collector have each finished a first poll.
//
// Since #336 a scrape no longer fetches anything, so a scrape taken during cold
// start replays only the collectors that happen to have polled already — with the
// startup jitter (up to 5s) and the poll-concurrency cap, a freshly started
// exporter needs tens of seconds to fill the snapshot. Readiness gates on this so
// an ordered startup (and CI's live-box smoke, #341) waits for a full snapshot
// instead of asserting against a partial one.
//
// Completeness, not success: a collector whose first poll errored has had its turn
// and counts as warm — the failure is reported by scrape_collector_success=0, and
// waiting for it to succeed would leave a box with one broken plugin never ready.
func (c *Collector) SnapshotWarm() bool {
	c.mutex.RLock()
	healthPolled := c.healthPolled
	c.mutex.RUnlock()
	if !healthPolled {
		return false
	}
	names := make([]string, 0, len(c.collectors))
	for _, coll := range c.collectors {
		names = append(names, coll.Name())
	}
	return c.store.allPolled(names)
}

// runCollectorPoller polls one collector immediately (jittered) then on a ticker,
// publishing the ticker's ACTUAL next fire as the collector's next-poll deadline
// (#385) so the exported metric and the console read the real schedule instead of
// each re-deriving lastPoll + interval, which drifts from the ticker the moment a
// poll takes any appreciable time.
//
// The ticker is started BEFORE the first poll, so the published deadline is correct
// from the outset rather than only after the first tick. On exit the deadline is
// cleared: a stopped poller has no next poll, and leaving the last value in place
// would let it age into a permanent, misleading "due".
func (c *Collector) runCollectorPoller(ctx context.Context, coll CollectorInstance, interval time.Duration) {
	defer c.pollWG.Done()
	if !sleepJitter(ctx, coll.Name(), interval) {
		return
	}
	name := coll.Name()
	defer c.publishDeadline(name, time.Time{})

	t := time.NewTicker(interval)
	defer t.Stop()
	next := time.Now().Add(interval)
	c.publishDeadline(name, next)
	c.pollCollector(ctx, coll)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			next = advanceDeadline(next, interval, time.Now())
			c.publishDeadline(name, next)
			c.pollCollector(ctx, coll)
		}
	}
}

// publishDeadline records one collector's next scheduled poll in both places that
// report it — the snapshot store (which backs the exported metric) and the status
// tracker (which backs the console) — so the two can never disagree about when the
// next poll is due. The zero time clears it, meaning "no poll scheduled".
func (c *Collector) publishDeadline(name string, at time.Time) {
	c.store.setDeadline(name, at)
	if c.statusTracker != nil {
		c.statusTracker.SetNextDeadline(name, at)
	}
}

// runHealthPoller polls the system health check on the global interval, setting
// the persistent health gauges the serving path re-emits.
func (c *Collector) runHealthPoller(ctx context.Context, interval time.Duration) {
	defer c.pollWG.Done()
	if !sleepJitter(ctx, "__health__", interval) {
		return
	}
	c.pollHealth(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.pollHealth(ctx)
		}
	}
}

// pollCollector runs one poll of coll under the concurrency cap, unless the last
// health poll found the box unreachable — in which case it skips (retaining the
// last-good snapshot) rather than adding to a burst of doomed dials (#127). Each
// poll is bounded by pollTimeout so a wedged endpoint frees its concurrency slot
// instead of holding it open indefinitely.
func (c *Collector) pollCollector(ctx context.Context, coll CollectorInstance) {
	if c.unreachable.Load() {
		return
	}
	select {
	case c.pollSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-c.pollSem }()

	// Re-check after admission (#383). The check above is not enough: with ~60
	// collectors sharing 8 slots, a caller can pass it, queue behind the cap, and
	// only then be admitted — after the health poller has already tripped the
	// circuit. The poll timeout starts only after admission, so queued work never
	// expires while waiting; without this second check every queued collector
	// drains as a doomed dial, several waves deep, for minutes. That is the exact
	// dial storm #127 exists to prevent.
	//
	// In-flight polls are deliberately left alone — they finish under their own
	// context. A tiny race remains between this check and the request itself;
	// closing it entirely would need a client-level circuit breaker, which is not
	// warranted for the failure mode being fixed here.
	if c.unreachable.Load() {
		return
	}

	pollCtx := ctx
	if d := c.pollTimeout(); d > 0 {
		var cancel context.CancelFunc
		pollCtx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	c.pollOnce(pollCtx, coll)
}

// pollTimeout bounds a single collector poll. It reuses --exporter.max-scrape-duration
// (now a per-poll bound rather than a per-scrape one, since serving no longer makes
// API calls), falling back to defaultMaxScrapeDuration when unset.
func (c *Collector) pollTimeout() time.Duration {
	if c.maxScrapeDuration > 0 {
		return c.maxScrapeDuration
	}
	return defaultMaxScrapeDuration
}

// pollOnce captures a single collector Update into a buffer, records the outcome
// into the StatusTracker, and stores it (D8 semantics live in snapshotStore.put).
// It shields the poll from panics, mirroring the old execute() path.
func (c *Collector) pollOnce(ctx context.Context, coll CollectorInstance) {
	client := c.Client.WithContext(ctx)
	begin := time.Now()

	buf := make([]prometheus.Metric, 0, 64)
	sink := make(chan prometheus.Metric, 4096)
	done := make(chan struct{})
	go func() {
		for m := range sink {
			buf = append(buf, m)
		}
		close(done)
	}()

	success := true
	var lastErr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				success = false
				lastErr = fmt.Sprintf("panic: %v", r)
				c.endpointErrors.WithLabelValues("panic:"+coll.Name(), c.instanceLabel).Inc()
				c.log.Error("panic in collector poll goroutine; skipping",
					"component", "collector",
					"collector_name", coll.Name(),
					"panic", fmt.Sprintf("%v", r),
				)
			}
		}()
		if apiErr := coll.Update(ctx, client, sink); apiErr != nil {
			success = false
			lastErr = apiErr.Error()
			c.endpointErrors.WithLabelValues(apiErr.Endpoint, c.instanceLabel).Inc()
			c.log.Error("failed to update",
				"component", "collector",
				"collector_name", coll.Name(),
				"err", apiErr,
			)
		}
	}()
	close(sink)
	<-done

	dur := time.Since(begin)
	c.store.put(coll.Name(), buf, dur, success)
	if c.statusTracker != nil {
		c.statusTracker.Record(coll.Name(), begin, dur.Seconds()*1000, success, lastErr)
		// Mirror the store's data clocks into the tracker so the console reports the
		// same data age the metrics do (#382). Read them back from the store rather
		// than recomputing here — put() owns the retain/replace decision, and a
		// second copy of that logic is exactly how the two would drift apart.
		e := c.store.entry(coll.Name())
		c.statusTracker.RecordClocks(coll.Name(), e.snapshotAt, e.lastSuccess)
	}
}

// pollHealth refreshes the persistent health gauges from one health check and
// tracks reachability. Transport-level failure (StatusCode==0) flags the box
// unreachable so collector pollers skip until it recovers.
func (c *Collector) pollHealth(ctx context.Context) {
	client := c.Client.WithContext(ctx)
	systemStatus, err := client.HealthCheck()

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Set regardless of outcome: an unreachable box must not hold the warm-up
	// signal open, since readiness already fails on its own health probe.
	c.healthPolled = true
	c.healthCheckedAt = time.Now()

	if err != nil {
		c.isUp.Set(0)
		c.healthOK = false
		c.healthLastError = err.Error()
		var apiErr *opnsense.APICallError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 0 {
			c.unreachable.Store(true)
			c.log.Warn("firewall unreachable (transport-level health-check failure)",
				"component", "collector", "err", err)
		} else {
			// Reachable but erroring: the box answered, so the circuit stays closed
			// and collectors keep polling. Only a transport failure means "nothing
			// is listening", and only that should pause the fleet (#384).
			c.unreachable.Store(false)
			c.log.Error("failed to fetch system health status", "component", "collector", "err", err)
		}
		return
	}

	c.unreachable.Store(false)
	c.healthOK = true
	c.healthLastError = ""
	c.isUp.Set(1)
	c.systemStatusCode.Set(float64(systemStatus.GetMetadataSystemStatus()))
	c.crashReporterStatus.Set(boolToGauge(systemStatus.CrashReporterIsHealthy()))
	c.firewallHealthStatus.Set(boolToGauge(firewallIsHealthy(systemStatus)))

	// Reset before repopulating: OPNsense omits healthy subsystems, so a stale label
	// set from a previous unhealthy state must not linger once the subsystem recovers.
	c.subsystemStatusCode.Reset()
	for name, entry := range systemStatus.AllSubsystems() {
		c.subsystemStatusCode.WithLabelValues(name).Set(float64(entry.ResolvedStatusCode()))
	}
}

// emitHealth re-emits the persistent health gauges into a scrape channel. It is
// the serving-path companion to pollHealth and makes no API call.
//
// opnsense_up reflects API REACHABILITY only: 1 whenever the last health poll
// reached and parsed the box, 0 otherwise. A reachable box that self-reports a
// degraded subsystem stays up=1 — that is surfaced via the lower-severity
// opnsense_system_status_code and the per-subsystem gauges, not by flipping up.
//
// The non-isUp gauges are gated on healthOK: during an outage (or before the first
// successful poll) they are left ABSENT rather than emitting a misleading 0 (0 is
// the WARNING status code, not "unknown"). opnsense_system_subsystem_status_code
// (#218) carries EVERY subsystem the payload reports, not just firewall/crashreporter.
func (c *Collector) emitHealth(ch chan<- prometheus.Metric) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	c.isUp.Collect(ch)
	if !c.healthOK {
		return
	}
	c.firewallHealthStatus.Collect(ch)
	c.crashReporterStatus.Collect(ch)
	c.systemStatusCode.Collect(ch)
	c.subsystemStatusCode.Collect(ch)
}

// advanceDeadline returns the next poll deadline on the FIXED cadence anchored at
// next, given that we have just observed the tick and it is now `now` (#385).
//
// This is the whole schedule contract in one function. The scheduler drives every
// collector from a time.Ticker, which fires on a fixed cadence and DROPS ticks that
// a slow receiver missed rather than sliding the schedule. So:
//
//   - A poll shorter than one interval leaves the cadence untouched: the answer is
//     simply the next multiple. Deriving completion + interval instead — what the
//     metric and console did before #385 — is late by exactly the poll duration.
//   - A poll that overran one or more intervals means the ticker already dropped
//     the fires we missed, so stepping once would hand back a deadline in the PAST.
//     Step until the result is strictly in the future, which is the fire the ticker
//     will actually deliver next.
//
// A non-positive interval cannot be stepped, so it is returned unchanged rather
// than looping forever.
func advanceDeadline(next time.Time, interval time.Duration, now time.Time) time.Time {
	if interval <= 0 {
		return next
	}
	for !next.After(now) {
		next = next.Add(interval)
	}
	return next
}

// sleepJitter waits a deterministic per-name offset in [0, min(interval, cap))
// before a poller's first poll, spreading the cold-start herd. Returns false if
// ctx is cancelled during the wait.
func sleepJitter(ctx context.Context, name string, interval time.Duration) bool {
	span := min(interval, coldStartJitterCap)
	if span <= 0 {
		return ctx.Err() == nil
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	offset := time.Duration(uint64(h.Sum32()) % uint64(span))
	if offset <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(offset)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
