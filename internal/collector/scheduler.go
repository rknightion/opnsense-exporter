package collector

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense-exporter/opnsense"
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

// resolveInterval returns the effective poll interval for a collector: an operator
// override (--collector.poll-interval-override) wins, else its code tier / the global
// default via resolvePollInterval. Always clamped.
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
	go c.runHealthPoller(ctx, c.pollGlobalInterval())

	for _, coll := range c.collectors {
		interval := c.resolveInterval(coll)
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

// runCollectorPoller polls one collector immediately (jittered) then on a ticker.
func (c *Collector) runCollectorPoller(ctx context.Context, coll CollectorInstance, interval time.Duration) {
	defer c.pollWG.Done()
	if !sleepJitter(ctx, coll.Name(), interval) {
		return
	}
	c.pollCollector(ctx, coll)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.pollCollector(ctx, coll)
		}
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

	if err != nil {
		c.isUp.Set(0)
		c.healthOK = false
		var apiErr *opnsense.APICallError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 0 {
			c.unreachable.Store(true)
			c.log.Warn("firewall unreachable (transport-level health-check failure)",
				"component", "collector", "err", err)
		} else {
			c.log.Error("failed to fetch system health status", "component", "collector", "err", err)
		}
		return
	}

	c.unreachable.Store(false)
	c.healthOK = true
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
