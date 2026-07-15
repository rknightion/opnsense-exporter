// Package profiling wires the pyroscope-go SDK so the exporter pushes
// continuous profiles to Grafana Cloud Pyroscope. It is the only package that
// imports the SDK; configuration is assembled in internal/options.
package profiling

import (
	"fmt"
	"log/slog"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

// Sampling settings applied when mutex/block profiling is enabled.
// Fixed, low-overhead defaults; not user-configurable. Note the two have
// different units (see runtime.SetMutexProfileFraction / SetBlockProfileRate).
const (
	// mutexProfileFraction reports 1/N of mutex contention events.
	mutexProfileFraction = 5
	// blockProfileRate is a nanosecond threshold: record blocking events that
	// last on average at least this long. 100µs keeps overhead modest while
	// still surfacing meaningful contention (a value like 5 would sample almost
	// everything).
	blockProfileRate = 100_000
)

// GoroutineLeakAvailable reports whether the runtime exposes the goroutineleak
// profile. It is registered only when the binary is built with
// GOEXPERIMENT=goroutineleakprofile (Go 1.26+); a binary built without it simply
// omits the type instead of pushing an empty/erroring profile. Our release builds
// set the experiment, so shipped binaries include it; a plain `go build` does not.
func GoroutineLeakAvailable() bool {
	return pprof.Lookup("goroutineleak") != nil
}

// profileTypes returns the set of profiles to collect. All standard types are on
// by default: cpu, the alloc/inuse memory set, and goroutines (a zero-overhead
// stack snapshot) plus the mutex/block contention profiles — which need the
// process-global SetMutexProfileFraction/SetBlockProfileRate rates and carry the
// only non-trivial per-event cost, so they are the one set an operator can turn
// off via disableMutexBlock. goroutineleak is appended when the runtime exposes it
// (built with the experiment).
func profileTypes(disableMutexBlock bool) []pyroscope.ProfileType {
	types := []pyroscope.ProfileType{
		pyroscope.ProfileCPU,
		pyroscope.ProfileAllocObjects,
		pyroscope.ProfileAllocSpace,
		pyroscope.ProfileInuseObjects,
		pyroscope.ProfileInuseSpace,
		pyroscope.ProfileGoroutines,
	}
	if !disableMutexBlock {
		types = append(types,
			pyroscope.ProfileMutexCount,
			pyroscope.ProfileMutexDuration,
			pyroscope.ProfileBlockCount,
			pyroscope.ProfileBlockDuration,
		)
	}
	if GoroutineLeakAvailable() {
		types = append(types, pyroscope.ProfileGoroutineLeak)
	}
	return types
}

// loggerAdapter adapts the exporter's *slog.Logger to pyroscope.Logger.
type loggerAdapter struct{ logger *slog.Logger }

func (l loggerAdapter) Infof(format string, args ...any) {
	l.logger.Info(fmt.Sprintf(format, args...))
}
func (l loggerAdapter) Debugf(format string, args ...any) {
	l.logger.Debug(fmt.Sprintf(format, args...))
}
func (l loggerAdapter) Errorf(format string, args ...any) {
	l.logger.Error(fmt.Sprintf(format, args...))
}

// stopFlushTimeout bounds the final synchronous flush on shutdown so a dead or
// unreachable Pyroscope server (which would otherwise hold Flush for the SDK's ~30s
// upload timeout) cannot hang exporter shutdown.
const stopFlushTimeout = 10 * time.Second

// Start begins continuous profiling and returns the running profiler. Callers should
// pass it to Stop() on shutdown to flush the final profiling window. instance and
// version are attached as tags.
func Start(cfg *options.PyroscopeConfig, instance, version string, logger *slog.Logger) (*pyroscope.Profiler, error) {
	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName:   cfg.ApplicationName,
		ServerAddress:     cfg.ServerAddress,
		BasicAuthUser:     cfg.AuthUser,
		BasicAuthPassword: cfg.AuthPassword,
		TenantID:          cfg.TenantID,
		Logger:            loggerAdapter{logger: logger},
		ProfileTypes:      profileTypes(cfg.DisableMutexBlock),
		Tags: map[string]string{
			"instance": instance,
			"version":  version,
		},
	})
	if err != nil {
		return nil, err
	}

	// Enable the process-global mutex/block sampling only after the profiler is
	// running, so a failed start does not leave these runtime knobs permanently
	// on with nothing consuming the samples. On by default; skipped only when the
	// operator disabled the contention profiles.
	if !cfg.DisableMutexBlock {
		runtime.SetMutexProfileFraction(mutexProfileFraction)
		runtime.SetBlockProfileRate(blockProfileRate)
	}

	return profiler, nil
}

// Stop flushes the in-progress profiling window and then stops the profiler on
// shutdown. It calls the SDK's real flush primitive Flush(true) BEFORE Stop() because
// Profiler.Stop() alone only uploads the CPU profile — it never resets/uploads the
// current delta window for the non-CPU profile types (heap/alloc/inuse/goroutine and,
// when enabled, mutex/block), silently dropping up to a full upload window of
// data on every restart. Flush(true) is the only path that resets + uploads + waits
// for those. It is safe only while CPU profiling stays in the profile set — the SDK
// deadlocks in Flush if CPU profiling is disabled — which profileTypes guarantees
// (ProfileCPU is always included). The flush is bounded by stopFlushTimeout so an
// unreachable server cannot hang shutdown; Profiler.Stop() always returns nil, so
// there is no meaningful error to surface from it (#121).
func Stop(profiler *pyroscope.Profiler, logger *slog.Logger) {
	if profiler == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		profiler.Flush(true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopFlushTimeout):
		logger.Warn(
			"pyroscope final flush timed out; the final profiling window may be lost",
			"timeout", stopFlushTimeout.String(),
		)
	}
	_ = profiler.Stop()
}
