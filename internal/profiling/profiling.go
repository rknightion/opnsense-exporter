// Package profiling wires the pyroscope-go SDK so the exporter pushes
// continuous profiles to Grafana Cloud Pyroscope. It is the only package that
// imports the SDK; configuration is assembled in internal/options.
package profiling

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
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

// stopFlushTimeout bounds the final synchronous flush+stop on shutdown so a dead or
// unreachable Pyroscope server cannot hang exporter shutdown. It is a package-level
// var, not a const, purely so tests can shrink it (see profiling_test.go); production
// code never mutates it.
var stopFlushTimeout = 10 * time.Second //nolint:gochecknoglobals

// uploadTimeout is the per-request HTTP timeout applied to profile uploads. It
// matches the vendored SDK's own default (vendor/github.com/grafana/pyroscope-go/
// api.go: Timeout: 30 * time.Second) — see the comment on limitedBodyHTTPClient for
// why this package must set it explicitly rather than relying on that default.
const uploadTimeout = 30 * time.Second

// maxUploadResponseBytes caps how much of a Pyroscope backend's HTTP response body
// this package will read into memory. Upload responses are small JSON/text; 1 MiB is
// generous headroom over any legitimate response (#309).
const maxUploadResponseBytes = 1 << 20 // 1 MiB

// limitedBodyHTTPClient implements the SDK's upstream/remote.HTTPClient interface
// (just Do) and plugs into pyroscope.Config.HTTPClient. It exists to cap the
// response body the vendored uploader reads: vendor/github.com/grafana/pyroscope-go/
// upstream/remote/remote.go does an unbounded io.ReadAll(response.Body) for both
// success and error responses, so a misbehaving or compromised Pyroscope backend
// (the endpoint is operator-chosen; profiling is opt-in) could drive large transient
// heap growth by returning an oversized body (#309). Wrapping response.Body in a
// io.LimitReader truncates what the uploader ever sees, regardless of how much the
// server actually sends.
//
// CRITICAL: setting HTTPClient on pyroscope.Config REPLACES the SDK's own default
// client wholesale. remote.NewRemote only builds its default *http.Client (with its
// 30s Timeout taken from cfg.Timeout) when cfg.HTTPClient is nil; when it is
// non-nil, that constructed default is discarded and our client's Do is called
// as-is. So this client MUST set its own Timeout — omitting it would silently turn
// a bounded upload into an unbounded one, since nothing else would ever apply the
// SDK's 30s default again. This directly matters for #310: an unbounded per-request
// timeout is exactly the failure mode that makes the flush/stop timeout in Stop()
// ineffective.
type limitedBodyHTTPClient struct {
	inner *http.Client
}

// newLimitedBodyHTTPClient builds a limitedBodyHTTPClient with the given per-request
// timeout. Production code always passes uploadTimeout; tests may pass a shorter one.
//
// CheckRedirect restores the vendored SDK's own no-redirect policy (vendor/github.com/
// grafana/pyroscope-go/upstream/remote/remote.go), which this custom client would
// otherwise silently drop by replacing pyroscope.Config.HTTPClient wholesale (#381).
// Returning http.ErrUseLastResponse tells net/http to stop at the first response
// instead of following the redirect — net/http then returns that response as-is
// (not an error) — so a compromised or misconfigured Pyroscope backend can't redirect
// an authenticated upload to another host and have Go forward the Authorization header
// and replay the profile body to it, mirroring the fix applied to the OPNsense API
// client in #306.
func newLimitedBodyHTTPClient(timeout time.Duration) *limitedBodyHTTPClient {
	return &limitedBodyHTTPClient{inner: &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// Do performs the request via the inner client and, on success, replaces the
// response body with one capped at maxUploadResponseBytes.
func (c *limitedBodyHTTPClient) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.inner.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedReadCloser{
		r:     io.LimitReader(resp.Body, maxUploadResponseBytes),
		inner: resp.Body,
	}
	return resp, nil
}

// limitedReadCloser reads through a capped io.LimitReader but closes the original,
// unbounded body — the limit only bounds how many bytes are ever copied out; the
// underlying connection is still released normally.
type limitedReadCloser struct {
	r     io.Reader
	inner io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *limitedReadCloser) Close() error               { return l.inner.Close() }

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
		// See limitedBodyHTTPClient's doc comment: this both caps the response body
		// read into memory (#309) and MUST carry its own Timeout, since injecting a
		// custom client bypasses the SDK's own 30s-timeout default entirely.
		HTTPClient: newLimitedBodyHTTPClient(uploadTimeout),
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
// (ProfileCPU is always included).
//
// Flush(true) AND Stop() run together in one background goroutine, and the whole
// pair is bounded by stopFlushTimeout: on timeout, Stop returns and abandons that
// goroutine rather than continuing to wait on it (#310). This used to call
// Flush(true) under the timeout but then call Profiler.Stop() unconditionally
// afterward, on the timeout branch too — but the vendored Profiler.Stop() does an
// uncancellable wg.Wait() on any in-flight upload goroutines, so a goroutine already
// blocked inside an HTTP round-trip kept the real bound at the HTTP client's ~30s
// timeout, not the advertised stopFlushTimeout, defeating the point of the timeout.
// Abandoning the goroutine on timeout is safe here specifically because stopProfiling
// is called LAST in main.go's gracefulShutdown, after every other subsystem has
// already been torn down — nothing downstream depends on Stop() having completed,
// and the leaked goroutine (at most one, since Stop is only ever called once at
// shutdown) is reclaimed moments later at process exit. Profiler.Stop() always
// returns nil, so there is no meaningful error to surface from it (#121).
func Stop(profiler *pyroscope.Profiler, logger *slog.Logger) {
	if profiler == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		profiler.Flush(true)
		_ = profiler.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopFlushTimeout):
		logger.Warn(
			"pyroscope final flush/stop timed out; the final profiling window may be lost "+
				"and the flush/stop goroutine was abandoned to bound shutdown",
			"timeout", stopFlushTimeout.String(),
		)
	}
}
