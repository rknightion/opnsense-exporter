// Package cpustream consumes OPNsense's `api/diagnostics/cpu_usage/stream` as a
// long-lived Server-Sent Events connection and reconstructs cumulative per-mode CPU
// counters from it (#559, the SSE pilot authorised in #553).
//
// WHY A STREAM AND NOT A POLL. CPU percentages used to come from
// `diagnostics/activity/get_activity`. That endpoint costs 2.15 s of firewall work
// per call, measured — inherent, because OPNsense's activity.py runs
// `top -aHSTn -d2 999999` and takes the SECOND display, since the first would be
// since-boot averages. At a 15s poll that is a permanent 14% duty cycle on the
// firewall, 331 KB per poll (1.9 GB/day), and it buys a 2-second CPU sample every 15
// seconds — 13% timeline coverage. This stream is `iostat -w 1` behind
// text/event-stream: continuous 1-second samples (100% coverage) at ~70 bytes/sec,
// no process-table walk, and it authenticates ONCE at connect rather than per poll.
//
// WHY CUMULATIVE COUNTERS. A 1s stream feeding a 60s export is worth nothing if the
// exported value is the last sample — 59 samples would be discarded and the result
// would be a point sample per export, exactly like polling. Folding the samples into
// cumulative seconds is the only shape where the coverage is real: rate() over any
// window is then correct, and the export interval stops mattering for this metric.
//
// EXACTLY ONE CONNECTION. The stream holds one php-cgi worker plus a persistent
// iostat process on the firewall. Measured capacity there is
// `max-procs 8 x PHP_FCGI_CHILDREN 5` = 40 workers; one held stream is ~2.5% of it.
// Acceptable, but permanent — never open a second.
package cpustream

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Defaults for Config. Frames arrive about once a second.
const (
	// defaultStallAfter is how long the stream tolerates no DATA frame before
	// tearing the connection down and re-dialling. Generous relative to the 1s frame
	// cadence so ordinary scheduling jitter on a busy firewall never trips it.
	defaultStallAfter = 10 * time.Second
	// DefaultGracePeriod is how long the counters keep publishing after the last
	// frame. Sized to one export interval: a blip covered by a reconnect must not
	// gap the graph, but a real outage must stop the counter lying. Exported so main
	// can use it as the floor when deriving the window from --otlp.export-interval.
	DefaultGracePeriod = 60 * time.Second
	// defaultMaxFrameGap bounds the wall time one frame may be credited with.
	defaultMaxFrameGap = 5 * time.Second

	defaultMinBackoff = 1 * time.Second
	defaultMaxBackoff = 60 * time.Second
)

// maxFrameBytes bounds one SSE event. Frames are ~70 bytes; this is three orders of
// magnitude of headroom. It exists because the body is appliance-controlled text on
// a connection we hold open indefinitely, so an unbounded reader would let a
// malformed or hostile stream grow a buffer without limit. Exceeding it fails the
// connection, which re-dials.
const maxFrameBytes = 64 * 1024

// Opener dials the stream and returns its response body. The returned body is closed
// by the caller; cancelling ctx must abort the read in flight, which is how the
// stall watchdog forces a re-dial.
type Opener func(ctx context.Context) (io.ReadCloser, error)

// Config tunes the connection lifecycle. A zero value takes every default above.
type Config struct {
	StallAfter  time.Duration
	GracePeriod time.Duration
	MaxFrameGap time.Duration
	MinBackoff  time.Duration
	MaxBackoff  time.Duration
	Logger      *slog.Logger
}

func (c Config) withDefaults() Config {
	if c.StallAfter <= 0 {
		c.StallAfter = defaultStallAfter
	}
	if c.GracePeriod <= 0 {
		c.GracePeriod = DefaultGracePeriod
	}
	if c.MaxFrameGap <= 0 {
		c.MaxFrameGap = defaultMaxFrameGap
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = defaultMinBackoff
	}
	if c.MaxBackoff < c.MinBackoff {
		c.MaxBackoff = defaultMaxBackoff
	}
	if c.MaxBackoff < c.MinBackoff {
		c.MaxBackoff = c.MinBackoff
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Snapshot is the stream's state at one instant, read by the cpu collector on each
// poll. Every field is always populated — health must be reportable even while the
// counters are not, or a stalled stream is indistinguishable from an idle CPU.
type Snapshot struct {
	// Connected reports whether a connection is currently established.
	Connected bool
	// HaveFrame reports whether any frame has ever been received.
	HaveFrame bool
	// LastFrameAge is time since the last frame; meaningless unless HaveFrame.
	LastFrameAge time.Duration
	// Reconnects counts re-dials after the initial connection.
	Reconnects uint64
	// Frames counts accepted data frames.
	Frames uint64
	// Fresh reports whether the counters are inside the grace window and may be
	// published. When false the caller must emit NO cpu_seconds_total series: a
	// frozen counter reads as exactly zero only when the whole rate() window falls
	// inside the freeze and understates proportionally otherwise, which is silently
	// wrong either way. Absent is honest.
	Fresh bool
	// Seconds is the cumulative per-mode counter, always carrying every mode.
	Seconds map[string]float64
}

// Stream owns the connection, the reconnect loop and the accumulator.
type Stream struct {
	open Opener
	cfg  Config
	log  *slog.Logger
	now  func() time.Time

	mu         sync.Mutex
	acc        *accumulator
	lastFrame  time.Time
	connected  bool
	reconnects uint64
	frames     uint64

	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// New builds a stream. It performs no I/O; call Start to connect.
func New(open Opener, cfg Config) *Stream {
	cfg = cfg.withDefaults()
	return &Stream{
		open: open,
		cfg:  cfg,
		log:  cfg.Logger.With("component", "cpustream"),
		now:  time.Now,
		acc:  newAccumulator(cfg.MaxFrameGap),
	}
}

// Start launches the connect/read/reconnect loop in its own goroutine and returns
// immediately. Call Close to stop it; safe to call once.
func (s *Stream) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go s.run(ctx)
}

// Close cancels the loop and waits for it to exit. Idempotent.
func (s *Stream) Close() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	s.wg.Wait()
}

// Snapshot returns the current state. Safe for concurrent use.
func (s *Stream) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap := Snapshot{
		Connected:  s.connected,
		HaveFrame:  !s.lastFrame.IsZero(),
		Reconnects: s.reconnects,
		Frames:     s.frames,
		Seconds:    s.acc.seconds(),
	}
	if snap.HaveFrame {
		snap.LastFrameAge = s.now().Sub(s.lastFrame)
		snap.Fresh = snap.LastFrameAge <= s.cfg.GracePeriod
	}
	return snap
}

// run is the reconnect loop. Reconnect is the PRIMARY recovery mechanism: it covers
// a dropped connection, lighttpd's `server.max-write-idle = 999` closing a quiet
// one, and a wedged iostat. It bounds an outage but does not remove it, which is why
// the grace window in Snapshot exists as well.
func (s *Stream) run(ctx context.Context) {
	defer s.wg.Done()

	backoff := s.cfg.MinBackoff
	first := true
	for ctx.Err() == nil {
		if !first {
			s.mu.Lock()
			s.reconnects++
			n := s.reconnects
			s.mu.Unlock()
			s.log.Debug("re-dialling cpu usage stream", "reconnects", n)
		}
		first = false

		delivered, err := s.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.log.Warn("cpu usage stream disconnected", "err", err, "retry_in", backoff.String())
		}
		if delivered {
			// The endpoint is healthy; a later failure starts from the floor again
			// rather than inheriting a long backoff from an old outage.
			backoff = s.cfg.MinBackoff
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		if backoff *= 2; backoff > s.cfg.MaxBackoff {
			backoff = s.cfg.MaxBackoff
		}
	}
}

// connectOnce holds one connection for its lifetime. It reports whether the
// connection delivered at least one frame, which is what distinguishes "the endpoint
// works and the connection ended" from "we cannot reach it at all".
func (s *Stream) connectOnce(ctx context.Context) (delivered bool, err error) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	body, err := s.open(connCtx)
	if err != nil {
		return false, err
	}
	defer func() { _ = body.Close() }()

	s.beginConnection()
	defer s.endConnection()

	stopWatchdog := s.startWatchdog(connCtx, cancel)
	defer stopWatchdog()

	err = readFrames(bufio.NewReaderSize(body, 4096), func(pct map[string]float64) {
		delivered = true
		s.observe(pct)
	})
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return delivered, err
}

// startWatchdog cancels the connection when no DATA frame has arrived for
// StallAfter. A connection-liveness check would not catch this: the documented SSE
// failure on this box is that keepalives keep flowing after the data has stopped, so
// the socket looks perfectly healthy while the stream is dead. Freshness of the data
// is the only signal that distinguishes them.
func (s *Stream) startWatchdog(ctx context.Context, cancel context.CancelFunc) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Half the stall window, so detection costs at most 1.5x StallAfter.
		tick := time.NewTicker(s.cfg.StallAfter / 2)
		defer tick.Stop()
		started := s.now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-tick.C:
				s.mu.Lock()
				last := s.lastFrame
				s.mu.Unlock()
				if last.Before(started) {
					// No frame on THIS connection yet: age from connect, so a
					// connection that never produces anything is torn down too.
					last = started
				}
				if s.now().Sub(last) > s.cfg.StallAfter {
					s.log.Warn("cpu usage stream stalled with the connection still open; re-dialling",
						"stall_after", s.cfg.StallAfter.String())
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

func (s *Stream) beginConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = true
	s.acc.beginConnection()
}

func (s *Stream) endConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = false
}

func (s *Stream) observe(pct map[string]float64) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acc.observe(pct, now)
	s.lastFrame = now
	s.frames++
}

// readFrames parses the SSE body, calling onFrame for each decodable data payload.
// It returns when the body ends or errors.
//
// SSE framing: `data:` lines accumulate (the optional single leading space is
// stripped), `event:`/`id:`/`retry:` lines and `:` comments are ignored, and a blank
// line dispatches the accumulated payload. cpu.py only ever emits one data line per
// event, but handling the multi-line form costs nothing and means a future payload
// that wraps does not silently parse as garbage.
//
// An undecodable frame is skipped rather than failing the connection: one corrupt
// payload should not cost a re-dial, and parseFrame already refuses anything that
// could poison the counter.
func readFrames(r *bufio.Reader, onFrame func(map[string]float64)) error {
	var data []byte
	for {
		line, err := readLine(r)
		if len(line) > 0 || err == nil {
			switch {
			case len(line) == 0:
				if len(data) > 0 {
					if pct, ok := parseFrame(data); ok {
						onFrame(pct)
					}
					data = data[:0]
				}
			case line[0] == ':':
				// Comment / keepalive. Deliberately does NOT count as a frame — see
				// startWatchdog.
			default:
				if field, value, found := bytes.Cut(line, []byte(":")); found && string(field) == "data" {
					data = append(data, bytes.TrimPrefix(value, []byte(" "))...)
				}
			}
		}
		if err != nil {
			return err
		}
		if len(data) > maxFrameBytes {
			return errors.New("cpu usage stream frame exceeded the size bound")
		}
	}
}

// readLine reads one \n-terminated line with its trailing CR/LF stripped, bounded by
// maxFrameBytes so a stream that never emits a newline cannot grow without limit.
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, more, err := r.ReadLine()
		out = append(out, chunk...)
		if len(out) > maxFrameBytes {
			return out, errors.New("cpu usage stream line exceeded the size bound")
		}
		if err != nil {
			return out, err
		}
		if !more {
			return out, nil
		}
	}
}

// sleepCtx sleeps for d, reporting false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
