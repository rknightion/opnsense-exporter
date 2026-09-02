package syslog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

type fakeUDPBufferSocket struct {
	requested int
	effective int
	setErr    error
	readErr   error
}

func (f *fakeUDPBufferSocket) SetReadBuffer(size int) error {
	f.requested = size
	return f.setErr
}

func (f *fakeUDPBufferSocket) ReadBuffer() (int, error) {
	return f.effective, f.readErr
}

func TestConfigureUDPReceiveBufferWarnsWhenClamped(t *testing.T) {
	socket := &fakeUDPBufferSocket{effective: 256 * 1024}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	if err := configureUDPReceiveBuffer(socket, 4*1024*1024, logger); err != nil {
		t.Fatalf("configureUDPReceiveBuffer: %v", err)
	}
	if socket.requested != 4*1024*1024 {
		t.Fatalf("requested receive buffer = %d, want %d", socket.requested, 4*1024*1024)
	}
	if !strings.Contains(logs.String(), "was clamped") {
		t.Fatalf("clamp warning = %q, want a portable clamp diagnostic", logs.String())
	}
	if runtime.GOOS == "linux" && !strings.Contains(logs.String(), "net.core.rmem_max") {
		t.Fatalf("Linux clamp warning = %q, want net.core.rmem_max", logs.String())
	}
}

func TestMinimumEffectiveUDPReceiveBufferAccountsForLinuxDoubling(t *testing.T) {
	const requested = 4 * 1024 * 1024
	if got := minimumEffectiveUDPReceiveBuffer(requested, "linux"); got != 2*requested {
		t.Fatalf("Linux minimum effective buffer = %d, want %d", got, 2*requested)
	}
	if got := minimumEffectiveUDPReceiveBuffer(requested, "darwin"); got != requested {
		t.Fatalf("Darwin minimum effective buffer = %d, want %d", got, requested)
	}
}

func TestConfigureUDPReceiveBufferDoesNotWarnWhenEffectiveSizeMeetsRequest(t *testing.T) {
	socket := &fakeUDPBufferSocket{effective: 8 * 1024 * 1024}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	if err := configureUDPReceiveBuffer(socket, 4*1024*1024, logger); err != nil {
		t.Fatalf("configureUDPReceiveBuffer: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("unexpected warning when receive buffer was sufficient: %q", logs.String())
	}
}

func TestConfigureUDPReceiveBufferReturnsSetError(t *testing.T) {
	socket := &fakeUDPBufferSocket{setErr: errors.New("set failed")}
	if err := configureUDPReceiveBuffer(socket, 4*1024*1024, testLogger()); err == nil {
		t.Fatal("configureUDPReceiveBuffer succeeded after SetReadBuffer failed")
	}
}

// counterValue reads a single counter sample out of reg. (prometheus/testutil is
// not vendored, and vendor/ is not this lane's file to touch.)
func counterValue(t *testing.T, reg *prometheus.Registry, name, label, value string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == label && lp.GetValue() == value {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// collector is a thread-safe handler sink.
type collector struct {
	mu    sync.Mutex
	lines []string
	ch    chan string
}

func newCollector() *collector { return &collector{ch: make(chan string, 64)} }

func (c *collector) handle(line []byte, _ netip.Addr) {
	s := string(line) // the handler must not retain the buffer
	c.mu.Lock()
	c.lines = append(c.lines, s)
	c.mu.Unlock()
	select {
	case c.ch <- s:
	default:
	}
}

func (c *collector) await(t *testing.T, d time.Duration) string {
	t.Helper()
	select {
	case s := <-c.ch:
		return s
	case <-time.After(d):
		t.Fatal("timed out waiting for a line")
		return ""
	}
}

// startListener binds on loopback ephemeral ports and runs the listener until the
// test finishes.
func startListener(t *testing.T, cfg Config, h func([]byte, netip.Addr), m *logship.ReceiverMetrics) *Listener {
	t.Helper()
	if cfg.UDPAddr == "" && cfg.TCPAddr == "" {
		cfg.UDPAddr = "127.0.0.1:0"
		cfg.TCPAddr = "127.0.0.1:0"
	}
	l := NewListener(cfg, h, m, testLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after ctx cancel")
		}
	})
	return l
}

func TestListenerUDPDelivers(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{UDPAddr: "127.0.0.1:0"}, c.handle, nil)
	if l.TCPAddr() != "" {
		t.Fatalf("TCPAddr = %q, want empty (transport disabled)", l.TCPAddr())
	}

	conn, err := net.Dial("udp", l.UDPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<134>hello udp")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != "<134>hello udp" {
		t.Fatalf("got %q", got)
	}
}

func TestListenerTCPDelivers(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0"}, c.handle, nil)
	if l.UDPAddr() != "" {
		t.Fatalf("UDPAddr = %q, want empty (transport disabled)", l.UDPAddr())
	}

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	body := "<134>hello tcp"
	// Newline framing then octet counting, on the same connection.
	if _, err := conn.Write([]byte(body + "\n" + strconv.Itoa(len(body)) + " " + body)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != body {
		t.Fatalf("first: got %q", got)
	}
	if got := c.await(t, 3*time.Second); got != body {
		t.Fatalf("second: got %q", got)
	}
}

func TestListenerOversizedTCPFrameCountedAndConnectionSurvives(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0"}, c.handle, m)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	n := maxMessageBytes + 100
	if _, err := conn.Write([]byte(strconv.Itoa(n) + " " + strings.Repeat("A", n) + "5 good!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 5*time.Second); got != "good!" {
		t.Fatalf("got %q, want good! (an oversized frame must not kill the connection)", got)
	}
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "oversized"); got != 1 {
		t.Fatalf("Rejected{oversized} = %v, want 1", got)
	}
}

// #398: a newline-framed payload above the cap, with no terminator anywhere near
// it, used to trip a TERMINAL bufio.ErrTooLong — killing the connection so the next
// valid frame never arrived, and never incrementing Rejected{oversized}. It must
// instead be skipped and counted exactly once, on a connection that keeps working.
func TestListenerOversizedNewlineFrameCountedAndConnectionSurvives(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0"}, c.handle, m)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	n := maxMessageBytes + 1000
	if _, err := conn.Write([]byte(strings.Repeat("A", n) + "\n<134>good\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 5*time.Second); got != "<134>good" {
		t.Fatalf("got %q, want <134>good (an oversized newline frame must not kill the connection)", got)
	}
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "oversized"); got != 1 {
		t.Fatalf("Rejected{oversized} = %v, want 1", got)
	}
}

// An unauthenticated ingress with unbounded goroutines is textbook slowloris: the
// TCP connection-cap refusal must be COUNTED, not just logged, so a capacity attack
// is visible on /metrics (#399).
func TestListenerTCPConnLimitCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0", MaxConns: 1}, c.handle, m)

	first, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = first.Close() }()
	if _, err := first.Write([]byte("<134>one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.await(t, 3*time.Second) // the first conn is established and served

	second, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer func() { _ = second.Close() }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit") == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit"); got != 1 {
		t.Fatalf("Rejected{conn_limit} = %v, want 1", got)
	}
}

func TestListenerPeerAllowlistUDP(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	// 192.0.2.0/24 is TEST-NET-1: loopback is definitely outside it.
	l := startListener(t, Config{
		UDPAddr:      "127.0.0.1:0",
		AllowedPeers: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}, c.handle, m)

	conn, err := net.Dial("udp", l.UDPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<134>should be dropped")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "peer") == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "peer"); got != 1 {
		t.Fatalf("Rejected{peer} = %v, want 1", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lines) != 0 {
		t.Fatalf("a disallowed peer's datagram was delivered: %q", c.lines)
	}
}

func TestListenerPeerAllowlistTCP(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	l := startListener(t, Config{
		TCPAddr:      "127.0.0.1:0",
		AllowedPeers: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}, c.handle, m)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("<134>should be dropped\n"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "peer") == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "peer"); got != 1 {
		t.Fatalf("Rejected{peer} = %v, want 1", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lines) != 0 {
		t.Fatalf("a disallowed peer's line was delivered: %q", c.lines)
	}
}

// A bad/in-use port must be a STARTUP error, not a silently dead receiver.
func TestListenerStartBindErrors(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = busy.Close() }()

	l := NewListener(Config{TCPAddr: busy.Addr().String()}, func([]byte, netip.Addr) {}, nil, testLogger())
	if err := l.Start(); err == nil {
		_ = l.Close()
		t.Fatal("Start on an in-use TCP port must error")
	}

	l2 := NewListener(Config{UDPAddr: "127.0.0.1:99999"}, func([]byte, netip.Addr) {}, nil, testLogger())
	if err := l2.Start(); err == nil {
		_ = l2.Close()
		t.Fatal("Start on an invalid UDP port must error")
	}
}

// Without this, ReadFrom/Accept never observe the context, pollerWG.Wait() blocks
// forever and THE EXPORTER NEVER EXITS ON SIGTERM.
func TestListenerRunReturnsOnContextCancel(t *testing.T) {
	l := NewListener(Config{UDPAddr: "127.0.0.1:0", TCPAddr: "127.0.0.1:0"}, func([]byte, netip.Addr) {}, nil, testLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Hold an idle connection open: its goroutine must not outlive Close either.
	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of ctx cancel — the exporter would hang on SIGTERM")
	}
	if err := l.Close(); err != nil { // sync.Once: a second Close is a no-op
		t.Fatalf("second Close: %v", err)
	}
}

// The listener must tolerate a nil *logship.ReceiverMetrics (tests, and any caller that opts out).
func TestListenerNilMetrics(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{
		UDPAddr:      "127.0.0.1:0",
		AllowedPeers: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}, c.handle, nil)
	conn, err := net.Dial("udp", l.UDPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<134>dropped")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // no panic is the assertion
}

// An unauthenticated ingress with unbounded goroutines is textbook slowloris: past
// MaxConns, further connections are refused rather than forked.
func TestListenerMaxConns(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0", MaxConns: 1}, c.handle, nil)

	first, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = first.Close() }()
	if _, err := first.Write([]byte("<134>one\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.await(t, 3*time.Second) // the first conn is established and served

	second, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := second.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Fatal("the over-cap connection should have been closed by the server")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the over-cap connection was left open — MaxConns is not enforced")
	}
}

func TestMetricsNilSafe(t *testing.T) {
	var m *logship.ReceiverMetrics
	m.ParseError("envelope") // must not panic
	m.Reject("peer")
}

// End-to-end #262: a multi-line message written to a real newline-framed TCP
// connection must arrive as ONE line at the handler, with its body intact — not as
// a truncated head plus a train of junk fragments.
func TestListenerTCPReassemblesMultiLineMessage(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0"}, c.handle, nil)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// syslog-ng writes the whole message, embedded newlines and all, then a delimiter.
	if _, err := conn.Write([]byte(configdTraceback + "\n<134>after\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := c.await(t, 3*time.Second); got != configdTraceback {
		t.Fatalf("multi-line message was not reassembled:\ngot:  %q\nwant: %q", got, configdTraceback)
	}
	if got := c.await(t, 3*time.Second); got != "<134>after" {
		t.Fatalf("the following message was corrupted: %q", got)
	}

	// And nothing else: no fragment records.
	select {
	case extra := <-c.ch:
		t.Fatalf("a fragment shipped as its own record: %q", extra)
	case <-time.After(500 * time.Millisecond):
	}
}

// The last message on a quiet connection has no successor to prove it complete. It
// must still ship, on the assembler's own idle timer, well before the connection
// closes.
func TestListenerTCPShipsLastMessageOnIdleConnection(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{TCPAddr: "127.0.0.1:0"}, c.handle, nil)

	conn, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("<134>only message\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The connection stays OPEN and silent: only the idle flush can deliver this.
	if got := c.await(t, 3*time.Second); got != "<134>only message" {
		t.Fatalf("got %q, want the pending message flushed on idle", got)
	}
}

// UDP has no continuation problem: one datagram is one message, always. A datagram
// containing newlines must be delivered whole and never reassembled or split.
func TestListenerUDPMultiLineDatagramIsUntouched(t *testing.T) {
	c := newCollector()
	l := startListener(t, Config{UDPAddr: "127.0.0.1:0"}, c.handle, nil)

	conn, err := net.Dial("udp", l.UDPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(configdTraceback)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != configdTraceback {
		t.Fatalf("UDP datagram was altered:\ngot:  %q\nwant: %q", got, configdTraceback)
	}
}
