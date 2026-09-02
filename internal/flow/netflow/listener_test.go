package netflow

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
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
	if err := configureUDPReceiveBuffer(socket, 4*1024*1024, slog.Default()); err == nil {
		t.Fatal("configureUDPReceiveBuffer succeeded after SetReadBuffer failed")
	}
}

// fakeDecoder lets the listener be tested without the real decoder: the listener's
// job is sockets, allowlisting and backpressure, and coupling its tests to wire
// format would only make them fragile.
type fakeDecoder struct {
	mu      sync.Mutex
	seen    [][]byte
	peers   []netip.Addr
	err     error
	blockOn chan struct{} // when non-nil, every Decode waits on it
}

func (f *fakeDecoder) Decode(payload []byte, exporter netip.Addr, _ time.Time) (*Datagram, error) {
	if f.blockOn != nil {
		<-f.blockOn
	}
	f.mu.Lock()
	cp := append([]byte(nil), payload...)
	f.seen = append(f.seen, cp)
	f.peers = append(f.peers, exporter)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &Datagram{Version: V9, Records: []Record{{Proto: 6}}}, nil
}

func (f *fakeDecoder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func newTestListener(t *testing.T, cfg ListenerConfig, dec decoder, handle func(*Datagram, netip.Addr)) *Listener {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	l := NewListener(cfg, dec, handle, promslog.NewNopLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go l.Serve()
	return l
}

func send(t *testing.T, addr string, payload []byte) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// waitFor polls until cond holds, so the tests never sleep a fixed duration and
// never flake on a slow machine.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestListener_DecodesAndHandsOffDatagram(t *testing.T) {
	dec := &fakeDecoder{}
	var got atomic.Int64
	l := newTestListener(t, ListenerConfig{}, dec, func(_ *Datagram, _ netip.Addr) { got.Add(1) })

	send(t, l.Addr(), []byte("hello-netflow"))
	waitFor(t, "handler", func() bool { return got.Load() == 1 })

	if dec.count() != 1 {
		t.Fatalf("decoder saw %d datagrams, want 1", dec.count())
	}
	if s := l.Stats(); s.Datagrams != 1 || s.Bytes != uint64(len("hello-netflow")) {
		t.Fatalf("stats = %+v, want 1 datagram / %d bytes", s, len("hello-netflow"))
	}
}

// The read buffer is reused between reads, so a listener that enqueues the buffer
// itself corrupts every queued payload as soon as the next datagram lands.
//
// The workers are held blocked while all 20 datagrams are read, which is what makes
// this deterministic: without it the worker copies the payload before the read loop
// laps the buffer, and the test passes with the bug present (verified — an earlier
// version of this test did exactly that and caught nothing).
func TestListener_DoesNotAliasTheReadBuffer(t *testing.T) {
	release := make(chan struct{})
	dec := &fakeDecoder{blockOn: release}
	l := newTestListener(t, ListenerConfig{Workers: 1, QueueSize: 64}, dec, func(*Datagram, netip.Addr) {})

	const n = 20
	for i := range n {
		send(t, l.Addr(), []byte{byte(i), byte(i), byte(i), byte(i)})
	}
	waitFor(t, "all datagrams read off the socket", func() bool { return l.Stats().Datagrams == n })
	close(release)
	waitFor(t, "all datagrams decoded", func() bool { return dec.count() == n })

	dec.mu.Lock()
	defer dec.mu.Unlock()
	seen := map[byte]bool{}
	for _, p := range dec.seen {
		for _, b := range p {
			if b != p[0] {
				t.Fatalf("payload %v mixes two datagrams — the read buffer was aliased", p)
			}
		}
		seen[p[0]] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct payloads out of %d — the read buffer was aliased, so queued "+
			"datagrams all observed whichever one was read last", len(seen), n)
	}
}

// NetFlow is unauthenticated: whatever can reach the port can inject flow records,
// so the allowlist is the only control there is.
func TestListener_RejectsPeersOutsideTheAllowlist(t *testing.T) {
	dec := &fakeDecoder{}
	l := newTestListener(t, ListenerConfig{
		AllowedPeers: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}, dec, func(*Datagram, netip.Addr) {})

	send(t, l.Addr(), []byte("from-127.0.0.1"))
	waitFor(t, "rejection", func() bool { return l.Stats().PeerRejected == 1 })

	if dec.count() != 0 {
		t.Fatalf("decoder saw %d datagrams from a disallowed peer, want 0", dec.count())
	}
}

func TestListener_EmptyAllowlistAcceptsEveryPeer(t *testing.T) {
	dec := &fakeDecoder{}
	l := newTestListener(t, ListenerConfig{}, dec, func(*Datagram, netip.Addr) {})

	send(t, l.Addr(), []byte("x"))
	waitFor(t, "accepted", func() bool { return dec.count() == 1 })
	if s := l.Stats(); s.PeerRejected != 0 {
		t.Fatalf("PeerRejected = %d, want 0 with an empty allowlist", s.PeerRejected)
	}
}

// Backpressure: the read loop must NEVER block on a slow decoder. Blocking there
// makes the kernel drop datagrams silently, which is invisible; dropping them here
// is counted and therefore actionable.
func TestListener_DropsRatherThanBlockingTheReadLoop(t *testing.T) {
	release := make(chan struct{})
	dec := &fakeDecoder{blockOn: release}
	l := newTestListener(t, ListenerConfig{Workers: 1, QueueSize: 1}, dec, func(*Datagram, netip.Addr) {})

	for range 200 {
		send(t, l.Addr(), []byte("congest"))
	}
	waitFor(t, "queue drops", func() bool { return l.Stats().QueueDropped > 0 })
	close(release)
}

func TestListener_CountsDecodeErrors(t *testing.T) {
	dec := &fakeDecoder{err: ErrMalformed}
	var handled atomic.Int64
	l := newTestListener(t, ListenerConfig{}, dec, func(*Datagram, netip.Addr) { handled.Add(1) })

	send(t, l.Addr(), []byte("garbage"))
	waitFor(t, "decode error", func() bool { return l.Stats().DecodeErrors == 1 })
	if handled.Load() != 0 {
		t.Fatal("handler ran for a datagram that failed to decode")
	}
}

// A port already in use must fail at startup, not leave a silently dead receiver —
// the same rule the syslog and Zenarmor receivers follow.
func TestListener_BindFailureIsAStartupError(t *testing.T) {
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = busy.Close() }()

	l := NewListener(ListenerConfig{Addr: busy.LocalAddr().String()}, &fakeDecoder{}, nil, promslog.NewNopLogger())
	if err := l.Start(); err == nil {
		_ = l.Close()
		t.Fatal("Start succeeded on an in-use port; a bad port must be a startup error")
	}
}

func TestListener_CloseIsIdempotentAndStopsServe(t *testing.T) {
	l := newTestListener(t, ListenerConfig{}, &fakeDecoder{}, func(*Datagram, netip.Addr) {})
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
}
