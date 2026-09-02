package netflow

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// maxDatagram is the largest UDP payload there can be. The read buffer is sized to
// it deliberately: a short buffer truncates silently, and a truncated flowset is
// indistinguishable from a malformed one, so the decoder would report corruption
// for what is really our own undersized read.
const maxDatagram = 65535

const (
	defaultWorkers   = 4
	defaultQueueSize = 1024

	// defaultUDPReceiveBuffer is the requested kernel receive-buffer size for the
	// datagram socket. Linux may cap it at net.core.rmem_max (and reports the
	// effective size through ReadBuffer), which configureUDPReceiveBuffer reports.
	defaultUDPReceiveBuffer = 4 * 1024 * 1024
)

// decoder is the slice of *Decoder the listener actually needs. Taking an
// interface here keeps socket handling testable without constructing real wire
// bytes, and keeps the listener honest about how little it knows about the format.
type decoder interface {
	Decode(payload []byte, exporter netip.Addr, now time.Time) (*Datagram, error)
}

// ListenerConfig configures the UDP receiver.
type ListenerConfig struct {
	Addr string
	// UDPReceiveBuffer is the requested kernel receive-buffer size in bytes. Zero
	// selects defaultUDPReceiveBuffer. The effective size is checked after bind;
	// when the operating system clamps it, Start logs a warning naming the Linux
	// net.core.rmem_max sysctl.
	UDPReceiveBuffer int
	// AllowedPeers, when non-empty, is an allowlist. NetFlow carries no
	// authentication of any kind — whatever can reach the port can inject flow
	// records — so this is the only access control that exists. Leaving it empty is
	// a deliberate choice to trust the network, not a default to drift into.
	AllowedPeers []netip.Prefix
	// Workers and QueueSize control the bounded decoder pool. Zero selects the
	// built-in defaults; NewListener also falls back for negative values as a
	// defensive boundary, while the options layer rejects negative flag values.
	Workers   int
	QueueSize int

	// Capture and CaptureMode are the opt-in debug capture (#360). Capture is where
	// datagrams are written; CaptureMode decides which ones. Both must be set for
	// anything to be written, and the default — a nil sink and CaptureOff — costs one
	// comparison per datagram. The always-on counting and rate-limited logging of
	// unidentified content happens regardless of these.
	Capture     CaptureSink
	CaptureMode CaptureMode
}

type udpBufferSocket interface {
	SetReadBuffer(int) error
	ReadBuffer() (int, error)
}

type netUDPBufferSocket struct {
	conn *net.UDPConn
}

func (s netUDPBufferSocket) SetReadBuffer(size int) error {
	return s.conn.SetReadBuffer(size)
}

func (s netUDPBufferSocket) ReadBuffer() (int, error) {
	return effectiveUDPReceiveBuffer(s.conn)
}

// configureUDPReceiveBuffer requests and verifies the kernel receive buffer. A
// successful SetReadBuffer call alone is not enough: kernels may silently clamp
// the request, so read the effective value back and make the loss of headroom
// visible to operators. Linux doubles SO_RCVBUF on read-back, including after a
// clamp, so its comparison threshold must be doubled too.
func configureUDPReceiveBuffer(socket udpBufferSocket, requested int, log *slog.Logger) error {
	if requested <= 0 {
		requested = defaultUDPReceiveBuffer
	}
	if err := socket.SetReadBuffer(requested); err != nil {
		return fmt.Errorf("set UDP receive buffer to %d bytes: %w", requested, err)
	}
	effective, err := socket.ReadBuffer()
	if err != nil {
		return fmt.Errorf("read effective UDP receive buffer after requesting %d bytes: %w", requested, err)
	}
	if effective < minimumEffectiveUDPReceiveBuffer(requested, runtime.GOOS) {
		if log == nil {
			log = slog.Default()
		}
		attrs := []any{
			"requested_bytes", requested,
			"effective_bytes", effective,
		}
		if runtime.GOOS == "linux" {
			attrs = append(attrs, "limit_setting", "net.core.rmem_max")
		}
		log.Warn("UDP receive buffer was clamped; raise the host socket receive-buffer limit", attrs...)
	}
	return nil
}

func minimumEffectiveUDPReceiveBuffer(requested int, goos string) int {
	if goos != "linux" {
		return requested
	}
	if requested > math.MaxInt/2 {
		return math.MaxInt
	}
	return requested * 2
}

// ListenerStats counts everything the listener discarded. Each becomes a metric:
// a receiver that drops input silently is indistinguishable from a quiet network.
type ListenerStats struct {
	Datagrams    uint64
	Bytes        uint64
	PeerRejected uint64
	QueueDropped uint64
	ReadErrors   uint64
	DecodeErrors uint64
}

// Listener is a UDP NetFlow receiver. Datagrams are read on one goroutine and
// decoded on a worker pool, so a slow decode can never stall the socket.
type Listener struct {
	cfg    ListenerConfig
	dec    decoder
	handle func(*Datagram, netip.Addr)
	log    *slog.Logger

	conn *net.UDPConn
	work chan job

	closing chan struct{}
	once    sync.Once
	wg      sync.WaitGroup

	// notices rate-limits the always-on log for content the decoder could not
	// interpret. Shared by every worker, hence its own mutex.
	notices *noticeLimiter

	datagrams, bytes  atomic.Uint64
	peerRejected      atomic.Uint64
	queueDropped      atomic.Uint64
	readErrs, decErrs atomic.Uint64
}

type job struct {
	payload []byte
	peer    netip.Addr
}

// NewListener builds a listener. handle may be nil (decode-only, for tests).
func NewListener(cfg ListenerConfig, dec decoder, handle func(*Datagram, netip.Addr), log *slog.Logger) *Listener {
	if cfg.Workers <= 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if log == nil {
		log = slog.Default()
	}
	return &Listener{
		cfg:     cfg,
		dec:     dec,
		handle:  handle,
		log:     log,
		work:    make(chan job, cfg.QueueSize),
		closing: make(chan struct{}),
		notices: newNoticeLimiter(maxNoticeKeys),
	}
}

// Start binds the socket EAGERLY, so a bad or in-use port is a startup error the
// operator sees immediately rather than a receiver that is quietly never there.
func (l *Listener) Start() error {
	if l.cfg.Addr == "" {
		return errors.New("netflow: no listen address configured")
	}
	addr, err := net.ResolveUDPAddr("udp", l.cfg.Addr)
	if err != nil {
		return fmt.Errorf("netflow: resolve %q: %w", l.cfg.Addr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("netflow: listen %q: %w", l.cfg.Addr, err)
	}
	l.conn = conn
	if err := configureUDPReceiveBuffer(netUDPBufferSocket{conn: conn}, l.cfg.UDPReceiveBuffer, l.log); err != nil {
		_ = l.conn.Close()
		l.conn = nil
		return fmt.Errorf("netflow: configure UDP receive buffer: %w", err)
	}
	return nil
}

// Addr returns the bound address, resolved (so a ":0" test port is usable).
func (l *Listener) Addr() string {
	if l.conn == nil {
		return ""
	}
	return l.conn.LocalAddr().String()
}

// Serve runs the read loop until Close. It returns when the socket is closed.
func (l *Listener) Serve() {
	if l.conn == nil {
		return
	}
	for range l.cfg.Workers {
		l.wg.Add(1)
		go l.worker()
	}

	buf := make([]byte, maxDatagram)
	for {
		n, from, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-l.closing:
			default:
				l.readErrs.Add(1)
			}
			// A closed socket is the ordinary shutdown path; anything else is still
			// terminal for the read loop, because a UDP socket does not recover.
			break
		}
		peer := from.Addr().Unmap()
		if !l.allowed(peer) {
			l.peerRejected.Add(1)
			continue
		}
		l.datagrams.Add(1)
		l.bytes.Add(uint64(n))

		// Copy: buf is reused by the next read, so handing it to a worker would let
		// two datagrams interleave in one buffer.
		payload := make([]byte, n)
		copy(payload, buf[:n])

		select {
		case l.work <- job{payload: payload, peer: peer}:
		default:
			// Never block the read loop. Blocking makes the KERNEL drop datagrams,
			// which is invisible and unattributable; dropping here is counted.
			l.queueDropped.Add(1)
		}
	}

	close(l.work)
	l.wg.Wait()
}

func (l *Listener) worker() {
	defer l.wg.Done()
	for j := range l.work {
		recv := time.Now()
		dg, err := l.dec.Decode(j.payload, j.peer, recv)
		if err != nil {
			l.decErrs.Add(1)
			// A datagram that would not decode is the most interesting thing this
			// socket ever sees, and the payload is about to be garbage — this is the
			// only place it still exists (#360).
			l.note(j.payload, j.peer, recv, []Unidentified{{Kind: errorNoticeKind(err)}}, nil, err)
			continue
		}
		var notices []Unidentified
		if dg != nil {
			notices = dg.Unidentified
		}
		l.note(j.payload, j.peer, recv, notices, dg, nil)
		if l.handle != nil && dg != nil {
			l.handle(dg, j.peer)
		}
	}
}

func (l *Listener) allowed(peer netip.Addr) bool {
	if len(l.cfg.AllowedPeers) == 0 {
		return true
	}
	for _, p := range l.cfg.AllowedPeers {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// Close stops the receiver. It is safe to call more than once.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closing)
		if l.conn != nil {
			err = l.conn.Close()
		}
	})
	return err
}

// Stats returns a snapshot of the drop counters.
func (l *Listener) Stats() ListenerStats {
	return ListenerStats{
		Datagrams:    l.datagrams.Load(),
		Bytes:        l.bytes.Load(),
		PeerRejected: l.peerRejected.Load(),
		QueueDropped: l.queueDropped.Load(),
		ReadErrors:   l.readErrs.Load(),
		DecodeErrors: l.decErrs.Load(),
	}
}
