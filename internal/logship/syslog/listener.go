package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
)

const (
	// defaultMaxConns caps concurrent TCP connections. Syslog is an unauthenticated
	// ingress: unbounded goroutines with no read deadline is textbook slowloris.
	defaultMaxConns = 64

	// defaultUDPReceiveBuffer is the requested kernel receive-buffer size for the
	// datagram socket. Linux may cap it at net.core.rmem_max (and reports the
	// effective size through ReadBuffer), which configureUDPReceiveBuffer reports.
	defaultUDPReceiveBuffer = 4 * 1024 * 1024

	// UDP needs a short, bounded shock absorber between the socket and parsing. A
	// full queue is observable as logs_rejected_total{reason="queue_full"}; blocking
	// the reader instead would lose datagrams in the kernel without attribution.
	defaultUDPWorkers   = 4
	defaultUDPQueueSize = 1024
)

// connIdleTimeout is refreshed per frame, so an idle peer cannot pin a goroutine
// forever, but a busy one is never cut off.
const connIdleTimeout = 5 * time.Minute

// defaultTLSHandshakeTimeout bounds how long a connection accepted on the TLS port may
// hold a capacity slot BEFORE it has authenticated. tls.NewListener is lazy: Accept
// returns a *tls.Conn whose handshake has not run, and left to the scan loop it would
// only run on the first read — under connIdleTimeout, so an anonymous peer could hold
// a slot for five minutes by simply connecting and saying nothing (#328). Ten seconds
// is far more than a handshake across any real link needs.
const defaultTLSHandshakeTimeout = 10 * time.Second

// refusalLogEvery bounds how often ONE class of refusal may write a log line. Every
// refusal below is something an unauthenticated peer can produce at line rate — a
// connection flood, a stalled handshake, a bad client certificate retried in a loop —
// so a Warn per refusal makes the exporter's own log the amplification vector (#399).
// The counter is the accurate record; the log is a breadcrumb, and one every 30s is
// enough to tell an operator which class is firing.
const refusalLogEvery = 30 * time.Second

// refusalLogKey is a CLOSED, code-defined set of throttle keys. It is deliberately
// NOT keyed by peer, certificate identity or error text: an attacker-controlled key
// would make the throttle map itself the memory leak the throttle exists to prevent,
// and the same rule that keeps those values out of metric labels keeps them out of
// here. Four constants, four map entries, for the life of the process.
type refusalLogKey string

const (
	refusalTCPConnLimit refusalLogKey = "tcp_conn_limit"
	refusalTLSConnLimit refusalLogKey = "tls_conn_limit"
	refusalTLSHandshake refusalLogKey = "tls_handshake"
	refusalTLSDeadline  refusalLogKey = "tls_deadline"
)

// Config configures the receiver's sockets. An empty address disables that
// transport. AllowedPeers, when non-empty, is an allowlist: anything else is
// dropped and counted (syslog is unauthenticated — whatever can reach the port can
// inject records).
type Config struct {
	UDPAddr, TCPAddr string
	// UDPReceiveBuffer is the requested kernel receive-buffer size in bytes. Zero
	// selects defaultUDPReceiveBuffer. The effective size is checked after bind;
	// when the operating system clamps it, Start logs a warning naming the Linux
	// net.core.rmem_max sysctl.
	UDPReceiveBuffer int
	// UDPWorkers and UDPQueueSize control the bounded UDP processing pool. Zero
	// selects the defaults above. More than one worker intentionally means UDP
	// delivery order is not preserved after the socket read loop.
	UDPWorkers, UDPQueueSize int
	// TLSAddr + TLSConfig together enable a third, TLS-wrapped TCP transport that
	// feeds the SAME handler as plain TCP. The TLS listener is enabled only when
	// BOTH are set (a non-empty address and a non-nil config).
	TLSAddr      string
	TLSConfig    *tls.Config
	AllowedPeers []netip.Prefix
	// MaxConns is PER TRANSPORT, not a single global pool: plain TCP and TLS hold
	// separate budgets of this size (see the semaphores on Listener).
	MaxConns int
	// TLSHandshakeTimeout bounds a pre-authentication TLS connection's hold on a slot.
	// Zero means defaultTLSHandshakeTimeout.
	TLSHandshakeTimeout time.Duration
	// Registerer is where the connection-slot headroom gauges register (#592). It is
	// separate from the ReceiverMetrics handle passed to NewListener because those are
	// SHARED, source-labelled counters owned by the pipeline, while these are this
	// listener's own gauges over its own budgets. Nil disables them, exactly as a nil
	// ReceiverMetrics disables the counters.
	Registerer prometheus.Registerer
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
	_, err := configureUDPReceiveBufferObserved(socket, requested, log)
	return err
}

// configureUDPReceiveBufferObserved is configureUDPReceiveBuffer's value-returning
// form. Start uses the effective value it read from the kernel to populate the
// receive-buffer gauge; the compatibility wrapper above keeps the existing helper
// contract for tests and callers that only need the startup error.
func configureUDPReceiveBufferObserved(socket udpBufferSocket, requested int, log *slog.Logger) (int, error) {
	if requested <= 0 {
		requested = defaultUDPReceiveBuffer
	}
	if log == nil {
		log = slog.Default()
	}

	accepted := requested
	setErr := socket.SetReadBuffer(accepted)
	if setErr != nil {
		// FreeBSD (and other BSDs) reject a SO_RCVBUF request above the kernel's
		// adjusted maximum with ENOBUFS instead of silently clamping it the way
		// Linux does, so the original request can make the receiver fail to
		// start outright. Retry with progressively smaller sizes, halving each
		// time, down to a 64 KiB floor; the first size the kernel accepts wins.
		// If even the floor is refused, surface the ORIGINAL refusal unchanged.
		originalErr := setErr
		fellBack := false
		for size := accepted / 2; size >= minUDPReceiveBufferFallback; size /= 2 {
			accepted = size
			if err := socket.SetReadBuffer(accepted); err != nil {
				continue
			}
			fellBack = true
			break
		}
		if !fellBack {
			return 0, fmt.Errorf("set UDP receive buffer to %d bytes: %w", requested, originalErr)
		}

		attrs := []any{
			"requested_bytes", requested,
			"accepted_bytes", accepted,
			"err", originalErr,
		}
		switch runtime.GOOS {
		case "freebsd":
			attrs = append(attrs, "limit_setting", "kern.ipc.maxsockbuf")
		case "linux":
			attrs = append(attrs, "limit_setting", "net.core.rmem_max")
		}
		log.Warn("kernel refused requested UDP receive buffer; falling back to a smaller size", attrs...)
	}

	effective, err := socket.ReadBuffer()
	if err != nil {
		return 0, fmt.Errorf("read effective UDP receive buffer after requesting %d bytes: %w", requested, err)
	}
	if effective < minimumEffectiveUDPReceiveBuffer(accepted, runtime.GOOS) {
		attrs := []any{
			"requested_bytes", accepted,
			"effective_bytes", effective,
		}
		if runtime.GOOS == "linux" {
			attrs = append(attrs, "limit_setting", "net.core.rmem_max")
		}
		log.Warn("UDP receive buffer was clamped; raise the host socket receive-buffer limit", attrs...)
	}
	return effective, nil
}

// minUDPReceiveBufferFallback is the smallest SO_RCVBUF size the fallback loop
// in configureUDPReceiveBufferObserved will try before giving up and returning
// the kernel's original refusal.
const minUDPReceiveBufferFallback = 64 * 1024

func minimumEffectiveUDPReceiveBuffer(requested int, goos string) int {
	if goos != "linux" {
		return requested
	}
	if requested > math.MaxInt/2 {
		return math.MaxInt
	}
	return requested * 2
}

// Listener is a hardened UDP + TCP syslog receiver. TCP hands each framed line to
// handle on its connection goroutine. UDP first copies each datagram into a bounded
// queue, then invokes handle from a worker pool; consequently, UDP delivery order
// is not guaranteed when more than one worker is configured. Handlers must not
// retain their line buffer.
type Listener struct {
	cfg    Config
	handle func(line []byte, peer netip.Addr)
	m      *logship.ReceiverMetrics
	log    *slog.Logger

	udp   *net.UDPConn
	tcp   *net.TCPListener
	tlsLn net.Listener
	udpQ  chan udpJob
	udpWG sync.WaitGroup
	udpM  *udpMetrics

	// tcpSem and tlsSem are SEPARATE budgets, deliberately. They were one shared
	// semaphore, which meant a plaintext flood — needing no credentials whatsoever —
	// consumed the very slots the operator's mTLS senders depend on, so the
	// authenticated transport could be starved by the unauthenticated one (#328).
	// Separate budgets over a reserved share: a reservation still lets plaintext take
	// the unreserved remainder of a shared pool, and there is no reason the two
	// transports should compete at all. MaxConns is therefore per transport.
	tcpSem chan struct{}
	tlsSem chan struct{}
	// slots reports the occupancy of the two budgets above. Nil when no registerer
	// was supplied; every call site goes through the nil-safe methods.
	slots *slotGauges

	conns sync.WaitGroup
	// connMu orders a conns.Add against Close's conns.Wait. Close closes closing
	// under it, so an accept loop either registers before the close is visible (and
	// Wait waits for it) or sees the listener closing and refuses the connection.
	// Checking closed() without the mutex leaves a few-instruction window in which
	// Add races Wait on the 0->1 transition — a real shutdown bug, and the flaky
	// race-detector failure of #655.
	connMu  sync.Mutex
	closing chan struct{}
	once    sync.Once
	closeMu sync.Mutex
	closeCh error

	// refusalMu guards refusalLast, the last-logged time per refusal class. Accept
	// loops for the two transports run concurrently and both write it.
	refusalMu   sync.Mutex
	refusalLast map[refusalLogKey]time.Time
}

// udpJob owns its payload. serveUDP reuses its read buffer on every datagram, so a
// worker must never be given a slice into that buffer.
type udpJob struct {
	line []byte
	peer netip.Addr
}

// logRefusal reports whether this class of refusal may log now, recording the time
// when it may. See refusalLogEvery for why refusals are throttled at all.
func (l *Listener) logRefusal(k refusalLogKey) bool {
	now := time.Now()
	l.refusalMu.Lock()
	defer l.refusalMu.Unlock()
	if last, ok := l.refusalLast[k]; ok && now.Sub(last) < refusalLogEvery {
		return false
	}
	l.refusalLast[k] = now
	return true
}

// NewListener builds a listener. The handler is fixed at construction; there is no
// SetHandler. m may be nil.
func NewListener(cfg Config, handle func(line []byte, peer netip.Addr), m *logship.ReceiverMetrics, log *slog.Logger) *Listener {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.UDPWorkers <= 0 {
		cfg.UDPWorkers = defaultUDPWorkers
	}
	if cfg.UDPQueueSize <= 0 {
		cfg.UDPQueueSize = defaultUDPQueueSize
	}
	if cfg.TLSHandshakeTimeout <= 0 {
		cfg.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	// Only the connection-oriented transports that are actually configured get slot
	// series. UDP is absent by nature — it is connectionless and holds no slot — and a
	// transport with no socket would publish a budget that can never be spent.
	var slotTransports []string
	if cfg.TCPAddr != "" {
		slotTransports = append(slotTransports, "tcp")
	}
	if cfg.TLSAddr != "" && cfg.TLSConfig != nil {
		slotTransports = append(slotTransports, "tls")
	}
	return &Listener{
		cfg:     cfg,
		handle:  handle,
		m:       m,
		log:     log,
		tcpSem:  make(chan struct{}, cfg.MaxConns),
		tlsSem:  make(chan struct{}, cfg.MaxConns),
		udpQ:    make(chan udpJob, cfg.UDPQueueSize),
		udpM:    newUDPMetrics(cfg.Registerer, cfg.UDPAddr != ""),
		slots:   newSlotGauges(cfg.Registerer, cfg.MaxConns, slotTransports),
		closing: make(chan struct{}),

		refusalLast: make(map[refusalLogKey]time.Time, 4),
	}
}

// Start binds both sockets EAGERLY, so a bad or in-use port is a startup error
// rather than a silently dead receiver. The resolved addresses (for ":0") are
// available from UDPAddr/TCPAddr afterwards.
func (l *Listener) Start() error {
	if l.cfg.UDPAddr == "" && l.cfg.TCPAddr == "" && !l.tlsEnabled() {
		return errors.New("syslog: no listen address configured (UDP, TCP and TLS are all empty)")
	}
	if l.cfg.UDPAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", l.cfg.UDPAddr)
		if err != nil {
			return fmt.Errorf("syslog: resolve UDP %q: %w", l.cfg.UDPAddr, err)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("syslog: listen UDP %q: %w", l.cfg.UDPAddr, err)
		}
		l.udp = conn
		effective, err := configureUDPReceiveBufferObserved(netUDPBufferSocket{conn: conn}, l.cfg.UDPReceiveBuffer, l.log)
		if err != nil {
			_ = l.closeSockets()
			return fmt.Errorf("syslog: configure UDP receive buffer: %w", err)
		}
		l.udpM.observeReceiveBuffer(effective)
	}
	if l.cfg.TCPAddr != "" {
		addr, err := net.ResolveTCPAddr("tcp", l.cfg.TCPAddr)
		if err != nil {
			// Roll back the already-bound UDP socket. Its close error is deliberately
			// discarded: the bind failure below is the one the operator needs to see.
			_ = l.closeSockets()
			return fmt.Errorf("syslog: resolve TCP %q: %w", l.cfg.TCPAddr, err)
		}
		ln, err := net.ListenTCP("tcp", addr)
		if err != nil {
			_ = l.closeSockets()
			return fmt.Errorf("syslog: listen TCP %q: %w", l.cfg.TCPAddr, err)
		}
		l.tcp = ln
	}
	if l.tlsEnabled() {
		addr, err := net.ResolveTCPAddr("tcp", l.cfg.TLSAddr)
		if err != nil {
			// Roll back the already-bound sockets, mirroring the TCP block above.
			_ = l.closeSockets()
			return fmt.Errorf("syslog: resolve TLS %q: %w", l.cfg.TLSAddr, err)
		}
		raw, err := net.ListenTCP("tcp", addr)
		if err != nil {
			_ = l.closeSockets()
			return fmt.Errorf("syslog: listen TLS %q: %w", l.cfg.TLSAddr, err)
		}
		// tls.NewListener yields *tls.Conn from Accept, with the handshake NOT yet run —
		// serveTLS drives it explicitly, under its own deadline, before serving (#328).
		l.tlsLn = tls.NewListener(raw, l.cfg.TLSConfig)
	}
	return nil
}

// tlsEnabled reports whether a TLS listener is configured: it needs BOTH a listen
// address and a tls.Config.
func (l *Listener) tlsEnabled() bool {
	return l.cfg.TLSAddr != "" && l.cfg.TLSConfig != nil
}

// UDPAddr returns the resolved UDP address, or "" when UDP is disabled or unbound.
func (l *Listener) UDPAddr() string {
	if l.udp == nil {
		return ""
	}
	return l.udp.LocalAddr().String()
}

// TCPAddr returns the resolved TCP address, or "" when TCP is disabled or unbound.
func (l *Listener) TCPAddr() string {
	if l.tcp == nil {
		return ""
	}
	return l.tcp.Addr().String()
}

// TLSAddr returns the resolved TLS listen address, or "" when TLS is disabled or
// unbound.
func (l *Listener) TLSAddr() string {
	if l.tlsLn == nil {
		return ""
	}
	return l.tlsLn.Addr().String()
}

// Run serves both transports until ctx is cancelled, then closes the sockets and
// waits for every connection goroutine.
//
// The ctx watchdog is load-bearing: net.UDPConn.ReadFrom and net.TCPListener.Accept
// do NOT observe a context. Without closing the sockets on ctx.Done, Run never
// returns, the pipeline's pollerWG.Wait() (which has no timeout) blocks forever and
// THE EXPORTER NEVER EXITS ON SIGTERM.
func (l *Listener) Run(ctx context.Context) {
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-l.closing:
		}
	}()

	var wg sync.WaitGroup
	if l.udp != nil {
		for range l.cfg.UDPWorkers {
			l.udpWG.Add(1)
			go l.serveUDPWorker()
		}
		wg.Add(1)
		go func() { defer wg.Done(); l.serveUDP() }()
	}
	if l.tcp != nil {
		wg.Add(1)
		go func() { defer wg.Done(); l.serveTCP() }()
	}
	if l.tlsLn != nil {
		wg.Add(1)
		go func() { defer wg.Done(); l.serveTLS() }()
	}
	wg.Wait()

	_ = l.Close() // idempotent: also waits for the connection goroutines
	// serveUDP is the sole closer of udpQ, after ReadFromUDPAddrPort has stopped.
	// Drain accepted work so Run's return is an explicit completion boundary; Close
	// itself only closes sockets, because it may be the call that unblocks serveUDP.
	l.udpWG.Wait()
	<-watchdogDone
}

// Close shuts the sockets and waits for every in-flight connection goroutine. It is
// sync.Once-guarded and safe to call repeatedly.
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.connMu.Lock()
		close(l.closing)
		l.connMu.Unlock()
		err := l.closeSockets()
		l.conns.Wait()
		l.closeMu.Lock()
		l.closeCh = err
		l.closeMu.Unlock()
	})
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	return l.closeCh
}

func (l *Listener) closeSockets() error {
	var errs []error
	if l.udp != nil {
		if err := l.udp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if l.tcp != nil {
		if err := l.tcp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if l.tlsLn != nil {
		if err := l.tlsLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// trackConn registers a connection goroutine on l.conns, reporting false when the
// listener is already closing and the caller must drop the connection instead.
func (l *Listener) trackConn() bool {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	if l.closed() {
		return false
	}
	l.conns.Add(1)
	return true
}

func (l *Listener) closed() bool {
	select {
	case <-l.closing:
		return true
	default:
		return false
	}
}

// allowed reports whether peer may send us records.
func (l *Listener) allowed(peer netip.Addr) bool {
	if len(l.cfg.AllowedPeers) == 0 {
		return true
	}
	peer = peer.Unmap() // a v4-mapped v6 peer must match a v4 prefix
	for _, p := range l.cfg.AllowedPeers {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// serveUDP reads datagrams: one datagram is one message, no framing. It never calls
// handle itself: parsing/enrichment/emission can be slow, but socket draining cannot
// wait for it. UDP workers race by design, so this transport has no delivery-order
// guarantee once UDPWorkers is greater than one.
func (l *Listener) serveUDP() {
	defer close(l.udpQ)
	buf := make([]byte, maxMessageBytes)
	for {
		n, addr, err := l.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if l.closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			l.log.Warn("syslog: UDP read failed", "err", err)
			continue
		}
		peer := addr.Addr().Unmap()
		if !l.allowed(peer) {
			l.m.Reject("peer")
			continue
		}
		if n == 0 {
			continue
		}
		// Copy before handoff: buf is reused by the next ReadFromUDPAddrPort.
		line := append([]byte(nil), buf[:n]...)
		select {
		case l.udpQ <- udpJob{line: line, peer: peer}:
			// Admission is the exact ingress boundary: count only after the
			// datagram has entered the bounded worker queue. A full queue and all
			// earlier filters remain excluded from this counter.
			l.udpM.observeAccepted()
		default:
			// A non-blocking enqueue keeps the reader ahead of the kernel receive
			// buffer. This drop is attributable and exported; a blocked reader would
			// turn the same overload into an invisible kernel-level loss.
			l.m.Reject("queue_full")
		}
	}
}

func (l *Listener) serveUDPWorker() {
	defer l.udpWG.Done()
	for job := range l.udpQ {
		l.handle(job.line, job.peer)
	}
}

// serveTCP accepts connections, capping concurrency and rejecting disallowed peers
// at accept. One bad connection never kills the listener.
func (l *Listener) serveTCP() {
	for {
		conn, err := l.tcp.AcceptTCP()
		if err != nil {
			if l.closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			l.log.Warn("syslog: TCP accept failed", "err", err)
			continue
		}

		peer := peerAddr(conn.RemoteAddr())
		if !l.allowed(peer) {
			l.m.Reject("peer")
			_ = conn.Close()
			continue
		}

		select {
		case l.tcpSem <- struct{}{}:
			l.slots.observe("tcp", len(l.tcpSem))
		default:
			// At the connection cap: refuse rather than fork an unbounded goroutine.
			// Counted, not merely logged (#399) — a capacity attack is exactly the
			// thing an operator needs to see on /metrics, and it was previously
			// visible only to whoever happened to be reading the exporter's log.
			l.m.Reject("conn_limit")
			if l.logRefusal(refusalTCPConnLimit) {
				l.log.Warn("syslog: TCP connection limit reached, refusing peer",
					"peer", peer.String(), "max_conns", l.cfg.MaxConns,
					"log_throttle", refusalLogEvery.String())
			}
			_ = conn.Close()
			continue
		}

		if !l.trackConn() {
			<-l.tcpSem
			l.slots.observe("tcp", len(l.tcpSem))
			_ = conn.Close()
			return
		}
		go func() {
			defer l.conns.Done()
			defer func() { <-l.tcpSem; l.slots.observe("tcp", len(l.tcpSem)) }()
			defer func() { _ = conn.Close() }()
			l.serveConn(conn, peer)
		}()
	}
}

// serveTLS accepts TLS-wrapped connections. It mirrors serveTCP — same peer allowlist
// at accept, same per-connection handoff to serveConn — differing in two ways: Accept
// yields a *tls.Conn (as net.Conn), and the slot it takes comes from the TLS budget,
// which no plaintext peer can touch. It also completes the handshake under its own
// short deadline before serveConn, so the slot is held pre-authentication for seconds
// rather than for connIdleTimeout (#328).
func (l *Listener) serveTLS() {
	for {
		conn, err := l.tlsLn.Accept()
		if err != nil {
			if l.closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			l.log.Warn("syslog: TLS accept failed", "err", err)
			continue
		}

		peer := peerAddr(conn.RemoteAddr())
		if !l.allowed(peer) {
			l.m.Reject("peer")
			_ = conn.Close()
			continue
		}

		select {
		case l.tlsSem <- struct{}{}:
			l.slots.observe("tls", len(l.tlsSem))
		default:
			// At the connection cap: refuse rather than fork an unbounded goroutine.
			// Counted under the SAME conn_limit reason as plaintext: the budgets are
			// separate, but "we are refusing connections" is one operational signal
			// and splitting it by transport would only fragment the alert (#399).
			l.m.Reject("conn_limit")
			if l.logRefusal(refusalTLSConnLimit) {
				l.log.Warn("syslog: TLS connection limit reached, refusing peer",
					"peer", peer.String(), "max_conns", l.cfg.MaxConns,
					"log_throttle", refusalLogEvery.String())
			}
			_ = conn.Close()
			continue
		}

		if !l.trackConn() {
			<-l.tlsSem
			l.slots.observe("tls", len(l.tlsSem))
			_ = conn.Close()
			return
		}
		go func() {
			defer l.conns.Done()
			defer func() { <-l.tlsSem; l.slots.observe("tls", len(l.tlsSem)) }()
			defer func() { _ = conn.Close() }()
			if !l.handshake(conn, peer) {
				return
			}
			l.serveConn(conn, peer)
		}()
	}
}

// handshake completes the TLS handshake under an explicit deadline, reporting whether
// the connection may proceed. It exists because tls.NewListener is LAZY: without it
// the handshake happens on the first read inside serveConn, whose only deadline is
// connIdleTimeout, so a peer that connects and never speaks holds a capacity slot for
// five minutes without ever presenting a credential (#328).
//
// A non-TLS conn passes through untouched, so the helper is safe for any caller.
func (l *Listener) handshake(conn net.Conn, peer netip.Addr) bool {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return true
	}
	// The wall-clock deadline covers the socket; the context is what also aborts the
	// handshake when the listener closes, so shutdown is never held up for the length
	// of the timeout by a peer that is deliberately stalling.
	if err := conn.SetDeadline(time.Now().Add(l.cfg.TLSHandshakeTimeout)); err != nil {
		// A LOCAL failure, not the peer's: without its deadline the handshake would
		// be unbounded, so the connection is dropped. Counted separately because a
		// listener failing its own syscalls is a different alert from a peer failing
		// to authenticate, and it used to be completely invisible (#399).
		l.rejectDeadline(err)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.TLSHandshakeTimeout)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-l.closing:
			cancel()
		case <-stop:
		}
	}()
	if err := tc.HandshakeContext(ctx); err != nil {
		// Our own shutdown cancelled the context. That is not a peer rejection and
		// must not be counted as one, or every restart would show a spike of
		// authentication failures that never happened.
		if errors.Is(err, context.Canceled) && l.closed() {
			return false
		}
		// Two reasons, both derived from the error's TYPE, never its text: a stalled
		// or silent client (tls_timeout) versus every other handshake-layer refusal —
		// missing/invalid/expired client certificate, unknown CA, protocol or cipher
		// mismatch (tls_auth_failed). The distinction is what separates "a sender is
		// misconfigured" from "a sender cannot reach us in time"; the specifics stay
		// in the log, where unbounded strings are safe (#399).
		//
		// Both reasons are passed as LITERALS rather than through the reason variable:
		// the vocabulary guard (TestReceiverVocabulariesMatchCallSites) reads the AST,
		// so a variable argument reads to it as "no call site can produce this" and
		// the pre-initialised zero series would quietly become a lie.
		reason := "tls_auth_failed"
		if isTimeoutErr(err) {
			reason = "tls_timeout"
			l.m.Reject("tls_timeout")
		} else {
			l.m.Reject("tls_auth_failed")
		}
		if l.logRefusal(refusalTLSHandshake) {
			l.log.Warn("syslog: TLS handshake failed", "peer", peer.String(),
				"reason", reason, "err", err, "log_throttle", refusalLogEvery.String())
		}
		return false
	}
	// Clear it again: serveConn drives its own per-frame idle deadline, and leaving the
	// handshake's short one in place would cut a healthy stream off mid-flight.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		// Same local-failure class as the deadline that was set above: proceeding
		// would hand serveConn a connection still carrying the short handshake
		// deadline, cutting a healthy stream off mid-stream.
		l.rejectDeadline(err)
		return false
	}
	return true
}

// rejectDeadline counts and (throttled) logs a failure of the listener's OWN
// SetDeadline calls around the TLS handshake.
func (l *Listener) rejectDeadline(err error) {
	l.m.Reject("tls_deadline_error")
	if l.logRefusal(refusalTLSDeadline) {
		l.log.Warn("syslog: TLS handshake deadline could not be set",
			"err", err, "log_throttle", refusalLogEvery.String())
	}
}

// isTimeoutErr reports whether err is a deadline/timeout rather than a refusal. All
// three forms occur here: the socket deadline surfaces as os.ErrDeadlineExceeded,
// the handshake context as context.DeadlineExceeded, and anything wrapping a
// net.Error reports it through Timeout().
func isTimeoutErr(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// serveConn reads framed messages from one connection. The read deadline is
// refreshed PER FRAME: an idle peer must not pin a goroutine forever, but a busy
// one is never cut off mid-stream.
//
// It takes net.Conn (not *net.TCPConn) so the SAME framing/assembly path serves
// both plain TCP and TLS: a *tls.Conn from serveTLS satisfies net.Conn, and its
// SetReadDeadline drives the same idle-deadline machinery. A TLS connection has
// already completed its handshake by the time it gets here (see handshake), so a
// client-cert failure never reaches this loop — it is refused, and its slot released,
// before serveConn is called at all.
func (l *Listener) serveConn(conn net.Conn, peer netip.Addr) {
	// Unblock the read when the listener closes, so a connection goroutine can never
	// outlive Close().
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-l.closing:
			_ = conn.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()

	fs := newFrameSplitter(func() { l.m.Reject("oversized") })
	sc := bufio.NewScanner(conn)
	// The max token size must EXCEED maxMessageBytes: a nominally-legal cap-sized
	// payload still arrives with framing overhead riding alongside it (an
	// octet-count prefix or a newline delimiter), and a scanner sized to exactly
	// the payload cap can trip bufio.ErrTooLong on that overhead alone (#398).
	sc.Buffer(make([]byte, 0, 4096), maxMessageBytes+scannerHeadroom)
	sc.Split(fs.splitFunc())

	// Multi-line messages arrive as several newline-framed lines and must be rejoined
	// before they are parsed (see assembler). An over-cap assembled message is counted
	// as oversized, exactly like an over-cap frame: same condition, same reason.
	asm := newAssembler(
		func(msg []byte) { l.handle(msg, peer) },
		func() { l.m.Reject("oversized") },
	)
	defer asm.close() // the last message has no successor to complete it

	// A pending message is only proven complete by the NEXT header, so on a quiet
	// connection the final line would otherwise sit in the assembler indefinitely.
	// This ticker bounds that wait. It joins l.conns so Close() waits for it and it
	// can never call handle after the listener has shut down.
	tickerDone := make(chan struct{})
	defer close(tickerDone)
	l.conns.Add(1)
	go func() {
		defer l.conns.Done()
		t := time.NewTicker(continuationWait)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				asm.flushIdle(continuationWait)
			case <-tickerDone:
				return
			}
		}
	}()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(connIdleTimeout)); err != nil {
			return
		}
		if !sc.Scan() {
			if err := sc.Err(); err != nil && !l.closed() && !errors.Is(err, net.ErrClosed) {
				l.log.Debug("syslog: TCP connection ended", "peer", peer.String(), "err", err)
			}
			return
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		asm.add(line, fs.octet)
	}
}

func peerAddr(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}
