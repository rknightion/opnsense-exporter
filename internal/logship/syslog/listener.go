package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// defaultMaxConns caps concurrent TCP connections. Syslog is an unauthenticated
// ingress: unbounded goroutines with no read deadline is textbook slowloris.
const defaultMaxConns = 64

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

// Config configures the receiver's sockets. An empty address disables that
// transport. AllowedPeers, when non-empty, is an allowlist: anything else is
// dropped and counted (syslog is unauthenticated — whatever can reach the port can
// inject records).
type Config struct {
	UDPAddr, TCPAddr string
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
}

// Listener is a hardened UDP + TCP syslog receiver. It hands each framed line to
// handle on the receiving goroutine — handle must not block and must not retain
// the line buffer.
type Listener struct {
	cfg    Config
	handle func(line []byte, peer netip.Addr)
	m      *logship.ReceiverMetrics
	log    *slog.Logger

	udp   *net.UDPConn
	tcp   *net.TCPListener
	tlsLn net.Listener

	// tcpSem and tlsSem are SEPARATE budgets, deliberately. They were one shared
	// semaphore, which meant a plaintext flood — needing no credentials whatsoever —
	// consumed the very slots the operator's mTLS senders depend on, so the
	// authenticated transport could be starved by the unauthenticated one (#328).
	// Separate budgets over a reserved share: a reservation still lets plaintext take
	// the unreserved remainder of a shared pool, and there is no reason the two
	// transports should compete at all. MaxConns is therefore per transport.
	tcpSem  chan struct{}
	tlsSem  chan struct{}
	conns   sync.WaitGroup
	closing chan struct{}
	once    sync.Once
	closeMu sync.Mutex
	closeCh error
}

// NewListener builds a listener. The handler is fixed at construction; there is no
// SetHandler. m may be nil.
func NewListener(cfg Config, handle func(line []byte, peer netip.Addr), m *logship.ReceiverMetrics, log *slog.Logger) *Listener {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if cfg.TLSHandshakeTimeout <= 0 {
		cfg.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	return &Listener{
		cfg:     cfg,
		handle:  handle,
		m:       m,
		log:     log,
		tcpSem:  make(chan struct{}, cfg.MaxConns),
		tlsSem:  make(chan struct{}, cfg.MaxConns),
		closing: make(chan struct{}),
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
	<-watchdogDone
}

// Close shuts the sockets and waits for every in-flight connection goroutine. It is
// sync.Once-guarded and safe to call repeatedly.
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closing)
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

// serveUDP reads datagrams: one datagram is one message, no framing.
func (l *Listener) serveUDP() {
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
		l.handle(buf[:n], peer)
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
		default:
			// At the connection cap: refuse rather than fork an unbounded goroutine.
			l.log.Warn("syslog: TCP connection limit reached, refusing peer",
				"peer", peer.String(), "max_conns", l.cfg.MaxConns)
			_ = conn.Close()
			continue
		}

		l.conns.Add(1)
		go func() {
			defer l.conns.Done()
			defer func() { <-l.tcpSem }()
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
		default:
			// At the connection cap: refuse rather than fork an unbounded goroutine.
			l.log.Warn("syslog: TLS connection limit reached, refusing peer",
				"peer", peer.String(), "max_conns", l.cfg.MaxConns)
			_ = conn.Close()
			continue
		}

		l.conns.Add(1)
		go func() {
			defer l.conns.Done()
			defer func() { <-l.tlsSem }()
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
		l.log.Debug("syslog: TLS handshake failed", "peer", peer.String(), "err", err)
		return false
	}
	// Clear it again: serveConn drives its own per-frame idle deadline, and leaving the
	// handshake's short one in place would cut a healthy stream off mid-flight.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return false
	}
	return true
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
