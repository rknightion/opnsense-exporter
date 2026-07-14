package syslog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// defaultMaxConns caps concurrent TCP connections. Syslog is an unauthenticated
// ingress: unbounded goroutines with no read deadline is textbook slowloris.
const defaultMaxConns = 64

// connIdleTimeout is refreshed per frame, so an idle peer cannot pin a goroutine
// forever, but a busy one is never cut off.
const connIdleTimeout = 5 * time.Minute

// Config configures the receiver's sockets. An empty address disables that
// transport. AllowedPeers, when non-empty, is an allowlist: anything else is
// dropped and counted (syslog is unauthenticated — whatever can reach the port can
// inject records).
type Config struct {
	UDPAddr, TCPAddr string
	AllowedPeers     []netip.Prefix
	MaxConns         int
}

// Listener is a hardened UDP + TCP syslog receiver. It hands each framed line to
// handle on the receiving goroutine — handle must not block and must not retain
// the line buffer.
type Listener struct {
	cfg    Config
	handle func(line []byte, peer netip.Addr)
	m      *Metrics
	log    *slog.Logger

	udp *net.UDPConn
	tcp *net.TCPListener

	sem     chan struct{}
	conns   sync.WaitGroup
	closing chan struct{}
	once    sync.Once
	closeMu sync.Mutex
	closeCh error
}

// NewListener builds a listener. The handler is fixed at construction; there is no
// SetHandler. m may be nil.
func NewListener(cfg Config, handle func(line []byte, peer netip.Addr), m *Metrics, log *slog.Logger) *Listener {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}
	if log == nil {
		log = slog.Default()
	}
	return &Listener{
		cfg:     cfg,
		handle:  handle,
		m:       m,
		log:     log,
		sem:     make(chan struct{}, cfg.MaxConns),
		closing: make(chan struct{}),
	}
}

// Start binds both sockets EAGERLY, so a bad or in-use port is a startup error
// rather than a silently dead receiver. The resolved addresses (for ":0") are
// available from UDPAddr/TCPAddr afterwards.
func (l *Listener) Start() error {
	if l.cfg.UDPAddr == "" && l.cfg.TCPAddr == "" {
		return errors.New("syslog: no listen address configured (both UDP and TCP are empty)")
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
	return nil
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
			l.m.reject("peer")
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
			l.m.reject("peer")
			_ = conn.Close()
			continue
		}

		select {
		case l.sem <- struct{}{}:
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
			defer func() { <-l.sem }()
			defer func() { _ = conn.Close() }()
			l.serveConn(conn, peer)
		}()
	}
}

// serveConn reads framed messages from one connection. The read deadline is
// refreshed PER FRAME: an idle peer must not pin a goroutine forever, but a busy
// one is never cut off mid-stream.
func (l *Listener) serveConn(conn *net.TCPConn, peer netip.Addr) {
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

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), maxMessageBytes)
	sc.Split(newFrameSplitter(func() { l.m.reject("oversized") }))

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
		l.handle(line, peer)
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
