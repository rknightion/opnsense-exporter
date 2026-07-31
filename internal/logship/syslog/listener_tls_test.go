package syslog

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v4/internal/logship"
)

// selfSignedCert mints an ephemeral in-test CA/leaf (one and the same — it is its
// own parent) valid for 127.0.0.1. It returns the parsed cert (for a client's
// RootCAs/ClientCAs pool), the key (to sign a client cert off the same CA), and the
// tls.Certificate to hand a server or client.
func selfSignedCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// signedClientCert mints a leaf signed by the given CA cert/key, for client-auth
// tests.
func signedClientCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "syslog-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestListenerTLSDelivers(t *testing.T) {
	c := newCollector()
	cert, _, srvCert := selfSignedCert(t, "syslog-server")
	l := startListener(t, Config{
		TLSAddr:   "127.0.0.1:0",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
	}, c.handle, nil)

	// The startListener harness also binds plain UDP+TCP on ephemeral ports (it
	// defaults them when both are empty); that is harmless here — we only ever dial
	// the TLS port. What matters is that the TLS socket bound.
	if l.TLSAddr() == "" {
		t.Fatal("TLSAddr() is empty; the TLS socket did not bind")
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	conn, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	body := "<134>hello tls"
	// One newline-framed message: it ships on the assembler's idle flush.
	if _, err := conn.Write([]byte(body + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != body {
		t.Fatalf("got %q, want %q", got, body)
	}
}

func TestListenerTLSPeerAllowlist(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	cert, _, srvCert := selfSignedCert(t, "syslog-server")
	// 192.0.2.0/24 is TEST-NET-1: loopback is definitely outside it.
	l := startListener(t, Config{
		TLSAddr:      "127.0.0.1:0",
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		AllowedPeers: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}, c.handle, m)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	conn, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err == nil {
		// The peer is rejected at accept, before the handshake completes; a write may
		// still buffer locally, so we don't assert on Write, only on the counter.
		_, _ = conn.Write([]byte("<134>should be dropped\n"))
		defer func() { _ = conn.Close() }()
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
		t.Fatalf("a disallowed peer's line was delivered: %q", c.lines)
	}
}

// A server demanding a client cert must reject an anonymous client and accept one
// whose cert chains to the configured ClientCAs. The rejected handshake surfaces as
// a read error inside the scan loop and never reaches the handler.
func TestListenerTLSClientCertRequired(t *testing.T) {
	c := newCollector()
	caCert, caKey, srvCert := selfSignedCert(t, "syslog-server")
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCert)
	l := startListener(t, Config{
		TLSAddr: "127.0.0.1:0",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{srvCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS12,
		},
	}, c.handle, nil)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	// No client cert: the handshake fails, nothing is delivered.
	noCert, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12})
	if err == nil {
		if _, werr := noCert.Write([]byte("<134>no client cert\n")); werr == nil {
			// A write may succeed before the server aborts; a Read must then fail.
			_ = noCert.SetReadDeadline(time.Now().Add(time.Second))
			if _, rerr := noCert.Read(make([]byte, 1)); rerr == nil {
				t.Fatal("server accepted a client with no certificate")
			}
		}
		_ = noCert.Close()
	}
	select {
	case line := <-c.ch:
		t.Fatalf("a certless client's line was delivered: %q", line)
	case <-time.After(500 * time.Millisecond):
	}

	// A client cert signed by the CA: delivery works.
	clientCert := signedClientCert(t, caCert, caKey)
	ok, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls dial with client cert: %v", err)
	}
	defer func() { _ = ok.Close() }()
	body := "<134>authenticated"
	if _, err := ok.Write([]byte(body + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != body {
		t.Fatalf("got %q, want %q", got, body)
	}
}

// waitForCounter polls until a counter reaches want, or fails. The reject happens on
// the listener's accept goroutine, so there is no synchronisation point the test can
// observe directly.
func waitForCounter(t *testing.T, reg *prometheus.Registry, name, label, value string, want float64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if counterValue(t, reg, name, label, value) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s{%s=%q} = %v, want %v", name, label, value,
		counterValue(t, reg, name, label, value), want)
}

// #399: a failed pre-authentication TLS handshake was Debug-logged and NOTHING else,
// so a sender with an expired or wrong client certificate looked, on /metrics,
// exactly like a sender that had simply stopped sending. The vocabulary guard only
// proves the literal exists in the source; this proves the call site is reachable at
// runtime and classified as an auth failure rather than a timeout.
func TestListenerTLSHandshakeFailureCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	caCert, _, srvCert := selfSignedCert(t, "syslog-server")
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCert)
	l := startListener(t, Config{
		TLSAddr: "127.0.0.1:0",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{srvCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS12,
		},
	}, c.handle, m)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)
	conn, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: rootPool, MinVersion: tls.VersionTLS12})
	if err == nil {
		// The server may only abort after the client believes it is done; poke it.
		_, _ = conn.Write([]byte("<134>no client cert\n"))
		_ = conn.Close()
	}

	waitForCounter(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "tls_auth_failed", 1)
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "tls_timeout"); got != 0 {
		t.Fatalf("Rejected{tls_timeout} = %v, want 0 (a certificate refusal is not a timeout)", got)
	}
}

// The other half of the classification: a peer that opens the socket and then says
// nothing must be counted as a TIMEOUT, not as an authentication failure. Conflating
// the two would tell an operator to go looking at certificates when the real problem
// is a stalled or half-open network path (#399).
func TestListenerTLSHandshakeTimeoutCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{})
	c := newCollector()
	_, _, srvCert := selfSignedCert(t, "syslog-server")
	l := startListener(t, Config{
		TLSAddr:             "127.0.0.1:0",
		TLSConfig:           &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 250 * time.Millisecond,
	}, c.handle, m)

	silent, err := net.Dial("tcp", l.TLSAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = silent.Close() }()

	waitForCounter(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "tls_timeout", 1)
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "tls_auth_failed"); got != 0 {
		t.Fatalf("Rejected{tls_auth_failed} = %v, want 0 (a stalled peer is not a credential failure)", got)
	}
}

// metricHasLabel distinguishes a pre-initialised zero counter from an absent series.
func metricHasLabel(t *testing.T, reg *prometheus.Registry, name, label, value string) bool {
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
					return true
				}
			}
		}
	}
	return false
}

func newSyslogReceiverMetrics(reg *prometheus.Registry) *logship.ReceiverMetrics {
	return logship.NewReceiverMetrics(reg, "syslog", logship.ReceiverVocab{Reasons: RejectReasons})
}

// startTLSListener starts only the TLS transport, optionally retaining its structured
// logs for assertions. The tests use a real loopback listener so cap refusals cover
// the actual accept loop rather than a duplicate of its semaphore logic.
func startTLSListener(t *testing.T, cfg Config, h func([]byte, netip.Addr), m *logship.ReceiverMetrics, log *slog.Logger) *Listener {
	t.Helper()
	l := NewListener(cfg, h, m, log)
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Run(ctx)
	}()
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

// A TLS-cap refusal is an operational signal shared with the plaintext cap, and it
// must advance the pre-initialised conn_limit series exactly once per refused socket.
// This would fail if serveTLS stopped rejecting at the cap, used a transport-specific
// label, or double-counted a single refusal.
func TestListenerTLSConnLimitIncrementsPreinitializedCounterExactly(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newSyslogReceiverMetrics(reg)
	c := newCollector()
	cert, _, srvCert := selfSignedCert(t, "syslog-server")
	l := startTLSListener(t, Config{
		TLSAddr:   "127.0.0.1:0",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		MaxConns:  1,
	}, c.handle, m, testLogger())

	if !metricHasLabel(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit") {
		t.Fatal("Rejected{conn_limit} was not pre-initialised")
	}
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit"); got != 0 {
		t.Fatalf("initial Rejected{conn_limit} = %v, want 0", got)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	first, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("first TLS dial: %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := net.Dial("tcp", l.TLSAddr())
	if err != nil {
		t.Fatalf("second TCP dial: %v", err)
	}
	defer func() { _ = second.Close() }()

	waitForCounter(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit", 1)
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit"); got != 1 {
		t.Fatalf("Rejected{conn_limit} = %v, want 1", got)
	}
}

var errDeadlineFailure = errors.New("test local SetDeadline failure")

// deadlineFaultConn keeps every real net.Conn operation intact except the local
// SetDeadline syscall branch under test. It deliberately has no call-count
// assertions: the listener's observable result is the metric and refused handshake.
type deadlineFaultConn struct {
	net.Conn
	failSet   bool
	failClear bool
}

func (c *deadlineFaultConn) SetDeadline(deadline time.Time) error {
	if (!deadline.IsZero() && c.failSet) || (deadline.IsZero() && c.failClear) {
		return errDeadlineFailure
	}
	return c.Conn.SetDeadline(deadline)
}

// A failed SetDeadline before the handshake, or failed clearing of it after a
// successful handshake, is a listener-local failure. Neither can be attributed to
// a sender's credential or timeout, so both paths must increment tls_deadline_error.
func TestListenerTLSDeadlineFailuresAreCounted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failSet   bool
		failClear bool
		runClient bool
	}{
		{name: "set", failSet: true},
		{name: "clear", failClear: true, runClient: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			m := newSyslogReceiverMetrics(reg)
			_, _, srvCert := selfSignedCert(t, "syslog-server")
			l := NewListener(Config{
				TLSHandshakeTimeout: time.Second,
			}, func([]byte, netip.Addr) {}, m, testLogger())

			serverRaw, clientRaw := net.Pipe()
			defer func() { _ = serverRaw.Close() }()
			defer func() { _ = clientRaw.Close() }()
			server := tls.Server(&deadlineFaultConn{
				Conn:      serverRaw,
				failSet:   tc.failSet,
				failClear: tc.failClear,
			}, &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12})

			result := make(chan bool, 1)
			go func() { result <- l.handshake(server, netip.MustParseAddr("127.0.0.1")) }()
			if tc.runClient {
				client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- in-memory test peer
				if err := client.Handshake(); err != nil {
					t.Fatalf("client handshake: %v", err)
				}
			}
			select {
			case ok := <-result:
				if ok {
					t.Fatal("handshake succeeded despite a local deadline failure")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("handshake did not return after local deadline failure")
			}

			if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "tls_deadline_error"); got != 1 {
				t.Fatalf("Rejected{tls_deadline_error} = %v, want 1", got)
			}
			for _, reason := range []string{"tls_auth_failed", "tls_timeout"} {
				if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", reason); got != 0 {
					t.Fatalf("Rejected{%s} = %v, want 0", reason, got)
				}
			}
		})
	}
}

// context cancellation is an exporter shutdown, not a refusal by the peer. The
// raw loopback connection makes the TLS server block in its real handshake, while
// the semaphore confirms it was accepted before the Run context is cancelled.
func TestListenerTLSShutdownCancellationDoesNotCountRejection(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newSyslogReceiverMetrics(reg)
	_, _, srvCert := selfSignedCert(t, "syslog-server")
	l := NewListener(Config{
		TLSAddr:             "127.0.0.1:0",
		TLSConfig:           &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: time.Minute,
	}, func([]byte, netip.Addr) {}, m, testLogger())
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Run(ctx)
	}()

	silent, err := net.Dial("tcp", l.TLSAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = silent.Close() }()

	deadline := time.Now().Add(3 * time.Second)
	for len(l.tlsSem) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(l.tlsSem) != 1 {
		t.Fatal("TLS connection did not enter the handshake before shutdown")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
	for _, reason := range []string{"tls_auth_failed", "tls_timeout", "tls_deadline_error"} {
		if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", reason); got != 0 {
			t.Fatalf("Rejected{%s} = %v, want 0 during shutdown", reason, got)
		}
	}
}

type lockedLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// Repeated cap refusals must remain fully counted but emit one throttled breadcrumb,
// not one warning per attacker-controlled connection. This would fail if the accept
// loop logged every refusal or stopped counting them while throttling the logs.
func TestListenerTLSRefusalLogsAreThrottled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newSyslogReceiverMetrics(reg)
	c := newCollector()
	cert, _, srvCert := selfSignedCert(t, "syslog-server")
	logs := &lockedLogBuffer{}
	l := startTLSListener(t, Config{
		TLSAddr:   "127.0.0.1:0",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		MaxConns:  1,
	}, c.handle, m, slog.New(slog.NewTextHandler(logs, nil)))

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	first, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("first TLS dial: %v", err)
	}
	defer func() { _ = first.Close() }()

	const refused = 5
	for range refused {
		conn, err := net.Dial("tcp", l.TLSAddr())
		if err != nil {
			t.Fatalf("refused TCP dial: %v", err)
		}
		_ = conn.Close()
	}
	waitForCounter(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit", refused)
	if got := counterValue(t, reg, "opnsense_exporter_logs_rejected_total", "reason", "conn_limit"); got != refused {
		t.Fatalf("Rejected{conn_limit} = %v, want %d", got, refused)
	}
	if got := strings.Count(logs.String(), "TLS connection limit reached"); got != 1 {
		t.Fatalf("TLS connection-limit warning count = %d, want 1 for %d refusals", got, refused)
	}
}
