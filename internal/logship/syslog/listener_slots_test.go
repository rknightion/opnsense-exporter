package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// #328: tls.NewListener is lazy, so a connection accepted on the TLS port has NOT
// handshaked yet — it only does so on the first read inside serveConn, whose single
// deadline is the 5-minute idle timeout. An unauthenticated peer that connects and
// then says nothing must not be able to hold a capacity slot for minutes: the
// handshake gets its own short deadline, after which the slot is released.
func TestTLSSlotReleasedWhenHandshakeNeverCompletes(t *testing.T) {
	c := newCollector()
	cert, _, srvCert := selfSignedCert(t, "syslog-server")
	l := startListener(t, Config{
		// The harness also binds plain UDP+TCP on ephemeral ports (it defaults them when
		// both are empty); nothing here ever dials those.
		TLSAddr:             "127.0.0.1:0",
		TLSConfig:           &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		MaxConns:            1,
		TLSHandshakeTimeout: 250 * time.Millisecond,
	}, c.handle, nil)

	// A peer that connects and never handshakes. Pre-fix this pins the only slot for
	// connIdleTimeout (5 minutes).
	silent, err := net.Dial("tcp", l.TLSAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = silent.Close() }()

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// Retry until the pre-auth connection's handshake deadline frees the slot. Every
	// attempt before that is refused at accept (the listener closes it), so the retry
	// loop is what distinguishes "released promptly" from "held for minutes".
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("a connection that never handshaked held the only TLS slot for 5s — the pre-auth deadline is not enforced")
		}
		conn, derr := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
		if derr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if _, werr := conn.Write([]byte("<134>hello tls\n")); werr != nil {
			_ = conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case got := <-c.ch:
			_ = conn.Close()
			if got != "<134>hello tls" {
				t.Fatalf("got %q, want the legitimate TLS line", got)
			}
			return
		case <-time.After(500 * time.Millisecond):
			_ = conn.Close()
		}
	}
}

// #328 (second half): the connection semaphore was SHARED between plain TCP and TLS,
// so a plaintext flood — which needs no credentials at all — starved the mTLS senders
// the operator actually trusts. Each transport must have its own budget.
func TestPlainTCPFloodCannotExhaustTLSBudget(t *testing.T) {
	c := newCollector()
	cert, _, srvCert := selfSignedCert(t, "syslog-server")
	l := startListener(t, Config{
		TCPAddr:   "127.0.0.1:0",
		TLSAddr:   "127.0.0.1:0",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		MaxConns:  1,
	}, c.handle, nil)

	// Fill the plain-TCP budget and keep it filled: the connection stays open.
	flood, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer func() { _ = flood.Close() }()
	if _, err := flood.Write([]byte("<134>tcp flood\n")); err != nil {
		t.Fatalf("write tcp: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != "<134>tcp flood" {
		t.Fatalf("got %q, want the TCP line", got)
	}

	// The TCP budget really is full: a second plaintext connection is refused.
	second, err := net.Dial("tcp", l.TCPAddr())
	if err != nil {
		t.Fatalf("dial tcp 2: %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := second.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("the over-cap plaintext connection should have been closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the over-cap plaintext connection was left open — MaxConns is not enforced on TCP")
	}

	// And yet an mTLS sender still gets in.
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	conn, err := tls.Dial("tcp", l.TLSAddr(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls dial: %v (a plaintext flood consumed the TLS budget)", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<134>hello tls\n")); err != nil {
		t.Fatalf("write tls: %v", err)
	}
	if got := c.await(t, 3*time.Second); got != "<134>hello tls" {
		t.Fatalf("got %q, want the TLS line delivered despite a full TCP budget", got)
	}
}
