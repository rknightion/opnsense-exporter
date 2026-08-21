package syslog

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestListenerShutdownDoesNotRaceConnRegistration walks a shutdown across the whole
// accept path, including the few instructions between serveTLS taking a slot and
// registering the connection on l.conns. Registering without the connMu ordering
// puts that Add on the 0->1 transition concurrently with Close's conns.Wait — a race
// the detector reports and, worse, a Close that can return while a connection
// goroutine is still live (#655). Run with -race or it proves nothing.
func TestListenerShutdownDoesNotRaceConnRegistration(t *testing.T) {
	_, _, srvCert := selfSignedCert(t, "syslog-server")
	for i := range 200 {
		l := NewListener(Config{
			TLSAddr:             "127.0.0.1:0",
			TLSConfig:           &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: time.Minute,
		}, func([]byte, netip.Addr) {}, newSyslogReceiverMetrics(prometheus.NewRegistry()), testLogger())
		if err := l.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); l.Run(ctx) }()

		conn, err := net.Dial("tcp", l.TLSAddr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		// Sweep the cancellation across the accept path in 5µs steps: the window is
		// only a handful of instructions wide, so a fixed delay would sit beside it.
		if d := time.Duration(i%40) * 5 * time.Microsecond; d > 0 {
			time.Sleep(d)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after context cancellation")
		}
		_ = conn.Close()
	}
}
