package syslog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense-exporter/internal/logship"
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
	m := logship.NewReceiverMetrics(reg, "syslog")
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
