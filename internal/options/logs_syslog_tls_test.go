package options

// Tests for buildSyslogServerTLS (#486). This function assembles the server-side
// *tls.Config for the TLS syslog listener from raw flag values, and is exercised
// nowhere else in the tree: internal/logship/syslog/listener_tls_test.go builds its
// own tls.Config literals by hand and only tests the listener's USE of a config, not
// this function's CONSTRUCTION of one. A wiring bug here -- most obviously omitting
// ClientAuth when a client-CA is configured -- would silently downgrade a configured
// mTLS listener to unauthenticated TLS while every other test in the repo stays
// green. See the mutation-test note on TestBuildSyslogServerTLS_MTLS below.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSelfSignedCert mints an ephemeral self-signed EC cert/key pair and writes
// both as PEM files under dir, returning their paths. Used as the server keypair.
func writeSelfSignedCert(t *testing.T, dir, prefix string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: prefix},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath = filepath.Join(dir, prefix+"-cert.pem")
	keyPath = filepath.Join(dir, prefix+"-key.pem")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

// writeCACert mints a self-signed CA-only cert (no matching private key needed by
// callers) and writes it as a PEM file, returning its path.
func writeCACert(t *testing.T, dir, prefix string) (caPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: prefix},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caPath = filepath.Join(dir, prefix+"-ca.pem")
	writePEM(t, caPath, "CERTIFICATE", der)
	return caPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode PEM %s: %v", path, err)
	}
}

// TestBuildSyslogServerTLS_NoListener proves that when no --logs.syslog.listen-tls
// address is configured, the function returns a nil config and no error -- TLS is
// simply not requested.
func TestBuildSyslogServerTLS_NoListener(t *testing.T) {
	tc, err := buildSyslogServerTLS("", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc != nil {
		t.Fatalf("expected nil *tls.Config when no TLS listener is configured, got %+v", tc)
	}
}

// TestBuildSyslogServerTLS_StrayFilesWithoutListener proves that setting cert/key/CA
// flags without a listen address is treated as a misconfiguration, not a silent
// no-op -- the whole point being that a user who thinks they configured TLS should
// see an error, not silently get plaintext.
func TestBuildSyslogServerTLS_StrayFilesWithoutListener(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")

	_, err := buildSyslogServerTLS("", certPath, keyPath, "")
	if err == nil {
		t.Fatal("expected an error for cert/key set without a TLS listen address")
	}
	if !strings.Contains(err.Error(), "listen-tls is empty") {
		t.Fatalf("expected error to name the missing listener, got: %v", err)
	}
}

// TestBuildSyslogServerTLS_MissingKeyPair proves that a listener address without
// both cert and key files is rejected before any file I/O is attempted, and that
// this is distinguishable from every other error branch by message.
func TestBuildSyslogServerTLS_MissingKeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")

	cases := []struct {
		name string
		cert string
		key  string
	}{
		{"no cert or key", "", ""},
		{"cert only", certPath, ""},
		{"key only", "", keyPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildSyslogServerTLS(":6514", tc.cert, tc.key, "")
			if err == nil {
				t.Fatal("expected an error for an incomplete cert/key pair")
			}
			if !strings.Contains(err.Error(), "requires both") {
				t.Fatalf("expected 'requires both' error, got: %v", err)
			}
		})
	}
}

// TestBuildSyslogServerTLS_CertLoadFailure proves that an unparseable cert/key pair
// (files exist but aren't valid PEM/X.509) is reported as a keypair load failure,
// distinguishable from the CA-file branch below.
func TestBuildSyslogServerTLS_CertLoadFailure(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad-cert.pem")
	badKey := filepath.Join(dir, "bad-key.pem")
	if err := os.WriteFile(badCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	if err := os.WriteFile(badKey, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}

	_, err := buildSyslogServerTLS(":6514", badCert, badKey, "")
	if err == nil {
		t.Fatal("expected an error for an unloadable TLS keypair")
	}
	if !strings.Contains(err.Error(), "load TLS keypair") {
		t.Fatalf("expected 'load TLS keypair' error, got: %v", err)
	}
}

// TestBuildSyslogServerTLS_CAFileUnreadable proves that a client-CA path pointing at
// a nonexistent file is reported as a CA read failure, distinguishable from a bad
// keypair and from an invalid-but-present CA file.
func TestBuildSyslogServerTLS_CAFileUnreadable(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")
	missingCA := filepath.Join(dir, "does-not-exist-ca.pem")

	_, err := buildSyslogServerTLS(":6514", certPath, keyPath, missingCA)
	if err == nil {
		t.Fatal("expected an error for an unreadable CA file")
	}
	if !strings.Contains(err.Error(), "read tls-client-ca-file") {
		t.Fatalf("expected 'read tls-client-ca-file' error, got: %v", err)
	}
}

// TestBuildSyslogServerTLS_CAFileInvalid proves that a client-CA file that exists
// but contains no valid PEM certificates is rejected with its own distinct message,
// not conflated with the unreadable-file case above.
func TestBuildSyslogServerTLS_CAFileInvalid(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("this is not PEM data"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}

	_, err := buildSyslogServerTLS(":6514", certPath, keyPath, badCA)
	if err == nil {
		t.Fatal("expected an error for an invalid CA file")
	}
	if !strings.Contains(err.Error(), "no valid certificates") {
		t.Fatalf("expected 'no valid certificates' error, got: %v", err)
	}
}

// TestBuildSyslogServerTLS_ServerOnly is the first of the two success shapes:
// server cert only, no client CA. This must produce TLS with NO client
// authentication -- ClientAuth must be tls.NoClientCert (its zero value), asserted
// explicitly so this shape is distinguishable from the mTLS shape below rather than
// merely "not erroring".
func TestBuildSyslogServerTLS_ServerOnly(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")

	tc, err := buildSyslogServerTLS(":6514", certPath, keyPath, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected a non-nil *tls.Config")
	}
	if tc.MinVersion != 0x0303 {
		t.Fatalf("expected MinVersion to be pinned at TLS 1.2 (0x0303), got %#x", tc.MinVersion)
	}
	if len(tc.Certificates) != 1 {
		t.Fatalf("expected exactly one server certificate, got %d", len(tc.Certificates))
	}
	if tc.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected ClientAuth to be tls.NoClientCert (0) with no client CA configured, got %v", tc.ClientAuth)
	}
	if tc.ClientCAs != nil {
		t.Fatalf("expected ClientCAs to be nil with no client CA configured, got %+v", tc.ClientCAs)
	}
}

// TestBuildSyslogServerTLS_MTLS is the second success shape and the one this issue
// exists for: server cert + client CA must enable mandatory client-cert
// verification. This is the assertion that would have caught the downgrade bug
// described in #486 (ClientCAs set but ClientAuth left at its zero value).
//
// Mutation-tested by hand: with the `tc.ClientAuth = tls.RequireAndVerifyClientCert`
// line in buildSyslogServerTLS temporarily commented out, this test failed with:
//
//	logs_syslog_tls_test.go:262: expected ClientAuth to be tls.RequireAndVerifyClientCert
//	(4) with a client CA configured (this is the mTLS downgrade this issue is about),
//	got 0
//
// confirming it actually exercises the branch. The source was restored immediately
// after (verified via `git diff` showing no changes to logs_syslog.go).
func TestBuildSyslogServerTLS_MTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir, "server")
	caPath := writeCACert(t, dir, "client")

	tc, err := buildSyslogServerTLS(":6514", certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected a non-nil *tls.Config")
	}
	if tc.MinVersion != 0x0303 {
		t.Fatalf("expected MinVersion to be pinned at TLS 1.2 (0x0303), got %#x", tc.MinVersion)
	}
	if tc.ClientCAs == nil {
		t.Fatal("expected ClientCAs to be set when a client CA file is configured")
	}
	if tc.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected ClientAuth to be tls.RequireAndVerifyClientCert (4) with a client CA "+
			"configured (this is the mTLS downgrade this issue is about), got %v", tc.ClientAuth)
	}
}
