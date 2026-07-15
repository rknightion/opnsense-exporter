package syslog

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// sshdSnapshot is the enrichment fixture for the sshd lane: 10.0.0.6 is the LAN
// laptop that originates the successful logins in the captured lines, 127.0.0.1
// is not in it (a loopback brute-force is "unknown host", which is normal).
func sshdSnapshot() *enrich.Snapshot {
	return &enrich.Snapshot{
		Hostnames: map[string]string{"10.0.0.6": "robs-laptop"},
		MACs:      map[string]string{"10.0.0.6": "aa:bb:cc:dd:ee:ff"},
		LocalNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
}

func sshdEnv(msg string) Envelope {
	return Envelope{
		Timestamp: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Hostname:  "opnsense",
		Program:   "sshd-session",
		PID:       "12345",
		Facility:  4, // auth
		Severity:  6, // info
		Message:   msg,
	}
}

// parseSSHDFor runs the parser the way BuildRecord does, so the test exercises
// registration too.
func mustParseSSHD(t *testing.T, msg string, snap *enrich.Snapshot) logship.Record {
	t.Helper()
	m := &missRecorder{}
	rec, ok := parseSSHD(sshdEnv(msg), snap, m.miss)
	if !ok {
		t.Fatalf("parseSSHD(%q) returned ok=false, want a structured record", msg)
	}
	if len(m.calls) != 0 {
		t.Fatalf("parseSSHD(%q) signalled enrichment misses %v; address lookups must never call miss()", msg, m.calls)
	}
	if rec.Body != msg {
		t.Errorf("Body = %q, want the raw message %q", rec.Body, msg)
	}
	return rec
}

func assertAttrs(t *testing.T, rec logship.Record, want map[string]string) {
	t.Helper()
	for k, v := range want {
		got, ok := rec.Attributes[k]
		if !ok {
			t.Errorf("attribute %q missing (got %v)", k, rec.Attributes)
			continue
		}
		if got != v {
			t.Errorf("attribute %q = %q, want %q", k, got, v)
		}
	}
}

func assertNoAttrs(t *testing.T, rec logship.Record, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := rec.Attributes[k]; ok {
			t.Errorf("attribute %q unexpectedly present = %q", k, v)
		}
	}
}

// TestSSHDRegistered guards the registry wiring: both program names OpenSSH uses
// on OPNsense (it renamed itself to sshd-session in 9.8) must dispatch here.
func TestSSHDRegistered(t *testing.T) {
	for _, prog := range []string{"sshd", "sshd-session"} {
		if _, ok := parserFor(prog); !ok {
			t.Errorf("no parser registered for program %q", prog)
		}
	}
}

// TestSSHDVerbatimLines covers every line captured verbatim from the live box,
// plus the "Accepted password" shape (no key fingerprint) OpenSSH emits when
// password auth is enabled.
func TestSSHDVerbatimLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
		none []string
	}{
		{
			name: "accepted publickey with fingerprint",
			msg:  "Accepted publickey for root from 10.0.0.6 port 34776 ssh2: ED25519 SHA256:bbpr/trEw6O5Z8tHHbOS9lGc2KQozzQIIYKQZkl/5EE",
			want: map[string]string{
				"auth.result":          "accepted",
				"auth.user":            "root",
				"user.name":            "root", // semconv dual-emit
				"auth.method":          "publickey",
				"auth.valid":           "true",
				"auth.key_type":        "ED25519",
				"auth.key_fingerprint": "SHA256:bbpr/trEw6O5Z8tHHbOS9lGc2KQozzQIIYKQZkl/5EE",
				"src.ip":               "10.0.0.6",
				"src.port":             "34776",
				"src.hostname":         "robs-laptop",
				"src.mac":              "aa:bb:cc:dd:ee:ff",
				"src.scope":            "local",
			},
		},
		{
			name: "accepted password has no fingerprint",
			msg:  "Accepted password for root from 10.0.0.6 port 34776 ssh2",
			want: map[string]string{
				"auth.result": "accepted",
				"auth.user":   "root",
				"auth.method": "password",
				"auth.valid":  "true",
				"src.ip":      "10.0.0.6",
				"src.port":    "34776",
			},
			none: []string{"auth.key_fingerprint", "auth.key_type"},
		},
		{
			name: "invalid user",
			msg:  "Invalid user nosuchuser_test from 127.0.0.1 port 36025",
			want: map[string]string{
				"auth.result": "invalid-user",
				"auth.user":   "nosuchuser_test",
				"auth.valid":  "false",
				"src.ip":      "127.0.0.1",
				"src.port":    "36025",
			},
			none: []string{"auth.method", "src.hostname"},
		},
		{
			name: "failed password for invalid user",
			msg:  "Failed password for invalid user nosuchuser_test from 127.0.0.1 port 36025 ssh2",
			want: map[string]string{
				"auth.result": "failed",
				"auth.user":   "nosuchuser_test",
				"auth.method": "password",
				"auth.valid":  "false",
				"src.ip":      "127.0.0.1",
				"src.port":    "36025",
			},
		},
		{
			name: "failed none for invalid user",
			msg:  "Failed none for invalid user nosuchuser_test from 127.0.0.1 port 36025 ssh2",
			want: map[string]string{
				"auth.result": "failed",
				"auth.user":   "nosuchuser_test",
				"auth.method": "none",
				"auth.valid":  "false",
				"src.ip":      "127.0.0.1",
				"src.port":    "36025",
			},
		},
		{
			name: "failed password for a real user",
			msg:  "Failed password for root from 10.0.0.6 port 34776 ssh2",
			want: map[string]string{
				"auth.result":  "failed",
				"auth.user":    "root",
				"auth.method":  "password",
				"auth.valid":   "true",
				"src.ip":       "10.0.0.6",
				"src.port":     "34776",
				"src.hostname": "robs-laptop",
			},
		},
		{
			name: "connection closed by invalid user",
			msg:  "Connection closed by invalid user nosuchuser_test 127.0.0.1 port 36025 [preauth]",
			want: map[string]string{
				"auth.result": "disconnected",
				"auth.user":   "nosuchuser_test",
				"auth.valid":  "false",
				"src.ip":      "127.0.0.1",
				"src.port":    "36025",
			},
		},
		{
			name: "connection closed by bare address",
			msg:  "Connection closed by 10.0.0.6 port 34776 [preauth]",
			want: map[string]string{
				"auth.result": "disconnected",
				"src.ip":      "10.0.0.6",
				"src.port":    "34776",
			},
			none: []string{"auth.user", "auth.valid"},
		},
		{
			name: "received disconnect",
			msg:  "Received disconnect from 10.0.0.6 port 59138:11: disconnected by user",
			want: map[string]string{
				"auth.result":  "disconnected",
				"src.ip":       "10.0.0.6",
				"src.port":     "59138",
				"src.hostname": "robs-laptop",
				"src.scope":    "local",
			},
			none: []string{"auth.user"},
		},
		{
			name: "disconnected from user",
			msg:  "Disconnected from user root 10.0.0.6 port 59138",
			want: map[string]string{
				"auth.result":  "disconnected",
				"auth.user":    "root",
				"auth.valid":   "true",
				"src.ip":       "10.0.0.6",
				"src.port":     "59138",
				"src.hostname": "robs-laptop",
			},
		},
		{
			name: "disconnected from invalid user",
			msg:  "Disconnected from invalid user nosuchuser_test 127.0.0.1 port 36025 [preauth]",
			want: map[string]string{
				"auth.result": "disconnected",
				"auth.user":   "nosuchuser_test",
				"auth.valid":  "false",
				"src.ip":      "127.0.0.1",
				"src.port":    "36025",
			},
		},
		{
			name: "disconnected from authenticating user",
			msg:  "Disconnected from authenticating user root 10.0.0.6 port 59138 [preauth]",
			want: map[string]string{
				"auth.result": "disconnected",
				"auth.user":   "root",
				"auth.valid":  "true",
				"src.ip":      "10.0.0.6",
				"src.port":    "59138",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := mustParseSSHD(t, tt.msg, sshdSnapshot())
			assertAttrs(t, rec, tt.want)
			assertNoAttrs(t, rec, tt.none...)
			// Envelope metadata rides along on every structured record.
			assertAttrs(t, rec, map[string]string{"program": "sshd-session", "host": "opnsense", "pid": "12345"})
		})
	}
}

// TestSSHDSeverity: a failed or invalid-user attempt is a security signal, so it
// is raised to Warn even though sshd logs it at syslog info.
func TestSSHDSeverity(t *testing.T) {
	tests := []struct {
		msg  string
		want logship.Severity
	}{
		{"Accepted publickey for root from 10.0.0.6 port 34776 ssh2: ED25519 SHA256:abc", logship.SeverityInfo},
		{"Failed password for invalid user x from 127.0.0.1 port 1 ssh2", logship.SeverityWarn},
		{"Invalid user x from 127.0.0.1 port 1", logship.SeverityWarn},
		{"Disconnected from user root 10.0.0.6 port 59138", logship.SeverityInfo},
	}
	for _, tt := range tests {
		rec := mustParseSSHD(t, tt.msg, sshdSnapshot())
		if rec.Severity != tt.want {
			t.Errorf("%q severity = %v, want %v", tt.msg, rec.Severity, tt.want)
		}
	}
}

// TestSSHDNilSnapshot: enrichment is best-effort. A nil snapshot must still yield
// a complete structured record, never a panic.
func TestSSHDNilSnapshot(t *testing.T) {
	rec := mustParseSSHD(t, "Accepted publickey for root from 10.0.0.6 port 34776 ssh2: ED25519 SHA256:abc", nil)
	assertAttrs(t, rec, map[string]string{
		"auth.result": "accepted",
		"auth.user":   "root",
		"src.ip":      "10.0.0.6",
	})
	assertNoAttrs(t, rec, "src.hostname", "src.mac", "src.scope")
}

// TestSSHDNilMiss: a nil miss callback must not panic either.
func TestSSHDNilMiss(t *testing.T) {
	if _, ok := parseSSHD(sshdEnv("Invalid user x from 127.0.0.1 port 1"), nil, nil); !ok {
		t.Fatal("parseSSHD returned ok=false on a known shape")
	}
}

// TestSSHDUnrecognised: anything that matches no shape returns ok=false so the
// caller degrades it to a generic record. Never a drop, never a panic.
func TestSSHDUnrecognised(t *testing.T) {
	lines := []string{
		"",
		"error: kex_exchange_identification: Connection closed by remote host",
		"Server listening on 0.0.0.0 port 22.",
		"pam_unix(sshd:session): session opened for user root(uid=0)",
		"Accepted",
		"Failed password for",
		"Connection closed by port",
		"Disconnected from",
		"Received disconnect from",
		"Invalid user",
		"\x00\xff garbage \xff\x00",
	}
	for _, msg := range lines {
		rec, ok := parseSSHD(sshdEnv(msg), sshdSnapshot(), func(string) {})
		if ok {
			t.Errorf("parseSSHD(%q) returned ok=true (attrs %v), want a generic fallback", msg, rec.Attributes)
		}
	}
}

// TestSSHDBuildRecordFallback: an unrecognised sshd line still ships, as a
// generic record with the raw body and the auth subsystem.
func TestSSHDBuildRecordFallback(t *testing.T) {
	const msg = "Server listening on 0.0.0.0 port 22."
	rec := BuildRecord(sshdEnv(msg), sshdSnapshot(), func(string) {})
	if rec.Body != msg {
		t.Errorf("Body = %q, want %q", rec.Body, msg)
	}
	assertAttrs(t, rec, map[string]string{"opnsense.subsystem": "auth", "program": "sshd-session"})
	assertNoAttrs(t, rec, "auth.result")
}

// TestSSHDBuildRecordStructured: a recognised line keeps its structure through
// BuildRecord and picks up the subsystem attribute.
func TestSSHDBuildRecordStructured(t *testing.T) {
	const msg = "Accepted publickey for root from 10.0.0.6 port 34776 ssh2: ED25519 SHA256:bbpr/trEw6O5Z8tHHbOS9lGc2KQozzQIIYKQZkl/5EE"
	rec := BuildRecord(sshdEnv(msg), sshdSnapshot(), func(string) {})
	assertAttrs(t, rec, map[string]string{
		"opnsense.subsystem":   "auth",
		"auth.result":          "accepted",
		"auth.key_fingerprint": "SHA256:bbpr/trEw6O5Z8tHHbOS9lGc2KQozzQIIYKQZkl/5EE",
		"src.ip":               "10.0.0.6",
	})
	// The parser resolved its own address, so BuildRecord must not re-scan the body
	// and emit it a second time under peer.*.
	assertNoAttrs(t, rec, "peer.ip", "peer.0.ip")
}
