package options

import (
	"strings"
	"testing"
)

// withZenarmorFlags sets flag values for one test and restores them after.
func withZenarmorFlags(t *testing.T, fn func()) {
	t.Helper()
	enabled, addr, families := *logsZenarmorEnabled, *logsZenarmorListenHTTP, *logsZenarmorFamilies
	user, pass := *logsZenarmorAuthUser, *logsZenarmorAuthPassword
	cert, key := *logsZenarmorTLSCertFile, *logsZenarmorTLSKeyFile
	peers, enrich := *logsZenarmorAllowedPeers, *logsZenarmorEnrich
	transport := *logsZenarmorTransport
	syslogEnabled, syslogPeers := *logsSyslogEnabled, *logsSyslogAllowedPeers
	syslogUDP, syslogTCP, syslogTLS := *logsSyslogListenUDP, *logsSyslogListenTCP, *logsSyslogListenTLS
	syslogClientCA := *logsSyslogTLSClientCAFile
	t.Cleanup(func() {
		*logsZenarmorEnabled, *logsZenarmorListenHTTP, *logsZenarmorFamilies = enabled, addr, families
		*logsZenarmorAuthUser, *logsZenarmorAuthPassword = user, pass
		*logsZenarmorTLSCertFile, *logsZenarmorTLSKeyFile = cert, key
		*logsZenarmorAllowedPeers, *logsZenarmorEnrich = peers, enrich
		*logsZenarmorTransport = transport
		*logsSyslogEnabled, *logsSyslogAllowedPeers = syslogEnabled, syslogPeers
		*logsSyslogListenUDP, *logsSyslogListenTCP, *logsSyslogListenTLS = syslogUDP, syslogTCP, syslogTLS
		*logsSyslogTLSClientCAFile = syslogClientCA
	})
	fn()
}

func TestLogsZenarmor_DisabledByDefault(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = false
		cfg, enabled, err := LogsZenarmor()
		if err != nil || enabled || cfg != nil {
			t.Fatalf("got (%v, %v, %v), want (nil, false, nil)", cfg, enabled, err)
		}
	})
}

// An unknown family must be an error, not a silent no-op: a typo would ship
// nothing for that family, which looks exactly like a quiet network.
func TestLogsZenarmor_RejectsUnknownFamily(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorFamilies = "conn,bogus"
		_, _, err := LogsZenarmor()
		if err == nil {
			t.Fatal("expected an error for an unknown family")
		}
		if !strings.Contains(err.Error(), "bogus") {
			t.Errorf("error should name the offending family, got: %v", err)
		}
	})
}

func TestLogsZenarmor_AcceptsEveryRealFamily(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorFamilies = "conn,dns,tls,http,alert,sip"
		cfg, enabled, err := LogsZenarmor()
		if err != nil || !enabled {
			t.Fatalf("got (%v, %v), want enabled with no error", enabled, err)
		}
		if len(cfg.Families) != 6 {
			t.Errorf("families = %v, want 6", cfg.Families)
		}
	})
}

func TestLogsZenarmor_EmptyListenAddrIsAnError(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ""
		if _, _, err := LogsZenarmor(); err == nil {
			t.Fatal("expected an error: an enabled receiver that binds nothing can never receive")
		}
	})
}

// A password with no username reads as "auth on" but leaves the ingress open.
func TestLogsZenarmor_PasswordWithoutUserIsAnError(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAuthUser = ""
		*logsZenarmorAuthPassword = "hunter2"
		if _, _, err := LogsZenarmor(); err == nil {
			t.Fatal("expected an error for a password with no username")
		}
	})
}

// #314: a username with no password reads as "auth on" too, but the receiver's
// constant-time comparison of an empty configured password against an empty
// client-supplied one succeeds — an auth bypass, not merely a misconfiguration.
func TestLogsZenarmor_UsernameWithoutPasswordIsAnError(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAuthUser = "admin"
		*logsZenarmorAuthPassword = ""
		if _, _, err := LogsZenarmor(); err == nil {
			t.Fatal("expected an error for a username with no password (auth bypass)")
		}
	})
}

func TestLogsZenarmor_AuthBothSetIsOK(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAuthUser = "admin"
		*logsZenarmorAuthPassword = "hunter2"
		if _, ok, err := LogsZenarmor(); err != nil || !ok {
			t.Fatalf("both auth fields set: got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
	})
}

func TestLogsZenarmor_AuthBothEmptyIsOK(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAuthUser = ""
		*logsZenarmorAuthPassword = ""
		if _, ok, err := LogsZenarmor(); err != nil || !ok {
			t.Fatalf("both auth fields empty (auth disabled): got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
	})
}

// #317: an enabled receiver with neither a peer allowlist nor authentication must
// warn (not fail) since open mode is a deliberate, documented option.
func TestLogsZenarmor_WarnsWhenNoAdmissionControl(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAllowedPeers = ""
		*logsZenarmorAuthUser = ""
		*logsZenarmorAuthPassword = ""
		cfg, ok, err := LogsZenarmor()
		if err != nil || !ok {
			t.Fatalf("got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings = %v, want exactly 1", cfg.Warnings)
		}
	})
}

func TestLogsZenarmor_NoWarningWithAllowlist(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAllowedPeers = "10.0.0.254/32"
		*logsZenarmorAuthUser = ""
		*logsZenarmorAuthPassword = ""
		cfg, ok, err := LogsZenarmor()
		if err != nil || !ok {
			t.Fatalf("got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("Warnings = %v, want none (allowlist set)", cfg.Warnings)
		}
	})
}

func TestLogsZenarmor_NoWarningWithAuth(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorAllowedPeers = ""
		*logsZenarmorAuthUser = "admin"
		*logsZenarmorAuthPassword = "hunter2"
		cfg, ok, err := LogsZenarmor()
		if err != nil || !ok {
			t.Fatalf("got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("Warnings = %v, want none (auth set)", cfg.Warnings)
		}
	})
}

func TestLogsZenarmor_SyslogEmptyParsedAllowlistStillWarns(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorTransport = "syslog"
		*logsSyslogEnabled = true
		*logsZenarmorAllowedPeers = ""
		*logsSyslogAllowedPeers = ","
		*logsSyslogListenUDP = ":5514"
		*logsSyslogListenTCP = ""
		*logsSyslogListenTLS = ""
		*logsSyslogTLSClientCAFile = ""
		cfg, ok, err := LogsZenarmor()
		if err != nil || !ok {
			t.Fatalf("got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
		if len(cfg.Warnings) != 1 {
			t.Fatalf("Warnings = %v, want exactly 1", cfg.Warnings)
		}
	})
}

func TestLogsZenarmor_SyslogExclusiveMTLSSuppressesWarning(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorTransport = "syslog"
		*logsSyslogEnabled = true
		*logsZenarmorAllowedPeers = ""
		*logsSyslogAllowedPeers = ""
		*logsSyslogListenUDP = ""
		*logsSyslogListenTCP = ""
		*logsSyslogListenTLS = ":6514"
		*logsSyslogTLSClientCAFile = "client-ca.pem"
		cfg, ok, err := LogsZenarmor()
		if err != nil || !ok {
			t.Fatalf("got ok=%v err=%v, want ok=true err=nil", ok, err)
		}
		if len(cfg.Warnings) != 0 {
			t.Fatalf("Warnings = %v, want none for exclusive mTLS", cfg.Warnings)
		}
	})
}

func TestLogsZenarmor_TLSHalfConfiguredIsAnError(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorListenHTTP = ":9200"
		*logsZenarmorTLSCertFile = "/nonexistent/cert.pem"
		*logsZenarmorTLSKeyFile = ""
		if _, _, err := LogsZenarmor(); err == nil {
			t.Fatal("expected an error: a cert without a key cannot serve TLS")
		}
	})
}

func TestLogsZenarmorTransport_Default(t *testing.T) {
	if got := LogsZenarmorTransport(); got != "elasticsearch" {
		t.Fatalf("default transport = %q, want elasticsearch", got)
	}
}

func TestLogsZenarmor_SyslogTransportSkipsListenValidation(t *testing.T) {
	// With transport=syslog, an empty listen-http must NOT be an error (no HTTP listener).
	// The syslog receiver must be enabled too, otherwise this now fails the
	// transport=syslog-requires-syslog-receiver check exercised separately below.
	*logsZenarmorEnabled = true
	*logsZenarmorTransport = "syslog"
	*logsZenarmorListenHTTP = ""
	*logsSyslogEnabled = true
	t.Cleanup(func() {
		*logsZenarmorEnabled = false
		*logsZenarmorTransport = "elasticsearch"
		*logsZenarmorListenHTTP = ":9200"
		*logsSyslogEnabled = false
	})
	_, ok, err := LogsZenarmor()
	if err != nil || !ok {
		t.Fatalf("syslog transport with empty listen-http: ok=%v err=%v, want ok/nil", ok, err)
	}
}

func TestLogsZenarmor_SyslogTransportRequiresSyslogEnabled(t *testing.T) {
	*logsZenarmorEnabled = true
	*logsZenarmorTransport = "syslog"
	*logsSyslogEnabled = false
	t.Cleanup(func() {
		*logsZenarmorEnabled = false
		*logsZenarmorTransport = "elasticsearch"
		*logsSyslogEnabled = false
	})
	if _, ok, err := LogsZenarmor(); err == nil || ok {
		t.Fatalf("transport=syslog without --logs.syslog.enabled: want error, got ok=%v err=%v", ok, err)
	}
}

func TestLogsZenarmor_SyslogTransportRejectsHTTPAuth(t *testing.T) {
	*logsZenarmorEnabled = true
	*logsZenarmorTransport = "syslog"
	*logsSyslogEnabled = true
	*logsZenarmorAuthUser = "user"
	*logsZenarmorAuthPassword = "pass"
	t.Cleanup(func() {
		*logsZenarmorEnabled = false
		*logsZenarmorTransport = "elasticsearch"
		*logsSyslogEnabled = false
		*logsZenarmorAuthUser, *logsZenarmorAuthPassword = "", ""
	})
	if _, _, err := LogsZenarmor(); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("syslog auth error = %v, want unsupported-auth error", err)
	}
}

func TestLogsZenarmor_RejectsUnknownTransport(t *testing.T) {
	*logsZenarmorEnabled = true
	*logsZenarmorTransport = "kafka"
	t.Cleanup(func() { *logsZenarmorEnabled = false; *logsZenarmorTransport = "elasticsearch" })
	if _, _, err := LogsZenarmor(); err == nil {
		t.Fatal("unknown transport: want error")
	}
}

// THE regression test for the enrichment gate.
//
// main.go's enrichment block used to be gated on `syslogEnabled && syslogCfg.Enrich`
// alone — the only thing that populates deps.Cache and deps.Miss. On a
// zenarmor-only box that left the cache nil, the receiver fell back to a cold one,
// and every interface/scope/service lookup missed FOREVER: no error, no log, no
// metric, while --logs.zenarmor.enrich defaulted to true and claimed otherwise.
//
// This asserts the predicate main.go now asks. If it regresses, enrichment silently
// stops working for the exact deployment this receiver was built for.
func TestLogsZenarmorEnrichWanted_GatesEnrichmentForAZenarmorOnlyBox(t *testing.T) {
	withZenarmorFlags(t, func() {
		*logsZenarmorEnabled = true
		*logsZenarmorEnrich = true
		if !LogsZenarmorEnrichWanted() {
			t.Error("a zenarmor-only box with enrich=true must want enrichment; " +
				"if this is false, main.go never builds the cache and every lookup misses silently")
		}

		*logsZenarmorEnrich = false
		if LogsZenarmorEnrichWanted() {
			t.Error("enrich=false must not request the refresher")
		}

		*logsZenarmorEnabled = false
		*logsZenarmorEnrich = true
		if LogsZenarmorEnrichWanted() {
			t.Error("a disabled receiver must not request the refresher")
		}
	})
}
