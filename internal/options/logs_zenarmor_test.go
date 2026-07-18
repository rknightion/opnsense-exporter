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
	t.Cleanup(func() {
		*logsZenarmorEnabled, *logsZenarmorListenHTTP, *logsZenarmorFamilies = enabled, addr, families
		*logsZenarmorAuthUser, *logsZenarmorAuthPassword = user, pass
		*logsZenarmorTLSCertFile, *logsZenarmorTLSKeyFile = cert, key
		*logsZenarmorAllowedPeers, *logsZenarmorEnrich = peers, enrich
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
