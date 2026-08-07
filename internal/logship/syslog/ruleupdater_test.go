package syslog

import (
	"testing"
	"time"
)

// ruleUpdaterEnv builds an Envelope for program `rule-updater.py`, mirroring
// dpingerEnv's shape (dpinger_test.go).
func ruleUpdaterEnv(t *testing.T, message string) Envelope {
	t.Helper()
	env, err := ParseEnvelope([]byte(
		"<134>1 2026-08-05T08:46:00Z test-firewall rule-updater.py 314 - [meta sequenceId=\"sanitized-sequence\"] "+message,
	), time.Time{})
	if err != nil {
		t.Fatalf("ParseEnvelope() error = %v", err)
	}
	return env
}

func TestRuleUpdaterRegistered(t *testing.T) {
	if _, ok := parserFor("rule-updater.py"); !ok {
		t.Fatal("no parser registered for program rule-updater.py")
	}
}

func TestRuleUpdaterSubsystem(t *testing.T) {
	// #666: rule-updater.py belongs under the same subsystem as the engine
	// it feeds. registry.go owns the actual entry (frozen for this change);
	// this only pins the observable contract so a regression there is caught
	// from this package too.
	if got := subsystemFor("rule-updater.py"); got != "ids" {
		t.Errorf("subsystemFor(rule-updater.py) = %q, want %q", got, "ids")
	}
}

// TestRuleUpdaterCapturedLines exercises the two shapes captured live in the
// camden capture archive for #666 (2026-08-04 08:46 -> 2026-08-07 16:33 UTC).
// The lines themselves are verbatim from the issue body.
func TestRuleUpdaterCapturedLines(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			// Capture-derived (#666 issue body, shape 1): 36 entries across
			// 12 distinct feed URLs. This one is OPNsense's own ruleset feed.
			name: "download completed",
			msg:  "download completed for https://rulesets.opnsense.org/suricata/opnsense.test.rules",
			want: map[string]string{
				"ids.event":       "ruleset_downloaded",
				"ids.ruleset_url": "https://rulesets.opnsense.org/suricata/opnsense.test.rules",
			},
		},
		{
			// Capture-derived (#666 issue body, shape 1): the one non-.rules,
			// trailing-slash URL in the captured set (urlhaus).
			name: "download completed trailing slash URL",
			msg:  "download completed for https://urlhaus.abuse.ch/downloads/suricata-ids/",
			want: map[string]string{
				"ids.event":       "ruleset_downloaded",
				"ids.ruleset_url": "https://urlhaus.abuse.ch/downloads/suricata-ids/",
			},
		},
		{
			// Capture-derived (#666 issue body, shape 2): Emerging Threats'
			// own ruleset serial, confirmed by the issue to increment by 1
			// per day rather than being a timestamp, so it is expected to
			// parse cleanly as an integer.
			name: "version response",
			msg:  "version response for https://rules.emergingthreats.net/open/suricata-8.0/version.txt : 11249",
			want: map[string]string{
				"ids.event":           "ruleset_version",
				"ids.ruleset_url":     "https://rules.emergingthreats.net/open/suricata-8.0/version.txt",
				"ids.ruleset_version": "11249",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseRuleUpdater(ruleUpdaterEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseRuleUpdater(%q) returned ok=false", tc.msg)
			}
			if rec.Body != tc.msg {
				t.Errorf("Body = %q, want raw message %q", rec.Body, tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestRuleUpdaterSourceDerivedFailureBranches covers every failure verb
// rule-updater.py can emit that did NOT occur in the capture window (nothing
// failed during 2026-08-04 08:46 -> 2026-08-07 16:33 UTC). Each case is
// derived from upstream source, not captured, per the repo fixture rule
// ("a fixture must never encode a shape upstream cannot produce"):
// opnsense/core, master @ commit 99aa4bf4a14affe0b2f127c9543b7dc9b80a76e7,
// src/opnsense/scripts/suricata/{rule-updater.py,lib/downloader.py}.
func TestRuleUpdaterSourceDerivedFailureBranches(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want map[string]string
	}{
		{
			// Source-derived: rule-updater.py:101 —
			// `syslog.syslog(syslog.LOG_NOTICE, 'download skipped %s, same version' % rule['filename'])`
			// — the local hash of an already-installed ruleset file matched
			// the remote version hash, so no re-download happened. Not a
			// failure, but the third informational outcome (alongside
			// completed/version response) that answers "is this feed being
			// checked" even when there's nothing new to fetch.
			name: "download skipped, same version",
			msg:  "download skipped opnsense.test.rules, same version",
			want: map[string]string{
				"ids.event":        "ruleset_skipped",
				"ids.ruleset_file": "opnsense.test.rules",
			},
		},
		{
			// Source-derived: lib/downloader.py:114 —
			// `syslog.syslog(syslog.LOG_ERR, 'download failed for %s (%s)' % (url, e))`
			// — a requests.exceptions.RequestException (connection refused,
			// TLS failure, DNS failure, timeout, ...). `e`'s str() is
			// exception-library free text, so it is deliberately NOT
			// captured as an attribute (unbounded, wire-adjacent).
			name: "download failed, network exception",
			msg:  "download failed for https://feodotracker.abuse.ch/downloads/feodotracker.rules (HTTPSConnectionPool(host='feodotracker.abuse.ch', port=443): Max retries exceeded)",
			want: map[string]string{
				"ids.event":       "ruleset_download_failed",
				"ids.ruleset_url": "https://feodotracker.abuse.ch/downloads/feodotracker.rules",
			},
		},
		{
			// Source-derived: lib/downloader.py:133 —
			// `syslog.syslog(syslog.LOG_ERR, 'download failed for %s (http_code: %d)' % (url, req.status_code))`
			// — the feed responded but not with 200 (a lapsed ET
			// subscription, a 404'd abuse.ch path — exactly the "quietly
			// stops updating" scenario the issue names).
			name: "download failed, http status",
			msg:  "download failed for https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz (http_code: 403)",
			want: map[string]string{
				"ids.event":       "ruleset_download_failed",
				"ids.ruleset_url": "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
				"ids.http_status": "403",
			},
		},
		{
			// Source-derived: lib/downloader.py:137 —
			// `syslog.syslog(syslog.LOG_ERR, 'unsupported download type for %s' % (url))`
			// — a configured feed URL whose scheme is neither http nor
			// https (Downloader.is_supported only allows those two).
			name: "unsupported download type",
			msg:  "unsupported download type for ftp://example.invalid/rules.tar.gz",
			want: map[string]string{
				"ids.event":       "ruleset_unsupported_type",
				"ids.ruleset_url": "ftp://example.invalid/rules.tar.gz",
			},
		},
		{
			// Source-derived: lib/downloader.py:201 —
			// `syslog.syslog(syslog.LOG_ERR, 'cannot write to %s' % target_filename)`
			// — an IOError writing the downloaded ruleset to its install
			// path (disk full, permissions). No URL on this line, only the
			// local install path.
			name: "cannot write to disk",
			msg:  "cannot write to /usr/local/etc/suricata/rules/opnsense.test.rules",
			want: map[string]string{
				"ids.event":        "ruleset_write_failed",
				"ids.ruleset_path": "/usr/local/etc/suricata/rules/opnsense.test.rules",
			},
		},
		{
			// Source-derived: lib/downloader.py:204-206 —
			// `syslog.syslog(syslog.LOG_ERR, 'unable to read %s from %s (decode error)' % (target_filename, fetch_result['filename']))`
			// — the downloaded archive member could not be decoded as text
			// (a corrupt or unexpectedly binary feed response).
			name: "decode error",
			msg:  "unable to read /usr/local/etc/suricata/rules/opnsense.test.rules from opnsense.test.rules (decode error)",
			want: map[string]string{
				"ids.event":        "ruleset_decode_error",
				"ids.ruleset_path": "/usr/local/etc/suricata/rules/opnsense.test.rules",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := parseRuleUpdater(ruleUpdaterEnv(t, tc.msg), nil, func(string) {})
			if !ok {
				t.Fatalf("parseRuleUpdater(%q) returned ok=false", tc.msg)
			}
			assertAttrs(t, rec, tc.want)
		})
	}
}

// TestRuleUpdaterVersionResponseNonInteger pins the "additionally emits
// ids.ruleset_version as an integer" acceptance criterion on its negative
// side: the version text is Downloader.fetch_version_hash's raw decoded
// response body (lib/downloader.py:157-160), which is not guaranteed
// numeric for every feed — only ET's version.txt is known to be. A non-
// numeric response must still classify as ruleset_version and carry the URL,
// just without a ruleset_version attribute that would otherwise carry
// unparseable free text.
func TestRuleUpdaterVersionResponseNonInteger(t *testing.T) {
	msg := "version response for https://example.invalid/version.txt : not-a-number"
	rec, ok := parseRuleUpdater(ruleUpdaterEnv(t, msg), nil, func(string) {})
	if !ok {
		t.Fatalf("parseRuleUpdater(%q) returned ok=false", msg)
	}
	assertAttrs(t, rec, map[string]string{
		"ids.event":       "ruleset_version",
		"ids.ruleset_url": "https://example.invalid/version.txt",
	})
	assertNoAttrs(t, rec, "ids.ruleset_version")
}

// TestRuleUpdaterUnmatched proves an unrecognised rule-updater.py line falls
// through to a generic record rather than being dropped or panicking, per
// the registry.go Parser contract and the issue's explicit acceptance
// criterion.
func TestRuleUpdaterUnmatched(t *testing.T) {
	tests := []string{
		"",
		"some entirely unrelated line",
		"download completed",                  // missing " for <url>"
		"version response for https://x/y : ", // empty version text, generic still fails: "" does not satisfy `.+`
	}
	for _, msg := range tests {
		t.Run(msg, func(t *testing.T) {
			env := ruleUpdaterEnv(t, msg)
			if _, ok := parseRuleUpdater(env, nil, func(string) {}); ok {
				t.Fatalf("parseRuleUpdater(%q) unexpectedly matched", msg)
			}
		})
	}
}
