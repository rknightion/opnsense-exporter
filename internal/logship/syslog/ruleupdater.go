package syslog

import (
	"regexp"
	"strconv"

	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
)

// rule-updater.py is OPNsense's Suricata ruleset downloader (#666). It is a
// separate program from suricata itself, but registry.go maps it into the
// same `ids` subsystem as the engine it feeds, so "everything IDS" reaches
// ruleset-freshness lines too.
//
// Every line this program can emit is a single syslog.syslog(...) call
// either in the driver script or in its lib/downloader.py helper. There is
// no JSON payload and no second shape to discriminate under the same
// program name the way suricata.go must for EVE-over-syslog: one program,
// one flat vocabulary.
//
// Two shapes are captured live (#666, camden capture archive,
// 2026-08-04 08:46 -> 2026-08-07 16:33 UTC):
//
//	download completed for https://rulesets.opnsense.org/suricata/opnsense.test.rules
//	version response for https://rules.emergingthreats.net/open/suricata-8.0/version.txt : 11249
//
// Nothing failed in the capture window, so the rest are read out of upstream
// source rather than captured (opnsense/core, master @ 99aa4bf, 2026-08-07):
//
//	download skipped <filename>, same version                            (src/opnsense/scripts/suricata/rule-updater.py:101)
//	download failed for <url> (<exception>)                               (src/opnsense/scripts/suricata/lib/downloader.py:114)
//	download failed for <url> (http_code: <n>)                            (src/opnsense/scripts/suricata/lib/downloader.py:133)
//	unsupported download type for <url>                                   (src/opnsense/scripts/suricata/lib/downloader.py:137)
//	cannot write to <path>                                                (src/opnsense/scripts/suricata/lib/downloader.py:201)
//	unable to read <path> from <filename> (decode error)                  (src/opnsense/scripts/suricata/lib/downloader.py:204)
//
// Attributes emitted:
//
//	ids.event            ruleset_downloaded | ruleset_version | ruleset_skipped |
//	                      ruleset_download_failed | ruleset_unsupported_type |
//	                      ruleset_write_failed | ruleset_decode_error
//	ids.ruleset_url       the feed URL, on every shape that carries one
//	ids.ruleset_version   the ET-style ruleset serial, when the version text parses as an integer
//	ids.ruleset_file      the ruleset filename, for the skipped-same-version line
//	ids.ruleset_path      the local install path, for the two on-disk failure lines
//	ids.http_status       the HTTP status code, for the http_code failure variant only
//
// The URL is a bounded set fixed by the operator's configured feeds (#666
// verdict), so it is safe as structured log metadata. This parser emits log
// attributes only — never a metric label, and never a derived counter.
//
// The free-form exception text in `download failed for <url> (<exception>)`
// is deliberately NOT captured as an attribute: Python's str(exception) is
// unbounded and can embed anything the underlying HTTP library chose to put
// there. It is exactly the kind of wire-adjacent free text this repo does
// not turn into a structured field. The raw line still ships in Body.
var (
	reRuleUpdaterDownloadCompleted = regexp.MustCompile(`^download completed for (\S+)$`)
	reRuleUpdaterVersionResponse   = regexp.MustCompile(`^version response for (\S+) : (.+)$`)
	reRuleUpdaterSkipped           = regexp.MustCompile(`^download skipped (\S+), same version$`)
	reRuleUpdaterFailedHTTP        = regexp.MustCompile(`^download failed for (\S+) \(http_code: (\d+)\)$`)
	reRuleUpdaterFailedGeneric     = regexp.MustCompile(`^download failed for (\S+) \(.+\)$`)
	reRuleUpdaterUnsupportedType   = regexp.MustCompile(`^unsupported download type for (\S+)$`)
	reRuleUpdaterCannotWrite       = regexp.MustCompile(`^cannot write to (.+)$`)
	reRuleUpdaterDecodeError       = regexp.MustCompile(`^unable to read (.+) from (.+) \(decode error\)$`)
)

func init() {
	RegisterParser(parseRuleUpdater, "rule-updater.py")
}

func parseRuleUpdater(env Envelope, _ *enrich.Snapshot, _ func(table string)) (logship.Record, bool) {
	if m := reRuleUpdaterDownloadCompleted.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_downloaded")
		set("ids.ruleset_url", m[1])
		return rec, true
	}
	if m := reRuleUpdaterVersionResponse.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_version")
		set("ids.ruleset_url", m[1])
		if _, err := strconv.Atoi(m[2]); err == nil {
			set("ids.ruleset_version", m[2])
		}
		return rec, true
	}
	if m := reRuleUpdaterSkipped.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_skipped")
		set("ids.ruleset_file", m[1])
		return rec, true
	}
	// The HTTP-status failure is a strict subset of the generic failure shape
	// (both are `download failed for <url> (...)`), so it MUST be tried
	// before reRuleUpdaterFailedGeneric or the generic pattern's `.+` would
	// win the match and the status code would never be extracted.
	if m := reRuleUpdaterFailedHTTP.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_download_failed")
		set("ids.ruleset_url", m[1])
		set("ids.http_status", m[2])
		return rec, true
	}
	if m := reRuleUpdaterFailedGeneric.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_download_failed")
		set("ids.ruleset_url", m[1])
		return rec, true
	}
	if m := reRuleUpdaterUnsupportedType.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_unsupported_type")
		set("ids.ruleset_url", m[1])
		return rec, true
	}
	if m := reRuleUpdaterCannotWrite.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_write_failed")
		set("ids.ruleset_path", m[1])
		return rec, true
	}
	if m := reRuleUpdaterDecodeError.FindStringSubmatch(env.Message); m != nil {
		rec, set := newRecord(env)
		set("ids.event", "ruleset_decode_error")
		set("ids.ruleset_path", m[1])
		return rec, true
	}
	return logship.Record{}, false
}
