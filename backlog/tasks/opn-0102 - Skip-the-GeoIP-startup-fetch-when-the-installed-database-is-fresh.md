---
id: OPN-0102
title: Skip the GeoIP startup fetch when the installed database is fresh
status: Done
assignee:
  - '@claude-opus'
created_date: '2026-09-06 14:30'
updated_date: '2026-09-06 15:27'
labels: []
dependencies: []
priority: medium
type: bug
ordinal: 56000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Every container start runs an unconditional MaxMind fetch for each edition (internal/geoip/updater.go Run does a startup pass regardless of --geoip.download.interval). The request is conditional (If-Modified-Since from the installed file mtime, internal/geoip/maxmind.go Fetch) but MaxMind still counts it: on the camden deployment the persisted /var/lib/opnsense2otel/geoip volume already holds current GeoLite2-City and GeoLite2-ASN files, yet each start logs "geoip database download failed; keeping the installed database ... HTTP 429 Too Many Requests" for both editions. The container follows the :main watchtower fastlane so it restarts on every merge, and the licence key is shared with tailscale2otel on the same host, so startup fetches alone can exhaust the daily quota. A fresh installed database should cost no network request at all on start; the periodic pass is what should discover a newer build.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A start with an installed database for every configured edition whose last successful check (not build time) is younger than --geoip.download.interval makes no request to MaxMind, and the log says why the startup pass was skipped
- [x] #2 A start with a missing edition, or one whose last check is older than the interval, still fetches at startup as today
- [x] #3 The "last checked" state survives a restart on a persisted --geoip.download.dir and is not confused with the file mtime, which Fetch deliberately sets to the server Last-Modified
- [x] #4 An HTTP 429 is counted under its own reason label on the download counters and is not retried before the next interval
- [x] #5 docs/geoip.md states the startup behaviour and that a 429 on start indicates quota exhaustion, not a broken key
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add internal/geoip/checkstate.go: a JSON store at <--geoip.download.dir>/download-state.json holding {schema, editions{<edition>: {checked_at, result}}}. Written atomically (temp + rename, 0o600). Deliberately separate from the .mmdb mtime, which Fetch sets to MaxMind's Last-Modified (the BUILD time).

2. Add ErrRateLimited to internal/geoip/maxmind.go, returned wrapped when the download endpoint answers HTTP 429, so callers can tell quota exhaustion from a generic fetch failure.

3. Count 429 under its own result: stats.downloadsRateLimited + Stats.DownloadsRateLimited, emitted as opnsense_flow_geoip_downloads_total{result="rate_limited"} in internal/collector/flow.go. Existing updated/unmodified/failure values are unchanged.

4. Updater: new UpdaterOptions.DownloadDir. update() skips an edition when the database file exists at DatabasePath(dir, edition) AND the persisted checked_at is younger than DownloadInterval, logging edition, checked_at, last result and time until the next check. A recorded result of updated/unmodified/rate_limited defers; a transport or non-429 HTTP failure records nothing so the next start retries (it burns no quota).

5. Replace the download ticker with a timer reset to the earliest due edition, so a deferred startup pass still runs at checked_at+interval. A plain ticker plus a startup skip would mean a container restarting more often than the interval never downloads at all.

6. Wire DownloadDir in main.go's geoip setup.

7. Tests (extend internal/geoip/updater_test.go and maxmind_test.go): fresh state + installed file => zero fetches at start; missing file => fetch; stale state => fetch; 429 => ErrRateLimited, rate_limited counter, state written so a restart does not re-request.

8. Docs: hand-write the startup behaviour and the 429/quota note into docs/geoip.md; update the downloads_total help text and the stale-database runbook check line; run just docs / just rules and keep the regenerated diff. No new flag.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented. New file internal/geoip/checkstate.go; changed internal/geoip/{updater.go,maxmind.go,geoip.go}, internal/collector/flow.go, main.go, docs/geoip.md, grafana/alerts/build_rules.py, plus the regenerated docs/metrics/metrics.md and grafana/runbooks.md.

Persisted last-check design: <--geoip.download.dir>/download-state.json, {"schema":1,"editions":{"<edition>":{"checked_at":"<RFC3339 UTC>","result":"updated|unmodified|rate_limited"}}}, written temp+rename at 0o600. A .json name beside <Edition>.mmdb cannot be confused with a database, one document keeps the editions' records together, and every read failure (absent, truncated, unknown schema) degrades to empty state, which costs one fetch and never a startup failure. It is deliberately NOT the file mtime: Fetch stamps that with the server Last-Modified, so a current database routinely carries a mtime days old, and reusing it would re-download every start. A hand-replaced database is unaffected because the record only ever defers a NETWORK check, never a load - the reload tick still picks the file up.

Only outcomes where MaxMind actually answered are recorded (200/304/429). A transport error, 401 or 5xx records nothing, so the next start retries; none of those burn download quota, and deferring a blip would cost a day of updates.

Scheduling: the download ticker became a timer reset to the earliest due edition (Updater.nextDownloadDelay). With a plain ticker plus a startup skip, a container restarting more often than --geoip.download.interval would never download at all - the deferral would silently become a permanent skip. The first wake is now last_checked+interval (+1s of slack, because the record carries wall-clock seconds and the timer runs on the monotonic clock), clamped to (0, interval] so a state file dated in the future after a clock step cannot stall the updater.

Metric: opnsense_flow_geoip_downloads_total gains result="rate_limited" (HTTP 429), alongside the unchanged updated/unmodified/failure. New geoip.ErrRateLimited sentinel, wrapped by Downloader.get on 429, is what ObserveDownload and the updater branch on. A skipped check is counted under no result at all - no request was made - and the help text says so. Also updated the OPNsenseFlowGeoIPDatabaseStale runbook first-check line so a 429 is not read as a fetch failure.

No new flag; --geoip.download.interval and --geoip.download.dir carry the whole behaviour, so docs/configuration.md, .env.example and the deployment reference are untouched.

Tests (test-first: the skip test was written first and failed to compile, then failed with 'startup fetches = 1, want 0' once the state helpers existed but the deferral was stubbed out - re-verified by forcing deferCheck to return false, which reddened three of the new tests).

internal/geoip/updater_test.go: TestUpdaterSkipsTheStartupFetchWhenTheDatabaseWasCheckedRecently (also asserts the skip log names the edition, last_checked and next_check_in); TestUpdaterStillFetchesAtStartWhenTheDeferralDoesNotApply (table: database missing / check older than the interval / no record at all); TestUpdaterRecordsTheCheckSoTheNextStartSkipsIt (second Updater over the same persisted dir fetches nothing, and asserts the installed fixture's mtime is >24h old so the mtime alone could not have produced the skip); TestUpdaterCountsAndDefersARateLimitedDownload; TestUpdaterDoesNotDeferAfterAGenericFailure; TestUpdaterSchedulesTheNextCheckFromTheLastRecordedOne.
internal/geoip/maxmind_test.go: TestFetchReportsAnExhaustedDownloadLimit (fake server 429 => errors.Is(err, ErrRateLimited), nothing installed), via a new rateLimited flag on the existing maxmindServer harness.

Observed skip log:
time=... level=INFO msg="geoip database download skipped; MaxMind was already asked inside the download interval and the database is installed" edition=GeoLite2-Country last_checked=2026-09-06T14:06:15.000Z last_result=unmodified next_check_in=23h0m0s

Gate: 'just check' exit 0 (fmt-check, golangci-lint, go test -race ./..., metric-lint, fuzz-smoke, check-public-ips, testbed-test, canary-test, gitsync-test, grafana-test, gen-check, vuln). Tail:

  validated 1248 Prometheus targets, 125 variable queries, 22 annotation queries and 78 rule expressions
  python3 grafana/alerts/validate_manifests.py
  validated 80 grafana-managed manifests: OK
  .tools/govulncheck ./...
  No vulnerabilities found.

'just gen' was run; only docs/metrics/metrics.md (the downloads_total help text) and grafana/runbooks.md (the first-check line) moved. Note for whoever commits: the grafana-check leg diffs the regenerated grafana artifacts against the WORKING TREE index, so those files must be staged for it to pass locally - they are staged in this worktree.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
A start no longer asks MaxMind for an edition it already has and already checked inside --geoip.download.interval. A new per-edition record in <--geoip.download.dir>/download-state.json (checked_at + result, written temp+rename) carries the last answered check across restarts; it cannot be the .mmdb mtime, which Fetch stamps with the server Last-Modified and is therefore the BUILD time. HTTP 429 became its own error (geoip.ErrRateLimited), its own counter value (opnsense_flow_geoip_downloads_total{result="rate_limited"}) and its own log line, and it defers like a successful check because the quota is already spent. The download ticker became a timer aimed at last_checked+interval, so a container restarting more often than the interval still updates instead of deferring forever. Verified by seven new tests in internal/geoip (skip, the three still-fetch cases, restart persistence against a deliberately old mtime, 429 counting and deferral, the 429 fetch path, and the schedule), written test-first and confirmed red with the deferral disabled; 'just check' exits 0 and 'just gen' left only the regenerated help text and runbook line.

Updater keeps download-state.json in --geoip.download.dir recording when MaxMind last answered per edition (200/304/429); a start with an installed edition checked inside --geoip.download.interval makes no request and logs why. Repeat is a timer aimed at last_checked+interval so restart-heavy deployments still download. Transport/401/5xx record nothing and retry next start. HTTP 429 is ErrRateLimited, counted as opnsense_flow_geoip_downloads_total{result="rate_limited"}, deferred like a successful check; docs/geoip.md gained a startup section and the 429-means-quota note. Verified: 7 new updater/maxmind tests red-then-green, just check exit 0, CodeRabbit no findings on the geoip code. Landed as 015a2f10 on main.
<!-- SECTION:FINAL_SUMMARY:END -->
