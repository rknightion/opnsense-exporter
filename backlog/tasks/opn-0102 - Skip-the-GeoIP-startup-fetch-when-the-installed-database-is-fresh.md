---
id: OPN-0102
title: Skip the GeoIP startup fetch when the installed database is fresh
status: To Do
assignee: []
created_date: '2026-09-06 14:30'
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
- [ ] #1 A start with an installed database for every configured edition whose last successful check (not build time) is younger than --geoip.download.interval makes no request to MaxMind, and the log says why the startup pass was skipped
- [ ] #2 A start with a missing edition, or one whose last check is older than the interval, still fetches at startup as today
- [ ] #3 The "last checked" state survives a restart on a persisted --geoip.download.dir and is not confused with the file mtime, which Fetch deliberately sets to the server Last-Modified
- [ ] #4 An HTTP 429 is counted under its own reason label on the download counters and is not retried before the next interval
- [ ] #5 docs/geoip.md states the startup behaviour and that a 429 on start indicates quota exhaustion, not a broken key
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
