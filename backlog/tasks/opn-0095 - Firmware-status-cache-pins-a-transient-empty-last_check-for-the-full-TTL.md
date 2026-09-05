---
id: OPN-0095
title: Firmware-status cache pins a transient empty last_check for the full TTL
status: To Do
assignee: []
created_date: '2026-09-05 19:53'
labels:
  - bug
  - external-report
dependencies: []
references:
  - 'https://github.com/rknightion/opnsense2otel/issues/724'
priority: medium
ordinal: 49000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
External report, GitHub issue 724 (2026-08-31). Confirmed against source 2026-09-05. opnsense/core/firmware/status can return an empty last_check mid-check or right after the stored status is cleared. The response cache (opnsense/client.go:835 via cache.put) stores any 2xx body for the positive TTL regardless of content, and --exporter.firmware-cache-ttl defaults to 12h (internal/options/cache.go:31). The LastCheck gate at opnsense/firmware.go:401 then makes every check-dependent series absent (update_check_success, update_check_state, package_update_available, pending_download_bytes, major_upgrade_available) and last_check_timestamp_seconds read 0 for the whole TTL, even though a check completing seconds later on the firewall would have populated them. Separately, opnsense_exporter_collector_last_success_timestamp_seconds{collector="firmware"} advances on every clean poll (internal/collector/snapshot.go put, lastSuccess iff ok) including a poll served from cache, so a 12h-stale replay is indistinguishable from a live fetch through that metric. The reporter worked around it by lowering the TTL to 1h and guarding the 0 sentinel in alerting. Two defects: a payload that carries no check result must not be cached for the success TTL, and the freshness clock must not claim a live fetch for a replay. Fix in the shape the code already uses: the client owns cache admission, the collector owns the gate. Consider whether the answer for the freshness half is a cache-hit-aware clock or a documented statement that last_success means the poll, not the upstream fetch, with opnsense_exporter_api_cache_hits_total as the disambiguator; decide from what an operator can alert on.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A firmware status response with an empty last_check is not replayed for the success TTL; the next poll fetches live (or a much shorter TTL applies and is documented)
- [ ] #2 An operator can tell a cache-replayed firmware poll from a live fetch through exported metrics, either a clock that only advances on a real upstream fetch or an explicitly documented pairing of last_success with the cache-hit counter
- [ ] #3 Regressions fail before the fix for both halves (cached empty last_check replay, and replay presented as fresh)
- [ ] #4 The metric help text and docs/ for the firmware collector state the actual staleness contract; just docs regenerated
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
