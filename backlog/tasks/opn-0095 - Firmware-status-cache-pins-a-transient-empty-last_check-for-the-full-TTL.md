---
id: OPN-0095
title: Firmware-status cache pins a transient empty last_check for the full TTL
status: Done
assignee:
  - '@claude'
created_date: '2026-09-05 19:53'
updated_date: '2026-09-05 21:03'
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
- [x] #1 A firmware status response with an empty last_check is not replayed for the success TTL; the next poll fetches live (or a much shorter TTL applies and is documented)
- [x] #2 An operator can tell a cache-replayed firmware poll from a live fetch through exported metrics, either a clock that only advances on a real upstream fetch or an explicitly documented pairing of last_success with the cache-hit counter
- [x] #3 Regressions fail before the fix for both halves (cached empty last_check replay, and replay presented as fresh)
- [x] #4 The metric help text and docs/ for the firmware collector state the actual staleness contract; just docs regenerated
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Client owns admission: responseCache gains a per-endpoint success-body admission rule (cacheAdmissionRules keyed by endpoint name, wired in SetEndpointCacheTTL); put() refuses a 2xx body the rule rejects and stores nothing, so the next poll fetches live. firmware: refuse when last_check is empty. 2. Freshness: cache entries record storedAt; CacheSnapshot exposes StoredAt; the collector emits opnsense_exporter_api_cache_fetched_timestamp_seconds{endpoint} for every held success body (skipping expired entries); collector_last_success help text states it advances on a cache-served poll and names the pairing. Dashboard: API Cache Body Age table on the API Response Cache row; annotation ledger NOT_ANNOTATED entry. 3. Sweep every body-cached endpoint for the same shape against upstream controller source; add rules where a 200 can mean 'no result now': firmwareInfo (empty package list = pkg answered nothing), unboundLocalZones/LocalData/InsecureDomains (status failed = unbound-control unreachable), idsRulesets (empty rows = metadata call decoded to null). FetchUnboundLocalData also returns a partial-fetch error on status failed instead of counting zero. 4. Regressions failing-before for each; just check; source CodeRabbit; commit to main.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Failing-before evidence: TestClient_CacheRefusesFirmwareStatusWithoutLastCheck failed at 'a firmware body with an empty last_check must not be cached' (snapshot held the entry); TestCacheFetchedTimestampGaugeReportsHeldBodiesOnly failed with an empty series map; TestCacheAdmissionRulesRefuseInterimBodies failed 'no admission rule registered' for firmwareInfo, the three unbound diagnostics and idsRulesets; TestClient_CacheRefusesFailedUnboundDiagnostics failed with the status-failed body held in the cache; TestFetchUnboundLocalData_FailedStatusIsAnError failed 'expected an error ... got nil'. After: ok opnsense 3.990s, ok internal/collector 8.602s. First full gate failed only on the Grafana annotation ledger (new instant-valued metric needed a NOT_ANNOTATED entry); fixed. First CodeRabbit pass: 2 minor. Fixed: skip expired entries (Remaining <= 0) in the fetched-timestamp loop. Left: README metric-count wording is generated docgen text unrelated to this change.

Cache sweep (Rob 2026-09-05: validate no other issues like 724). Verified against upstream opnsense/core master controllers via WebFetch. Same shape, fixed here: firmwareInfo (FirmwareController::infoAction builds package[] and installed flags from firmware local; empty package list means pkg answered nothing), unboundLocalZones/unboundLocalData/unboundInsecureDomains (DiagnosticsController returns 200 {status: failed} without data when unbound-control is unreachable, which every Unbound reload triggers), idsRulesets (SettingsController::listRulesetsAction returns empty rows when the configd list decoded to null; the installable catalogue ships with core so it is never legitimately empty). Reviewed and left uncached-rule-free with reason: cpuType, systemInformation, dmidecodeInfo, certificates, caCertificates, acmeCertificates, unboundBlocklistPolicies, backupHistory, auth*, nat*, idsSettings, kea*/dnsmasqRanges, captivePortalVoucherProviders, netflowGetConfig/IsEnabled are configuration or inventory reads whose 200 is always the current state; snapshotsIsSupported/snapshotsSearch and torHiddenServices are static per box; clamavVersion and crowdsecVersion read version strings independent of the daemon state; firewallGeoIP reads a stats file that is legitimately absent until the first cron update, a real state rather than a transient one; interfacesOverview (60s) and firewallRuleIDs (1m) have TTLs too short for the class to matter.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Landed in 32a7509a on main. The response cache now has per-endpoint success-body admission rules (opnsense/cache.go cacheAdmissionRules, applied in put); a firmware status body with an empty last_check is decoded and served but never held, so the next poll fetches live (TestClient_CacheRefusesFirmwareStatusWithoutLastCheck failed before, passes after). New gauge opnsense_exporter_api_cache_fetched_timestamp_seconds{endpoint} reports when each held body was read off the firewall; collector_last_success help text states it advances on a cache-served poll and names the pairing; dashboard-health gains the API Cache Body Age table; annotation ledger entry added (TestCacheFetchedTimestampGaugeReportsHeldBodiesOnly failed before, passes after). Sweep of all body-cached endpoints against upstream controller source added the same rule to firmwareInfo (empty package list), unboundLocalZones/LocalData/InsecureDomains (status failed) and idsRulesets (empty rows), and FetchUnboundLocalData now returns a partial-fetch error on status failed instead of zero counts; three stale fieldaudit ledger entries removed because the Status fields are now read. Verification: ok opnsense, ok internal/collector, ok cmd/fieldaudit; full just check green through gen-check and vuln (Your code is affected by 0 vulnerabilities); CodeRabbit two passes, second review_completed with findings=0. Docs, dashboard and alert manifests regenerated and committed. GitHub issue 724 answered after the push.
<!-- SECTION:FINAL_SUMMARY:END -->
