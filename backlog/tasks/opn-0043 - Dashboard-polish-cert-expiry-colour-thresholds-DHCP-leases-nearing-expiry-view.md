---
id: OPN-0043
title: >-
  Dashboard polish: cert-expiry colour thresholds + DHCP leases-nearing-expiry
  view
status: Done
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-03 07:11'
labels: []
milestone: m-4
dependencies: []
priority: low
type: enhancement
ordinal: 509
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Colour thresholds on Certificate Expiry days-left (`grafana/tabs/certificates.py:35-56`) and a leases-nearing-expiry view on the DHCP tab (`grafana/tabs/dhcp.py`).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Both panels updated; just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Convert certificate days-left to a threshold-coloured timeseries while preserving expired values, add a combined dnsmasq/Kea under-24-hour lease-expiry table gated on detail metrics, regenerate dashboard artifacts, validate the authored certificate blob against the completed Grafana review, run the full gate, and land as one task commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lower-priority dashboard polish because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands; author only in `grafana/tabs/` and regenerate the dashboard artifacts.

Unblocked 2026-09-02: OPN-0056 landed on main in `a482f637`. Author the certificate colour thresholds and the DHCP leases-nearing-expiry view in the tab modules, then regenerate.

Converted certificate days-left from a sorted table to a timeseries with explicit expired, 0-3, 3-14, 14-30, and 30-plus-day threshold colours while preserving negative expired values. Added a combined dnsmasq/Kea v4/Kea v6 leases-under-24-hours table with normalized backend labels; ISC is deliberately excluded because its lease_info value is not an expiry timestamp. The certificate authored blob exactly matches the completed phase1-grafana CodeRabbit review, and the DHCP source retains the already-landed reservation row while adding the reviewed expiry view. No bespoke unit test was added because this is declarative dashboard configuration; generation and repository Grafana/PromQL checks are the validation. just gen completed with 1,052/1,052 coverage and 179 schemas; just check passed with 427 Grafana tests and 1,209 Prometheus target validations.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added certificate-expiry colour bands and a backend-labelled dnsmasq/Kea leases-nearing-expiry table. Generated artifacts and the full just check gate passed.
<!-- SECTION:FINAL_SUMMARY:END -->
