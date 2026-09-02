---
id: OPN-0043
title: >-
  Dashboard polish: cert-expiry colour thresholds + DHCP leases-nearing-expiry
  view
status: Parked
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 07:02'
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
- [ ] #1 Both panels updated; just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lower-priority dashboard polish because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands; author only in `grafana/tabs/` and regenerate the dashboard artifacts.
<!-- SECTION:NOTES:END -->
