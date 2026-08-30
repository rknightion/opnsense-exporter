---
id: OPN-0043
title: >-
  Dashboard polish: cert-expiry colour thresholds + DHCP leases-nearing-expiry
  view
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: low
type: enhancement
ordinal: 43000
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
