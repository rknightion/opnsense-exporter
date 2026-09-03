---
id: OPN-0053
title: Restyle the embedded console onto design system v2 (family follower)
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-31 12:12'
updated_date: '2026-09-03 09:37'
labels:
  - design-system
dependencies: []
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The v2 design is committed at design/console-v2/: this repo's Console v2 canvas, opnsense2otel-implementation-spec.md, implementation-spec.md (THE FAMILY SPEC from tailscale2otel - its section 1 is the shared token block, byte-identical across tailscale2otel, opnsense2otel, graph2otel and codexlb2otel; copy it, never edit it per repo), and internal/webui/ holding a draft restyled page.html.tmpl - treat the draft as reference, not finished code. Read both specs in full before any code change.

Scope: Go html/template + inline CSS/vanilla JS + go:embed stays; no framework, no build step, no CDN, no external network request. Fonts self-hosted per the family spec. Light default honouring prefers-color-scheme with the existing data-theme toggle kept and winning. The family standards apply (underline tabs, word+shape health badge, dense-table standard, diagnostic action placement); this repo's differentiators are the Devices tab (device/vendor inventory) and the ifIndex mapping table, drawn in its canvas; other tabs derive from the family patterns per the repo spec. The GeoIP (DB-IP Lite) footer attribution is a licence requirement: restyled, never removed. SEQUENCING: tailscale2otel task TSO-0103 defines the family standard and lands first; if it extended the shared token block, inherit the extended version.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the console page renders on the family token block, light and dark, light default
- [ ] #2 the shared token block matches the family spec section 1 byte-for-byte (as landed by the standard-setter)
- [ ] #3 Devices and ifIndex tabs match their canvas; remaining tabs follow the family patterns
- [ ] #4 GeoIP attribution present and restyled; no external network requests; AA pairs hold
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
- [ ] #3 just check green
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: resume only after tailscale2otel TSO-0103 lands the family design-system v2 standard. At resume, read its final shared token block and both committed specs, copy that block byte-for-byte, and treat design/console-v2 as reference rather than production-ready code. No implementation change was made in this wave.
<!-- SECTION:NOTES:END -->
