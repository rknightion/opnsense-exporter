---
id: OPN-0053
title: Restyle the embedded console onto design system v2 (family follower)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-31 12:12'
updated_date: '2026-09-05 22:22'
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
- [x] #1 the console page renders on the family token block, light and dark, light default
- [x] #2 the shared token block matches the family spec section 1 byte-for-byte (as landed by the standard-setter)
- [x] #3 Devices and ifIndex tabs match their canvas; remaining tabs follow the family patterns
- [x] #4 GeoIP attribution present and restyled; no external network requests; AA pairs hold
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
- [x] #3 just check green
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 8: one Luna/max EXECUTION lane owns internal/webui, reads both committed specs in full, implements the complete v2 console with embedded allowlisted fonts and required negative guards. Preserve seven tabs, three badges, theme storage behavior and GeoIP credit. Do not add CSP; report the follow-up. Root integrates only the whole console after focused tests, CodeRabbit and just check.

Correction from baseline evidence: retain all eight shipped tabs and IDs, including pipeline (Logs / Flow); the brief counted seven. No CSP added.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: resume only after tailscale2otel TSO-0103 lands the family design-system v2 standard. At resume, read its final shared token block and both committed specs, copy that block byte-for-byte, and treat design/console-v2 as reference rather than production-ready code. No implementation change was made in this wave.

Unparked 2026-09-05: tailscale2otel TSO-0103 is Done (family standard-setter landed, its final summary records shared token extension: none). Verified this repo's design/console-v2/implementation-spec.md section 1 is byte-identical to tailscale2otel's copy. Reference implementation for the self-hosted font route, CSP font-src and the negative guards (TestFamilyTokenBlockMatchesTheSpec, TestFontAllowsOnlyThePublishedConsoleFiles) is the tailscale2otel internal/ tree. Eligible for the next wave.

Wave 8 whole-console verification: just check exit 0 on final corrected tree; TestFamilyTokenBlockMatchesSpec, TestConsoleFontsUseFixedAllowlistAndRoute, TestRenderedConsoleIsOfflineAndLightByDefault, TestThemeContrastPairsMeetAA and pipeline render guard passed (webui 0.255s). Twenty computed AA text pairs pass, minimum 4.84. DOM simulation exercised eight tabs, pipeline deep link, invalid hash fallback, keyboard navigation, lazy-load once, OS theme and stored toggle. Three embedded fonts byte-match the reference. Browser unavailable after two auth-token failures; no pixel/browser proof claimed. Devices/ifIndex and other tabs accepted using rendered-template, DOM and contrast evidence. GeoIP footer and three badges retained. Two completed nine-file CodeRabbit passes: unchanged deadline-bounded device-fetch cancellation suggestion left out of scope; final minor bounds check would improve only a failing test diagnostic (panic already fails closed), left. No critical/major findings. Root integration incident: concurrent lane staging entered local commit 4ab20cee before console review/gate; root failed to fence the shared index/use a commit pathspec. No remote publication occurred; final corrected console is now gated/reviewed before publication via a forward correction commit, without rewriting history. Follow-up questions: confirm eight-tab preservation and whether to specify a CSP in a future scoped change.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented complete family-v2 console with self-hosted allowlisted fonts, original eight tabs, theme persistence, GeoIP attribution and three badges. Verified by final just check, rendered guards, DOM interaction simulation and 20 passing AA pairs. No browser visual claim. See notes for local precommit ordering violation and CSP follow-up.

Landed across 4ab20cee and forward correction 7a34b51b; published only after final whole-console review and just check. Local precommit-order exception remains explicitly recorded above.
<!-- SECTION:FINAL_SUMMARY:END -->
