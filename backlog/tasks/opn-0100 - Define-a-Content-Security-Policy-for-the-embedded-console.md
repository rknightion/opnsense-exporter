---
id: OPN-0100
title: Define a Content-Security-Policy for the embedded console
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 22:56'
updated_date: '2026-09-06 11:03'
labels:
  - webui
  - security
dependencies:
  - OPN-0053
priority: low
ordinal: 54000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave 8 (OPN-0053) restyled the console onto design system v2 and self-hosted the fonts under /_static/fonts/. The family spec assumes the admin server already sends a CSP and says only to add font-src self; this console has never sent a CSP header at all (internal/webui sets none), so the lane deliberately did not invent one and raised the question. The console is Go html/template with inline CSS and inline vanilla JS, one page, a JSON poll to /api/status.json, lazy-loaded device and ifIndex fragments, and no external resource of any kind. A CSP therefore needs either nonces or hashes for the inline script and style, or a move of the inline blocks to embedded files served from the same origin, and font-src self plus connect-src self for the poll. Decide the shape against the family: tailscale2otel sets its CSP in internal/app/adminheaders.go with font-src self; copy the policy vocabulary from there and adapt to this console, do not fork a different scheme. Owner decision 2026-09-05 to file this as a separate task rather than adopt the assumed policy blind.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The console responses carry a Content-Security-Policy that allows exactly the inline script and style the page uses (nonce or hash or same-origin files), the /_static/fonts/ route, and the same-origin JSON poll, and nothing else
- [x] #2 A render test asserts the header is present and the page still functions under it (no inline handler or eval left that the policy would block), and the no-external-request guard still passes
- [x] #3 docs describe the policy in one paragraph and note any operator-facing change
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 9: exclusive webui execution lane reads the family adminheaders reference, applies nonce middleware over the mux, moves inline handlers/styles, and proves render/header/no-external contracts. Root supplies the documentation paragraph, runs just check, source-only CodeRabbit and REVIEW before the phase-ordered commit. D6 nonce choice is frozen and batched for the report.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 9: nonce middleware wraps the entire console mux, including JSON, lazy fragments, fonts and errors; script/style elements receive the per-response crypto/rand nonce, inline handlers/style attributes are moved, and HTML/JSON are no-store. Fonts retain immutable caching. Embedded data favicon requires img-src data:. No HSTS because the listener has no TLS. Render/header/offline-resource tests passed and independent REVIEW found no blocking or material findings. Source-only CodeRabbit completed with no CSP findings. D6 nonce-versus-family-unsafe-inline choice remains a batched question, not a runtime fork.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wave 9 completed at f968453f829792592bc8736281fddab1c1e293d2. Whole-mux per-request nonce CSP, nosniff, no-referrer and no-store on HTML/JSON; immutable bundled fonts remain cached, data favicon allowed, no HSTS on the plaintext listener. Render tests verify headers on HTML/JSON/lazy routes, all script/style nonces, no inline handler/style/javascript URL, and the existing no-external-resource guard. just check passed; independent REVIEW and source-only CodeRabbit completed without CSP findings. D6 default is recorded for the final questions batch; no browser-enforcement measurement is claimed beyond the rendered DOM assertions.
<!-- SECTION:FINAL_SUMMARY:END -->
