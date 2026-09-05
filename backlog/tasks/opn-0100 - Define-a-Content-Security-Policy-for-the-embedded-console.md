---
id: OPN-0100
title: Define a Content-Security-Policy for the embedded console
status: To Do
assignee: []
created_date: '2026-09-05 22:56'
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
- [ ] #1 The console responses carry a Content-Security-Policy that allows exactly the inline script and style the page uses (nonce or hash or same-origin files), the /_static/fonts/ route, and the same-origin JSON poll, and nothing else
- [ ] #2 A render test asserts the header is present and the page still functions under it (no inline handler or eval left that the policy would block), and the no-external-request guard still passes
- [ ] #3 docs describe the policy in one paragraph and note any operator-facing change
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
