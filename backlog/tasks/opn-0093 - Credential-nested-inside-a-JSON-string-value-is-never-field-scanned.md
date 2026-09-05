---
id: OPN-0093
title: Credential nested inside a JSON string value is never field-scanned
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:59'
updated_date: '2026-09-05 19:20'
labels:
  - bug
dependencies: []
priority: high
ordinal: 47000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
opnsense/client.go, jsonLikeQuotedTokenCanSkip. The skip rule that closed the overlapping-quote bypass also makes the field-name vocabulary refuse to look inside a well-formed quoted token, so a credential-bearing document one level inside a JSON string ships verbatim. Executed through truncateBody against the pinned tree:

    {"message":"configd: {'password': 'SYNTH-PW-1'}"}          -> unchanged
    {"message":"backend: {\"password\":\"SYNTH-PW-2\"}"}       -> unchanged
    {"errorMessage":"cmd '{password:\"SYNTH-PW-3\"}' failed"}  -> unchanged
    "{'password':'SYNTH-PW-9'}"                                -> unchanged

Controls that scope the defect precisely: the same payloads unwrapped both redact correctly, so this is the enclosing-token skip and not a general vocabulary gap.

    {'password':'SYNTH-CTL-1'}   -> {'password':"[REDACTED]"}
    {"api_key":"SYNTH-CTL-2"}     -> {"api_key":"[REDACTED]"}

The asymmetry is the finding. A URL in that same string position IS caught:

    {"message":"url https://u:SYNTH-URL-PW@h/ failed"}  ->  ...u:[REDACTED]@h/...

redactSensitiveURLsInJSONStrings already decodes the string and runs the URL scrubbers over the decoded view; it never runs the two field scrubbers on that same view. Running them there closes every shape above without touching any offset arithmetic.

Gate it on the decoded view containing an opening brace, or benign prose starts getting redacted: {"m":"the password: field is required"} must stay intact.

Reachability: the code defect is certain. Whether an OPNsense box emits a body of this shape is plausible but unproven. configd is Python and a Python dict repr looks exactly like the first case, and several endpoints wrap backend output as a string field, but no live box or repo fixture settles it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A sensitive field nested inside a JSON string value is redacted
- [x] #2 Benign prose containing a sensitive word inside a string value is preserved
- [x] #3 Regressions cover the single-quoted, escaped-double-quoted, unquoted-key and whole-body-quoted shapes, each failing before the fix
- [x] #4 The existing overlapping-quote regressions still pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 7 triage confirms complete quoted values bypass field scanning. Extend the existing decoded JSON-string redaction pass with both existing field scanners for decoded object-shaped content, preserving benign prose and existing malformed-token fail-closed behavior. Add synthetic failing-before nested-field regressions and run relevant overlap/URL controls; no claim of observed firewall response reachability.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Synthetic nested-field regression failed before for all four valid enclosing JSON forms (after correcting a missing test import). Both field scanners now run on decoded object-shaped strings, including tolerant detection views that replace uncertain malformed tokens wholesale. Focused TestTruncateBody and vocabulary checks passed: ok github.com/rknightion/opnsense2otel/v4/opnsense 0.326s. No real-firewall response occurrence asserted.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Source landed in c67a6060d0d7ea09d95e3b155fe92a043a0f3dea. Final eight-file source-only CodeRabbit event: review_completed, findings=0. Security slice took two completed passes (initial six files, then eight after fixing an integration regression). Final just check exit 0; terminal: Your code is affected by 0 vulnerabilities. No generated artifacts changed; just gen not applicable. Four synthetic nested JSON-string forms failed before and pass afterward with valid JSON and benign prose preserved. Existing truncateBody controls pass. Focused output: ok github.com/rknightion/opnsense2otel/v4/opnsense 0.326s. No live-firewall occurrence or final live redaction proof claimed.
<!-- SECTION:FINAL_SUMMARY:END -->
