---
id: OPN-0092
title: Config diff loses redaction state when the diff prefix changes mid-element
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:59'
updated_date: '2026-09-05 19:20'
labels:
  - bug
dependencies: []
priority: high
ordinal: 46000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
internal/logship/configchange.go:307 clears openTag whenever the diff prefix changes:

    if openTag != "" && prefix != openPrefix { openTag = "" }

A sensitive element whose value spans several diff lines therefore loses suppression at the first prefix change, and every later line of that value is written verbatim. Executed against the pinned tree, all three shapes leak:

    -<prv>SYNTH-OLD-CHUNK1          ->  -<prv>[redacted]
    +<prv>SYNTH-NEW-CHUNK1          ->  +<prv>[redacted]
     SYNTH-SHARED-CHUNK2            ->   SYNTH-SHARED-CHUNK2          LEAK
     SYNTH-SHARED-CHUNK3</prv>      ->   SYNTH-SHARED-CHUNK3</prv>    LEAK

    -<privatekey>SYNTH-CHUNK1       ->  -<privatekey>[redacted]
     SYNTH-CHUNK2</privatekey>      ->   SYNTH-CHUNK2</privatekey>    LEAK

    +<privatekey>SYNTH-CHUNK1       ->  +<privatekey>[redacted]
    (blank line)                    ->  (blank line)
    +SYNTH-CHUNK2</privatekey>      ->  +SYNTH-CHUNK2</privatekey>    LEAK

The same-prefix control redacts both lines correctly, and that is the only shape TestRedactConfigChangeDiff_RedactsWrappedValues covers. That test's own comment asserts wrapped key material is the routine case, so the design intent is exactly the shape that breaks.

The blank-line variant matters because FetchConfigBackupDiff joins items with a newline and the repo's own fixture carries an empty trailing item.

Fix direction: key the open-element state on the element rather than dropping it on prefix change, or keep suppressing until the closing tag or a hunk header regardless of prefix. Over-redaction is already the stated safe direction in that function's doc comment.

Reachability: the code defect is certain. Whether OPNsense's config.xml writer ever wraps a sensitive element across lines is unproven; prv and privkey hold base64-of-PEM which is normally one line. If it never wraps this is dead code rather than a live leak, but the repo already assumes it does.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A sensitive element spanning a prefix change stays suppressed to its closing tag
- [x] #2 Regressions cover the minus-to-space, minus-to-plus-to-space and blank-line-interrupted shapes, each failing before the fix
- [x] #3 A hunk header still clears the state
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 7 triage confirms prefix-state loss. Remove prefix-specific state reset, retain suppression until closing tag or hunk header, and add synthetic failing-before mixed-prefix/blank continuation regressions. Preserve ordinary content. Correct wrapped-material comments: normal upstream Trust writes store base64 on one line; live multiline reachability is unproven.

Root adversarial integration found that simply retaining one open tag still leaks when a removed closing tag precedes an added continuation. Added a failing regression for this real unified-diff structure. Track old/new element state separately; context lines use both redacted views, and conflicting rewritten spans fail closed for that line. Hunk headers clear both.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Original three synthetic mixed-prefix cases failed before repair. Additional common-opening/deleted-closing/added-continuation case also failed against the first one-state repair, so that approach was replaced before review.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Source landed in c67a6060d0d7ea09d95e3b155fe92a043a0f3dea. Final eight-file source-only CodeRabbit event: review_completed, findings=0. Security slice took two completed passes (initial six files, then eight after fixing an integration regression). Final just check exit 0; terminal: Your code is affected by 0 vulnerabilities. No generated artifacts changed; just gen not applicable. Old/new diff sides now keep independent sensitive-element state; context uses both views and hunk headers reset both. Four synthetic cases failed during development, including one that disproved the initial one-state repair. Focused final output: ok github.com/rknightion/opnsense2otel/v4/internal/logship 0.428s. Standard upstream Trust writes are single-line base64; no real wrapped credential delivery is claimed.
<!-- SECTION:FINAL_SUMMARY:END -->
