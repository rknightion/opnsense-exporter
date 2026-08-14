---
id: OPN-0002
title: >-
  main is red: WAN address reintroduced into public fixtures, check-public-ips
  failing since 2026-08-08
status: To Do
assignee: []
created_date: '2026-08-14 14:09'
updated_date: '2026-08-14 14:10'
labels:
  - bug
  - security
  - 'area:logship'
  - needs-triage
dependencies: []
priority: high
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during the GitHub → backlog.md tracker migration on 2026-08-14, not migrated from an issue.
`main` is red and has been for a week, and the reason is the gate that exists to keep Rob's own
network addresses out of a public repository.

**This task deliberately names no literal.** `backlog/` is committed and is scanned by
`make check-public-ips` like any other content, so quoting the offending addresses here would add
violations rather than describe them. Run the gate, or open the lines below.

## State

`make check-public-ips` fails on clean `main` with **13 un-allowlisted globally routable literals**,
all in `internal/logship/`:

| file:line | what is there |
|---|---|
| `internal/logship/syslog/dpinger.go:55` | a sample dpinger config line carrying both a public resolver address and the box's own WAN bind address |
| `internal/logship/syslog/dpinger_test.go:138,167,171,172,222` | the same pair, in the fixture strings and in the comment that justifies them |
| `internal/logship/unbound_test.go:414` | one v6 literal in the same ISP's space, counted three times because the table row repeats it in three columns |

Every CI run on `main` from 2026-08-08 onward fails on the **Tests & Linters** job at
`make check-public-ips`, which fails `ci-success`. (The failures on 2026-08-06 have a different
cause — the generated-docs job — so do not assume one fix turns everything green.)

## Why this is not just a red build

The v4 literal is **the box's own WAN bind address**, and the comment at `dpinger_test.go:138` says
so in as many words while arguing it is fine to commit: the lines carry no WAN address, it says, and
the values are just the gateway monitor's configured dest_addr/bind_addr, and the identifier is a
gateway name rather than a secret.

That reasoning is the exact thing #565 rejected, and it is wrong on its own terms — `bind_addr` **is**
the WAN address. The concern was never secrecy. It is that a globally routable literal committed to a
public repository is durable public metadata about whoever's box produced it.

## This is the third reintroduction, which is the actual finding

```
4a62a580  2026-07-30  security: replace live firewall addresses with documentation ranges, and gate it
a02e9eec  2026-08-01  feat(logship): parse ppp, firewall aliases, acme and unbound's dnsbl chatter   <- back
a493795f  2026-08-01  test(syslog): use RFC 5737 documentation addresses in the ppp fixtures         <- scrubbed
8cca5da9  2026-08-07  feat(logship): structure dpinger lifecycle...                                  <- back
3726ca97  2026-08-07  fix(logs): stop the unbound lane's client field being a mixed type             <- the v6 one
```

The gate works — it caught all three. What failed twice is the response: on 2026-08-01 it was fixed
the same day; on 2026-08-07 it was left red for a week.

The mechanism is consistent: live-box captures get pasted into fixtures verbatim, because a real
capture is the honest source for a parser test. Each time, a comment is written explaining why *these
particular* values are acceptable. Any fix that does not address that habit will see a fourth
reintroduction.

## Do not just add allowlist entries

The public-resolver address is benign and belongs in `scripts/public-ip-allowlist.json` with a
justification, alongside the resolver entries already there.

The WAN address and the v6 literal do not. Replace them with RFC 5737 / RFC 3849 documentation
addresses, the way a493795f already did for the ppp fixtures. **An allowlist entry for a real WAN
address defeats the gate rather than satisfying it.**

Replacing them means updating the fixture strings *and* the surrounding comments, which currently
assert the literals are genuine unsanitised capture output. A fixture carrying a documentation
address must say it was sanitised — the standing rule is that a fixture must never encode a shape
upstream cannot produce, and a comment claiming provenance it no longer has is the same defect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 make check-public-ips passes on a clean checkout
- [ ] #2 Comments claiming the fixtures are unsanitised live captures are corrected to say they were sanitised
- [ ] #3 ci-success is green on main, or the remaining failure is identified as a separate cause and tracked
- [ ] #4 The WAN bind address and the v6 literal are replaced with RFC 5737 / RFC 3849 documentation addresses, not allowlisted
- [ ] #5 The public-resolver address carries a justified scripts/public-ip-allowlist.json entry
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make lint
- [ ] #2 make test
- [ ] #3 make check-public-ips
- [ ] #4 make docs-check
- [ ] #5 make grafana-check
<!-- DOD:END -->
