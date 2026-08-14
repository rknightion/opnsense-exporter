# GitHub Issues archive

`github-issues-2026-08-14.json` is the complete contents of this repository's GitHub Issues tracker
as of **2026-08-14**, captured immediately before most of those issues were deleted. The project
moved to Backlog.md on that date; see the *Pre-backlog issue numbers* doc (`backlog doc list --plain`)
for what the frequently-cited numbers mean, and this file for the bodies and replies behind them.

**This is the record, not a convenience copy.** For every issue we filed, `gh issue view <N>` now
404s. Anything in the repository that cites `#NNN` — `AGENTS.md`, `CHANGELOG.md`, commit messages,
code comments — resolves here.

## What it contains

527 issues and all 897 comments — the entire tracker, including the issues that were **not** deleted.
Per issue: number, title, body, state, state reason, author, labels, milestone, assignees,
created/updated/closed timestamps, URL, and every comment with its author and timestamp. The
top-level JSON is a bare array.

```sh
jq '.[] | select(.number == 336)' archive/github-issues-2026-08-14.json          # one issue
jq -r '.[] | select(.number == 336) | .comments[].body' archive/…                # its replies
jq -r '.[] | select(.title | test("canary"; "i")) | "#\(.number) \(.title)"' archive/…
jq -r '.[] | select(.author.login != "rknightion") | "#\(.number) \(.author.login)"' archive/…
```

## Completeness was verified, and the obvious check is wrong

`gh issue list --json comments` paginates, so the comment arrays are not trustworthy on their own.
They were checked against **GraphQL `comments.totalCount`** for all 527 issues: exact match, 897 both
sides.

The REST issue object's own `.comments` counter disagreed on **#72** — it reports 13 where the
comment list, the timeline and GraphQL all report 12. That counter is a stale denormalised value
(a comment was deleted and it never decremented), not a lost comment. Anything verifying this file
should use GraphQL `totalCount`, not `.comments`.

## It is redacted, and the placeholders are stable

The tracker is a live-lab project's, and issue bodies quoted host names, LAN and tailnet addresses,
MAC addresses and a WAN address — exactly what this repository's own rules (`make check-public-ips`,
`#565`) keep out of tracked files. Committing the raw dump would have moved those identifiers from
somewhere deletable into permanent public git history at the very moment they were being deleted.

**1011 substitutions over 160 distinct values.**

| Placeholder | Was | Distinct |
| --- | --- | ---: |
| `<host-N>` | machine names and lab FQDNs | 37 |
| `<lan-ip-N>` | RFC1918 addresses | 68 |
| `<pub-ip-N>` | globally routable addresses, including the WAN address and third-party endpoints | 24 |
| `<tailnet-ip-N>` | tailnet CGNAT addresses | 3 |
| `<tailnet-N>` | tailnet `*.ts.net` names | 4 |
| `<mac-N>` | MAC addresses | 11 |
| `<duid-N>` | DHCPv6 DUIDs (which embed a MAC) | 2 |
| `<ula-ip-N>` | a ULA v6 address | 1 |
| `<hash-N>` | md5-shaped fingerprints (token fingerprints from the canary-credential thread) | 9 |
| `<email-N>` | an email-shaped identifier | 1 |
| `<lab-domain>` | the private domain, where it appeared bare | 1 |

**One distinct real value maps to one placeholder throughout**, so a reader can still tell that two
issues discuss the same host without learning which host.

Deliberately **not** redacted, because they identify nobody: loopback, `0.0.0.0`, link-local,
multicast, the RFC 5737 / RFC 3849 documentation ranges, the CGNAT range base `100.64.0.0`, and
`100.100.100.100` (Tailscale MagicDNS, identical for every tailnet). `rknightion` as an author login
is left intact — it is the repository owner's public handle and appears in every commit anyway.

## Two verification traps, both of which produced a confident false pass here

**Sweep the decoded fields, never the serialized JSON.** In `json.dumps` output an escape such as
`\n` leaves a literal `n` immediately before the following word, which breaks a `\b` word boundary
and silently undercounts. This file is swept per decoded field — 3172 of them.

**Use the same regex to find and to replace.** The first redaction pass built a literal alternation
with lookarounds and reported success; the residue check then found **257 surviving occurrences**,
because a trailing `.` at the end of a sentence, or the `:` of an abbreviated v6 address, defeated
the trailing lookahead. Rewriting it so the detector *is* the substituter took residue to zero. A
redaction that is verified by a different expression than the one that performed it is not verified.

The residue check greps for every class above and currently reports **none**.
