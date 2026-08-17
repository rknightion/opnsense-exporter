---
id: doc-0003
title: Closed GitHub issues (pre-Backlog history index)
type: other
created_date: '2026-08-14 14:05'
updated_date: '2026-08-17 09:03'
---
**Any `#NNNN` reference below 656 in this repo is a GitHub issue, not a backlog task.** Tracking moved
in-repo on 2026-08-14 at issue #655; `OPN-0001` onwards are backlog tasks and the two numbering
schemes do not overlap. Commit messages, `CHANGELOG.md`, code comments, `AGENTS.md` and the
`grafana/` and `scripts/` sources are full of the old numbers and were deliberately left alone —
rewriting 524 issues' worth of references would have been churn with no reader.

**Those issues were deleted from GitHub on 2026-08-14, so `gh issue view <n>` 404s.** They are
archived instead, in full, at `archive/github-issues-2026-08-14.json` — that file is the record and
this doc is the index into it:

```bash
jq '.[] | select(.number == 336)' archive/github-issues-2026-08-14.json      # one issue
jq -r '.[] | select(.number == 336) | .comments[].body' archive/…            # its replies
```

The load-bearing detail — closing decisions, corrections, acceptance evidence — is usually in the
comments rather than the body, so read the archive, not just the table below. **The archive is
redacted**: host names, LAN and tailnet addresses, the WAN address, MACs and token fingerprints were
replaced with stable placeholders before it was committed, one real value to one token.
`archive/README.md` carries the mapping and the two verification traps worth knowing.

**GitHub Issues stays enabled on this repo, deliberately.** External contributors can still file —
`#40` is one such report and was kept, as was Renovate's Dependency Dashboard (`#22`, and `#7`).
Anything arriving that way becomes an `OPN-NNNN` task; the board, not the issue, is where it is
worked.

## Why there was no bulk import as tasks

524 issues were deleted, 506 of them Rob's own project tracking and 18 filed by CI. Importing them as
`Done` tasks fails twice over: it creates a **second ID space over the same history** — backlog IDs
follow creation order, so no `OPN-NNNN` could ever line up with the `#NNN` already cited in
`AGENTS.md`, `CHANGELOG.md`, commit messages and code comments — and hundreds of `Done` rows would
compete with the board's only real signal, *what is left*. Archiving the bodies to one JSON file and
indexing the load-bearing numbers here keeps the history readable from the checkout alone, keeps the
original ID space as the only one, and costs two files.

## The numbers `AGENTS.md` cites, and what they mean

`AGENTS.md` refers to these nine by number as if the reader knows them. They are the ones worth
resolving without a `gh` call.

| # | Meaning |
|---|---|
| #235 | A live-box canary drift run. Flagged `healthCheck subsystems`; #243 did not. **Two runs disagreeing is a box-state tell, not intermittent drift** — this pair is the worked example behind that rule. |
| #243 | The canary run that did *not* flag it. 7/7 of its findings were box-state. |
| #248 | The syslog receiver with API enrichment — replaced the firewall/diaglog **poll** lanes with a push receiver. Why `internal/logship/` exists and why it is not a collector. |
| #271 | Another canary drift run; 7/7 box-state. With #243, the evidence that box-state is the most common verdict in practice, not the exotic one. |
| #284 | `metadata.subsystems` is **never populated** — the 26.1.11 health model rested on a false premise. Cost two fabricated fixtures and a permanently dead branch. The canonical instance of modelling a shape upstream cannot produce. |
| #302 | The multi-page operator console at `/`. Why `internal/webui/` renders only from `metricsnap`, `StatusTracker` and the client cache view, and must never `Gather()` on the live registry. |
| #336 | The epic that decoupled collectors from the scrape: per-collector poll scheduler, volatility tiers, in-memory snapshot. Why `/metrics` and the OTLP bridge **replay** a snapshot and make no live API call. |
| #346 | NetFlow v9 receiver + Zenarmor rollups + the correlator that merges fragments into one flow log per connection-window. The origin of `internal/flow/` and of its correlation defect class. |
| #495 | Plugin-gating and 404-cacheability are **two questions, not one list**. The canary was misreporting `vnstatGetJsonData` as a vanished core route because its real request path carries a query string the cache key does not. |

## Three more worth knowing

| # | Meaning |
|---|---|
| #544 | Five payloads decoded with the identifying dimension discarded. Produced `make fieldaudit` and its unit-test gate. |
| #565 | Live firewall addresses removed from public repository content. Produced `make check-public-ips` and `scripts/public-ip-allowlist.json`. |
| #625 | The testbed guests power down outside the canary window (06:00–08:30 UTC). The reason the lab is unreachable most of the day, and the reason the canary is dispatch-triggered rather than cron-triggered. |

## The two issues open at cutover

| # | Disposition |
|---|---|
| #654 | live-canary never ran inside the testbed power window. **Closed as complete** — its last criterion, one unattended green run, was satisfied by seven consecutive green 06:05 UTC dispatch runs, 2026-08-08 to 2026-08-14. Not migrated; archived and deleted with the rest. |
| #655 | Rare data race in the syslog `Listener` shutdown path. **Migrated to `OPN-0001`** with its ~290 negative reproduction runs intact. Archived and deleted; `OPN-0001` carries the full reproduction record, so nothing depends on the issue. |
