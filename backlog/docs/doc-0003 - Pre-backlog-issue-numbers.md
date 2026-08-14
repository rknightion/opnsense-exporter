---
id: doc-0003
title: Pre-backlog issue numbers
type: other
created_date: '2026-08-14 14:05'
updated_date: '2026-08-14 14:06'
---
**Any `#NNNN` reference below 656 in this repo is a GitHub issue, not a backlog task.** Tracking moved
in-repo on 2026-08-14 at issue #655; `OPN-0001` onwards are backlog tasks and the two numbering
schemes do not overlap. Commit messages, `CHANGELOG.md`, code comments, `AGENTS.md` and the
`grafana/` and `scripts/` sources are full of the old numbers and were deliberately left alone —
rewriting 524 closed issues' worth of references would have been churn with no reader.

Read any of them with:

```bash
gh issue view <n>          # add --comments; several carry more in comments than in the body
```

GitHub Issues stays enabled on this repo. Closed issues remain the historical archive, external bug
reports are still welcome there, and Renovate's Dependency Dashboard (#22) still lives there.

## Why there was no bulk import

524 closed issues, 504 of them Rob's own project tracking. The value in a closed issue is the
reasoning in its body and comments, not its title, so a title-only import would have been noise and a
full-fidelity import would have been a large committed blob nothing queries. It would also not have
made anything more durable — the issues stay readable, and their distilled lessons are already in
`AGENTS.md`. And 504 `Done` tasks would have pushed live work to `OPN-0505`, in a tool where
archiving releases an ID for reuse.

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
| #654 | live-canary never ran inside the testbed power window. **Closed as complete** — its last criterion, one unattended green run, was satisfied by seven consecutive green 06:05 UTC dispatch runs, 2026-08-08 to 2026-08-14. Not migrated. |
| #655 | Rare data race in the syslog `Listener` shutdown path. **Migrated to `OPN-0001`** with its ~290 negative reproduction runs intact, then closed on GitHub. |
