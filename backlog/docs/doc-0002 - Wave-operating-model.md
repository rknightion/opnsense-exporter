---
id: doc-0002
title: Wave operating model
type: guide
created_date: '2026-08-14 14:04'
updated_date: '2026-08-14 14:17'
---
This document carries **only what is specific to opnsense2otel**. The campaign model itself — run
modes, the routing contract, authority and the thread pool, child lane briefs, external-contract
freezing, the unattended blocker contract, the goal-file template, the pre-flight checklist — lives
in the *Codex fan-out protocol (canonical)* doc and is not repeated here. If something below could be
pasted into another repo unchanged, it is in the wrong document.

## Run-end against this tracker

The goal file does not enumerate the work. The queue is:

```bash
backlog task list --plain -s "To Do"
```

Task state is the record, not a report file:

- landed work is `Done` with the commit SHA in its final summary;
- blocked work is `Parked` with a concrete resume boundary — the next action, not "blocked on X";
- untouched work is self-evidently still `To Do`;
- discovered work is a new task labelled `needs-triage`.

The run's closing message goes to the terminal as a covering note: what did this run learn that no
single task captures. Nothing durable may live only there. Writing it is the last unit of work, not a
reply to a request.

Acceptance criteria live on the task, so a lane reads its own contract with
`backlog task view <id> --plain` and the goal file stops restating them.

## Gates

`backlog/config.yml`'s `definition_of_done` seeds every task with the five local gates:

```
make lint            make test            make check-public-ips
make docs-check      make grafana-check
```

Two additions a lane must make for itself, because they are conditional:

- **Touching anything under `grafana/` also requires `make grafana-test`.** It is a separate CI step
  and deliberately *not* a prerequisite of `grafana-check` (#429 — the prerequisite ran the 198-test
  suite twice per job). A lane that runs only `grafana-check` has not run the builders' unit tests.
- **Touching `scripts/testbed/` or `scripts/canary/` requires `make testbed-test` / `make canary-test`.**
  Neither script can run end to end in CI, so those targets drive the `--decide-only` seams. The
  testbed allowlist test is the load-bearing one: it is what stands between a typo and powering off
  Rob's home automation or the CI runners.

The heavy CI-only gates — race detector, bounded fuzz, docker build, helm-in-kind, deployment
contracts — are not a lane's job. Do not skip them by claiming they are; say the change is untested
against them and let CI answer.

## Exclusive resources — serialise these, never fan out across them

**The testbed is a single physical resource on a power window.** Six guests on `oli`, up 06:00–08:30
UTC only (#625, to reclaim idle draw). `opnsense-testbed-canary.timer` fires at 06:05 UTC, dispatches
`live-canary.yml` and **holds the lab up for the duration**, releasing only a hold it took itself.

Consequences for a wave:

- **At most one lane may use the testbed at a time.** There is no locking; two lanes will interleave
  API writes against the same firewall and produce results neither can trust.
- **An ad-hoc `testbed up <seconds>` is left alone by the canary's hold**, which is deliberate — but
  it also means a lane that takes a hold and dies leaves the lab powered on. A lane touching the
  testbed owns releasing it.
- **Outside the window the box is simply down.** A pre-flight probe failure at 09:00 UTC is not drift,
  not a box fault and not a regression. Do not open a task for it.

**camden's prod canary runs against Rob's production firewall.** It is not a test target. No lane
writes to it, and its `--decide-only` seam is the only part a lane exercises.

**Grafana Cloud is live.** `make grafana-check` regenerates and diffs local artifacts and touches
nothing remote. Pushing dashboards or rules to a stack is a main-thread action, not a lane's.

## Ownership — the append-only registries

Adding a collector or an endpoint touches a fixed set of shared files that every lane wants to append
to. **One owner per file, or a single wiring pass at the end.** The registries, in the order the
collector checklist in `AGENTS.md` hits them:

| File | What every lane wants to append |
|---|---|
| `internal/collector/collector.go` | subsystem const, `Without*Collector()`, `SubsystemDisplayNames` |
| `internal/collector/interval_tiers.go` | `collectorTiers` entry |
| `internal/options/collectors.go` | flag, `CollectorsDisableSwitch` field, switch entry, `CollectorFlags` |
| `main.go` | the `if !collectorsSwitches.X` wiring |
| `opnsense/client.go` | `defaultEndpoints()` |
| `opnsense/contract.go` | `postEndpoints` |
| `opnsense/cache.go` | `NegativeCacheable404Endpoints()` / `PluginGatedEndpoints()` |
| `opnsense/schema_registry.go` | `schemaRegistry` |
| `opnsense/testdata/schemas/exemptions.json` | `missingOK` / `knownExtraTopKeys` |
| `grafana/build_dashboard.py` | `register_subsystem_tabs` |

Counts pinned in tests move with these (`TestNewClient_EndpointCount`, the golden POST count, the
docs count pins, the rule-count pins). A lane that appends without bumping its count leaves the build
red for everyone.

**Escape hatch.** A lane that needs a change outside its boundary states the exact edit and stops —
it does not make it, and it does not silently work around it. A boundary with no escape hatch is a
stop condition wearing a safety label.

## Recurring defects in this codebase

Five classes, each with instances. These are what a review pass should actually look for.

### 1. Modelling a payload shape upstream cannot produce

The single most expensive class here. A struct is written against one observed response and the
branch it invents is never taken.

- `metadata.subsystems` was modelled as "the 26.1.11 shape"; upstream never populated it on any
  release. Cost two fabricated fixtures and a permanently dead branch (#284).
- unbound query-class counters decoded as a fixed `IN` field, when it is a map.
- nginx `overCounts` modelled as one union struct, when it is per zone kind — and as a number, when
  it is an object.
- smartctl wear percentages decoded as numbers, when they are objects.
- `endurance_used` given a `threshold_percent` it does not have.

**The rule that prevents it:** verify against the OPNsense controller/script that *builds* the
payload, and check whether the key is conditional, before writing the struct. The canary triage
verdicts in `AGENTS.md` are the decision procedure; the trap is reaching for `drop`/`chase` before
asking whether upstream changed at all. `box-state` was the right answer 7/7 in #271 and 7/7 in #243.

### 2. Flow correlation: orientation, pairing and double-counting

`internal/flow/` has produced more corrections than any other package. Every one is a case where two
records that describe the same connection were treated as independent, or one record's direction was
inferred from something that is not evidence.

- orientation decided by arrival order rather than by evidence;
- merge endpoints paired by position rather than by address;
- NAT'd conversations counted twice, then paired by conversation only when the exact window cannot
  close;
- a merged record's two halves not split into Tx and Rx;
- a window partial compared against a whole connection without stating the byte basis;
- repair markers not unioned across a conversation's fragments.

**Assume any new flow logic double-counts or mis-orients until a test says otherwise.** This is the
one area where test-first is not negotiable regardless of change size.

### 3. Alert rules that fire on a single sample

Rules authored against one observed spike, with no sustain and no hysteresis.

- `OPNsenseDHCP6AllocationFailures` fired on a single event;
- `OPNsenseNetmapRingFull` meant one burst, not a sustained condition;
- the gateway flapping rule had no hysteresis;
- `OPNsenseFlowSourceDivergence` was deleted outright — its threshold sat **below the metric's
  floor**, so it could never mean anything.

**Before adding a rule, state what the metric's floor and normal range actually are.** A threshold
that cannot be crossed, or that any single sample crosses, is worse than no rule.

### 4. Decoded and dropped

A per-row payload is unmarshalled and its identifying dimension quietly discarded (#544). This has a
mechanical detector: `make fieldaudit` reports struct fields in package `opnsense` that are
unmarshalled and never read, and the same analysis runs as a unit test, so `make test` already gates
it. If you add an exemption, write the reason.

### 5. Public metadata leaking into a public repo

This repository is public and `backlog/` is now committed with it.

- `make check-public-ips` rejects any globally routable IP literal in source, tests, fixtures or docs
  without a justified entry in `scripts/public-ip-allowlist.json` (#565). RFC1918, loopback,
  link-local, CGNAT, multicast and the RFC 5737 / RFC 3849 documentation ranges are never flagged.
- Golden schemas are **structure-only** — key paths and JSON types, never response values.
- Credentials have twice reached places they should not: request headers into a capture, and a bearer
  token surviving a redirect. Redact at the boundary, not at the sink.

**This now extends to the tracker, and `make check-public-ips` scans `backlog/` like any other
committed content** — verified 2026-08-14 by writing a task that quoted the offending literals from
OPN-0002 and watching the gate flag 18 new violations in the task file. **A task about a leaked
address must describe it, never quote it**: give `file:line` and say what kind of address it is, and
let the reader open the line. The same holds for docs.

Tasks and docs must not carry real account identifiers, hostnames beyond the ones already public in
this repo, device names, addresses, or data-archive cell values. Write the shape, not the instance.
Sweep before committing:

```bash
grep -rniE "rob-knight\.net|@gmail|@rob-knight|github_pat_|[0-9]{1,3}(\.[0-9]{1,3}){3}" backlog/ \
  && echo "REVIEW THESE"
```

Tailnet host names (`camden`, `oli`) are already all over this repo's scripts and issue history, so
they are not the thing to hunt for. Tokens, IPs and account identifiers are.

## Lane conventions

- **Never two lanes on one task.** The v1.50.x fix covers the `task edit` funnel but not reorder,
  draft saves, the TUI path, `doc update` or decision updates.
- **`--append-notes` and `--append-plan` only.** Bare `--notes` / `--plan` silently replace the whole
  section and destroy another session's writes with exit code 0. A `PreToolUse` hook on Rob's
  machines denies the bare form, so being blocked there is the guard working. It does not fire in
  CI or on a machine without that config, which is why the rule is written down as well.
- **Finalize in one call** so an interrupted lane cannot leave finished work looking unfinished:
  `backlog task edit OPN-0007 --check-ac 1 --check-ac 2 -s Done`.
- **Commits come from the campaign root only.** Lanes do not commit. `auto_commit` is off.
- **Generated artifacts are regenerated, never hand-edited** — anything between `docgen` markers,
  `grafana/dashboard*.json`, the grafana-managed manifests, `opnsense/testdata/schemas/`. A lane that
  hand-edits one produces a diff that `make docs-check` or `make grafana-check` reverts on the next
  regeneration, silently losing the work.

## Issue numbers below #656

They are GitHub issues, not tasks. See the *Pre-backlog issue numbers* doc.
