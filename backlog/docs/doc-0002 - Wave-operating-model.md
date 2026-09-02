---
id: doc-0002
title: Wave operating model
type: guide
created_date: '2026-08-14 14:04'
updated_date: '2026-09-02 15:56'
---
This document carries **only what is specific to opnsense2otel**. The campaign model itself — run
modes, the routing contract, authority and the thread pool, child lane briefs, external-contract
freezing, the unattended blocker contract, the goal-file template, the pre-flight checklist — lives
in the *Agent fan-out protocol (canonical)* doc and is not repeated here. If something below could be
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

`backlog/config.yml`'s `definition_of_done` seeds every task with two gates:

```
just check
just gen        # only if a generated artifact changed; commit the diff
```

`just check` is the whole bare-toolchain gate and it is **not** the old five-command list. It runs
`fmt-check lint test metric-lint fuzz-smoke check-public-ips testbed-test canary-test grafana-test gen-check vuln`,
so the two conditional additions a lane used to have to remember — `grafana-test` when touching
`grafana/`, `testbed-test` / `canary-test` when touching `scripts/testbed/` or `scripts/canary/` —
are already inside it. There is nothing conditional left for a lane to add.

Every `make` target this repo once had is gone (OPN-0006). `make lint`, `make test`,
`make check-public-ips`, `make docs-check`, `make grafana-check` and `make grafana-test` do not
exist; a lane that reaches for one gets `command not found`, not a gate. Discover the surface with
`just --list`, never from memory.

The heavy CI-only gates — race-detector matrix, docker build, helm-in-kind, deployment contracts,
cross-compilation — are not a lane's job. `just ci` adds the subset that needs Docker or
cross-compilation locally. Do not skip a gate by claiming it is CI-only; say the change is untested
against it and let CI answer.

### CodeRabbit: review the source, not the generated tree

**A whole-wave review does not fail, it disconnects.** Past about 100 files the CLI drops the
socket during the connect phase and emits
`{"type":"error","errorType":"connection","message":"Connection failed: WebSocket closed"}` with no
`complete` event. It never reaches analysis, so there is nothing to triage and nothing to retry
usefully — a second attempt fails identically. This is not a service outage and not an auth problem:
`coderabbit doctor` passes all nine checks while it happens, and a one-file review against the same
service, account and repository completes normally in the same minute.

Wave 2 read two of those as a hard gate failure and parked seven finished, gated, reviewed lanes.
The whole loss was avoidable.

**Split the review by what the review policy already covers.** Generated artifacts are outside the
gate anyway — `grafana/dashboard*.json`, `grafana/sentinel-contract.json`, `grafana/runbooks.md`,
`grafana/tabs/AUTHORING.md`, `grafana/alerts/grafana-managed/`, `opnsense/testdata/schemas/`,
`docs/`, `README.md`. On a wave-sized change those are most of the bytes and none of the branching:
in wave 2 they were 4,957 of 8,180 changed lines, `dashboard.json` alone 4,642. Reviewing the 48
source files completed and found six findings, two of them major.

Do it in a scratch worktree so the real checkout is never disturbed:

```bash
git worktree add -f --detach /tmp/cr-src origin/main
cd /tmp/cr-src && git apply <the wave patch>
# restore generated paths to base: checkout the tracked ones, rm the new ones
git add -A && coderabbit review --agent --base main
```

If the source slice is itself too large, split it again by package. Every changed source file must
appear in some completed review; record which review covered which files.

**A slice has one cost, and it is predictable:** a finding raised against a file you excluded is a
false positive, because the reviewer is reading a tree where that file was never updated. Wave 2's
`log-shipping.md` source-table finding was exactly this. Check any docs- or generated-file finding
against the real tree before acting on it.

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

**Bringing the lab up out of hours.** Authorised, including for an unattended run. `oli` is reachable
over the tailnet as `root` and carries the power scheduler:

```bash
ssh oli '/usr/local/bin/opnsense-testbed-power.sh status'      # hold state + every guest
ssh oli '/usr/local/bin/opnsense-testbed-power.sh up 7200'     # start in dependency order, 2h hold
ssh oli '/usr/local/bin/opnsense-testbed-power.sh release'     # clear the hold
ssh oli '/usr/local/bin/opnsense-testbed-power.sh down'        # refuses while a hold is live
```

`up` blocks until **both** firewalls serve `:443`, so its return is the readiness signal — never poll
for it yourself. Take a hold no longer than the work needs; the default is 8h and it lapses on its
own. Whoever takes a hold owns releasing it, and `down` will not run until they do.

**Never call `qm` or `pct` on `oli` directly.** The scheduler's hardcoded allowlist (102, 106, 105,
110, 111, 112) is the only thing standing between a typo and powering off home automation (100), the
CI runners (101), unifi-os (103), winsrv (104) or postgres (107). Drive power through the script,
always, and never derive an id from `qm list`.

**The testbed firewalls' API credentials are not on any laptop** — they live only in the repository's
`tailnet` GitHub environment (`DEVBOX_API_KEY`/`DEVBOX2_API_KEY`, and the DEVBOX2 pair for the release
box). So local `just capture` and `just run` cannot reach the testbed, and the only unattended route
to live evidence is to power the lab up and dispatch the canary, which holds those secrets:

```bash
gh workflow run live-canary.yml --ref main
gh run list --workflow live-canary.yml --limit 1 --json databaseId,status,conclusion
```

That gives a **structure verdict, not a payload** — `cmd/apidrift` writes its captures to the
runner's temp and nothing uploads them. The consequence is a two-pass loop for any new endpoint:
land the struct derived from upstream source, push, dispatch the canary, and read its verdict against
the golden schema. A lane that needs to *see* a real payload cannot get one this way, and should say
so rather than inventing one.

**camden's prod canary runs against Rob's production firewall.** It is not a test target. No lane
writes to it, and its `--decide-only` seam is the only part a lane exercises.

**Grafana Cloud is live.** `just grafana-check` regenerates and diffs local artifacts and touches
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
mechanical detector: `just fieldaudit` reports struct fields in package `opnsense` that are
unmarshalled and never read, and the same analysis runs as a unit test, so `just test` already gates
it. If you add an exemption, write the reason.

### 5. Public metadata leaking into a public repo

This repository is public and `backlog/` is now committed with it.

- `just check-public-ips` rejects any globally routable IP literal in source, tests, fixtures or docs
  without a justified entry in `scripts/public-ip-allowlist.json` (#565). RFC1918, loopback,
  link-local, CGNAT, multicast and the RFC 5737 / RFC 3849 documentation ranges are never flagged.
- Golden schemas are **structure-only** — key paths and JSON types, never response values.
- Credentials have twice reached places they should not: request headers into a capture, and a bearer
  token surviving a redirect. Redact at the boundary, not at the sink.

**This now extends to the tracker, and `just check-public-ips` scans `backlog/` like any other
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
  hand-edits one produces a diff that `just docs-check` or `just grafana-check` reverts on the next
  regeneration, silently losing the work.

## Issue numbers below #656

They are GitHub issues, not tasks. See the *Pre-backlog issue numbers* doc.
