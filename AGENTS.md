# opnsense2otel

A Prometheus and OpenTelemetry exporter for OPNsense firewalls. It polls OPNsense REST APIs and
serves `/metrics`, and it also *receives* pushed telemetry - syslog, Zenarmor and NetFlow - which it
ships as OTLP logs. Both halves matter: treating it as a poll-only exporter is the usual wrong
mental model.

## Task interface

`just check` is the gate and must pass before you commit. `just ci` adds the deployment contracts,
cross-compilation and the container image. Discover the rest with `just --list`; run `just` with
stdin from `/dev/null`. GitHub API metadata validation and the full Docker/kind orchestration stay
workflow-only and have no recipe.

`just bump-module-major` is the one `[confirm]` recipe - stop and ask, never pass `--yes` or
`JUST_YES=1`.

Narrow the suite with the filter argument: `just test TestFetchGateways`.

## Tracker

Tasks are `OPN-NNNN` in `backlog/`. Read the **Agent fan-out protocol (canonical)** doc before
designing a wave, and the **Wave operating model** doc for this project's own rules, exclusive
resources and recurring defects.

Any `#NNN` **below 656** in code comments, task text or docs is a retired GitHub issue, not a task:
the 524 pre-migration issues were deleted, so `gh issue view <N>` 404s on those. Numbers at or above
656 are live GitHub issues and resolve normally. Bodies and replies for the deleted set live in
`archive/github-issues-2026-08-14.json` (redacted; `archive/README.md` has the placeholder mapping)
and the **Pre-backlog issue numbers** doc explains the load-bearing ones. The two ID spaces do not
overlap.

**The GitHub issue tracker stays enabled deliberately** - external contributors file there and
Renovate's dependency dashboard lives there. Anything arriving that way becomes an `OPN-NNNN` task;
the board, not the issue, is where it is worked.

Tracker traps:

- **Never `--notes` or `--plan` bare.** They *silently replace* the whole section and exit 0,
  destroying another session's writes. Use `--append-notes` and `--append-plan`. A `PreToolUse` hook
  denies the bare form, so a block there is the guard working, not a broken harness; `task create` is
  exempt because a new task has no section to overwrite.
- Break an HTML-comment section marker by hand-editing task markdown and the section is silently
  dropped, still in the file but invisible until the next write destroys it. There is no repair
  command - `backlog doctor` only fixes duplicate task IDs. `backlog/config.yml` is the one file
  edited by hand.
- **Finalize in a single call** so an interrupted session cannot leave finished work looking
  unfinished: `backlog task edit OPN-0007 --check-ac 1 --check-ac 2 -s Done`.
- **Never let two agents edit the same task.** The v1.50.x concurrency fix covers the `task edit`
  funnel only - not reorder, draft saves, the TUI path, `doc update` or decision updates.
- **Do not build on `backlog decision` or the MCP server.** Decisions are half-built upstream (no
  edit, no view, no supersede) and the MCP server costs 10-50k tokens of permanent context against
  1-2k for the CLI. Durable reference goes in **docs**; tasks are the unit of work.
- **`backlog/` is committed to a public repository.** No account identifiers, tokens, IP literals or
  personal data in tasks or docs - write the shape, not the instance. `just check-public-ips` catches
  IP literals against `scripts/public-ip-allowlist.json`; nothing catches the rest.

## Design invariants

- **Collection is decoupled from the scrape.** A poll scheduler (`internal/collector/scheduler.go`)
  runs each of the 82 sub-collectors' `Update()` on its own volatility tier (docgen keeps that
  figure current; do not hand-edit it)
  (`internal/collector/interval_tiers.go`: fast 15s / medium 60s / slow 5m / cold 15m) into an
  in-memory snapshot (`snapshot.go`). Serving `/metrics` and the OTLP bridge both *replay* that
  snapshot; the request path makes no live API call. Never reintroduce a fetch on the request path.
- **Sub-collectors register themselves from `init()`**, appending to the global `collectorInstances`
  slice. Adding one is a file plus its `init()`, not an edit to a central list.
- **`internal/webui` must never call `Gather()` on the live registry.** The operator console renders
  only from `internal/metricsnap`, `collector.StatusTracker` and the API-client cache view; gathering
  there would trigger a firewall scrape from an unrelated page load.
- **`internal/logship` and `internal/flow` are push-based.** OPNsense, Zenarmor and NetFlow send to
  us; nothing there polls.
- Every env var is prefixed `OPN2OTEL_`, except the standard OTel SDK pair
  `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`, which the log shipper
  honours unprefixed (`docs/log-shipping.md`). The `*_FILE` secret vars also accept legacy unprefixed
  aliases (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`, `PYROSCOPE_AUTH_USER_FILE`,
  `PYROSCOPE_AUTH_PASSWORD_FILE`) for backwards compatibility, with the prefixed form winning.

## Conventions

- **The vendor directory is committed.** Run `just sync-vendor` after any `go.mod` change.
- Release binaries are static: `CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w -X main.version=..."`.
  A local `just build` embeds `local-test`; GoReleaser uses the git tag.
- `version.txt` and `CHANGELOG.md` are managed by release-please from conventional commits. There is
  no "changes from upstream" list to maintain - the README carries a short hard-fork notice and
  nothing else.
- `misspell` and `revive` are on, `unused` is off, deliberately.
- Never hand-edit generated output: content between `<!-- docgen:begin/end -->` markers, the
  docgen-generated doc pages, `grafana/dashboard*.json`, or the alert manifests. Edit the builder and
  run the generator.

## Deeper references

- `reference/adding-a-collector.md` - read before adding a collector, a `Fetch*` method or a new
  OPNsense endpoint. Holds the eight-file registration contract and the two 404 caching rules.
- `reference/canary-triage.md` - read before acting on a `cmd/apidrift` finding or editing
  `opnsense/testdata/schemas/exemptions.json`.
- `grafana/tabs/AUTHORING.md` and `grafana/README.md` - read before adding dashboard panels or
  alert rules.
- `docs/compatibility.md` - the record of data upstream removed and the support window it is kept for.

<!-- BACKLOG.MD GUIDELINES START -->
<!-- backlog.md-instructions-version: 1.50.1 -->
<CRITICAL_INSTRUCTION>

## Backlog.md Workflow

This project uses Backlog.md for task and project management.

**For every user request in this project, run `backlog instructions overview` before answering or taking action.**

Use the overview to decide whether to search, read, create, or update Backlog tasks.

Before task lifecycle actions, read the matching detailed guide:
- `backlog instructions task-creation` before creating or splitting tasks
- `backlog instructions task-execution` before planning, changing status or assignee, adding a plan or implementation notes, or implementing task work
- `backlog instructions task-finalization` before checking acceptance criteria, writing final summaries, or moving tasks to terminal statuses

Use `backlog <command> --help` before running unfamiliar commands. Help shows options, fields, and examples.

Do not edit Backlog task, draft, document, decision, or milestone markdown files directly. Use the `backlog` CLI so metadata, relationships, and history stay consistent.

</CRITICAL_INSTRUCTION>
<!-- BACKLOG.MD GUIDELINES END -->
