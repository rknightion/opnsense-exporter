# AGENTS.md

Guidance for agents working in this repository. Claude Code and Codex both read this file —
`CLAUDE.md` is a one-line import of it, so there is only ever one copy to keep current.

## Issue tracking

Tasks live **in this repo**, in `backlog/`, managed by the `backlog` CLI.

```bash
backlog task list --plain        # the queue
backlog doc list --plain         # the durable docs
```

GitHub Issues was retired for project work on **2026-08-14**, and the 524 issues we and CI had filed
were archived and then **deleted from GitHub** — so `gh issue view <N>` 404s. Historical work is
still cited as `#NNN`: the *Pre-backlog issue numbers* doc explains the load-bearing ones, and
`archive/github-issues-2026-08-14.json` holds every body and reply (redacted; `archive/README.md`
has the placeholder mapping). New work is `OPN-NNNN`. Two ID spaces, no overlap.

**The GitHub tracker is still enabled, deliberately** — external contributors can file issues, and
Renovate's dependency dashboard still lives there. Anything arriving that way becomes an `OPN-NNNN`
task; the board, not the issue, is where it is worked.

Read the **Agent fan-out protocol (canonical)** doc before designing a wave, and the **Wave operating
model** doc for this project's own rules, exclusive resources and recurring defects. The protocol is
harness-neutral — it routes lanes by **role**, and its Appendix A (Codex) or Appendix B (Claude Code)
resolves a role into a concrete model and reasoning depth. Name the harness in the run contract and
resolve every lane from that profile; the two differ in kind, not just in model names. Any `#NNNN`
below 656 is a GitHub issue, not a task — the **Pre-backlog issue numbers** doc says what the ones
cited below actually mean.

## Tracker rules that are not optional

- **Never `--notes` or `--plan` bare.** They *silently replace* the whole section, exit 0, and
  destroy another session's writes. Use `--append-notes` and `--append-plan`. This is an open
  upstream bug, not a misunderstanding. On Rob's machines a `PreToolUse` hook denies the bare form
  outright, so a block there is the guard working, not a broken harness — `task create` is exempt
  because a task being created has no section to overwrite.
- **Never hand-edit task, draft, doc, decision or milestone markdown.** Section boundaries are HTML
  comment markers; break one and the section is silently dropped with the data still in the file but
  invisible until the next write destroys it. There is no repair command — `backlog doctor` only
  fixes duplicate task IDs. `backlog/config.yml` is the one file edited by hand.
- **Finalize in a single call**, so an interrupted session cannot leave finished work looking
  unfinished: `backlog task edit OPN-0007 --check-ac 1 --check-ac 2 -s Done`.
- **Never let two agents edit the same task.** The v1.50.x concurrency fix covers the `task edit`
  funnel only — not reorder, draft saves, the TUI path, `doc update` or decision updates.
- **`backlog/` is committed to a public repository.** No account identifiers, tokens, IP literals or
  personal data in tasks or docs — write the shape, not the instance. `just check-public-ips` catches
  IP literals; nothing catches the rest.
- **Do not build on decisions or MCP.** `backlog decision` is half-built upstream (no edit, no view,
  no supersede) and the MCP server is frozen and costs 10-50k tokens of permanent context against
  1-2k for the CLI. Durable reference goes in **docs**; tasks are the unit of work.

## Task interface

This repo's task surface is a `justfile`. Discover it, don't guess it:

    just --list                        # human-readable
    just --dump --dump-format json     # machine-readable
    just --show <recipe>               # what a recipe actually runs

- `just check` is the bare-toolchain pre-commit gate and must pass before you commit.
- `just ci` adds only CI legs that need Docker or cross-compilation. GitHub API metadata validation
  and the full Docker/kind orchestration remain workflow-only.
- Prefer `just <recipe>` over the underlying tool. If you are typing `go test`, you want `just test`.
- Run `just` with stdin from `/dev/null`. Recipes marked `[confirm]` are destructive — stop and ask
  before running one; never pass `--yes` or `JUST_YES=1`.
- If a task you need does not exist, add a recipe with a `#` doc comment and a `[group(...)]`
  rather than running a bare command.

Run a single test:

    just test TestFetchGateways
    go test ./opnsense/ -run TestFetchGateways    # when you need a specific package

## Architecture

This is a Prometheus exporter for OPNsense firewalls. It polls OPNsense REST APIs and exposes metrics at `/metrics`, and also *receives* pushed telemetry — syslog, Zenarmor and NetFlow — which it ships as OTLP logs.

**Seven packages:**

- **`opnsense/`** — API client. Each subsystem has a dedicated `Fetch*()` method (e.g., `FetchGateways()`, `FetchWireguardConfig()`). The client handles TLS, basic auth, retries (max 3), and gzip decompression. Data structs for JSON unmarshaling live here too.

- **`internal/collector/`** — Prometheus collector implementations. `collector.go` holds the top-level `Collector` struct. An internal **poll scheduler** (`scheduler.go`, #336) runs each of the 65 sub-collectors' `Update()` on its own interval — its data-volatility tier (`interval_tiers.go`: fast 15s / medium 60s / slow 5m / cold 15m) — into an in-memory **snapshot** (`snapshot.go`). Serving `/metrics` (`ScrapeView`) and the OTLP bridge both **replay that snapshot**: the request path makes no live API call. Each sub-collector (one file per subsystem) implements `CollectorInstance` with `Name()`, `Register()`, `Describe()`, and `Update()`. **Sub-collectors register themselves via `init()` functions** appending to the global `collectorInstances` slice — adding a new collector requires only creating the file with an `init()` function.

- **`internal/options/`** — Configuration via kingpin CLI flags and env vars. `ops.go` handles OPNsense connection config; `exporter.go` handles server config; `collectors.go` has per-collector disable switches; `otlp.go` and `pyroscope.go` configure the opt-in OTLP-tracing and Pyroscope-profiling telemetry families; `log.go` handles logging config and `init.go` wires the flag registration. All env vars are prefixed `OPN2OTEL_`; the `*_FILE` secret vars also accept legacy unprefixed aliases (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`, `PYROSCOPE_AUTH_USER_FILE`, `PYROSCOPE_AUTH_PASSWORD_FILE`) for backwards compatibility, with the prefixed form taking precedence.

- **`internal/logship/`** — the syslog receiver (#248), the Zenarmor receiver, per-program parser registry (`syslog/`), enrichment (`enrich/`), and the OTLP log sink. Push-based, not polled: OPNsense/Zenarmor send us data, we don't fetch it.

- **`internal/flow/`** — the NetFlow receiver (`netflow/`), flow rollup, and the correlator that merges NetFlow fragments with Zenarmor conn documents into one flow log per connection-window (#346). Also push-based.

- **`internal/webui/`** — the operator console served at `/` (#302). Renders only from `internal/metricsnap`, `collector.StatusTracker`, and the API-client cache view; handlers must never call `Gather()` on the live registry, since that would trigger a firewall scrape from an unrelated page load.

- **`internal/metricsnap/`** — passively records the metric families produced by real scrapes (teed at both the `/metrics` handler and the OTLP bridge), so the webui console can read a last-scrape snapshot without ever gathering on its own.

**Data flow:** `main.go` → builds API client + options → creates `Collector` → `StartPolling` launches per-collector poll goroutines that fill the snapshot on their own intervals → registers with Prometheus registry → serves HTTP. On each scrape (and on each OTLP export), `Collector.Collect()` **replays the latest snapshot** — collection is decoupled from the scrape (#336). `--collector.poll-interval` sets the global default; `--collector.poll-interval-override=<collector>=<dur>` overrides one; the code tier lives in `collectorTiers` (`interval_tiers.go`).

## Adding a New Collector

**Code:**

1. Create `internal/collector/<subsystem>.go` implementing `CollectorInstance` with an `init()` that appends to `collectorInstances`
1a. Assign a poll tier if the data is not medium-volatility: add the subsystem to `collectorTiers` in `internal/collector/interval_tiers.go` (fast/slow/cold). Collectors absent from that table poll at the 60s medium default. Operators can override any collector via `--collector.poll-interval-override`.
2. Add a `Fetch<Subsystem>()` method in `opnsense/` with data structs, register its endpoint(s) in `defaultEndpoints()` in `opnsense/client.go`, and bump the endpoint count in `opnsense/client_test.go`. Tests build their client from `defaultEndpoints()` directly (there is no separate `testEndpoints()` copy to keep in sync), and `TestNewClient_EndpointCount` asserts content-equality. For plugin-gated endpoints, treat a 404 as "feature absent" (return empty data + `nil`, mirroring `FetchACMECertificates`) so the collector stays silent when the plugin is missing.
2a. If the new endpoint is called with POST (`c.do("POST", ...)` or `c.doForm(...)`), add its
    endpoint-name key to `postEndpoints` in `opnsense/contract.go` and bump the golden POST count in
    `opnsense/contract_test.go`. GET endpoints need no change — the contract manifest derives them
    automatically. The `cmd/apicontract` canary cross-checks every endpoint against OPNsense source.
2b. If the new endpoint is plugin-gated (its `Fetch*` treats 404 as "feature absent" per step 2), add
    its endpoint name to `NegativeCacheable404Endpoints()` in `opnsense/cache.go` — GET **or** POST. Its
    404 is then cached (`--exporter.cache-ttl`), so boxes without the plugin stop re-asking on every
    scrape. Never list a core endpoint there (a cached 404 on `healthCheck` would keep reporting a
    recovered firewall as down) — `TestPluginGatedEndpoints` enforces this.
    **Two lists, two questions (#495):** `NegativeCacheable404Endpoints()` answers "may this 404 be
    cached?", `PluginGatedEndpoints()` answers "does this 404 mean a plugin is absent?". The second is a
    superset and is what the canary and `acl.go` read. They differ when an endpoint's real request path
    carries a query string the cache key does not (`vnstatGetJsonData`'s `?iface=`), making a TTL a
    no-op while the 404 is still plugin-absence. If your endpoint is in that shape, add it to
    `PluginGatedEndpoints()` only — otherwise the canary files its 404 under "core route vanished
    upstream".
2c. Add the endpoint's response struct to `schemaRegistry` in `opnsense/schema_registry.go` and run
    `just schemas` (`TestSchemaRegistryComplete` / `TestSchemasUpToDate` fail otherwise). If the
    endpoint is POST, also add its request body to `captureRequests` in `opnsense/capture_requests.go`
    (`TestCaptureRequestsCoverPostEndpoints` enforces parity). These feed the daily live-box schema
    canary (`cmd/apidrift`, `.github/workflows/live-canary.yml`), which validates real payload
    structure against the structs. Golden schemas are structure-only (key paths + JSON types) — never
    commit response values.

**Caching:** the client has a per-endpoint TTL response cache (`opnsense/cache.go`), opt-in per
endpoint. Two rules, and they are not the same rule:

- **A successful body** may only be cached for a **GET**, and only if the payload is **wholly**
  slow-moving. If it carries any counter, rate or live status (a service's running state, a link's
  up/down), caching it would freeze the series and invent flat `rate()` plateaus. A POST's body is
  never cached: `smartInfo` is POSTed once per device, so replaying one response for another request
  would return the wrong device's data.
- **A 404** may be cached for **any method**, including POST, and even for endpoints whose success
  payload is live. A 404 is a property of the route (`{"errorMessage":"Endpoint not found"}` — the
  plugin is not installed), not of the request body, so it is body-independent and changes only when
  an admin installs the plugin. Verified against a live OPNsense 26.1: a bad *resource* does not 404
  (`smartInfo` with a nonexistent device returns 200 `{"message":"Invalid device name"}`).
3. Add a `<Subsystem>Subsystem` const and a `Without<Subsystem>Collector()` option in `internal/collector/collector.go`
4. Add the flag + `CollectorsDisableSwitch` field + switch entry in `internal/options/collectors.go`. Use `exporter.disable-*` (default-on) for low-cardinality collectors; reserve `exporter.enable-*` (default-off) for collectors with extra per-scrape API cost or high cardinality
5. Wire it in `main.go` (`if !collectorsSwitches.<X> { ... WithoutXCollector() }`) (a unit test fails without it — `TestEveryDisableSwitchWiredInMain` reflects every `CollectorsDisableSwitch` field against the `collectorsSwitches.<X>` references in `main.go`, so a documented flag can't silently be a no-op)

**Docs (generated — do not hand-edit tables):**

6. Add the subsystem's display name to `SubsystemDisplayNames` in `internal/collector/collector.go` (a unit test fails without it)
7. Add a `CollectorFlags` entry in `internal/options/collectors.go` binding the new flag to the subsystem string (a unit test fails without it)
8. Run `just docs` and commit the result. It regenerates the metrics/collector references, re-injects the flag tables in `docs/configuration.md`, re-pins metric/collector counts across the site and README, lints all doc flag/env tokens, and cross-checks docs against the live collector registry. CI (`just docs-check`) fails if any of this is stale.

**Dashboard (required — a coverage gate enforces this):**

9. Add panels for the new metrics to the Grafana dashboard. Each tab lives in a module under `grafana/tabs/` (see `grafana/tabs/AUTHORING.md` for the builder API); add panels to the relevant tab (or a new module wired into `register_subsystem_tabs` in `grafana/build_dashboard.py`). Then run `just dashboard` — it **fails the build (non-zero exit, in both write and `--check` mode) if any catalogue metric is left off the dashboard**. Optionally add alert/recording rules in `grafana/alerts/build_rules.py` and run `just rules`. See `grafana/README.md`. CI enforces all of this via `just grafana-check` (a required `ci-success` job): the coverage gate, regeneration staleness of `dashboard.json`/`dashboard-stats.json`/`grafana/alerts/grafana-managed/*.json`, and Grafana-managed manifest validity.

## Canary Drift Triage

Every finding from the daily live-box schema canary (`cmd/apidrift`) gets exactly one of five verdicts.

**Ask "did upstream actually change?" FIRST.** Four of the five presuppose it did; **box-state** is the one that does not, and it is the most common answer in practice (7/7 of #271's findings, 7/7 of #243's). Reach for it before the others, or you will force-fit `drop` onto a live tunnel that merely fell over.

- **box-state** — the box has nothing to report, so the key is absent. NOT drift, and **never a code change**. A missing path proves nothing on its own: an endpoint with no IPsec SAs, no nginx cache node, no reporting subsystem or an empty vnstat DB legitimately omits the key. Confirm against upstream *source* that the key is conditional, then either exempt it with a `missingOK` entry whose prune trigger names the **box state** (not a release), or fix the testbed so the data exists — prefer fixing the testbed when the field backs an exported metric, because an exemption there blinds the canary to real drift on a consumed field.
- **absorb** — the payload changed representation only (a number arrived as a string, an object as an array of one). Flex types / `KindNumeric` usually already handle it; retype the field and move on.
- **chase** — the data moved or was renamed. Write a **tolerant reader**: keep the legacy field, add the new one alongside it, and resolve new-wins-else-legacy in an accessor method. Template: `opnsense/health_check.go`.
- **drop** — upstream removed the data. Keep the legacy field for the length of the support window; the metric reads absent/zero on newer releases. Document it in `docs/compatibility.md`.
- **opportunity** — new data we don't model yet. Roadmap candidate, not a bug: exempt it via `knownExtraTopKeys` so the canary stops flagging it.

Rules:

- **Verify against upstream source before assigning any verdict.** Read the controller/script that builds the payload and check whether the key is conditional. Two runs disagreeing (#235 flagged `healthCheck subsystems`, #243 did not) is a box-state tell, not intermittent drift. Guessing here is how a phantom generation gets modelled: `metadata.subsystems` was modelled as "the 26.1.11 shape" and upstream never populated it on any release, which cost two fabricated fixtures and a permanently dead branch (#284).
- **Support window is current + previous stable OPNsense.** Never version-sniff — resolve by payload *shape*. Never remove a legacy field while a release that sends it is still in the window.
- **A fixture must never encode a shape upstream cannot produce.** Derive fixtures from a real capture or from the source's own branches. If one is deliberately synthetic (pinning parser tolerance rather than a captured payload), say so in the case comment.
- **`opnsense/testdata/schemas/exemptions.json` is the compat ledger.** Every kept-legacy path gets a `missingOK` entry (the prefix form `section.*` is supported) with a note naming the generation it belongs to and the trigger that will let us prune it. Unmodelled new top-level keys go in `knownExtraTopKeys`.
- After changing structs, run `just schemas`. Goldens are structure-only — they must never contain response values.

## Key Conventions

- **Vendor directory is committed** — always run `just sync-vendor` after `go.mod` changes
- **Static binary build** with `-ldflags "-s -w"` and `CGO_ENABLED=0`
- **Version** — the repository root contains a `version.txt` file managed by release-please; the binary version is embedded at build time via `-X main.version=...` (GoReleaser uses the git tag; local `just build` builds embed `local-test`)
- Linters: `misspell` and `revive` are enabled; `unused` is disabled
- API key/secret support file-based secrets (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`)
- **Changelog** — release history lives in `CHANGELOG.md`, managed by release-please from conventional commits. There is no separate "changes from upstream" list to maintain; the README carries only a short hard-fork notice.
- **Generated docs** — never hand-edit content between `<!-- docgen:begin/end -->` markers or the docgen-generated pages; run `just docs` instead.

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
