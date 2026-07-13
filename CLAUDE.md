# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make              # Build binary (static, version-embedded)
make test         # Run all tests: go test ./...
make lint         # Run gofmt + golangci-lint --fix
make docs         # Regenerate all generated docs (metrics, collector reference, config tables, counts) + doclint
make docs-check   # CI gate: fail if generated docs are stale or doc tokens are invalid (alias: pre-commit hook via make install-hooks)
make sync-vendor  # go mod tidy && go mod vendor (run after dependency changes)
make clean        # Format, remove binary
```

Run a single test:
```bash
go test ./internal/collector/ -run TestCollector
go test ./opnsense/ -run TestFetchGateways
```

## Architecture

This is a Prometheus exporter for OPNsense firewalls. It polls OPNsense REST APIs and exposes metrics at `/metrics`.

**Three main packages:**

- **`opnsense/`** — API client. Each subsystem has a dedicated `Fetch*()` method (e.g., `FetchGateways()`, `FetchWireguardConfig()`). The client handles TLS, basic auth, retries (max 3), and gzip decompression. Data structs for JSON unmarshaling live here too.

- **`internal/collector/`** — Prometheus collector implementations. `collector.go` holds the top-level `Collector` struct that runs 55 sub-collectors concurrently via goroutines. Each sub-collector (one file per subsystem) implements `CollectorInstance` with `Name()`, `Register()`, `Describe()`, and `Update()`. **Sub-collectors register themselves via `init()` functions** appending to the global `collectorInstances` slice — adding a new collector requires only creating the file with an `init()` function.

- **`internal/options/`** — Configuration via kingpin CLI flags and env vars. `ops.go` handles OPNsense connection config; `exporter.go` handles server config; `collectors.go` has per-collector disable switches; `otlp.go` and `pyroscope.go` configure the opt-in OTLP-tracing and Pyroscope-profiling telemetry families; `log.go` handles logging config and `init.go` wires the flag registration. All env vars are prefixed `OPNSENSE_EXPORTER_`; the `*_FILE` secret vars also accept legacy unprefixed aliases (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`, `PYROSCOPE_AUTH_USER_FILE`, `PYROSCOPE_AUTH_PASSWORD_FILE`) for backwards compatibility, with the prefixed form taking precedence.

**Data flow:** `main.go` → builds API client + options → creates `Collector` → registers with Prometheus registry → serves HTTP. On each scrape, `Collector.Collect()` fans out to all enabled sub-collectors in parallel.

## Adding a New Collector

**Code:**

1. Create `internal/collector/<subsystem>.go` implementing `CollectorInstance` with an `init()` that appends to `collectorInstances`
2. Add a `Fetch<Subsystem>()` method in `opnsense/` with data structs, register its endpoint(s) in `defaultEndpoints()` in `opnsense/client.go`, and bump the endpoint count in `opnsense/client_test.go`. Tests build their client from `defaultEndpoints()` directly (there is no separate `testEndpoints()` copy to keep in sync), and `TestNewClient_EndpointCount` asserts content-equality. For plugin-gated endpoints, treat a 404 as "feature absent" (return empty data + `nil`, mirroring `FetchACMECertificates`) so the collector stays silent when the plugin is missing.
2a. If the new endpoint is called with POST (`c.do("POST", ...)` or `c.doForm(...)`), add its
    endpoint-name key to `postEndpoints` in `opnsense/contract.go` and bump the golden POST count in
    `opnsense/contract_test.go`. GET endpoints need no change — the contract manifest derives them
    automatically. The `cmd/apicontract` canary cross-checks every endpoint against OPNsense source.
2b. If the new endpoint is plugin-gated (its `Fetch*` treats 404 as "feature absent" per step 2), add
    its endpoint name to `PluginGatedEndpoints()` in `opnsense/cache.go` — GET **or** POST. Its 404 is
    then cached (`--exporter.cache-ttl`), so boxes without the plugin stop re-asking on every scrape.
    Never list a core endpoint there (a cached 404 on `healthCheck` would keep reporting a recovered
    firewall as down) — `TestPluginGatedEndpoints` enforces this.
2c. Add the endpoint's response struct to `schemaRegistry` in `opnsense/schema_registry.go` and run
    `make schemas` (`TestSchemaRegistryComplete` / `TestSchemasUpToDate` fail otherwise). If the
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
8. Run `make docs` and commit the result. It regenerates the metrics/collector references, re-injects the flag tables in `docs/configuration.md`, re-pins metric/collector counts across the site and README, lints all doc flag/env tokens, and cross-checks docs against the live collector registry. CI (`make docs-check`) fails if any of this is stale.

**Dashboard (required — a coverage gate enforces this):**

9. Add panels for the new metrics to the Grafana dashboard. Each tab lives in a module under `grafana/tabs/` (see `grafana/tabs/AUTHORING.md` for the builder API); add panels to the relevant tab (or a new module wired into `register_subsystem_tabs` in `grafana/build_dashboard.py`). Then run `make dashboard` — it **fails the build (non-zero exit, in both write and `--check` mode) if any catalogue metric is left off the dashboard**. Optionally add alert/recording rules in `grafana/alerts/build_rules.py` and run `make rules`. See `grafana/README.md`. CI enforces all of this via `make grafana-check` (a required `ci-success` job): the coverage gate, regeneration staleness of `dashboard.json`/`dashboard-stats.json`/`grafana/alerts/grafana-managed/*.json`, and Grafana-managed manifest validity.

## Canary Drift Triage

Every finding from the daily live-box schema canary (`cmd/apidrift`) gets exactly one of four verdicts:

- **absorb** — the payload changed representation only (a number arrived as a string, an object as an array of one). Flex types / `KindNumeric` usually already handle it; retype the field and move on.
- **chase** — the data moved or was renamed. Write a **tolerant reader**: keep the legacy field, add the new one alongside it, and resolve new-wins-else-legacy in an accessor method. Template: `opnsense/health_check.go`.
- **drop** — upstream removed the data. Keep the legacy field for the length of the support window; the metric reads absent/zero on newer releases. Document it in `docs/compatibility.md`.
- **opportunity** — new data we don't model yet. Roadmap candidate, not a bug: exempt it via `knownExtraTopKeys` so the canary stops flagging it.

Rules:

- **Support window is current + previous stable OPNsense.** Never version-sniff — resolve by payload *shape*. Never remove a legacy field while a release that sends it is still in the window.
- **`opnsense/testdata/schemas/exemptions.json` is the compat ledger.** Every kept-legacy path gets a `missingOK` entry (the prefix form `section.*` is supported) with a note naming the generation it belongs to and the trigger that will let us prune it. Unmodelled new top-level keys go in `knownExtraTopKeys`.
- After changing structs, run `make schemas`. Goldens are structure-only — they must never contain response values.

## Key Conventions

- **Vendor directory is committed** — always run `make sync-vendor` after `go.mod` changes
- **Static binary build** with `-ldflags "-s -w"` and `CGO_ENABLED=0`
- **Version** — the repository root contains a `version.txt` file managed by release-please; the binary version is embedded at build time via `-X main.version=...` (GoReleaser uses the git tag; local `make` builds embed `local-test`)
- Linters: `misspell` and `revive` are enabled; `unused` is disabled
- API key/secret support file-based secrets (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`)
- **Changelog** — release history lives in `CHANGELOG.md`, managed by release-please from conventional commits. There is no separate "changes from upstream" list to maintain; the README carries only a short hard-fork notice.
- **Generated docs** — never hand-edit content between `<!-- docgen:begin/end -->` markers or the docgen-generated pages; run `make docs` instead.
