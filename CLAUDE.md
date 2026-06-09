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

- **`internal/collector/`** — Prometheus collector implementations. `collector.go` holds the top-level `Collector` struct that runs 30 sub-collectors concurrently via goroutines. Each sub-collector (one file per subsystem) implements `CollectorInstance` with `Name()`, `Register()`, `Describe()`, and `Update()`. **Sub-collectors register themselves via `init()` functions** appending to the global `collectorInstances` slice — adding a new collector requires only creating the file with an `init()` function.

- **`internal/options/`** — Configuration via kingpin CLI flags and env vars. `ops.go` handles OPNsense connection config; `exporter.go` handles server config; `collectors.go` has per-collector disable switches. All env vars are prefixed `OPNSENSE_EXPORTER_`.

**Data flow:** `main.go` → builds API client + options → creates `Collector` → registers with Prometheus registry → serves HTTP. On each scrape, `Collector.Collect()` fans out to all enabled sub-collectors in parallel.

## Adding a New Collector

**Code:**

1. Create `internal/collector/<subsystem>.go` implementing `CollectorInstance` with an `init()` that appends to `collectorInstances`
2. Add a `Fetch<Subsystem>()` method in `opnsense/` with data structs, register its endpoint(s) in the `endpoints` map in `opnsense/client.go`, and add the endpoint name(s) to `testEndpoints()` in `opnsense/testhelpers_test.go` (and bump the count in `opnsense/client_test.go`). For plugin-gated endpoints, treat a 404 as "feature absent" (return empty data + `nil`, mirroring `FetchACMECertificates`) so the collector stays silent when the plugin is missing.
3. Add a `<Subsystem>Subsystem` const and a `Without<Subsystem>Collector()` option in `internal/collector/collector.go`
4. Add the flag + `CollectorsDisableSwitch` field + switch entry in `internal/options/collectors.go`. Use `exporter.disable-*` (default-on) for low-cardinality collectors; reserve `exporter.enable-*` (default-off) for collectors with extra per-scrape API cost or high cardinality
5. Wire it in `main.go` (`if !collectorsSwitches.<X> { ... WithoutXCollector() }`)

**Docs (generated — do not hand-edit tables):**

6. Add the subsystem's display name to `SubsystemDisplayNames` in `internal/collector/collector.go` (a unit test fails without it)
7. Add a `CollectorFlags` entry in `internal/options/collectors.go` binding the new flag to the subsystem string (a unit test fails without it)
8. Run `make docs` and commit the result. It regenerates the metrics/collector references, re-injects the flag tables in `docs/configuration.md`, re-pins metric/collector counts across the site and README, lints all doc flag/env tokens, and cross-checks docs against the live collector registry. CI (`make docs-check`) fails if any of this is stale.

**Dashboard (required — a coverage gate enforces this):**

9. Add panels for the new metrics to the Grafana dashboard. Each tab lives in a module under `grafana/tabs/` (see `grafana/tabs/AUTHORING.md` for the builder API); add panels to the relevant tab (or a new module wired into `register_subsystem_tabs` in `grafana/build_dashboard.py`). Then run `make dashboard` — it **fails the build if any catalogue metric is left off the dashboard**. Optionally add alert/recording rules in `grafana/alerts/build_rules.py` and run `make rules`. See `grafana/README.md`.

## Key Conventions

- **Vendor directory is committed** — always run `make sync-vendor` after `go.mod` changes
- **Static binary build** with `-ldflags "-s -w"` and `CGO_ENABLED=0`
- **Version** — the repository root contains a `version.txt` file managed by release-please; the binary version is embedded at build time via `-X main.version=...` (GoReleaser uses the git tag; local `make` builds embed `local-test`)
- Linters: `misspell` and `revive` are enabled; `unused` is disabled
- API key/secret support file-based secrets (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`)
- **Changelog** — release history lives in `CHANGELOG.md`, managed by release-please from conventional commits. There is no separate "changes from upstream" list to maintain; the README carries only a short hard-fork notice.
- **Generated docs** — never hand-edit content between `<!-- docgen:begin/end -->` markers or the docgen-generated pages; run `make docs` instead.
