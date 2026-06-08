# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make              # Build binary (static, version-embedded)
make test         # Run all tests: go test ./...
make lint         # Run gofmt + golangci-lint --fix
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

**Docs (required — keep collectors/metrics in sync):**

6. Add the new subsystem to the **two hand-maintained maps** in `scripts/docgen/main.go`: `flagToSubsystem` (flag → subsystem) and `subsystemToDisplayName` (subsystem → pretty name). docgen will otherwise render the collector with a blank flag and lowercase name.
7. Run `make docgen` (regenerates `docs/metrics/metrics.md` and `docs/collectors/reference.md` only) and commit the result
8. Manually update the flag/env-var tables that docgen does **not** touch: the README "Collector Options" tables and the `docs/configuration.md` "Collector switches" tables. Refresh the verbatim `--help` block in `docs/configuration.md` by building (`CGO_ENABLED=0 go build`) and pasting `./opnsense-exporter --help`
9. Add a bullet to the README "Changes from Upstream" fork changelog (see Key Conventions)

**Dashboard (required — a coverage gate enforces this):**

10. Add panels for the new metrics to the Grafana dashboard. Each tab lives in a module under `grafana/tabs/` (see `grafana/tabs/AUTHORING.md` for the builder API); add panels to the relevant tab (or a new module wired into `register_subsystem_tabs` in `grafana/build_dashboard.py`). Then run `make dashboard` — it **fails the build if any catalogue metric is left off the dashboard**. Optionally add alert/recording rules in `grafana/alerts/build_rules.py` and run `make rules`. See `grafana/README.md`.

## Key Conventions

- **Vendor directory is committed** — always run `make sync-vendor` after `go.mod` changes
- **Static binary build** with `-ldflags "-s -w"` and `CGO_ENABLED=0`
- **Version** — the repository root contains a `version.txt` file managed by release-please; the binary version is embedded at build time via `-X main.version=...` (GoReleaser uses the git tag; local `make` builds embed `local-test`)
- Linters: `misspell` and `revive` are enabled; `unused` is disabled
- API key/secret support file-based secrets (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`)
- **Fork changelog** — This is a fork of AthennaMind/opnsense-exporter. The "Changes from Upstream" section in `README.md` must be kept up to date. When adding new collectors, enhancing existing collectors, changing build/infrastructure, or making any other notable change, add a bullet to the appropriate subsection in that list.
