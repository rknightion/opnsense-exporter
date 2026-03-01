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

- **`internal/collector/`** — Prometheus collector implementations. `collector.go` holds the top-level `Collector` struct that runs 14 sub-collectors concurrently via goroutines. Each sub-collector (one file per subsystem) implements `CollectorInstance` with `Name()`, `Register()`, `Describe()`, and `Update()`. **Sub-collectors register themselves via `init()` functions** appending to the global `collectorInstances` slice — adding a new collector requires only creating the file with an `init()` function.

- **`internal/options/`** — Configuration via kingpin CLI flags and env vars. `ops.go` handles OPNsense connection config; `exporter.go` handles server config; `collectors.go` has per-collector disable switches. All env vars are prefixed `OPNSENSE_EXPORTER_`.

**Data flow:** `main.go` → builds API client + options → creates `Collector` → registers with Prometheus registry → serves HTTP. On each scrape, `Collector.Update()` fans out to all enabled sub-collectors in parallel.

## Adding a New Collector

1. Create `internal/collector/<subsystem>.go` implementing `CollectorInstance`
2. Add an `init()` that appends to `collectorInstances`
3. Add a `Fetch<Subsystem>()` method in `opnsense/` with corresponding data structs
4. Add a disable flag in `internal/options/collectors.go`
5. Wire the disable flag into `internal/collector/collector.go`

## Key Conventions

- **Vendor directory is committed** — always run `make sync-vendor` after `go.mod` changes
- **Static binary build** with `-ldflags "-s -w"` and `CGO_ENABLED=0`
- **Version** is read from the `VERSION` file and embedded at build time
- Linters: `misspell` and `revive` are enabled; `unused` is disabled
- API key/secret support file-based secrets (`OPS_API_KEY_FILE`, `OPS_API_SECRET_FILE`)
