---
title: Contributing
description: How to contribute to the OPNsense Exporter project, including build, test, and lint instructions
tags:
  - OPNsense
---

# Contributing

Thank you for your interest in contributing to the OPNsense Exporter. This guide covers the development workflow, tooling, and conventions.

## Prerequisites

- **Go** -- Check `go.mod` for the required version (currently Go 1.26)
- **Make** -- For build automation
- **golangci-lint** -- Optional; runs in CI but can be used locally
- **Docker** -- Optional; for container builds

## Getting started

Clone the repository:

```bash
git clone https://github.com/rknightion/opnsense-exporter.git
cd opnsense-exporter
```

## Build commands

| Command | Description |
|---------|-------------|
| `make` | Build the binary (static, version-embedded) |
| `make test` | Run all tests: `go test ./...` |
| `make lint` | Run `gofmt` and `golangci-lint --fix` |
| `make sync-vendor` | `go mod tidy && go mod vendor` |
| `make clean` | Format source and remove the binary |

### Building on macOS

The Makefile uses `-extldflags "-static"` which does not work on macOS. Use this instead:

```bash
CGO_ENABLED=0 go build -o opnsense-exporter .
```

### Running a single test

```bash
go test ./internal/collector/ -run TestCollector
go test ./opnsense/ -run TestFetchGateways
```

## Project conventions

### Vendor directory

The vendor directory is committed to the repository. Always run `make sync-vendor` after modifying `go.mod`:

```bash
make sync-vendor
```

### Static binary

The build produces a fully static binary with:

- `CGO_ENABLED=0`
- `-ldflags "-s -w"` for stripped, optimized output
- `-trimpath` and `-mod=vendor` for reproducibility

### Version

The version is read from the `VERSION` file at the repository root and embedded at build time via `-ldflags`.

### Linters

The project uses `golangci-lint` with:

- `misspell` and `revive` enabled
- `unused` disabled

Linting runs in CI. Locally, `make lint` will run `gofmt` formatting (the `golangci-lint` step may fail if the tool is not installed, which is expected).

### Commit messages

This project uses [conventional commits](https://www.conventionalcommits.org/) for automated changelog generation via [release-please](https://github.com/googleapis/release-please):

```
feat(collector): add new subsystem collector
fix(kea): handle disabled DHCP service response
docs: update README with new collector descriptions
refactor: modernize Go syntax patterns
```

### Fork changelog

When making notable changes (new collectors, enhanced collectors, build/infrastructure changes), update the "Changes from Upstream" section in `README.md`. Add a bullet under the appropriate subsection.

## Pull request checklist

Before submitting a PR:

- [ ] Code compiles: `make` or `CGO_ENABLED=0 go build`
- [ ] Tests pass: `make test`
- [ ] Code is formatted: `gofmt -w .`
- [ ] Vendor is synced (if dependencies changed): `make sync-vendor`
- [ ] Conventional commit messages used
- [ ] README "Changes from Upstream" section updated (if applicable)
- [ ] New collectors follow the [adding a collector](adding-collector.md) guide

## Project structure

```
.
+-- main.go                      # Entry point
+-- internal/
|   +-- collector/               # Prometheus collectors
|   |   +-- collector.go         # Top-level collector, interface
|   |   +-- arp_table.go         # Per-subsystem collector files
|   |   +-- gateways.go
|   |   +-- ...
|   +-- options/                 # CLI flags and configuration
|       +-- ops.go               # OPNsense connection config
|       +-- exporter.go          # Server config
|       +-- collectors.go        # Collector enable/disable switches
+-- opnsense/                    # API client
|   +-- client.go                # HTTP client, TLS, retries
|   +-- gateways.go              # Per-subsystem Fetch methods
|   +-- ...
+-- deploy/                      # Deployment manifests
|   +-- k8s/                     # Kubernetes manifests
|   +-- grafana/                 # Grafana dashboard JSON
+-- docs/                        # Documentation
+-- vendor/                      # Vendored dependencies
```
