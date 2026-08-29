---
id: OPN-0006
title: Migrate the repo task surface to just and retire Makefiles and ad-hoc scripts
status: To Do
assignee: []
created_date: '2026-08-28 19:05'
updated_date: '2026-08-29 09:18'
labels:
  - 'wave:2-fleet'
dependencies: []
priority: medium
type: chore
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Fleet-wide migration of the repo task surface from `make` + ad-hoc shell to a single top-level
`justfile`, per the frozen fleet justfile standard (mandatory seven-recipe vocabulary, six groups,
`bash -euo pipefail` shell, no unstable features, CI calls `just`).

This repo is Go 1.27 + a Helm chart + systemd packaging + a Python Grafana-artifact builder tree. It
has one root `Makefile` (12 KB, 30 targets), 14 tracked shell scripts outside `vendor/`, and 21
workflow files. `ci-success` gates on eight jobs, six of which shell out to `make`.

---

## 1. Outcome

`justfile` at the repo root is the only task surface. `just --list` names every developer and CI
task, grouped. `just check` is the complete local gate and reproduces every `ci-success` job that
can run off a GitHub runner (all except `docker-build-verify`, which needs docker+kind+sudo, and
`repo-meta`, which needs the GitHub API). `Makefile` and `scripts/sbom.sh` are gone. The eleven
scripts that must survive as files — shipped runtime artifacts, real programs, and shell test
suites — stay exactly where they are and each gains a recipe that is now the only supported way to
invoke it. `ci.yml` and `publish.yml` install a SHA-pinned `just` and every build/test/lint/generate
step is a one-line `just <recipe>`. `renovate.json`'s Makefile customManager is repointed at the
justfile so the `go-licenses` / `syft` / `kubeconform` pins keep getting bumped. Docs, `AGENTS.md`,
`backlog/config.yml`'s `definition_of_done`, the pre-commit hook, and every generator that *emits*
the string `make …` into a generated file all say `just`.

---

## 2. The complete justfile

Drop this in at `/Users/rob/repos/opnsense2otel/justfile`, then run `just --fmt` once and commit
whatever it reflows (long parameterised-dependency lines in particular).

```just
set shell := ["bash", "-euo", "pipefail", "-c"]

binary_name := "opnsense2otel-local"
tools_dir := justfile_directory() / ".tools"
version := env('VERSION', `git describe --tags --always --dirty 2>/dev/null || echo dev`)

# ── pinned release-tooling versions (override GO_LICENSES_VERSION etc. via env is NOT
# supported any more; edit here — this is the single source of truth, #436) ───────────
# GO_LICENSES_VERSION is the ONE source of truth for the go-licenses version *and* module
# path shared by `just notices`, the Dockerfile image build, and Renovate (#436).
# go-licenses v2+ is published under the semantic-import path
# github.com/google/go-licenses/v2 (v1.x was github.com/google/go-licenses with no
# suffix) — the module path is therefore pinned below alongside the version, so a future
# v3 bump updates both together instead of silently reintroducing the v2.0.1 "post-v2
# module path" install failure this fixed. The Dockerfile does NOT keep its own copy: it
# declares GO_LICENSES_VERSION/GO_LICENSES_MODULE as required build-args with no default,
# and every caller (ci.yml's docker-build-verify job, publish.yml's release build)
# resolves the current pin via `just print-go-licenses-version` /
# `just print-go-licenses-module` below and passes it in — so the two paths cannot select
# different versions unnoticed.
# renovate: datasource=go depName=github.com/google/go-licenses/v2
go_licenses_version := "v2.0.1"
go_licenses_module := "github.com/google/go-licenses/v2"
# renovate: datasource=go depName=github.com/anchore/syft
syft_version := "v1.51.1"
# renovate: datasource=github-releases depName=yannh/kubeconform
kubeconform_version := "v0.8.0"

# show the task surface
default:
    @just --list

# install the repo-local toolchain into .tools/ and warm the module cache (idempotent)
setup: _tool-go-licenses _tool-syft _tool-kubeconform
    go mod download
    @test -n '{{ which("golangci-lint") }}' || echo "note: golangci-lint is not on PATH — install it (brew install golangci-lint); CI pins v2.13.2 via golangci/golangci-lint-action"
    @echo "setup: .tools populated, modules downloaded"

# ── check ────────────────────────────────────────────────────────────────────────────

# format Go sources and the justfile in place
[group('check')]
fmt:
    gofmt -s -w $(find . -type f -name '*.go' -not -path './vendor/*' -not -path './.git/*')
    just --fmt

# verify formatting without writing (justfile + gofmt -s)
[group('check')]
[no-exit-message]
fmt-check:
    just --fmt --check
    @out=$(gofmt -s -l $(find . -type f -name '*.go' -not -path './vendor/*' -not -path './.git/*')); if [ -n "$out" ]; then echo "gofmt -s would rewrite:"; echo "$out"; exit 1; fi

# run golangci-lint over every package (read-only; use `just fmt` to rewrite)
[group('check')]
[no-exit-message]
lint:
    golangci-lint run ./...

# run the Go test suite; pass a filter to narrow it (e.g. just test TestFetchGateways)
[group('check')]
[no-exit-message]
test filter="":
    go test {{ if filter != "" { "-run " + filter } else { "" } }} ./...

# run the full Go suite under the race detector
[group('check')]
[no-exit-message]
test-race:
    go test -race -timeout 15m ./...

# write an atomic coverage profile to coverage.out (uploaded to Codacy by CI)
[group('check')]
test-coverage:
    go test -covermode=atomic -coverprofile=coverage.out ./...

# run one bounded fuzz target
[group('check')]
[no-exit-message]
fuzz-one package target fuzztime="10s" timeout="3m":
    go test '{{ package }}' -run='^$' -fuzz='^{{ target }}$' -fuzztime={{ fuzztime }} -parallel=1 -timeout={{ timeout }}

# run every fuzz target for 10s as a deterministic smoke gate
[group('check')]
fuzz-smoke: (fuzz-one "./internal/flow/netflow" "FuzzDecodePacketAndTemplate") (fuzz-one "./internal/logship/syslog" "FuzzParseEnvelope") (fuzz-one "./internal/logship/syslog" "FuzzTCPFrames") (fuzz-one "./internal/logship/zenarmor" "FuzzParseDocument")

# reject globally routable IP literals that are not in scripts/public-ip-allowlist.json (#565)
[group('check')]
[no-exit-message]
check-public-ips:
    python3 scripts/check_public_ips.py --selftest
    python3 scripts/check_public_ips.py

# run the executable deployment contracts (Compose, systemd, k8s manifests, Helm chart)
[group('check')]
[no-exit-message]
deployment-test: _tool-kubeconform
    bash -n scripts/deployment/test_examples.sh scripts/systemd/*.sh
    scripts/deployment/test_examples.sh
    scripts/systemd/test_documentation.sh
    scripts/systemd/test_secret_permissions.sh
    scripts/systemd/test_unit.sh
    {{ tools_dir }}/kubeconform -strict -summary deploy/k8s/deployment.yaml
    PATH="{{ tools_dir }}:$PATH" charts/opnsense2otel/tests/test-chart.sh

# unit-test the testbed tooling's host-independent seams (#504, #625)
[group('check')]
[no-exit-message]
[working-directory('scripts/testbed')]
testbed-test:
    bash -n opnsense-testbed-power.sh
    python3 -m unittest discover -p '*_test.py' -q

# unit-test camden's prod canary open-vs-closed decision logic (#612)
[group('check')]
[no-exit-message]
[working-directory('scripts/canary')]
canary-test:
    bash -n opnsense-prod-canary.sh
    python3 -m unittest discover -p '*_test.py' -q

# run the grafana/ builders' own unit tests plus the promqlcheck tool's
[group('check')]
[no-exit-message]
grafana-test:
    cd grafana && python3 -m unittest discover -s tests -t . -q
    go test -C tools/promqlcheck ./...

# THE GATE — everything a PR must pass. Exactly what CI enforces, minus the
# docker+kind image job and the GitHub-API repo-meta job, neither of which can run
# off a runner.
[group('check')]
check: fmt-check lint test test-race fuzz-smoke check-public-ips deployment-test testbed-test canary-test grafana-test gen-check

# ── gen ──────────────────────────────────────────────────────────────────────────────

# regenerate every committed generated artifact (dashboard -> rules -> docs -> schemas)
[group('gen')]
gen: dashboard rules docs schemas

# fail if any committed generated artifact is stale — the drift gate
[group('gen')]
gen-check: docs-check grafana-check

# regenerate the metrics/collector/config docs, .env.example and the doc-token lint
[group('gen')]
docs:
    go run ./scripts/docgen

# fail if the generated docs are stale or a doc flag/env token is invalid
[group('gen')]
[no-exit-message]
docs-check:
    go run ./scripts/docgen -check

# rebuild grafana/dashboard*.json + sentinel-contract.json + the AUTHORING.md region
[group('gen')]
[working-directory('grafana')]
dashboard:
    python3 build_dashboard.py

# rebuild the Grafana-managed alert/recording manifests and grafana/runbooks.md
[group('gen')]
[working-directory('grafana/alerts')]
rules:
    python3 build_rules.py

# regenerate the structure-only golden schemas in opnsense/testdata/schemas/
[group('gen')]
schemas:
    go run ./cmd/apischema

# coverage gate + regeneration staleness + manifest validity for grafana/ (#84)
[group('gen')]
[no-exit-message]
grafana-check:
    cd grafana && python3 build_dashboard.py --check
    cd grafana && python3 build_dashboard.py
    cd grafana/alerts && python3 build_rules.py
    cd tools/promqlcheck && go run . ../../grafana/dashboard.json ../../grafana/dashboard-health.json ../../grafana/alerts/grafana-managed/*.json
    git diff --exit-code -- grafana/dashboard.json grafana/dashboard-health.json grafana/dashboard-stats.json grafana/sentinel-contract.json grafana/tabs/AUTHORING.md grafana/alerts/grafana-managed/
    python3 grafana/alerts/validate_manifests.py

# re-tidy and re-vendor after a go.mod change (the vendor dir is committed)
[group('gen')]
sync-vendor:
    go mod tidy
    go mod vendor

# redownload the IEEE OUI registry and rebuild internal/webui/oui_data.txt (network)
[group('gen')]
gen-oui:
    scripts/gen_oui.sh

# ── build ────────────────────────────────────────────────────────────────────────────

# build the local static test binary
[group('build')]
build:
    go build -tags osusergo,netgo -ldflags '-w -extldflags "-static" -X main.version=local-test' -v -o {{ binary_name }}

# build the container image locally (same required build-args the release build uses)
[group('build')]
image tag="opnsense2otel:dev":
    docker build --build-arg VERSION='{{ version }}' --build-arg GO_LICENSES_VERSION='{{ go_licenses_version }}' --build-arg GO_LICENSES_MODULE='{{ go_licenses_module }}' -t '{{ tag }}' .

# remove build output, the coverage profile and the .tools/ toolchain (all reproducible)
[group('build')]
clean:
    go clean
    rm -f {{ binary_name }} coverage.out
    rm -rf bin dist/sbom {{ tools_dir }}

# ── dev ──────────────────────────────────────────────────────────────────────────────

# Credentials go via the exporter's env vars, NOT the --api-key/--api-secret flags:
# argv is world-readable (ps, /proc/<pid>/cmdline), so flag-passed creds leak to every
# local user for the process lifetime. The env is only owner-readable (#160).
# Reads OPS_ADDRESS (required), OPS_API_KEY, OPS_API_SECRET, OPS_EXPORTER_PORT,
# OPS_INSTANCE, OPS_ADDITIONAL_ARGS.

# run the exporter locally against a real OPNsense box (long-running; ctrl-c to stop)
[group('dev')]
run: build
    OPN2OTEL_OPS_API_KEY="${OPS_API_KEY:-}" OPN2OTEL_OPS_API_SECRET="${OPS_API_SECRET:-}" ./{{ binary_name }} --log.level=debug --log.format=logfmt --web.telemetry-path=/metrics --web.listen-address=":{{ env('OPS_EXPORTER_PORT', '8080') }}" --exporter.instance-label="{{ env('OPS_INSTANCE', 'opnsense-local1') }}" --opnsense.protocol=https --opnsense.address="{{ env('OPS_ADDRESS') }}" --web.disable-exporter-metrics ${OPS_ADDITIONAL_ARGS:-}

# capture live-box responses into the gitignored opnsense/testdata/captures/ (#157, #160)
[group('dev')]
capture args="":
    OPN2OTEL_OPS_API_KEY="${OPS_API_KEY:-}" OPN2OTEL_OPS_API_SECRET="${OPS_API_SECRET:-}" go run ./cmd/apicapture --base-url "{{ env('OPS_BASE_URL', 'https://' + env('OPS_ADDRESS', '')) }}" ${OPS_INSECURE:+--insecure} {{ args }}

# report opnsense struct fields decoded from the API and then never read (#544)
[group('dev')]
fieldaudit args="":
    go run ./cmd/fieldaudit {{ args }}

# install the docs-staleness pre-commit hook into .git/hooks/
[group('dev')]
install-hooks:
    cp scripts/hooks/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    @echo "pre-commit hook installed"

# ── release ──────────────────────────────────────────────────────────────────────────

# regenerate THIRD_PARTY_NOTICES.md from the shipped binary's import graph
[group('release')]
notices: _tool-go-licenses
    GO_LICENSES={{ tools_dir }}/go-licenses bash scripts/notices.sh

# build a static binary and emit SPDX + CycloneDX SBOMs for it
[group('release')]
sbom target="bin/opnsense2otel" out_dir="dist/sbom" name="opnsense2otel": _tool-syft
    CGO_ENABLED=0 go build -mod=vendor -tags osusergo,netgo -trimpath -ldflags "-s -w -X main.version={{ version }}" -o bin/opnsense2otel .
    mkdir -p '{{ out_dir }}'
    {{ tools_dir }}/syft '{{ target }}' -q -o "spdx-json={{ out_dir }}/{{ name }}.spdx.json" -o "cyclonedx-json={{ out_dir }}/{{ name }}.cdx.json"
    @echo "sbom: wrote {{ out_dir }}/{{ name }}.spdx.json + {{ out_dir }}/{{ name }}.cdx.json"

# rewrite the Go module path to a new major (release-please does not do this)
[group('release')]
[confirm('rewrite the Go module path to a new major version? this edits every tracked file that references it.')]
bump-module-major major="":
    scripts/bump-module-major.sh {{ major }}

# ── private helpers ──────────────────────────────────────────────────────────────────

[private]
_tool-go-licenses:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/go-licenses' && '{{ tools_dir }}/go-licenses' --help >/dev/null 2>&1; } || GOBIN='{{ tools_dir }}' go install {{ go_licenses_module }}@{{ go_licenses_version }}

[private]
_tool-syft:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/syft' && '{{ tools_dir }}/syft' version >/dev/null 2>&1; } || GOBIN='{{ tools_dir }}' go install github.com/anchore/syft/cmd/syft@{{ syft_version }}

[private]
_tool-kubeconform:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/kubeconform' && '{{ tools_dir }}/kubeconform' -v >/dev/null 2>&1; } || GOBIN='{{ tools_dir }}' go install github.com/yannh/kubeconform/cmd/kubeconform@{{ kubeconform_version }}

# Emit the pinned go-licenses version/module so other build surfaces (the Dockerfile's
# GO_LICENSES_VERSION/GO_LICENSES_MODULE build-args, supplied by ci.yml and publish.yml)
# resolve the SAME pin declared above instead of holding an independent copy (#436).
# Private so `just --list` stays a task surface; still invocable by name from CI.
[private]
print-go-licenses-version:
    @echo {{ go_licenses_version }}

[private]
print-go-licenses-module:
    @echo {{ go_licenses_module }}
```

---

## 3. Makefile disposition

Every target in `/Users/rob/repos/opnsense2otel/Makefile`.

| Make target | Replacement recipe | Notes |
|---|---|---|
| `default` (build binary) | `just build` | make's `default` was the build; just's `default` is `@just --list` (fleet-frozen). The build moves to `build`. |
| `sync-vendor` | `just sync-vendor` | Unchanged body. |
| `local-run` | `just run` | Renamed to the fleet's optional vocabulary. Keep the #160 credentials-via-env comment verbatim above the recipe. `$(or $(OPS_EXPORTER_PORT), 8080)` → `env('OPS_EXPORTER_PORT', '8080')`; `$(if $(OPS_ADDITIONAL_ARGS),…)` → `${OPS_ADDITIONAL_ARGS:-}`. |
| `test` | `just test` | Gains an optional `filter` param. |
| `coverage` | `just test-coverage` | Renamed: `coverage` is not fleet vocabulary and the profile is a test artifact. |
| `tools-licensing` | `just _tool-go-licenses` | Private; a dependency of `notices`. |
| `tools-sbom` | `just _tool-syft` | Private; a dependency of `sbom`. |
| `tools-kubeconform` | `just _tool-kubeconform` | Private; a dependency of `deployment-test`. |
| `print-go-licenses-version` | `just print-go-licenses-version` | `[private]`. **Called by `ci.yml` and `publish.yml` — must keep working.** |
| `print-go-licenses-module` | `just print-go-licenses-module` | `[private]`. Same. |
| `notices` | `just notices` | Still shells `scripts/notices.sh` (KEEP). |
| `sbom` | `just sbom` | `scripts/sbom.sh` ABSORBED; the env-var overrides become recipe params. |
| `clean` | `just clean` | Drops the `gofmt -s -w` (that is `fmt`; §2 says `clean` removes only reproducible output) and adds `bin/`, `dist/sbom/`, `.tools/`. Does **not** touch the rest of `dist/`. |
| `lint` | `just lint` + `just fmt` | Split: make's `lint` mutated (`gofmt -w` + `golangci-lint --fix`). Fleet contract says `lint` never mutates. `golangci-lint run ./...` only; `.golangci.yml` already enables the `gofmt` formatter so formatting is still gated. |
| `docs` | `just docs` | Unchanged body. |
| `docgen` (alias) | — | Dropped. Retire the back-compat alias; `just docs` is the one name. |
| `docs-check` | `just docs-check` | Unchanged body. |
| `deployment-test` | `just deployment-test` | Unchanged body; `$(TOOLS_DIR)` → `{{ tools_dir }}`, `PATH="$(TOOLS_DIR):$(PATH)"` → `PATH="{{ tools_dir }}:$PATH"`. |
| `testbed-test` | `just testbed-test` | `cd scripts/testbed &&` → `[working-directory('scripts/testbed')]`; the `bash -n` path becomes relative. |
| `canary-test` | `just canary-test` | Same shape. |
| `install-hooks` | `just install-hooks` | Unchanged body. The hook's own body changes (§4). |
| `dashboard` | `just dashboard` | `cd grafana &&` → `[working-directory('grafana')]`. |
| `rules` | `just rules` | `cd grafana/alerts &&` → `[working-directory('grafana/alerts')]`. |
| `grafana-check` | `just grafana-check` | Body unchanged, including the `git diff --exit-code` staleness gate. Keep the multi-`cd` lines as-is: each is a single line, so `cd` persists within it. |
| `grafana-test` | `just grafana-test` | Unchanged. Keep the Makefile comment explaining why `grafana-check` is not a prerequisite (#429). |
| `fieldaudit` | `just fieldaudit` | `$(ARGS)` → an `args=""` param. |
| `schemas` | `just schemas` | Unchanged. |
| `check-public-ips` | `just check-public-ips` | Unchanged. |
| `capture` | `just capture` | `$(CAPTURE_ARGS)` → an `args=""` param; `$(or $(OPS_BASE_URL),https://$(OPS_ADDRESS))` → nested `env()`. |
| `.PHONY:` line | — | Delete. Meaningless in just. |
| `TOOLS_DIR` / `export PATH` | `tools_dir := justfile_directory() / ".tools"` | Deliberately **not** a global `export PATH` — see Traps §9. Each recipe that needs a `.tools` binary names it explicitly or prefixes `PATH=` on its own line. |
| `BINARY_NAME` / `VERSION` | `binary_name := …` / `version := env('VERSION', \`git describe …\`)` | See Traps §9 for the `:=`-vs-`?=` evaluation change. |
| `GO_LICENSES_VERSION` etc. | `go_licenses_version := "v2.0.1"` etc. | The `# renovate:` annotations move with them. **`renovate.json` must be repointed** — §5. |

**Then: `git rm Makefile`.** No repo in the fleet keeps a Makefile. Do this LAST (order of work, §8),
after nothing references it.

---

## 4. Script disposition

Every tracked shell/Python script outside `vendor/` that is used as a dev or CI task.

| Script | Verdict | Recipe | Notes |
|---|---|---|---|
| `scripts/sbom.sh` | **ABSORB** | `just sbom` | 38 lines: env defaults, a `command -v` guard, `mkdir -p`, one `syft` call. Textbook thin wrapper. Recipe lines given in §2; the four env overrides (`SYFT`, `SBOM_TARGET`, `OUT_DIR`, `SBOM_NAME`) become the recipe params `target` / `out_dir` / `name` plus the `_tool-syft` dependency. `git rm scripts/sbom.sh`. |
| `scripts/notices.sh` | **KEEP** | `just notices` | 112 lines: heredoc, `mktemp`+`trap`, a `while IFS=$'\t' read` loop over go-licenses TSV, per-module NOTICE discovery. A real program, not a task. |
| `scripts/gen_oui.sh` | **KEEP** | `just gen-oui` | 124 lines wrapping an embedded Python heredoc with a 55-entry vendor regex table. A real program. |
| `scripts/bump-module-major.sh` | **KEEP** | `just bump-module-major` | 110 lines: shell functions, five validation branches, a `git ls-files | xargs grep -l` sweep, a BSD/GNU-portable in-place rewrite loop. Non-trivial control flow. |
| `scripts/cloud-environment-setup.sh` | **KEEP** | none — leave unreferenced | 175 lines, provisions hosted Codex/Claude cloud environments and is executed by the environment service, not by a developer or CI. §6 "scripts invoked by something other than a developer or CI". Do **not** wire it to `just setup`; do **not** delete it. |
| `scripts/systemd/verify-release.sh` | **KEEP** | none | Shipped runtime artifact: end users download and run it to verify a release archive. Runs on a machine with no `just`. |
| `scripts/hooks/pre-commit` | **KEEP** | `just install-hooks` | Shipped runtime artifact (copied into `.git/hooks/`). **Its body changes**: `make docs-check` → `just docs-check`, and the header comment `Regenerate with: make docs` → `just docs`. |
| `scripts/testbed/opnsense-testbed-power.sh` | **KEEP** | `just testbed-test` (syntax check + unit tests only) | 393 lines, runs on the `oli` Proxmox host from a systemd timer. Not a developer task. |
| `scripts/testbed/opnsense-testbed-canary-dispatch.sh` | **KEEP** | none | Runs on `oli`; POSTs a workflow_dispatch once the lab is warm. Not a developer task. |
| `scripts/canary/opnsense-prod-canary.sh` | **KEEP** | `just canary-test` (syntax check + unit tests only) | 131 lines, runs on `camden` against the production firewall with an admin credential. |
| `charts/opnsense2otel/tests/test-chart.sh` | **KEEP** | `just deployment-test` | 210-line shell test suite with assertion helpers over rendered Helm output. §6 "shell test suites". |
| `scripts/deployment/test_examples.sh` | **KEEP** | `just deployment-test` | Shell test suite; embeds a Python heredoc that parses `docs/deployment/docker.md`. |
| `scripts/systemd/test_documentation.sh` | **KEEP** | `just deployment-test` | Shell test suite. |
| `scripts/systemd/test_secret_permissions.sh` | **KEEP** | `just deployment-test` | Shell test suite; drives an Alpine container. |
| `scripts/systemd/test_unit.sh` | **KEEP** | `just deployment-test` | 105-line shell test suite; boots the documented unit under real systemd in a container. |
| `scripts/check_public_ips.py` (+ `_test.py`) | **KEEP** | `just check-public-ips` | A real Python program with its own `--selftest`. |
| `scripts/testbed/config_lint.py` (+ `_test.py`) | **KEEP** | `just testbed-test` (its unit tests) | Real program; needs a firewall's `config.xml`, unrunnable in CI. |
| `scripts/testbed/testbed_power_test.py` | **KEEP** | `just testbed-test` | Test file. |
| `scripts/canary/prod_canary_test.py` | **KEEP** | `just canary-test` | Test file. |
| `scripts/grafana-prune-rules.py` | **KEEP** | none — called by `grafana-sync.yml:204` | Operational workflow tooling; out of scope this pass. |
| `scripts/verify-gitsync.py` | **KEEP** | none — called by `grafana-sync.yml:157` | Same. |
| `scripts/docgen/**` (Go) | **KEEP** | `just docs` / `just docs-check` | A Go program (30 files). |
| `grafana/build_dashboard.py`, `grafana/alerts/build_rules.py`, `grafana/alerts/validate_manifests.py`, `grafana/tabs/**`, `grafana/tests/**` | **KEEP** | `just dashboard` / `just rules` / `just grafana-check` / `just grafana-test` | Real programs and a real test suite. |
| `tools/opnsense_api_contract/extract.py` | **KEEP** | none — called by `api-contract.yml` | Out of scope this pass (needs a cloned upstream repo). |

Net deletions from this section: **`scripts/sbom.sh` only.**

---

## 5. CI changes

### 5.0 The `setup-just` step (exact YAML)

Insert this immediately **after** the `actions/setup-go` step in each job listed below, before the
first `run: just …`. Resolve the SHA before writing it — do not invent one:

```bash
gh api repos/extractions/setup-just/git/refs/tags/v4 --jq '.object.sha'
# if that returns an annotated-tag object, dereference it:
gh api repos/extractions/setup-just/git/tags/<sha> --jq '.object.sha'
```

```yaml
      - uses: extractions/setup-just@<RESOLVED-40-CHAR-SHA> # v4
        with:
          just-version: '1.58.0'
```

`just-version` is pinned exactly because `just --fmt` output carries no backwards-compatibility
guarantee — an unpinned bump can turn `fmt-check` red with no repo change.

### 5.1 `.github/workflows/ci.yml`

| Job | Line | Current | Becomes |
|---|---|---|---|
| `tests` | 42 (`Run tests`) | `run: go test -v ./...` | `run: just test` — the `-v` is dropped; per-test output is not worth a second recipe. |
| `tests` | 48 | `run: make check-public-ips` | `run: just check-public-ips` |
| `race` | 78 | `run: go test -race -timeout 15m ./...` | `run: just test-race` |
| `fuzz-smoke` | 118–130 (`Run bounded fuzz target`) | the `run: >-` `go test … -fuzztime=10s … -timeout=3m` block | `run: just fuzz-one "$FUZZ_PACKAGE" "$FUZZ_TARGET"` — **keep the `env:` block and the matrix exactly as they are.** The inline comments explaining the 3m-vs-5m timeout reasoning (#469) move into the `fuzz-one` recipe's default params. |
| `docs` | 139 | `run: make docs-check` | `run: just docs-check` |
| `deployment-contracts` | 159 | `run: make deployment-test` | `run: just deployment-test` |
| `deployment-contracts` | 164 | `run: make testbed-test` | `run: just testbed-test` |
| `deployment-contracts` | 170 | `run: make canary-test` | `run: just canary-test` |
| `grafana` | 189 | `run: make grafana-test` | `run: just grafana-test` |
| `grafana` | 195 | `run: make grafana-check` | `run: just grafana-check` |
| `docker-build-verify` | 219–220 | `echo "version=$(make -s print-go-licenses-version)"` / `…module…` | `echo "version=$(just print-go-licenses-version)"` / `echo "module=$(just print-go-licenses-module)"` — `just`'s echoed command line goes to **stderr**, so command substitution stays clean. |
| `coverage` | 399 | `run: make coverage` | `run: just test-coverage` |

Jobs needing the `setup-just` step: `tests`, `race`, `fuzz-smoke`, `docs`, `deployment-contracts`,
`grafana`, `docker-build-verify`, `coverage`.

`docker-build-verify` has no `actions/setup-go` step before line 219 — its `setup-go` is at line ~330,
after the image build. Put `setup-just` immediately after that job's `actions/checkout`.

**Must NOT change in `ci.yml`:**

- `ci-success` (name, `if: always()`, and the `needs: [repo-meta, tests, race, fuzz-smoke, docs, deployment-contracts, grafana, docker-build-verify]` list). The branch ruleset gates on that exact check name.
- `permissions: contents: read` at the top; `concurrency: group: ci-${{ github.ref }}`.
- Every `persist-credentials: false`.
- Every SHA pin and its `# vN` comment: `actions/checkout@3d3c42e5…`, `actions/setup-go@b7ad1dad…`, `golangci/golangci-lint-action@ba0d7d2e…`, `azure/setup-helm@9bc31f4e…`, `docker/setup-buildx-action@37fe6310…`, `docker/build-push-action@53b7df96…`, `codacy/codacy-coverage-reporter-action@89d6c85c…`.
- The `Run linters` step: it is a `uses:` (`golangci/golangci-lint-action`), never convert a `uses:` to `run: just`. Its `version: v2.13.2` and the `# renovate:` annotation above it stay put — `renovate.json`'s second customManager matches on that exact shape.
- `uses: ./.github/workflows/repo-meta.yml`.
- The `fuzz-smoke` matrix (`include:` with `name`/`package`/`target`) and its `timeout-minutes: 5`.
- The whole `docker-build-verify` job body below line 222: the docker/kind/compose `run:` blocks stay as YAML. They need `sudo`, a Docker daemon, and a kind cluster; they are CI-environment orchestration, not a developer task. `just image` exists for a plain local image build only.
- The `coverage` job's deliberate absence from `ci-success`'s `needs:` and the `if: ${{ env.CODACY_PROJECT_TOKEN != '' }}` guard.

### 5.2 `.github/workflows/publish.yml`

| Job | Line | Current | Becomes |
|---|---|---|---|
| `go-licenses-pin` | 34–35 | `make -s print-go-licenses-version` / `…module` | `just print-go-licenses-version` / `just print-go-licenses-module`; add `setup-just` after the checkout step. |
| `notices` | 82 | `make notices` | `just notices`; add `setup-just` after the `actions/setup-go` step. |

**Must NOT change:** the `workflow_call` / `workflow_dispatch` inputs and their defaults;
`permissions:` on every job; `step-security/harden-runner@05e31511…`; the
`uses: rknightion/.github/.github/workflows/container-publish.yml@f3169068… # v1.3.1` reusable call
and its `with:` block including the `helm-chart-path` conditional; the `gh release upload` line
after `just notices`.

### 5.3 `.github/workflows/api-contract-enrich.yml`

| Line | Current | Becomes |
|---|---|---|
| 101 | prose: `path changed, runs \`make docs\`, and runs \`CGO_ENABLED=0 go test ./...\`` | `runs \`just docs\`` |
| 105 | `--allowedTools "…,Bash(make docs:*),Bash(make docs-check:*),…"` | `…,Bash(just docs:*),Bash(just docs-check:*),…` |

This is the easiest miss in the repo: an agent-tool allowlist string, not a `run:` body. Miss it and
the enrichment agent silently loses permission to regenerate docs.

### 5.4 Workflows explicitly NOT touched

`release-please.yml`, `codeql.yml`, `zizmor.yml`, `actionlint.yml`, `scorecard.yml`,
`dependency-review.yml`, `docker-security.yml`, `trigger-docs-sync.yml`, `ghcr-cleanup.yml`,
`arm-automerge.yml`, `auto-rc.yml`, `geoip-refresh.yml`, `live-canary.yml`, `grafana-sync.yml`,
`api-contract.yml`, `repo-meta.yml`, `fuzz.yml`.

Reasons, where they are not simply GitHub-native:

- `fuzz.yml` — it *could* call `just fuzz-one "$FUZZ_PACKAGE" "$FUZZ_TARGET" 5m 7m`, and the recipe's params exist for exactly that. Deferred to keep this change's blast radius on the required gate; the scheduled corpus-retaining run has its own cache-key coupling. Convert it in a follow-up if desired.
- `repo-meta.yml` — its `run:` blocks are GitHub-metadata validation (issue-template schema, CODEOWNERS write-access probe via the API) with a `pip install pyyaml` of their own. Not a developer task. Deferred.
- `api-contract.yml` — needs a cloned `opnsense/docs` checkout at a Renovate-pinned SHA plus `pip install -r tools/opnsense_api_contract/requirements.txt`. Deferred.
- `grafana-sync.yml`, `live-canary.yml`, `geoip-refresh.yml` — operational/deployment workflows, not the PR gate.

---

## 6. Docs and agent-contract changes

### 6.1 `AGENTS.md`

Replace the `## Commands` fenced block (lines 57–66) with the §9 Task-interface section. **Do not
paste the recipe list.**

```markdown
## Task interface

This repo's task surface is a `justfile`. Discover it, don't guess it:

    just --list                        # human-readable
    just --dump --dump-format json     # machine-readable
    just --show <recipe>               # what a recipe actually runs

- `just check` is the full gate and is exactly what CI enforces. It must pass before you commit.
  It is `ci-success` minus the two jobs that cannot run off a GitHub runner: `docker-build-verify`
  (needs docker + kind + sudo) and `repo-meta` (needs the GitHub API).
- Prefer `just <recipe>` over the underlying tool. If you are typing `go test`, you want `just test`.
- Run `just` with stdin from /dev/null. Recipes marked `[confirm]` are destructive — stop and ask
  before running one; never pass `--yes` or `JUST_YES=1`.
- If a task you need does not exist, add a recipe with a `#` doc comment and a `[group(...)]`
  rather than running a bare command.

Run a single test:

    just test TestFetchGateways
    go test ./opnsense/ -run TestFetchGateways    # when you need a specific package
```

Other `AGENTS.md` lines:

| Line | Current | Becomes |
|---|---|---|
| 49 | `` `make check-public-ips` catches `` | `` `just check-public-ips` catches `` |
| 119 | `` `make schemas` `` | `` `just schemas` `` |
| 147 | `Run \`make docs\` …` and `CI (\`make docs-check\`)` | `just docs` / `just docs-check` |
| 151 | `run \`make dashboard\``, `run \`make rules\``, `via \`make grafana-check\`` | `just dashboard` / `just rules` / `just grafana-check` |
| 171 | `run \`make schemas\`` | `just schemas` |
| 175 | `always run \`make sync-vendor\`` | `just sync-vendor` |
| 181 | `run \`make docs\` instead` | `just docs` |

`CLAUDE.md` is a four-line `@AGENTS.md` import — no change.

### 6.2 Other prose files

| File:line | Current | Becomes |
|---|---|---|
| `CONTRIBUTING.md:22` | `- GNU Make` (Requirements list) | `- [just](https://just.systems) 1.58+` |
| `CONTRIBUTING.md:28` | `… make local-run` | `… just run` |
| `CONTRIBUTING.md` (new) | — | Add one line: run `just setup` first. |
| `README.md:180` | `run \`make docs\` after changing flags` | `just docs` |
| `.github/pull_request_template.md:27` | `I ran \`make docs\`` | `just docs` |
| `.github/pull_request_template.md:28` | `ran \`make dashboard\`` | `just dashboard` |
| `.github/pull_request_template.md:29` | `I ran \`make sync-vendor\`` | `just sync-vendor` |
| `.github/pull_request_template.md:32` | `Local gate is green: \`go test ./...\`, \`go test -race ./...\`, \`golangci-lint run ./...\`, \`make docs-check\`, \`make grafana-check\`` | `Local gate is green: \`just check\`` — collapse the whole list; that is the point of the fleet contract. Keep the trailing sentence about `docker build .`. |
| `docs/development/contributing.md:36–39` | the `make test` / `make lint` / `make sync-vendor` / `make clean` table | `just test` / `just lint` / `just sync-vendor` / `just clean`; add rows for `just setup` and `just check`. |
| `docs/development/contributing.md:60,63` | `make sync-vendor` | `just sync-vendor` |
| `docs/development/contributing.md:85` | `\`make lint\` will run \`gofmt\` formatting` | rewrite: `just fmt` rewrites, `just lint` only reports. |
| `docs/development/contributing.md:110–117` | the six-item PR checklist naming `make test` / `make lint` / `make docs-check` / `make grafana-check` / `make dashboard` / `make rules` / `make sync-vendor` | rewrite around `just check` plus `just gen` for the regeneration step. |
| `docs/development/adding-collector.md:19,238,242,257` | `run \`make docs\``, `(\`make docs-check\`)`, `- [ ] \`make docs\` run` | `just docs` / `just docs-check` |
| `docs/development/release-process.md:163–165` | `(\`make docs-check\`)`, `\`make grafana-test\` and \`make grafana-check\`` | `just docs-check` / `just grafana-test` / `just grafana-check` |
| `cmd/apicapture/README.md:24,30,31,44,55` | `make capture`, `make local-run` | `just capture`, `just run` |
| `grafana/README.md:16` | `Regenerate with \`make rules\`` | `just rules` |
| `archive/README.md:40` | `(\`make check-public-ips\`, …)` | `just check-public-ips` |
| `scripts/hooks/pre-commit` | `# Regenerate with: make docs` and `make docs-check` | `just docs` / `just docs-check` |

`CHANGELOG.md` and `THIRD_PARTY_NOTICES.md` are **not** edited — they are historical records, and
`CHANGELOG.md` is release-please-owned.

### 6.3 Generated files — edit the GENERATOR, not the output

These files contain `make …` but are regenerated by `just gen`. Hand-editing them is reverted by the
next `just docs` / `just dashboard` and then fails `just gen-check`. Change the source string:

| Generator:line | String | Emits into |
|---|---|---|
| `scripts/docgen/main.go:977` | `Run 'make docgen' to regenerate.` | `docs/metrics/metrics.md:1` |
| `scripts/docgen/main.go:1029` | `Run 'make docgen' to regenerate.` | `docs/collectors/reference.md:1` |
| `scripts/docgen/main.go:207` | `generated docs are stale, run 'make docs'` | the `-check` failure message |
| `scripts/docgen/compose_reference.go:96` | ``Generated by `make docs`.`` | `docs/deployment/reference.md:12` |
| `scripts/docgen/env_example.go:67` | ``GENERATED by `make docs``` | `.env.example:1` |
| `scripts/docgen/selfmetrics.go:434` | ``run `make docs`.`` | `docs/metrics/self-metrics.md:3` |
| `scripts/docgen/selfmetrics.go:439` | ``(`make grafana-check`) reads this table`` | `docs/metrics/self-metrics.md:10` |
| `scripts/docgen/stats.go:25,37,40,51,75` | `run 'make dashboard' first` / `rerun 'make rules'` | fatal messages |
| `grafana/alerts/build_rules.py:2677` | ``run `make rules``` | `grafana/runbooks.md:1` |
| `grafana/alerts/build_rules.py:2297` | ``Run `make dashboard` before `make rules`.`` | a fatal message |
| `grafana/sentinel_contract.py:11,22,169` | ``fails `make grafana-check``` | `grafana/tabs/AUTHORING.md` generated region + comments |
| `grafana/build_dashboard.py:2293` | comment: ``AGENTS.md promises `make dashboard``` | comment only |

Also update the plain-comment/error-string references that are neither generated nor prose (safe to
edit in place, no assertion depends on the text): `scripts/docgen/agents_md_test.go:33`,
`selfmetrics_test.go:280,297`, `compose_reference_test.go:30`, `flags_test.go:13`,
`cmd/apischema/main.go:7`, `cmd/apicapture/main.go:42`, `cmd/apicontract/main.go:42`,
`internal/options/exporter.go:83`, `internal/options/ops.go:84`, `internal/logship/metrics.go:80`,
`opnsense/protocol_statistics.go:219`, `opnsense/response_contract.go:67`,
`grafana/tests/test_field_overrides.py:12`, `test_runbooks.py:15,70,219,224`,
`test_self_metric_coverage.py:51`, `test_sentinel_contract.py:9,142,147,160`,
`grafana/tabs/AUTHORING.md:306,307` (source region — check whether it is inside a generated marker
first; if it is, change `sentinel_contract.py` instead).

After all of that: `just gen && git diff --exit-code` must be clean.

---

## 7. `backlog/config.yml`

Current:

```yaml
definition_of_done:
  - "make lint"
  - "make test"
  - "make check-public-ips"
  - "make docs-check"
  - "make grafana-check"
```

Replace with:

```yaml
definition_of_done:
  - "just check"
  - "just gen (if any generated artifact changed) and the diff committed"
```

`just check` subsumes all five of the old entries and adds the race, fuzz, deployment, testbed and
canary gates the old list silently omitted. This is the one file under `backlog/` edited by hand —
`AGENTS.md:43` already says so. Do **not** hand-edit anything else under `backlog/`.

---

## 8. Order of work

Green at every step. Do not reorder; deletions are last.

1. Write `justfile` from §2. Run `just --fmt`, then `just --list`, `just --dump --dump-format json >/dev/null` and `just --groups`. All three must exit 0 — a single unstable feature makes `--list` and `--dump` exit 1 for the whole file.
2. `just setup` on a clean-ish checkout. Then prove each recipe against its Makefile twin: for each of `build test test-race fuzz-smoke check-public-ips docs-check deployment-test testbed-test canary-test grafana-test grafana-check lint fmt-check`, run the `just` recipe and the `make` target and confirm the same outcome. The Makefile still exists at this point — that is the point.
3. `just print-go-licenses-version` must print exactly `v2.0.1` and `just print-go-licenses-module` exactly `github.com/google/go-licenses/v2`, with no extra output on stdout. Verify with `test "$(just print-go-licenses-version)" = v2.0.1`.
4. `just check` end to end. Fix ordering or working-directory problems here, not later.
5. Update `renovate.json`'s fourth customManager (§9 trap 1). Validate the regex against the new justfile before committing — a silently non-matching manager is invisible until a pin rots.
6. Resolve the `extractions/setup-just` v4 SHA and edit `ci.yml` + `publish.yml` per §5.1–5.2. Push and confirm `ci-success` is green with the Makefile still present. Both surfaces working simultaneously is the safe state.
7. Edit `api-contract-enrich.yml` lines 101 and 105 (§5.3).
8. Update the generator sources (§6.3), then `just gen`, then `git diff --exit-code` — expect the regenerated headers to change and commit them together with the generator change.
9. Update `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, the PR template, `docs/**`, `cmd/apicapture/README.md`, `grafana/README.md`, `archive/README.md`, `scripts/hooks/pre-commit` (§6.1–6.2).
10. Update `backlog/config.yml` (§7).
11. Grep-prove nothing is left: `git grep -n 'make [a-z-]' -- ':!CHANGELOG.md' ':!vendor' ':!THIRD_PARTY_NOTICES.md'` returns only English uses of the verb "make".
12. **Deletions last.** `git rm Makefile scripts/sbom.sh`. Re-run `just check` and push; confirm `ci-success` green.

---

## 9. Traps specific to this repo

1. **Deleting the `Makefile` silently kills a Renovate customManager.** `renovate.json`'s fourth entry is `"managerFilePatterns": ["/^Makefile$/"]` with `matchStrings: ["# renovate: datasource=(?<datasource>\\S+) depName=(?<depName>\\S+)\\s+[A-Z_]+_VERSION\\s*\\?=\\s*(?<currentValue>v[0-9.]+)"]`. That regex matches make's `GO_LICENSES_VERSION ?= v2.0.1`. It matches nothing in a justfile. Repoint it:

   ```json
   {
     "description": "Bump the syft / go-licenses / kubeconform pins in the justfile via # renovate: annotations (#135).",
     "customType": "regex",
     "managerFilePatterns": ["/^justfile$/"],
     "matchStrings": [
       "# renovate: datasource=(?<datasource>\\S+) depName=(?<depName>\\S+)\\s+[a-z_]+_version\\s*:=\\s*\"(?<currentValue>v[0-9.]+)\""
     ]
   }
   ```

   Note `[a-z_]+` (just variables are lowercase), `:=` not `?=`, and the value is **quoted**. `kubeconform_version` was already covered by the old regex and must stay covered. Leave the other three customManagers untouched.

2. **`make VERSION ?= $(shell …)` is lazy; `just version := \`…\`` is not.** make re-evaluated `git describe` only when `$(VERSION)` was actually used; just runs the backtick at parse time, on **every** `just` invocation including `just --list`. `env('VERSION', …)` still evaluates the backtick eagerly — that is how just works. It costs ~5 ms. Accept it. If it ever matters, move the `git describe` into the two recipe bodies that use it (`image`, `sbom`) as `$(git describe …)`.

3. **Do NOT add a global `export PATH := tools_dir + ":" + env('PATH')`** even though the Makefile did. Combined with the `version` backtick this walks into the verified just gotcha that exported variables are invisible to backticks in the same assignment scope, and the failure mode is an "unbound variable" at parse time that kills `just --list` for every recipe. The justfile in §2 instead names `{{ tools_dir }}/<tool>` explicitly and prefixes `PATH="{{ tools_dir }}:$PATH"` on the one line (`test-chart.sh`) that needs the tool on `PATH`.

4. **`cd` does not persist between recipe lines.** Five Makefile targets relied on it. `dashboard`, `rules`, `testbed-test` and `canary-test` use `[working-directory(...)]`. `grafana-check` and `grafana-test` keep `cd X && cmd` as **single lines** — that is fine, each is one shell. Do not split them across lines "for readability".

5. **`grafana-check` ends in `git diff --exit-code`.** It regenerates into the working tree and then asserts the tree is clean for six paths. Never run it as part of a recipe that has already dirtied those paths, and never run `just gen` and `just check` in the same breath expecting `check` to pass — commit the `gen` output first.

6. **Ordering inside `gen` is load-bearing.** `build_rules.py:2297` fails outright if `dashboard.json` has not been built (`Run make dashboard before make rules`), and `scripts/docgen/stats.go:25` reads `grafana/dashboard-stats.json` and fatals if it is absent or zero. Hence `gen: dashboard rules docs schemas`, in that order. Getting this wrong produces a confusing fatal about a missing JSON file, not a clear ordering error.

7. **`grafana-test` runs before `grafana-check` in `check`, matching CI.** `grafana/tests/test_rule_behaviour.py` reads the *generated* manifests. The committed manifests are what it reads on a clean tree. `check`'s dependency list is `… grafana-test gen-check`, so `gen-check`'s `grafana-check` runs after. Do not "tidy" this into `gen-check grafana-test`.

8. **The `-run='^$'` / `-fuzz='^TARGET$'` quoting.** In `fuzz-one`, keep the **single** quotes. `-fuzz="^{{ target }}$"` in a double-quoted bash string leaves a literal `$` only by luck of position; single quotes make it unambiguous, and `{{ target }}` is interpolated by just before bash ever sees it.

9. **`{{ args }}` in `capture` and `fieldaudit` is deliberately unquoted** so `ARGS=-all` and multi-flag capture arguments word-split the way `$(ARGS)` did in make. This is the documented just interpolation-quoting hazard, taken on purpose. Do not "fix" it to `'{{ args }}'` — that would pass `-a -b` as one argv element.

10. **`run` requires `OPS_ADDRESS`.** `env('OPS_ADDRESS')` with no default halts the recipe with a clear error. make silently passed an empty `--opnsense.address=`. This is a deliberate improvement; do not add a default.

11. **`lint` no longer mutates.** `make lint` ran `gofmt -s -w` and `golangci-lint run --fix`. The fleet contract forbids that. Anyone with `make lint` muscle memory now wants `just fmt`. Say so in `docs/development/contributing.md:85`.

12. **`.tools/` is not in `.gitignore`.** Check before `just setup` writes binaries there — `git status` after a `setup` must be clean. `.gitignore` line 22 covers `*opnsense2otel-local` and there is a `*.out` rule for `coverage.out`, but confirm `.tools/`, `bin/` and `dist/` are ignored; add them if not. This is the one place this task may add a line to `.gitignore`.

13. **`deployment-test` shells out to `scripts/systemd/test_secret_permissions.sh` and `test_unit.sh`, which need Docker.** They exit 2 with a clear message when Docker is absent — under `set -euo pipefail` that aborts the recipe. Expected on a machine with no Docker; it is not a justfile bug.

14. **`just --fmt` will reflow the `fuzz-smoke` parameterised-dependency line.** Run it once and commit the result before adding `fmt-check` to CI, or the first CI run fails on formatting the migration itself introduced.

15. **`just print-go-licenses-*` must produce clean stdout.** just writes the echoed command line and its own errors to **stderr**, and the recipes use `@echo`, so `$(just print-go-licenses-version)` is clean. Verify it explicitly (order of work step 3) — a stray newline or banner here silently ships images with a broken `GO_LICENSES_MODULE` build-arg, which is exactly the #436 regression class the pin exists to prevent.

16. **`scripts/hooks/pre-commit` is copied into `.git/hooks/` on developer machines.** Editing the tracked file does not update an already-installed hook. After the change, anyone with the hook installed must re-run `just install-hooks` or their pre-commit will keep invoking a `Makefile` that no longer exists. Note it in the PR body.

---

## 10. Out of scope

Do not touch, delete, absorb or rewrite:

**KEEP scripts (files stay exactly where they are):** `scripts/notices.sh`, `scripts/gen_oui.sh`,
`scripts/bump-module-major.sh`, `scripts/cloud-environment-setup.sh`,
`scripts/systemd/verify-release.sh`, `scripts/systemd/test_documentation.sh`,
`scripts/systemd/test_secret_permissions.sh`, `scripts/systemd/test_unit.sh`,
`scripts/deployment/test_examples.sh`, `charts/opnsense2otel/tests/test-chart.sh`,
`scripts/testbed/opnsense-testbed-power.sh`, `scripts/testbed/opnsense-testbed-canary-dispatch.sh`,
`scripts/testbed/config_lint.py`, `scripts/canary/opnsense-prod-canary.sh`,
`scripts/grafana-prune-rules.py`, `scripts/verify-gitsync.py`, `scripts/check_public_ips.py`,
`scripts/docgen/**`, `scripts/hooks/pre-commit` (body changes, file stays), `grafana/**`,
`tools/**`, and every `*_test.py` beside them.

**GitHub-native workflows — never folded into `just`:** `release-please.yml`, `codeql.yml`,
`zizmor.yml`, `actionlint.yml`, `scorecard.yml`, `dependency-review.yml`, `docker-security.yml`,
`trigger-docs-sync.yml`, `ghcr-cleanup.yml`, `arm-automerge.yml`, `auto-rc.yml`.

**Workflows deferred by decision (not GitHub-native, but out of scope this pass):** `fuzz.yml`,
`repo-meta.yml`, `api-contract.yml`, `grafana-sync.yml`, `live-canary.yml`, `geoip-refresh.yml`.

**Never convert a `uses:` into a `run: just`** — in particular the `golangci/golangci-lint-action`
step in `ci.yml`'s `tests` job and every `uses: rknightion/.github/.github/workflows/…` reusable call
in `publish.yml`, `release-please.yml` and `auto-rc.yml`.

**`ci-success`** — its name, its `if: always()`, and its `needs:` list are what the `main` branch
ruleset gates on. Unchanged.

**`ci.yml`'s `docker-build-verify` job body** below the go-licenses-pin step: the docker build, the
image version/GeoIP assertions, the Compose secrets+healthcheck block, and the kind-cluster
chart-contract block all stay as workflow YAML. They need `sudo`, a Docker daemon and a kind
cluster; they are CI orchestration, not developer tasks. `just image` covers only a plain local
image build.

**`CHANGELOG.md`, `THIRD_PARTY_NOTICES.md`, `.env.example`** — release-please-owned or generated;
`.env.example` changes only as output of `just docs`.

**Everything under `backlog/` except `config.yml`** — driven through the `backlog` CLI only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A top-level justfile exists with the seven mandatory recipes (default, setup, fmt, fmt-check, lint, test, check); default is `@just --list`, the header is `set shell := ["bash", "-euo", "pipefail", "-c"]`, and there is no `set quiet` and no `set minimum-version`.
- [ ] #2 `just check` passes on a clean checkout and its dependency list covers every ci-success gate reproducible off a GitHub runner: fmt-check, lint, test, test-race, fuzz-smoke, check-public-ips, deployment-test, testbed-test, canary-test, grafana-test, and gen-check (docs-check + grafana-check). Only docker-build-verify and repo-meta are CI-only, and the justfile says so.
- [ ] #3 `just --fmt --check` exits 0, `just --dump --dump-format json` exits 0 (no unstable features), and `just --list` shows a # doc comment and one of the six fleet groups (check/build/dev/gen/infra/release) for every public recipe; setup and default are ungrouped and _tool-*/print-go-licenses-* are private.
- [ ] #4 `Makefile` is deleted via `git rm`, `scripts/sbom.sh` is deleted and its behaviour lives in `just sbom`, and `git grep -n 'make [a-z-]' -- ':!CHANGELOG.md' ':!vendor' ':!THIRD_PARTY_NOTICES.md'` returns only English uses of the verb.
- [ ] #5 Every KEEP script still exists and is reachable from a recipe: scripts/notices.sh via `just notices`, scripts/gen_oui.sh via `just gen-oui`, scripts/bump-module-major.sh via `just bump-module-major`, scripts/check_public_ips.py via `just check-public-ips`, charts/opnsense2otel/tests/test-chart.sh + scripts/deployment/test_examples.sh + scripts/systemd/test_*.sh via `just deployment-test`, scripts/testbed/* via `just testbed-test`, scripts/canary/* via `just canary-test`; scripts/cloud-environment-setup.sh and scripts/systemd/verify-release.sh are untouched and deliberately unreferenced.
- [ ] #6 ci.yml and publish.yml carry a SHA-pinned `extractions/setup-just` step with `just-version: '1.58.0'` and call just recipes at ci.yml lines 42/48/78/118-130/139/159/164/170/189/195/219-220/399 and publish.yml lines 34-35/82; ci-success's name and needs: list, all permissions:/concurrency: blocks, every persist-credentials: false, every action SHA pin, the golangci/golangci-lint-action uses: step, the fuzz-smoke matrix, and every rknightion/.github reusable uses: call are byte-unchanged.
- [ ] #7 renovate.json's fourth customManager targets `/^justfile$/` with a regex matching the justfile's # renovate:-annotated `:=` assignments, so go_licenses_version, syft_version and kubeconform_version keep getting bumped; `just print-go-licenses-version` prints exactly v2.0.1 and `just print-go-licenses-module` exactly github.com/google/go-licenses/v2 on clean stdout.
- [ ] #8 api-contract-enrich.yml's --allowedTools string (line 105) and its prose (line 101) name `just docs`/`just docs-check` instead of `make docs`/`make docs-check`.
- [ ] #9 AGENTS.md's ## Commands block is replaced by the fleet '## Task interface' section naming `just check` as the gate and NOT listing recipes; AGENTS.md lines 49/119/147/151/171/175/181, README.md:180, CONTRIBUTING.md:22,28, .github/pull_request_template.md:27-32, docs/development/contributing.md, docs/development/adding-collector.md, docs/development/release-process.md, cmd/apicapture/README.md, grafana/README.md, archive/README.md and scripts/hooks/pre-commit no longer reference make.
- [ ] #10 The generators that emit 'make ...' into generated files are changed at source (scripts/docgen/main.go:207,977,1029, compose_reference.go:96, env_example.go:67, selfmetrics.go:434,439, stats.go, grafana/alerts/build_rules.py:2297,2677, grafana/sentinel_contract.py), and `just gen && git diff --exit-code` is clean afterwards.
- [ ] #11 backlog/config.yml's definition_of_done names just recipes (`just check` plus the `just gen` regeneration step) and no longer lists make lint / make test / make check-public-ips / make docs-check / make grafana-check.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make lint
- [ ] #2 make test
- [ ] #3 make check-public-ips
- [ ] #4 make docs-check
- [ ] #5 make grafana-check
<!-- DOD:END -->

## Comments

<!-- COMMENTS:BEGIN -->
author: campaign-ordering
created: 2026-08-29 09:18
---
## Fleet ordering — WAVE 2. Starts after the Wave 0 pilot (`sf2loki` / SFL-0073) and the Wave 1 hubs land.

Within Wave 2 the order is free — these repos do not depend on each other. Batching by language is worthwhile so one lane reuses its Makefile-to-recipe mapping across similar repos.

Do not start before the pilot reports. The standard may be amended off the back of it, and picking this up early risks coding against a superseded seam.

**Provisioning `just` in CI.** Which mechanism depends on the runner, and the two must not be mixed:

| Runner | Mechanism |
| --- | --- |
| `arc-arm64` (m7kni self-hosted) | `just` is **baked into the runner image** by `m7kni/ci-tools` (`runner-image/Dockerfile`, `ARG JUST_VERSION`). Do **not** add `extractions/setup-just`, and delete the step if this repo already has one — it installs a second `just` earlier on `PATH` and turns the image pin into a lie. |
| GitHub-hosted (all `rknightion` repos) | `extractions/setup-just`, SHA-pinned, with an explicit `just-version:`. |

Both sides currently sit on **1.58.0** and are Renovate-managed. `ci-tools`' `Tool version drift` workflow fails if the Dockerfile `ARG` and the published image ever disagree, and lists any repo still carrying a second pin.

**While you are in the workflow files, check the hub pin.** On 2026-08-29 Renovate was unfrozen for `rknightion/.github` in `m7kni/renovate-config` — it had been `enabled: false` on the mistaken belief that callers tracked `@main`, which froze the fleet across 19 different hub SHAs (v1.3.1 June → v1.9.7 August) so that no hub fix ever propagated. Bumps now arrive as one grouped, CI-gated, automerged PR per repo. **A `uses:` whose comment is not a real `# vX.Y.Z` still cannot be bumped** (it resolves to a digest-only update, which the fleet rules disable) — if you find one, repair the comment as part of this task.
---
<!-- COMMENTS:END -->
