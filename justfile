set shell := ["bash", "-euo", "pipefail", "-c"]

binary_name := "opnsense2otel-local"
tools_dir := justfile_directory() / ".tools"
version := env('VERSION', `git describe --tags --always --dirty 2>/dev/null || echo dev`)

# ── pinned release-tooling versions ─────────────────────────────────────────
# GO_LICENSES_VERSION is the one source of truth for the go-licenses version and
# module path shared by `just notices`, the Dockerfile image build, and Renovate.
# The Dockerfile has no default for these build args: CI and publish resolve the
# values via the private print recipes below, so the two paths cannot diverge.
# renovate: datasource=go depName=github.com/google/go-licenses/v2
go_licenses_version := "v2.0.1"
go_licenses_module := "github.com/google/go-licenses/v2"
# renovate: datasource=go depName=github.com/anchore/syft
syft_version := "v1.51.1"
# renovate: datasource=github-releases depName=yannh/kubeconform
kubeconform_version := "v0.8.0"
# renovate: datasource=go depName=golang.org/x/vuln
govulncheck_version := "v1.7.0"
# renovate: datasource=go depName=github.com/goreleaser/goreleaser/v2
goreleaser_version := "v2.18.0"

# show the task surface
default:
    @just --list

# install the repo-local release tooling and warm the module cache (idempotent)
setup: _tool-go-licenses _tool-syft _tool-kubeconform _tool-govulncheck _tool-goreleaser
    go mod download
    @command -v golangci-lint >/dev/null 2>&1 || echo "note: golangci-lint is not on PATH — install it (brew install golangci-lint); CI pins v2.13.2 via golangci/golangci-lint-action"
    @echo "setup: .tools populated, modules downloaded"

# ── check ───────────────────────────────────────────────────────────────────

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

# run the full Go suite under the race detector; pass a filter to narrow it
[group('check')]
[no-exit-message]
test filter="":
    go test -race -timeout 15m {{ if filter != "" { "-run " + filter } else { "" } }} ./...

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

# enforce Prometheus metric naming contracts, including the OPN-0033 legacy ledger
[group('check')]
[no-exit-message]
metric-lint:
    go run ./cmd/metriclint

# unit-test the Grafana GitSync verifier's repository and live-apply seams
[group('check')]
[no-exit-message]
gitsync-test:
    python3 -m unittest scripts/verify_gitsync_test.py -q

# run the executable deployment contracts (Compose, systemd, k8s manifests, Helm chart)
[group('infra')]
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

# unit-test the prod canary's open-vs-closed decision logic (#612)
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

# scan Go dependencies against the vulnerability database
[group('check')]
[no-exit-message]
vuln: _tool-govulncheck
    {{ tools_dir }}/govulncheck ./...

# THE PRE-COMMIT GATE — every leg that needs only the language toolchains.
# CI-only GitHub API metadata validation and the full docker/kind orchestration
# stay in workflows; the heavy local counterparts are collected by `just ci`.
# run the bare-toolchain pre-commit gate
[group('check')]
check: fmt-check lint test metric-lint fuzz-smoke check-public-ips testbed-test canary-test gitsync-test grafana-test gen-check vuln

# deployment-test needs a Docker daemon for the containerised systemd contracts.
# snapshot needs cross-compilation for the release archive matrix.
# image needs a Docker daemon to build the container image.
# Run the sanctioned CI superset after `check` when those prerequisites are available.
[group('check')]
ci: check deployment-test snapshot image

# ── gen ─────────────────────────────────────────────────────────────────────

# regenerate every committed generated artifact. The first docs pass refreshes the
# metric catalogue before dashboard coverage; the second refreshes docs' dashboard
# and rule statistics after those generators have produced their artifacts.
[group('gen')]
gen:
    just docs
    just dashboard
    just rules
    just docs
    just schemas

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
    git diff --exit-code -- grafana/dashboard.json grafana/dashboard-health.json grafana/dashboard-stats.json grafana/sentinel-contract.json grafana/runbooks.md grafana/tabs/AUTHORING.md grafana/alerts/grafana-managed/
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

# ── build ───────────────────────────────────────────────────────────────────

# build the local static test binary
[group('build')]
build:
    go build -tags osusergo,netgo -ldflags '-w -extldflags "-static" -X main.version=local-test' -v -o {{ binary_name }}

# build the dispatched exporter and the delivered-body verifier for the live proof
[group('build')]
build-live-proof exporter verifier:
    CGO_ENABLED=0 go build -o '{{ exporter }}' .
    CGO_ENABLED=0 go build -o '{{ verifier }}' ./cmd/configredactionverify

# build the container image locally (same required build-args the release build uses)
[group('build')]
image tag="opnsense2otel:dev":
    docker build --build-arg VERSION='{{ version }}' --build-arg GO_LICENSES_VERSION='{{ go_licenses_version }}' --build-arg GO_LICENSES_MODULE='{{ go_licenses_module }}' -t '{{ tag }}' .

# cross-compile the release matrix without publishing it (Syft emits archive SBOMs)
[group('build')]
snapshot: _tool-goreleaser _tool-syft
    PATH="{{ tools_dir }}:$PATH" {{ tools_dir }}/goreleaser release --snapshot --clean --skip=sign

# remove build output, the coverage profile and the .tools/ toolchain (all reproducible)
[group('build')]
clean:
    go clean
    rm -f {{ binary_name }} coverage.out
    rm -rf bin dist/sbom {{ tools_dir }}

# ── dev ─────────────────────────────────────────────────────────────────────

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

# ship read-only testbed configuration telemetry and verify delivered bodies in m7kni
[group('dev')]
live-delivery-proof exporter verifier:
    python3 scripts/testbed/live_delivery_proof.py --exporter '{{ exporter }}' --redaction-verifier '{{ verifier }}'

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

# ── release ─────────────────────────────────────────────────────────────────

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
[confirm('rewrite the Go module path to a new major version? this edits every tracked file that references it.')]
[group('release')]
bump-module-major major="":
    scripts/bump-module-major.sh {{ major }}

# ── private helpers ─────────────────────────────────────────────────────────

[private]
_tool-go-licenses:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/go-licenses' && test "$(cat '{{ tools_dir }}/go-licenses.pin' 2>/dev/null)" = '{{ go_licenses_module }}@{{ go_licenses_version }}' && '{{ tools_dir }}/go-licenses' --help >/dev/null 2>&1; } || { GOBIN='{{ tools_dir }}' go install {{ go_licenses_module }}@{{ go_licenses_version }} && printf '%s\n' '{{ go_licenses_module }}@{{ go_licenses_version }}' > '{{ tools_dir }}/go-licenses.pin'; }

[private]
_tool-syft:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/syft' && test "$(cat '{{ tools_dir }}/syft.pin' 2>/dev/null)" = 'github.com/anchore/syft/cmd/syft@{{ syft_version }}' && '{{ tools_dir }}/syft' version >/dev/null 2>&1; } || { GOBIN='{{ tools_dir }}' go install github.com/anchore/syft/cmd/syft@{{ syft_version }} && printf '%s\n' 'github.com/anchore/syft/cmd/syft@{{ syft_version }}' > '{{ tools_dir }}/syft.pin'; }

[private]
_tool-kubeconform:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/kubeconform' && test "$(cat '{{ tools_dir }}/kubeconform.pin' 2>/dev/null)" = 'github.com/yannh/kubeconform/cmd/kubeconform@{{ kubeconform_version }}' && '{{ tools_dir }}/kubeconform' -v >/dev/null 2>&1; } || { GOBIN='{{ tools_dir }}' go install github.com/yannh/kubeconform/cmd/kubeconform@{{ kubeconform_version }} && printf '%s\n' 'github.com/yannh/kubeconform/cmd/kubeconform@{{ kubeconform_version }}' > '{{ tools_dir }}/kubeconform.pin'; }

[private]
_tool-govulncheck:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/govulncheck' && test "$(cat '{{ tools_dir }}/govulncheck.pin' 2>/dev/null)" = 'golang.org/x/vuln/cmd/govulncheck@{{ govulncheck_version }}' && '{{ tools_dir }}/govulncheck' -version >/dev/null 2>&1; } || { GOBIN='{{ tools_dir }}' go install golang.org/x/vuln/cmd/govulncheck@{{ govulncheck_version }} && printf '%s\n' 'golang.org/x/vuln/cmd/govulncheck@{{ govulncheck_version }}' > '{{ tools_dir }}/govulncheck.pin'; }

[private]
_tool-goreleaser:
    @mkdir -p '{{ tools_dir }}'
    @{ test -x '{{ tools_dir }}/goreleaser' && test "$(cat '{{ tools_dir }}/goreleaser.pin' 2>/dev/null)" = 'github.com/goreleaser/goreleaser/v2@{{ goreleaser_version }}' && '{{ tools_dir }}/goreleaser' --version >/dev/null 2>&1; } || { GOBIN='{{ tools_dir }}' go install github.com/goreleaser/goreleaser/v2@{{ goreleaser_version }} && printf '%s\n' 'github.com/goreleaser/goreleaser/v2@{{ goreleaser_version }}' > '{{ tools_dir }}/goreleaser.pin'; }

# Emit the pinned go-licenses version/module so CI and publish resolve the same pin.
[private]
print-go-licenses-version:
    @echo {{ go_licenses_version }}

[private]
print-go-licenses-module:
    @echo {{ go_licenses_module }}
