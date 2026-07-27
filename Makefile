BINARY_NAME=opnsense-exporter-local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# ── pinned release-tooling versions (override via env) ────────────────────────
# GO_LICENSES_VERSION is the ONE source of truth for the go-licenses version *and*
# module path shared by `make notices`, the Dockerfile image build, and Renovate
# (#436). go-licenses v2+ is published under the semantic-import path
# github.com/google/go-licenses/v2 (v1.x was github.com/google/go-licenses with no
# suffix) — the module path is therefore baked into GO_LICENSES_MODULE below, not
# just the version, so a future v3 bump updates both together instead of silently
# reintroducing the v2.0.1 "post-v2 module path" install failure this fixed.
# The Dockerfile does NOT keep its own copy: it declares GO_LICENSES_VERSION/
# GO_LICENSES_MODULE as required build-args with no default (see Dockerfile), and every
# caller (ci.yml's docker-build-verify job, publish.yml's release build) resolves the
# current pin via `make print-go-licenses-version` / `make print-go-licenses-module`
# below and passes it in — so the two paths cannot select different versions unnoticed.
# renovate: datasource=go depName=github.com/google/go-licenses/v2
GO_LICENSES_VERSION ?= v2.0.1
GO_LICENSES_MODULE  := github.com/google/go-licenses/v2
# renovate: datasource=go depName=github.com/anchore/syft
SYFT_VERSION        ?= v1.49.0
# renovate: datasource=github-releases depName=yannh/kubeconform
KUBECONFORM_VERSION ?= v0.8.0

TOOLS_DIR := $(CURDIR)/.tools
export PATH := $(TOOLS_DIR):$(PATH)

# Build with the goroutineleakprofile runtime experiment so the shipped binary
# registers the goroutineleak pprof profile (pushed to Pyroscope by default). The
# profiling code guards on availability, so a build without this simply omits that
# one profile type. Overriding to empty drops it. Must match the Dockerfile and
# .goreleaser.yml. A future Go that removes the experiment fails the build loudly.
GOEXPERIMENT ?= goroutineleakprofile

.PHONY: default docgen docs docs-check dashboard rules compat compat-verify grafana-check grafana-test install-hooks capture \
        schemas coverage notices sbom tools-licensing tools-sbom print-go-licenses-version \
        print-go-licenses-module tools-kubeconform deployment-test
default:
	GOEXPERIMENT=$(GOEXPERIMENT) go build \
	-tags osusergo,netgo \
	-ldflags '-w -extldflags "-static" -X main.version=local-test' \
	-v -o ${BINARY_NAME}

sync-vendor:
	go mod tidy
	go mod vendor

local-run: default
	# Pass the API key/secret via the exporter's env vars (see internal/options/ops.go),
	# NOT the api-key/api-secret CLI flags: argv is world-readable (ps, /proc/<pid>/cmdline),
	# so flag-passed creds leak to every local user for the process lifetime. The env is
	# only owner-readable (#160).
	OPNSENSE_EXPORTER_OPS_API_KEY="$(OPS_API_KEY)" \
	OPNSENSE_EXPORTER_OPS_API_SECRET="$(OPS_API_SECRET)" \
	./${BINARY_NAME} --log.level="debug" \
		--log.format="logfmt" \
		--web.telemetry-path="/metrics" \
		--web.listen-address=":$(or $(OPS_EXPORTER_PORT), 8080)" \
		--exporter.instance-label="$(or $(OPS_INSTANCE), opnsense-local1)" \
		--opnsense.protocol="https" \
		--opnsense.address="${OPS_ADDRESS}" \
		--web.disable-exporter-metrics \
		$(if $(OPS_ADDITIONAL_ARGS),"${OPS_ADDITIONAL_ARGS}")

test:
	go test ./...

# coverage: atomic coverage profile over the full test scope. Uploaded to Codacy by
# the ci.yml `coverage` job (non-blocking). Locally: `go tool cover -html=coverage.out`.
# coverage.out is gitignored (*.out).
coverage:
	go test -covermode=atomic -coverprofile=coverage.out ./...

# ── third-party license notices + SBOM (RELEASE ARTIFACTS; not committed/gated) ────
# THIRD_PARTY_NOTICES.md and the SBOMs change on every dependency bump, so they are
# regenerated at release time rather than committed: the image build bakes notices into
# /licenses/, and release-please.yml attaches notices + both SBOMs to the GitHub Release.
# They are deliberately NOT part of any gate — committing+gating a deps-derived file would
# block hosted-Renovate automerge (it can't self-regenerate it).
tools-licensing:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/go-licenses && $(TOOLS_DIR)/go-licenses --help >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) go install $(GO_LICENSES_MODULE)@$(GO_LICENSES_VERSION)

# Print the pinned go-licenses version/module so other build surfaces (the Dockerfile's
# GO_LICENSES_VERSION/GO_LICENSES_MODULE build-args, supplied by ci.yml and publish.yml)
# resolve the SAME pin declared above instead of holding an independent copy (#436).
print-go-licenses-version:
	@echo $(GO_LICENSES_VERSION)
print-go-licenses-module:
	@echo $(GO_LICENSES_MODULE)

tools-sbom:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/syft && $(TOOLS_DIR)/syft version >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)

tools-kubeconform:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/kubeconform && $(TOOLS_DIR)/kubeconform -v >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) go install github.com/yannh/kubeconform/cmd/kubeconform@$(KUBECONFORM_VERSION)

# Regenerate THIRD_PARTY_NOTICES.md (LICENSE + NOTICE texts) from the binary's import graph.
notices: tools-licensing
	GO_LICENSES=$(TOOLS_DIR)/go-licenses bash scripts/notices.sh

# Generate SPDX + CycloneDX SBOMs into dist/sbom/. Builds a static binary (CGO disabled,
# so no external linker — works on macOS too) and scans it so the SBOM reflects exactly the
# linked modules. Override SBOM_TARGET (e.g. an image ref) to scan something else.
sbom: tools-sbom
	CGO_ENABLED=0 GOEXPERIMENT=$(GOEXPERIMENT) go build -mod=vendor -tags osusergo,netgo -trimpath \
	  -ldflags "-s -w -X main.version=$(VERSION)" -o bin/opnsense-exporter .
	SYFT=$(TOOLS_DIR)/syft bash scripts/sbom.sh

clean:
	gofmt -s -w $(shell find . -type f -name '*.go'| grep -v "/vendor/\|/.git/")
	go clean
	rm ./${BINARY_NAME}

lint:
	gofmt -s -w $(shell find . -type f -name '*.go'| grep -v "/vendor/\|/.git/")
	golangci-lint run --fix

docs:
	go run ./scripts/docgen

# Back-compat alias
docgen: docs

docs-check:
	go run ./scripts/docgen -check

deployment-test: tools-kubeconform
	bash -n scripts/deployment/test_examples.sh scripts/systemd/*.sh
	scripts/deployment/test_examples.sh
	scripts/systemd/test_documentation.sh
	scripts/systemd/test_secret_permissions.sh
	scripts/systemd/test_unit.sh
	$(TOOLS_DIR)/kubeconform -strict -summary deploy/k8s/deployment.yaml
	PATH="$(TOOLS_DIR):$(PATH)" charts/opnsense-exporter/tests/test-chart.sh

install-hooks:
	cp scripts/hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed"

dashboard:
	cd grafana && python3 build_dashboard.py

rules:
	cd grafana/alerts && python3 build_rules.py

# The Grafana 11/12 compatibility artifact (#420, from the #22 report). CONVERTED
# from dashboard.json, never authored — see grafana/build_compat.py. `compat-verify`
# imports it into pinned Grafana containers and reads it back; it needs docker, so it
# is deliberately NOT part of grafana-check (which must run without one) and is
# enforced by .github/workflows/grafana-compat.yml instead.
compat:
	cd grafana && python3 build_compat.py

compat-verify: compat
	grafana/verify_compat_import.sh

# CI gate for the generated grafana/ artifacts (#84): coverage gate + regeneration
# staleness + manifest validity. Fails if any catalogue metric is off the dashboard,
# if dashboard.json / dashboard-stats.json / sentinel-contract.json / AUTHORING.md's
# generated section / the grafana-managed manifests are stale relative to their
# builders, or if a manifest is malformed. sentinel-contract.json + the generated
# AUTHORING.md region are the feature-sentinel documentation contract (#417).
grafana-check: grafana-test
	cd grafana && python3 build_dashboard.py --check
	cd grafana && python3 build_dashboard.py
	go run -C tools/promqlcheck . ../../grafana/dashboard.json
	cd grafana/alerts && python3 build_rules.py
	cd grafana && python3 build_compat.py
	git diff --exit-code -- grafana/dashboard.json grafana/dashboard-stats.json grafana/sentinel-contract.json grafana/tabs/AUTHORING.md grafana/alerts/grafana-managed/ grafana/dashboard-compat.json
	python3 grafana/alerts/validate_manifests.py

# The grafana/ builders' own unit tests (stdlib unittest, no deps). A prerequisite
# of grafana-check rather than a separate CI job so it cannot be forgotten: these
# existed for weeks with nothing running them and three had rotted into failure,
# which is the same as not having them.
grafana-test:
	cd grafana && python3 -m unittest discover -s tests -t . -q
	go test -C tools/promqlcheck ./...

# Regenerate the committed structure-only golden schemas (opnsense/testdata/schemas/)
# from the response structs (cmd/apischema). Run after changing any response
# struct; opnsense.TestSchemasUpToDate fails CI when these are stale.
schemas:
	go run ./cmd/apischema

# Capture live-box responses for the response-shape canary (cmd/apicapture).
# Writes to the gitignored opnsense/testdata/captures/ scratch dir; then run
# `go test ./opnsense/ -run TestResponseContracts` to validate them. Reuses the
# same OPS API credential vars as local-run — including the file-based
# OPS_API_KEY_FILE / OPS_API_SECRET_FILE secrets, resolved identically to the
# exporter (#157); set OPS_INSECURE=1 for self-signed certs.
capture:
	# Creds via env (apicapture reads the exporter's OPS API env vars as flag defaults,
	# and OPS_API_KEY_FILE/OPS_API_SECRET_FILE via internal/options), not via CLI flags,
	# to keep them out of world-readable argv (#160).
	OPNSENSE_EXPORTER_OPS_API_KEY="$(OPS_API_KEY)" \
	OPNSENSE_EXPORTER_OPS_API_SECRET="$(OPS_API_SECRET)" \
	go run ./cmd/apicapture \
		--base-url "$(or $(OPS_BASE_URL),https://$(OPS_ADDRESS))" \
		$(if $(OPS_INSECURE),--insecure) $(CAPTURE_ARGS)
