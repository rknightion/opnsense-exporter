BINARY_NAME=opnsense-exporter-local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# ── pinned release-tooling versions (override via env) ────────────────────────
GO_LICENSES_VERSION ?= v1.6.0
SYFT_VERSION        ?= v1.18.1

TOOLS_DIR := $(CURDIR)/.tools
export PATH := $(TOOLS_DIR):$(PATH)

.PHONY: default docgen docs docs-check dashboard rules install-hooks capture \
        coverage notices sbom tools-licensing tools-sbom
default:
	go build \
	-tags osusergo,netgo \
	-ldflags '-w -extldflags "-static" -X main.version=local-test' \
	-v -o ${BINARY_NAME}

sync-vendor:
	go mod tidy
	go mod vendor

local-run: default
	./${BINARY_NAME} --log.level="debug" \
		--log.format="logfmt" \
		--web.telemetry-path="/metrics" \
		--web.listen-address=":$(or $(OPS_EXPORTER_PORT), 8080)" \
		--exporter.instance-label="$(or $(OPS_INSTANCE), opnsense-local1)" \
		--opnsense.protocol="https" \
		--opnsense.address="${OPS_ADDRESS}" \
		--opnsense.api-key="${OPS_API_KEY}" \
		--opnsense.api-secret="${OPS_API_SECRET}" \
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
	  GOBIN=$(TOOLS_DIR) go install github.com/google/go-licenses@$(GO_LICENSES_VERSION)
tools-sbom:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/syft && $(TOOLS_DIR)/syft version >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) go install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)

# Regenerate THIRD_PARTY_NOTICES.md (LICENSE + NOTICE texts) from the binary's import graph.
notices: tools-licensing
	GO_LICENSES=$(TOOLS_DIR)/go-licenses bash scripts/notices.sh

# Generate SPDX + CycloneDX SBOMs into dist/sbom/. Builds a static binary (CGO disabled,
# so no external linker — works on macOS too) and scans it so the SBOM reflects exactly the
# linked modules. Override SBOM_TARGET (e.g. an image ref) to scan something else.
sbom: tools-sbom
	CGO_ENABLED=0 go build -mod=vendor -tags osusergo,netgo -trimpath \
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

install-hooks:
	cp scripts/hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed"

dashboard:
	cd grafana && python3 build_dashboard.py

rules:
	cd grafana/alerts && python3 build_rules.py

# Capture live-box responses for the response-shape canary (cmd/apicapture).
# Writes to the gitignored opnsense/testdata/captures/ scratch dir; then run
# `go test ./opnsense/ -run TestResponseContracts` to validate them. Reuses the
# same OPS_* vars as local-run; set OPS_INSECURE=1 for self-signed certs.
capture:
	go run ./cmd/apicapture \
		--base-url "$(or $(OPS_BASE_URL),https://$(OPS_ADDRESS))" \
		--api-key "$(OPS_API_KEY)" \
		--api-secret "$(OPS_API_SECRET)" \
		$(if $(OPS_INSECURE),--insecure) $(CAPTURE_ARGS)
