# Digest-pinned builder (matches the pinned distroless runtime below) so a mutable-tag
# push can't slip an unreviewed builder image into a release build (#148). Digest is the
# multi-arch index for golang:1.26-alpine; Renovate keeps it fresh (pinDigests, renovate.json).
FROM --platform=${BUILDPLATFORM:-linux/amd64} mirror.gcr.io/library/golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION

WORKDIR /go/src/github.com/rknightion/opnsense-exporter
COPY . .

# GOEXPERIMENT=goroutineleakprofile registers the goroutineleak pprof profile, which
# the exporter pushes to Pyroscope by default (profiling code guards on availability).
# Keep in sync with the Makefile + .goreleaser.yml.
RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  GOEXPERIMENT=goroutineleakprofile \
  go build \
  -mod=vendor \
  -tags osusergo,netgo \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o /usr/bin/opnsense-exporter .

# Third-party notices (LICENSE + NOTICE texts of the linked modules) baked into /licenses/
# below. Runs once on the BUILDPLATFORM (not per target arch); pinned go-licenses. See
# scripts/notices.sh, which forces module mode + `go mod download` (network required here).
#
# GO_LICENSES_VERSION / GO_LICENSES_MODULE have NO default here on purpose (#436): a prior
# independent `ARG GO_LICENSES_VERSION=v1.6.0` silently diverged from the Makefile's v2.0.1
# pin for months, so this image build never caught the release-only "post-v2 module path"
# install failure. The Makefile (`GO_LICENSES_VERSION`/`GO_LICENSES_MODULE`) is the one
# source of truth; every caller resolves the current pin via `make print-go-licenses-version`
# / `make print-go-licenses-module` and supplies it as a build-arg (ci.yml's
# docker-build-verify job, publish.yml's release build) — Dockerfile itself cannot select a
# different version unnoticed because it has nothing to select. `test -n` below fails the
# build loudly if a caller forgets to pass them, e.g. a bare local:
#   docker build \
#     --build-arg GO_LICENSES_VERSION="$(make -s print-go-licenses-version)" \
#     --build-arg GO_LICENSES_MODULE="$(make -s print-go-licenses-module)" .
ARG GO_LICENSES_VERSION
ARG GO_LICENSES_MODULE
RUN --mount=type=cache,target=/root/.cache/go-build \
  apk add --no-cache bash && \
  test -n "${GO_LICENSES_VERSION}" && test -n "${GO_LICENSES_MODULE}" || \
    { echo "GO_LICENSES_VERSION and GO_LICENSES_MODULE build-args are required (#436) — pass" \
           "them from 'make print-go-licenses-version' / 'make print-go-licenses-module'" >&2; exit 1; } && \
  GOBIN=/usr/local/bin go install ${GO_LICENSES_MODULE}@${GO_LICENSES_VERSION} && \
  GO_LICENSES=go-licenses OUT=/THIRD_PARTY_NOTICES.md bash scripts/notices.sh

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

ARG VERSION

LABEL org.opencontainers.image.source=https://github.com/rknightion/opnsense-exporter
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.authors="rknightion"
LABEL org.opencontainers.image.title="OPNsense Prometheus Exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for OPNsense"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /usr/bin/opnsense-exporter /
# License compliance travels with the image (OCI /licenses convention): Apache text + third-party notices.
COPY --from=build /go/src/github.com/rknightion/opnsense-exporter/LICENSE /licenses/LICENSE
COPY --from=build /THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/opnsense-exporter"]
