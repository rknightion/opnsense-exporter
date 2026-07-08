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

RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build \
  -mod=vendor \
  -tags osusergo,netgo \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o /usr/bin/opnsense-exporter .

# Third-party notices (LICENSE + NOTICE texts of the linked modules) baked into /licenses/
# below. Runs once on the BUILDPLATFORM (not per target arch); pinned go-licenses. See
# scripts/notices.sh, which forces module mode + `go mod download` (network required here).
ARG GO_LICENSES_VERSION=v1.6.0
RUN --mount=type=cache,target=/root/.cache/go-build \
  apk add --no-cache bash && \
  GOBIN=/usr/local/bin go install github.com/google/go-licenses@${GO_LICENSES_VERSION} && \
  GO_LICENSES=go-licenses OUT=/THIRD_PARTY_NOTICES.md bash scripts/notices.sh

FROM gcr.io/distroless/static-debian13:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

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
