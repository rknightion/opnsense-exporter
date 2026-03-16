FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.26-alpine AS build

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG Version

WORKDIR /go/src/github.com/rknightion/opnsense-exporter
COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build \
  -mod=vendor \
  -tags osusergo,netgo \
  -trimpath \
  -ldflags "-s -w -X main.version=${Version}" \
  -o /usr/bin/opnsense-exporter .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e3f945647ffb95b5839c07038d64f9811adf17308b9121d8a2b87b6a22a80a39

ARG Version

LABEL org.opencontainers.image.source=https://github.com/rknightion/opnsense-exporter
LABEL org.opencontainers.image.version=${Version}
LABEL org.opencontainers.image.authors="rknightion"
LABEL org.opencontainers.image.title="OPNsense Prometheus Exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for OPNsense"

COPY --from=build /usr/bin/opnsense-exporter /
EXPOSE 8080
ENTRYPOINT ["/opnsense-exporter"]
