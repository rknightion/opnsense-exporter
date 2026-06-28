FROM --platform=${BUILDPLATFORM:-linux/amd64} mirror.gcr.io/library/golang:1.26-alpine AS build

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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

ARG Version

LABEL org.opencontainers.image.source=https://github.com/rknightion/opnsense-exporter
LABEL org.opencontainers.image.version=${Version}
LABEL org.opencontainers.image.authors="rknightion"
LABEL org.opencontainers.image.title="OPNsense Prometheus Exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for OPNsense"

COPY --from=build /usr/bin/opnsense-exporter /
EXPOSE 8080
ENTRYPOINT ["/opnsense-exporter"]
