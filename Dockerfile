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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f512d819b8f109f2375e8b51d8cfd8aafe81034bc3e319740128b7d7f70d5036

ARG Version

LABEL org.opencontainers.image.source=https://github.com/rknightion/opnsense-exporter
LABEL org.opencontainers.image.version=${Version}
LABEL org.opencontainers.image.authors="rknightion"
LABEL org.opencontainers.image.title="OPNsense Prometheus Exporter"
LABEL org.opencontainers.image.description="Prometheus exporter for OPNsense"

COPY --from=build /usr/bin/opnsense-exporter /
EXPOSE 8080
ENTRYPOINT ["/opnsense-exporter"]
