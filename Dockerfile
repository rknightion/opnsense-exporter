# Digest-pinned builder (matches the pinned distroless runtime below) so a mutable-tag
# push can't slip an unreviewed builder image into a release build (#148). Digest is the
# multi-arch index for golang:1.27.0-alpine; Renovate keeps it fresh (pinDigests, renovate.json).
FROM --platform=${BUILDPLATFORM:-linux/amd64} mirror.gcr.io/library/golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION

WORKDIR /go/src/github.com/rknightion/opnsense2otel
COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build \
  -mod=vendor \
  -tags osusergo,netgo \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o /usr/bin/opnsense2otel .

# Third-party notices (LICENSE + NOTICE texts of the linked modules) baked into /licenses/
# below. Runs once on the BUILDPLATFORM (not per target arch); pinned go-licenses. See
# scripts/notices.sh, which forces module mode + `go mod download` (network required here).
#
# GO_LICENSES_VERSION / GO_LICENSES_MODULE have NO default here on purpose (#436): a prior
# independent `ARG GO_LICENSES_VERSION=v1.6.0` silently diverged from the justfile's v2.0.1
# pin for months, so this image build never caught the release-only "post-v2 module path"
# install failure. The justfile (`go_licenses_version`/`go_licenses_module`) is the one
# source of truth; every caller resolves the current pin via `just print-go-licenses-version`
# / `just print-go-licenses-module` and supplies it as a build-arg (ci.yml's
# docker-build job, publish.yml's release build) — Dockerfile itself cannot select a
# different version unnoticed because it has nothing to select. `test -n` below fails the
# build loudly if a caller forgets to pass them, e.g. a bare local:
#   docker build \
#     --build-arg GO_LICENSES_VERSION="$(just print-go-licenses-version)" \
#     --build-arg GO_LICENSES_MODULE="$(just print-go-licenses-module)" .
ARG GO_LICENSES_VERSION
ARG GO_LICENSES_MODULE
RUN --mount=type=cache,target=/root/.cache/go-build \
  apk add --no-cache bash && \
  test -n "${GO_LICENSES_VERSION}" && test -n "${GO_LICENSES_MODULE}" || \
    { echo "GO_LICENSES_VERSION and GO_LICENSES_MODULE build-args are required (#436) — pass" \
           "them from 'just print-go-licenses-version' / 'just print-go-licenses-module'" >&2; exit 1; } && \
  GOBIN=/usr/local/bin go install ${GO_LICENSES_MODULE}@${GO_LICENSES_VERSION} && \
  GO_LICENSES=go-licenses OUT=/THIRD_PARTY_NOTICES.md bash scripts/notices.sh

# ── Bundled GeoIP databases: DB-IP Lite Country + ASN (#549) ─────────────────────
# Fetched at image build time, NOT committed: ~17.8 MB of binary republished every
# month would grow this repository's history permanently and irreversibly. GeoLite2
# cannot be bundled at all (MaxMind's paid Commercial Redistribution License plus a
# downstream EULA we cannot impose); DB-IP Lite is CC BY 4.0, so redistribution is
# fine as long as DB-IP is credited — see /licenses/GEOIP-DB-IP-ATTRIBUTION.txt
# below, docs/geoip.md, and the operator console footer.
#
# Same pinned builder image as the Go build (one digest to keep fresh, and it is
# already proven present). Runs on the BUILDPLATFORM only: an .mmdb is
# architecture-independent, so fetching per target arch would download the same
# ~9 MB twice for a multi-arch build.
#
# The paths written here are the flag defaults in internal/geoip/bundled.go. Change
# one and TestBundledPathsAreStable / TestGeoIPFlagDefaultsPointAtTheBundledDatabases
# fail, which is the point: an image whose databases nothing opens looks exactly
# like a firewall with nothing to report.
FROM --platform=${BUILDPLATFORM:-linux/amd64} mirror.gcr.io/library/golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS geoip

# Empty = "the current UTC year-month, falling back to the previous one". Set it
# (e.g. --build-arg DBIP_MONTH=2026-07) to pin a reproducible build to a known file.
ARG DBIP_MONTH=""

RUN set -eu; \
  apk add --no-cache curl >/dev/null; \
  mkdir -p /geoip; \
  # DB-IP publishes on the 1st, and their publish can lag UTC midnight — so a
  # scheduled build early on the 1st legitimately 404s on the current month. Try
  # the previous month rather than failing the build; one-month-old country data
  # is worth incomparably more than a red build. Month arithmetic strips the
  # leading zero by hand ($((10#$m)) is a bashism and this is busybox ash).
  y="$(date -u +%Y)"; m="$(date -u +%m)"; \
  pm="$(( ${m#0} - 1 ))"; py="$y"; \
  if [ "$pm" -eq 0 ]; then pm=12; py="$(( y - 1 ))"; fi; \
  if [ -n "$DBIP_MONTH" ]; then months="$DBIP_MONTH"; \
  else months="$(printf '%04d-%02d %04d-%02d' "$y" "${m#0}" "$py" "$pm")"; fi; \
  fetch() { \
    product="$1"; marker="$2"; out="$3"; \
    for mo in $months; do \
      url="https://download.db-ip.com/free/dbip-${product}-lite-${mo}.mmdb.gz"; \
      echo "geoip: fetching ${url}"; \
      if curl -fsSL --retry 3 --retry-delay 5 --max-time 300 -o /tmp/db.gz "$url"; then \
        # gunzip failing is the CRC check: a truncated or HTML error page never
        # reaches the output file.
        gunzip -c /tmp/db.gz > "$out"; \
        rm -f /tmp/db.gz; \
        sz="$(wc -c < "$out")"; \
        [ "$sz" -ge 4000000 ] || { echo "::error::${out} is only ${sz} B — not a full DB-IP database" >&2; exit 1; }; \
        # Structural check, not just "a file arrived": the MMDB metadata section
        # lives at the END of the file and carries the reader's magic marker plus
        # the database_type. Both must be the ones we expect, so a silently
        # renamed or re-typed product fails the build instead of shipping.
        # Punch the metadata's control bytes out to newlines first: grep treats a
        # line of binary as binary and reports no match even where the marker is
        # plainly present (measured, both here and on macOS). The character set is
        # spelled out rather than [:print:] because busybox tr silently no-ops on
        # a complemented character CLASS — it passed the file through unchanged and
        # every marker check failed, which is exactly the shape of bug this whole
        # verification block exists to catch. Redirect, not a pipe, so a failing
        # tail cannot be masked (and hadolint DL4006 has nothing to complain about).
        tail -c 262144 "$out" > /tmp/meta.bin; \
        LC_ALL=C tr -c 'a-zA-Z0-9.-' '\n' < /tmp/meta.bin > /tmp/meta.txt; \
        grep -q 'MaxMind.com' /tmp/meta.txt || { echo "::error::${out} carries no MMDB metadata marker" >&2; exit 1; }; \
        grep -q "$marker" /tmp/meta.txt || { echo "::error::${out} is not a ${marker} database" >&2; exit 1; }; \
        rm -f /tmp/meta.txt /tmp/meta.bin; \
        echo "geoip: ${out} ok (${sz} B, ${marker}, ${mo})"; \
        echo "$mo" > /geoip-month; \
        return 0; \
      fi; \
      echo "geoip: ${url} unavailable, trying the previous month"; \
    done; \
    echo "::error::could not fetch dbip-${product}-lite for any of: ${months}" >&2; \
    exit 1; \
  }; \
  fetch country DBIP-Country-Lite /geoip/dbip-country-lite.mmdb; \
  fetch asn     DBIP-ASN-Lite     /geoip/dbip-asn-lite.mmdb

# The CC BY 4.0 credit travels in the image beside the data it covers, so it cannot
# be lost by a change to the Go-module notices pipeline (THIRD_PARTY_NOTICES.md is
# generated by go-licenses from the linked modules and knows nothing about bundled
# data). Wording is kept in step with geoip.Attribution().
RUN set -eu; mkdir -p /geoip-licenses; { \
  echo "Bundled IP geolocation databases"; \
  echo "================================"; \
  echo; \
  echo "IP geolocation data by DB-IP (https://db-ip.com), licensed under CC BY 4.0"; \
  echo "(https://creativecommons.org/licenses/by/4.0/)."; \
  echo; \
  echo "Files (unmodified as published by DB-IP):"; \
  echo "  /usr/share/opnsense2otel/geoip/dbip-country-lite.mmdb  (DB-IP Country Lite)"; \
  echo "  /usr/share/opnsense2otel/geoip/dbip-asn-lite.mmdb      (DB-IP ASN Lite)"; \
  echo "  Edition: $(cat /geoip-month)"; \
  echo; \
  echo "They are redistributed byte-for-byte, not adapted. Each database's own build"; \
  echo "date is exported as opnsense_flow_geoip_database_build_timestamp_seconds."; \
  } > /geoip-licenses/GEOIP-DB-IP-ATTRIBUTION.txt

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

ARG VERSION

LABEL org.opencontainers.image.source=https://github.com/rknightion/opnsense2otel
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.authors="rknightion"
LABEL org.opencontainers.image.title="opnsense2otel"
LABEL org.opencontainers.image.description="OpenTelemetry and Prometheus observability for OPNsense firewalls"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /usr/bin/opnsense2otel /
# License compliance travels with the image (OCI /licenses convention): Apache text + third-party notices.
COPY --from=build /go/src/github.com/rknightion/opnsense2otel/LICENSE /licenses/LICENSE
COPY --from=build /THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
# Bundled DB-IP Lite databases (#549) + the CC BY 4.0 credit they require. The path
# is the default value of --geoip.country-database / --geoip.asn-database
# (internal/geoip/bundled.go); read-only image content, deliberately NOT under
# --geoip.download.dir, which is operator-writable state.
COPY --from=geoip /geoip/ /usr/share/opnsense2otel/geoip/
COPY --from=geoip /geoip-licenses/GEOIP-DB-IP-ATTRIBUTION.txt /licenses/GEOIP-DB-IP-ATTRIBUTION.txt
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/opnsense2otel"]
