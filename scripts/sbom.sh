#!/usr/bin/env bash
# sbom.sh — generate SPDX + CycloneDX SBOMs for the shipped artifact.
#
# Writes two SBOMs (standard formats, both JSON) into dist/sbom/:
#   <name>.spdx.json   SPDX 2.3
#   <name>.cdx.json    CycloneDX 1.6
#
# Default target is the built binary (bin/opnsense-exporter), which embeds the Go
# module build info — i.e. exactly the modules linked into the release. Set
# SBOM_TARGET to scan something else (e.g. an image ref
# `ghcr.io/rknightion/opnsense-exporter:vX.Y.Z` or `dir:.`). These are RELEASE
# ARTIFACTS (timestamps/UUIDs make them non-deterministic), so they are attached to
# the GitHub Release rather than committed.
#
# Env:
#   SYFT          syft binary (default: syft on PATH; Makefile passes .tools/)
#   SBOM_TARGET   what syft scans (default: bin/opnsense-exporter)
#   OUT_DIR       output directory (default: dist/sbom)
#   SBOM_NAME     output basename (default: opnsense-exporter)
set -euo pipefail

SYFT="${SYFT:-syft}"
SBOM_TARGET="${SBOM_TARGET:-bin/opnsense-exporter}"
OUT_DIR="${OUT_DIR:-dist/sbom}"
SBOM_NAME="${SBOM_NAME:-opnsense-exporter}"

command -v "$SYFT" >/dev/null 2>&1 || {
  echo "sbom: syft not found ('$SYFT') — run 'make tools-sbom'" >&2
  exit 1
}

mkdir -p "$OUT_DIR"
echo "sbom: scanning $SBOM_TARGET"
"$SYFT" "$SBOM_TARGET" -q \
  -o "spdx-json=$OUT_DIR/$SBOM_NAME.spdx.json" \
  -o "cyclonedx-json=$OUT_DIR/$SBOM_NAME.cdx.json"

echo "sbom: wrote $OUT_DIR/$SBOM_NAME.spdx.json + $OUT_DIR/$SBOM_NAME.cdx.json"
