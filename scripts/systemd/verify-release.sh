#!/usr/bin/env bash
# Download and verify one Linux release archive before it is installed.
set -euo pipefail

readonly repository='rknightion/opnsense-exporter'
readonly signing_identity='https://github.com/rknightion/.github/.github/workflows/binaries.yml@d1c590b295b9d7f2535fadc7bc5e74f2eddbd512'
readonly signing_issuer='https://token.actions.githubusercontent.com'

usage() {
  cat <<'EOF'
Usage: verify-release.sh <version> <x86_64|arm64> [output-directory]

Downloads a Linux release archive plus its checksum and Sigstore bundle, verifies
the constrained GitHub Actions identity and checksum, then extracts the archive
into output-directory (or the current directory). The verified binary is printed
on stdout and has already run --version before this command succeeds.
EOF
}

if (($# < 2 || $# > 3)); then
  usage >&2
  exit 2
fi

version=$1
architecture=$2
output_directory=${3:-$PWD}

case "$architecture" in
  x86_64|arm64) ;;
  *) printf 'unsupported Linux architecture: %s\n' "$architecture" >&2; exit 2 ;;
esac

mkdir -p "$output_directory"
output_directory=$(cd "$output_directory" && pwd)
output_binary="$output_directory/opnsense-exporter"
if [[ -e "$output_binary" ]]; then
  printf 'refusing to reuse existing output binary: %s\n' "$output_binary" >&2
  exit 1
fi

for command in curl cosign sha256sum tar mktemp install; do
  command -v "$command" >/dev/null || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 2
  }
done

archive="opnsense-exporter_Linux_${architecture}.tar.gz"
base_url="https://github.com/${repository}/releases/download/${version}"
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT

curl -fsSLo "$temporary_directory/checksums.txt" "$base_url/checksums.txt"
curl -fsSLo "$temporary_directory/checksums.txt.sigstore.json" "$base_url/checksums.txt.sigstore.json"
curl -fsSLo "$temporary_directory/$archive" "$base_url/$archive"

cosign verify-blob \
  --bundle "$temporary_directory/checksums.txt.sigstore.json" \
  --certificate-identity "$signing_identity" \
  --certificate-oidc-issuer "$signing_issuer" \
  "$temporary_directory/checksums.txt"

checksum_line=$(awk -v archive="$archive" '$2 == archive { print }' "$temporary_directory/checksums.txt")
if [[ $(printf '%s\n' "$checksum_line" | sed '/^$/d' | wc -l | tr -d ' ') != 1 ]]; then
  printf 'checksums.txt does not contain exactly one checksum for %s\n' "$archive" >&2
  exit 1
fi
printf '%s\n' "$checksum_line" | (cd "$temporary_directory" && sha256sum -c -)

staging_directory="$temporary_directory/extracted"
mkdir "$staging_directory"
tar -xzf "$temporary_directory/$archive" -C "$staging_directory"
staged_binary="$staging_directory/opnsense-exporter"
if [[ ! -x "$staged_binary" ]]; then
  printf 'verified archive did not extract an executable opnsense-exporter\n' >&2
  exit 1
fi
"$staged_binary" --version

# Publish only the binary that was extracted and executed in this invocation.
# Refusing an existing destination above prevents a stale prior extraction from
# satisfying either check when a release archive is incomplete.
install -m 0755 "$staged_binary" "$output_binary"
printf '%s\n' "$output_binary"
