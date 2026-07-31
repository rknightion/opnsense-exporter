#!/usr/bin/env bash
# Regression checks for the commands copied from docs/deployment/systemd.md.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
systemd_doc="$root/docs/deployment/systemd.md"
security_doc="$root/docs/security.md"

require() {
  local needle=$1
  local file=$2
  if ! grep -Fq -- "$needle" "$file"; then
    printf 'missing %q in %s\n' "$needle" "$file" >&2
    exit 1
  fi
}

reject() {
  local needle=$1
  local file=$2
  if grep -Fq -- "$needle" "$file"; then
    printf 'obsolete %q remains in %s\n' "$needle" "$file" >&2
    exit 1
  fi
}

require 'opnsense2otel_Linux_x86_64.tar.gz' "$systemd_doc"
require 'opnsense2otel_Linux_arm64.tar.gz' "$systemd_doc"
require '{{- title .Os }}_' "$root/.goreleaser.yml"
require 'if eq .Arch "amd64" }}x86_64' "$root/.goreleaser.yml"
require 'scripts/systemd/verify-release.sh' "$systemd_doc"
require "git clone --depth 1 --branch \"\$VERSION\"" "$systemd_doc"
require "INSTALL_ROOT=\$(mktemp -d)" "$systemd_doc"
require "UPGRADE_ROOT=\$(mktemp -d)" "$systemd_doc"
require 'https://github.com/rknightion/.github/.github/workflows/binaries.yml@d1c590b295b9d7f2535fadc7bc5e74f2eddbd512' "$systemd_doc"
require 'https://token.actions.githubusercontent.com' "$systemd_doc"
require 'sudo install -d -o root -g opnsense2otel -m 0710' "$systemd_doc"
require 'sudo install -d -o root -g opnsense2otel -m 0710' "$security_doc"
require "printf '%s\\n' 'your-api-key'" "$systemd_doc"
require "printf '%s\\n' 'your-api-secret'" "$systemd_doc"
require "printf '%s\\n' 'your-api-key'" "$security_doc"
require "printf '%s\\n' 'your-api-secret'" "$security_doc"
require 'sudo install -o root -g opnsense2otel -m 0640' "$systemd_doc"
require 'sudo install -o root -g opnsense2otel -m 0640' "$security_doc"
require 'systemctl is-active --quiet opnsense2otel' "$systemd_doc"
require '/-/healthy' "$systemd_doc"
reject 'opnsense2otel_linux_amd64' "$systemd_doc"

for script in \
  "$root/scripts/systemd/verify-release.sh" \
  "$root/scripts/systemd/test_secret_permissions.sh"; do
  if [[ ! -x "$script" ]]; then
    printf 'required script is not executable: %s\n' "$script" >&2
    exit 1
  fi
done

# The verifier must never accept an executable left by an earlier extraction.
# This guard runs before external tool checks or downloads, so it is deterministic.
stale_output=$(mktemp -d)
trap 'rm -rf "$stale_output"' EXIT
touch "$stale_output/opnsense2otel"
if "$root/scripts/systemd/verify-release.sh" v0.0.0 x86_64 "$stale_output" \
    >"$stale_output/stdout" 2>"$stale_output/stderr"; then
  printf 'verifier accepted an existing output binary\n' >&2
  exit 1
fi
require 'refusing to reuse existing output binary' "$stale_output/stderr"

printf 'systemd documentation regression checks passed\n'
