#!/usr/bin/env bash
# Exercise the documented root:opnsense2otel 0640 secret model on Linux.
set -euo pipefail

if ! command -v docker >/dev/null; then
  printf 'docker is required to run the portable permission regression test\n' >&2
  exit 2
fi

docker run --rm -i --platform linux/amd64 alpine:3.22 sh -s <<'EOF'
  set -eu
  addgroup -g 4242 opnsense2otel
  adduser -D -H -u 4242 -G opnsense2otel opnsense2otel
  adduser -D -H -u 4243 unrelated
  install -d -o root -g opnsense2otel -m 0710 /etc/opnsense2otel
  printf "%s\n" api-key | install -o root -g opnsense2otel -m 0640 /dev/stdin /etc/opnsense2otel/api-key
  printf "%s\n" api-secret | install -o root -g opnsense2otel -m 0640 /dev/stdin /etc/opnsense2otel/api-secret

  # Single quotes defer command substitution until the target user's shell runs.
  su -s /bin/sh -c 'test "$(id -u)" = 4242 && test "$(cat /etc/opnsense2otel/api-key)" = api-key' opnsense2otel
  su -s /bin/sh -c 'test "$(id -u)" = 4242 && test "$(cat /etc/opnsense2otel/api-secret)" = api-secret' opnsense2otel
  if su -s /bin/sh -c 'cat /etc/opnsense2otel/api-key' unrelated >/dev/null 2>&1; then
    printf "%s\n" "unrelated user read api-key" >&2
    exit 1
  fi
  if su -s /bin/sh -c 'cat /etc/opnsense2otel/api-secret' unrelated >/dev/null 2>&1; then
    printf "%s\n" "unrelated user read api-secret" >&2
    exit 1
  fi

  test "$(stat -c '%U:%G %a' /etc/opnsense2otel)" = "root:opnsense2otel 710"
  test "$(stat -c '%U:%G %a' /etc/opnsense2otel/api-key)" = "root:opnsense2otel 640"
  test "$(stat -c '%U:%G %a' /etc/opnsense2otel/api-secret)" = "root:opnsense2otel 640"
  stat -c "%U:%G %a" /etc/opnsense2otel /etc/opnsense2otel/api-key /etc/opnsense2otel/api-secret
EOF
