#!/usr/bin/env bash
# Exercise the documented root:opnsense-exporter 0640 secret model on Linux.
set -euo pipefail

if ! command -v docker >/dev/null; then
  printf 'docker is required to run the portable permission regression test\n' >&2
  exit 2
fi

docker run --rm -i --platform linux/amd64 alpine:3.22 sh -s <<'EOF'
  set -eu
  addgroup -g 4242 opnsense-exporter
  adduser -D -H -u 4242 -G opnsense-exporter opnsense-exporter
  adduser -D -H -u 4243 unrelated
  install -d -o root -g opnsense-exporter -m 0710 /etc/opnsense-exporter
  printf "%s\n" api-key | install -o root -g opnsense-exporter -m 0640 /dev/stdin /etc/opnsense-exporter/api-key
  printf "%s\n" api-secret | install -o root -g opnsense-exporter -m 0640 /dev/stdin /etc/opnsense-exporter/api-secret

  # Single quotes defer command substitution until the target user's shell runs.
  su -s /bin/sh -c 'test "$(id -u)" = 4242 && test "$(cat /etc/opnsense-exporter/api-key)" = api-key' opnsense-exporter
  su -s /bin/sh -c 'test "$(id -u)" = 4242 && test "$(cat /etc/opnsense-exporter/api-secret)" = api-secret' opnsense-exporter
  if su -s /bin/sh -c 'cat /etc/opnsense-exporter/api-key' unrelated >/dev/null 2>&1; then
    printf "%s\n" "unrelated user read api-key" >&2
    exit 1
  fi
  if su -s /bin/sh -c 'cat /etc/opnsense-exporter/api-secret' unrelated >/dev/null 2>&1; then
    printf "%s\n" "unrelated user read api-secret" >&2
    exit 1
  fi

  test "$(stat -c '%U:%G %a' /etc/opnsense-exporter)" = "root:opnsense-exporter 710"
  test "$(stat -c '%U:%G %a' /etc/opnsense-exporter/api-key)" = "root:opnsense-exporter 640"
  test "$(stat -c '%U:%G %a' /etc/opnsense-exporter/api-secret)" = "root:opnsense-exporter 640"
  stat -c "%U:%G %a" /etc/opnsense-exporter /etc/opnsense-exporter/api-key /etc/opnsense-exporter/api-secret
EOF
