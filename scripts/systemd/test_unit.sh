#!/usr/bin/env bash
# Boot the documented unit under real systemd with the current Linux binary.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
container="opnsense2otel-systemd-$PPID-$$"

cleanup() {
  docker stop "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

for command in docker go python3; do
  command -v "$command" >/dev/null || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 2
  }
done

case "$(docker info --format '{{.Architecture}}')" in
  amd64|x86_64) goarch=amd64 ;;
  arm64|aarch64) goarch=arm64 ;;
  *) printf 'unsupported Docker architecture\n' >&2; exit 2 ;;
esac

python3 - "$root/docs/deployment/systemd.md" "$work/opnsense2otel.service" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
fence = '```ini title="/etc/systemd/system/opnsense2otel.service"'
if source.count(fence) != 1:
    raise SystemExit("systemd guide must contain exactly one executable unit fence")
region = source.split(fence, 1)[1].split("```", 1)[0].strip()
if not region.startswith("[Unit]") or "[Service]" not in region:
    raise SystemExit("documented systemd unit is incomplete")
Path(sys.argv[2]).write_text(region + "\n")
PY

cat >"$work/exporter.env" <<'EOF'
OPN2OTEL_OPS_PROTOCOL=https
OPN2OTEL_OPS_API=127.0.0.1
OPS_API_KEY_FILE=/etc/opnsense2otel/api-key
OPS_API_SECRET_FILE=/etc/opnsense2otel/api-secret
OPN2OTEL_INSTANCE_LABEL=systemd-smoke
EOF
printf '%s\n' 'smoke-api-key' >"$work/api-key"
printf '%s\n' 'smoke-api-secret' >"$work/api-secret"

CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
  go build -o "$work/opnsense2otel" "$root"

# The digest pins the Ubuntu 24.04 multi-architecture base. Package installation
# happens only in this disposable test image.
docker build -t opnsense2otel-systemd-test:local -f - "$root" <<'DOCKERFILE'
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
ENV container=docker
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl mask systemd-remount-fs.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
DOCKERFILE

docker run --rm --privileged -d \
  --name "$container" \
  --mount "type=bind,src=$work,dst=/fixture,readonly" \
  opnsense2otel-systemd-test:local >/dev/null

state=starting
for _ in $(seq 1 30); do
  state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
  if [[ "$state" == running || "$state" == degraded ]]; then
    break
  fi
  sleep 1
done
if [[ "$state" != running && "$state" != degraded ]]; then
  printf 'systemd did not finish starting: %s\n' "$state" >&2
  exit 1
fi

docker exec "$container" groupadd --system opnsense2otel
docker exec "$container" useradd --system --no-create-home --shell /usr/sbin/nologin --gid opnsense2otel opnsense2otel
docker exec "$container" install -o root -g root -m 0755 /fixture/opnsense2otel /usr/local/bin/opnsense2otel
docker exec "$container" install -d -o root -g opnsense2otel -m 0710 /etc/opnsense2otel
docker exec "$container" install -o root -g root -m 0600 /fixture/exporter.env /etc/opnsense2otel/exporter.env
docker exec "$container" install -o root -g opnsense2otel -m 0640 /fixture/api-key /etc/opnsense2otel/api-key
docker exec "$container" install -o root -g opnsense2otel -m 0640 /fixture/api-secret /etc/opnsense2otel/api-secret
docker exec "$container" install -o root -g root -m 0644 /fixture/opnsense2otel.service /etc/systemd/system/opnsense2otel.service

docker exec "$container" systemctl daemon-reload
if ! docker exec "$container" systemctl start opnsense2otel; then
  docker exec "$container" systemctl status --no-pager opnsense2otel >&2 || true
  docker exec "$container" journalctl --no-pager -u opnsense2otel >&2 || true
  exit 1
fi
docker exec "$container" systemctl is-active --quiet opnsense2otel
docker exec "$container" curl --fail --silent --show-error http://127.0.0.1:8080/-/healthy
docker exec "$container" systemctl show opnsense2otel -p User -p Group --value

printf 'documented systemd unit reached /-/healthy with file credentials\n'
