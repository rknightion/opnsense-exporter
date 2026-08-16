#!/usr/bin/env bash
# LOCAL AGENT WARNING: this script provisions hosted cloud environments. If you
# are not a cloud agent, do not execute it. Configure the environment service to
# run `bash scripts/cloud-environment-setup.sh`; do not use it for local setup.
# Compatible with Codex cloud and Claude Code cloud setup scripts.

set -euo pipefail

GO_VERSION="1.26.4"
GOLANGCI_LINT_VERSION="2.12.2"
HELM_VERSION="3.19.0"
BACKLOG_VERSION="1.50.1"

LOCAL_BIN="${HOME}/.local/bin"
LOCAL_SHARE="${HOME}/.local/share"
GO_ROOT="${LOCAL_SHARE}/go"
PYTHON_VENV="${LOCAL_SHARE}/opnsense2otel-python"
mkdir -p "${LOCAL_BIN}" "${LOCAL_SHARE}"

# Codex setup and agent commands run in different shells, while Claude cloud
# persists the setup filesystem in its environment cache. Keep every user-installed
# tool available to either agent rather than relying on this process's exports.
PATH_LINE='export GOROOT="$HOME/.local/share/go"; export PATH="$HOME/.local/bin:$GOROOT/bin:$HOME/.local/share/opnsense2otel-python/bin:$PATH"'
touch "${HOME}/.bashrc"
if ! grep -Fqx "${PATH_LINE}" "${HOME}/.bashrc"; then
  printf '\n# opnsense2otel Codex cloud tools\n%s\n' "${PATH_LINE}" >>"${HOME}/.bashrc"
fi
export PATH="${LOCAL_BIN}:${GO_ROOT}/bin:${PATH}"

require_bootstrap_tools() {
  local missing=()
  local command
  for command in curl docker gcc git make npm python3 sha256sum tar; do
    command -v "${command}" >/dev/null 2>&1 || missing+=("${command}")
  done

  if ((${#missing[@]} == 0)); then
    return
  fi

  if ! command -v apt-get >/dev/null 2>&1; then
    printf 'Missing bootstrap tools and apt-get is unavailable: %s\n' "${missing[*]}" >&2
    exit 1
  fi

  local apt=(apt-get)
  if ((EUID != 0)); then
    command -v sudo >/dev/null 2>&1 || {
      printf 'Installing bootstrap tools requires root or sudo: %s\n' "${missing[*]}" >&2
      exit 1
    }
    apt=(sudo -n apt-get)
  fi
  "${apt[@]}" update
  DEBIAN_FRONTEND=noninteractive "${apt[@]}" install -y --no-install-recommends \
    build-essential ca-certificates coreutils curl docker.io git make nodejs npm \
    python3 python3-pip python3-venv tar
}

install_go() {
  # GOTOOLCHAIN=auto can make an older launcher report the go.mod toolchain.
  # Inspect the installed binary itself so later commands do not trigger another
  # toolchain download outside this repository.
  if [[ -x "${GO_ROOT}/bin/go" ]] && \
    [[ "$(GOTOOLCHAIN=local "${GO_ROOT}/bin/go" version | awk '{print $3}')" == "go${GO_VERSION}" ]]; then
    return
  fi

  local go_arch archive metadata checksum
  case "$(uname -m)" in
    x86_64) go_arch=amd64 ;;
    aarch64 | arm64) go_arch=arm64 ;;
    *) printf 'Unsupported architecture for Go: %s\n' "$(uname -m)" >&2; exit 1 ;;
  esac
  archive="go${GO_VERSION}.linux-${go_arch}.tar.gz"
  metadata="$(mktemp)"
  curl --fail --location --retry 3 --silent --show-error \
    'https://go.dev/dl/?mode=json&include=all' -o "${metadata}"
  checksum="$(python3 - "${metadata}" "${archive}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    releases = json.load(source)
for release in releases:
    for artifact in release["files"]:
        if artifact["filename"] == sys.argv[2]:
            print(artifact["sha256"])
            raise SystemExit
raise SystemExit(f"Go download metadata does not contain {sys.argv[2]}")
PY
)"
  rm -f "${metadata}"

  local download
  download="$(mktemp)"
  curl --fail --location --retry 3 --silent --show-error \
    "https://go.dev/dl/${archive}" -o "${download}"
  printf '%s  %s\n' "${checksum}" "${download}" | sha256sum --check --status
  rm -rf "${GO_ROOT}"
  tar -C "${LOCAL_SHARE}" -xzf "${download}"
  rm -f "${download}"
}

install_golangci_lint() {
  if command -v golangci-lint >/dev/null 2>&1 && \
    golangci-lint version 2>/dev/null | grep -Fq "version ${GOLANGCI_LINT_VERSION}"; then
    return
  fi
  GOBIN="${LOCAL_BIN}" go install \
    "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_LINT_VERSION}"
}

install_helm() {
  if command -v helm >/dev/null 2>&1 && \
    [[ "$(helm version --template '{{.Version}}')" == "v${HELM_VERSION}" ]]; then
    return
  fi

  local helm_arch archive download_dir
  case "$(uname -m)" in
    x86_64) helm_arch=amd64 ;;
    aarch64 | arm64) helm_arch=arm64 ;;
    *) printf 'Unsupported architecture for Helm: %s\n' "$(uname -m)" >&2; exit 1 ;;
  esac
  archive="helm-v${HELM_VERSION}-linux-${helm_arch}.tar.gz"
  download_dir="$(mktemp -d)"
  curl --fail --location --retry 3 --silent --show-error \
    "https://get.helm.sh/${archive}" -o "${download_dir}/${archive}"
  curl --fail --location --retry 3 --silent --show-error \
    "https://get.helm.sh/${archive}.sha256sum" -o "${download_dir}/${archive}.sha256sum"
  (cd "${download_dir}" && sha256sum --check "${archive}.sha256sum")
  tar -C "${download_dir}" -xzf "${download_dir}/${archive}"
  install -m 0755 "${download_dir}/linux-${helm_arch}/helm" "${LOCAL_BIN}/helm"
  rm -rf "${download_dir}"
}

install_python_tools() {
  if [[ ! -x "${PYTHON_VENV}/bin/python" ]]; then
    python3 -m venv "${PYTHON_VENV}"
  fi
  "${PYTHON_VENV}/bin/python" -m pip install --disable-pip-version-check --quiet \
    -r scripts/requirements-cloud-setup.txt
  "${PYTHON_VENV}/bin/python" -m pip install --disable-pip-version-check --quiet \
    -r tools/opnsense_api_contract/requirements.txt
}

install_backlog() {
  local npm_prefix="${HOME}/.local"
  if command -v backlog >/dev/null 2>&1 && \
    [[ "$(backlog --version)" == "${BACKLOG_VERSION}" ]]; then
    return
  fi
  npm install --global --prefix "${npm_prefix}" --no-audit --no-fund \
    "backlog.md@${BACKLOG_VERSION}"
}

require_bootstrap_tools
install_go
export GOROOT="${GO_ROOT}"
install_golangci_lint
install_helm
install_python_tools
install_backlog

# Prime the committed module graph while setup still has internet access. Project
# builds normally use vendor/, but the Go tool can still need toolchain metadata.
go mod download

printf 'Codex cloud environment ready:\n'
go version
golangci-lint version
helm version --short
"${PYTHON_VENV}/bin/python" --version
backlog --version
