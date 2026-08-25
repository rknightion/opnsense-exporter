#!/usr/bin/env bash
set -euo pipefail

# This exercises the rendered chart boundary.  It catches a missing receiver flag,
# port, credential mount, or hardening control even when Helm accepts the YAML.
chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_dir="$chart_dir/tests/fixtures"
render_dir="$chart_dir/tests/.rendered"

rm -rf "$render_dir"
mkdir -p "$render_dir"
trap 'rm -rf "$render_dir"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file="$1" pattern="$2"
  grep -Fq -- "$pattern" "$file" || fail "expected $pattern in $file"
}

assert_not_contains() {
  local file="$1" pattern="$2"
  if grep -Fq -- "$pattern" "$file"; then
    fail "did not expect $pattern in $file"
  fi
}

assert_count() {
  local file="$1" pattern="$2" expected="$3" count
  count="$(grep -Fc -- "$pattern" "$file" || true)"
  [[ "$count" == "$expected" ]] || fail "expected $expected occurrences of $pattern in $file, got ${count:-0}"
}

render() {
  local name="$1" values="$2"
  helm template contract "$chart_dir" --namespace monitoring -f "$values" > "$render_dir/$name.yaml"
}

helm lint "$chart_dir" --strict -f "$fixture_dir/minimal.yaml"
render minimal "$fixture_dir/minimal.yaml"
minimal="$render_dir/minimal.yaml"

assert_contains "$minimal" 'kind: Deployment'
assert_contains "$minimal" 'kind: Service'
assert_not_contains "$minimal" 'kind: ServiceAccount'
assert_not_contains "$minimal" 'kind: Secret'
assert_not_contains "$minimal" 'kind: ConfigMap'
assert_contains "$minimal" 'value: "edge-fw.example.net"'
assert_contains "$minimal" 'name: opnsense2otel'
assert_contains "$minimal" 'secretName: edge-fw-api'
assert_contains "$minimal" 'key: "key"'
assert_contains "$minimal" 'key: "secret"'
assert_contains "$minimal" 'value: /etc/opnsense2otel/creds/api-key'
assert_contains "$minimal" 'value: /etc/opnsense2otel/creds/api-secret'
assert_contains "$minimal" 'opnsense2otel/secret-revision: "42"'
assert_contains "$minimal" 'image: "ghcr.io/rknightion/opnsense2otel:main"'
assert_contains "$minimal" 'mountPath: /etc/opnsense2otel/creds'
assert_contains "$minimal" 'automountServiceAccountToken: false'
assert_contains "$minimal" 'runAsUser: 65532'
assert_contains "$minimal" 'runAsGroup: 65532'
assert_contains "$minimal" 'runAsNonRoot: true'
assert_contains "$minimal" 'readOnlyRootFilesystem: true'
assert_contains "$minimal" 'allowPrivilegeEscalation: false'
assert_contains "$minimal" 'type: RuntimeDefault'
assert_contains "$minimal" 'path: /-/healthy'
assert_contains "$minimal" 'containerPort: 8080'
assert_contains "$minimal" 'name: config-check'
assert_contains "$minimal" '"--config.check"'
assert_not_contains "$minimal" 'syslog-udp'
assert_not_contains "$minimal" 'syslog-tcp'
assert_not_contains "$minimal" 'zenarmor'
assert_not_contains "$minimal" 'netflow'
assert_not_contains "$minimal" 'supersecret'

render syslog "$fixture_dir/syslog.yaml"
syslog="$render_dir/syslog.yaml"
assert_contains "$syslog" '"--logs.enabled"'
assert_contains "$syslog" '"--logs.syslog.enabled"'
assert_contains "$syslog" '"--logs.syslog.allowed-peers=10.0.0.254/32,10.0.1.254/32"'
assert_contains "$syslog" 'name: syslog-udp'
assert_contains "$syslog" 'name: syslog-tcp'
assert_contains "$syslog" 'protocol: UDP'

render zenarmor "$fixture_dir/zenarmor.yaml"
zenarmor="$render_dir/zenarmor.yaml"
assert_contains "$zenarmor" '"--logs.enabled"'
assert_contains "$zenarmor" '"--logs.zenarmor.enabled"'
assert_contains "$zenarmor" '"--logs.zenarmor.allowed-peers=10.0.0.254/32,10.0.1.254/32"'
assert_contains "$zenarmor" 'name: zenarmor'
assert_contains "$zenarmor" 'containerPort: 9200'

render netflow "$fixture_dir/netflow.yaml"
netflow="$render_dir/netflow.yaml"
assert_contains "$netflow" '"--flow.enabled"'
assert_contains "$netflow" '"--flow.netflow.enabled"'
assert_contains "$netflow" '"--flow.netflow.allowed-peers=10.0.0.254/32"'
assert_contains "$netflow" 'name: netflow'
assert_contains "$netflow" 'protocol: UDP'
assert_contains "$netflow" 'containerPort: 2055'

render all-receivers "$fixture_dir/all-receivers.yaml"
all_receivers="$render_dir/all-receivers.yaml"
assert_contains "$all_receivers" 'name: syslog-udp'
assert_contains "$all_receivers" 'name: syslog-tcp'
assert_contains "$all_receivers" 'name: zenarmor'
assert_contains "$all_receivers" 'name: netflow'
assert_count "$all_receivers" '"--logs.enabled"' 2
assert_count "$all_receivers" '"--logs.syslog.enabled"' 2
assert_count "$all_receivers" '"--logs.zenarmor.enabled"' 2
assert_count "$all_receivers" '"--flow.enabled"' 2
assert_count "$all_receivers" '"--flow.netflow.enabled"' 2
assert_count "$all_receivers" '"--collector.poll-interval=30s"' 2
assert_count "$all_receivers" '"--logs.sink=stdout"' 2
assert_count "$all_receivers" '"--config.check"' 1

render settings "$fixture_dir/settings.yaml"
settings="$render_dir/settings.yaml"
assert_contains "$settings" '"--opnsense.max-retries=5"'
assert_contains "$settings" '"--opnsense.insecure=true"'
# repeatable settings values: one --flag=value arg per list element, not a comma join.
assert_contains "$settings" '"--collector.poll-interval-override=arp_table=30s"'
assert_contains "$settings" '"--collector.poll-interval-override=carp=45s"'
assert_contains "$settings" '"--annotations.extra-tags=env=prod"'

# A setting value remains one argv scalar even when it contains YAML-significant
# quotes and newlines. It must not grow a sibling argument that overrides a
# protected env-derived option.
render quoted-args "$fixture_dir/quoted-args.yaml"
quoted_args="$render_dir/quoted-args.yaml"
assert_not_contains "$quoted_args" '    - "--opnsense.address=attacker.example.net'
assert_contains "$quoted_args" '\n    - \"--opnsense.address=attacker.example.net'

helm template contract "$chart_dir" -f "$fixture_dir/upgrade.yaml" --is-upgrade > "$render_dir/upgrade.yaml"
assert_contains "$render_dir/upgrade.yaml" 'kind: Deployment'

if helm template contract "$chart_dir" --set opnsense.address= --set opnsense.apiKey=supersecret > /dev/null 2>&1; then
  fail 'schema accepted a credential value'
fi
if helm template contract "$chart_dir" --set opnsense.address= > /dev/null 2>&1; then
  fail 'template accepted a missing OPNsense address'
fi
if helm template contract "$chart_dir" -f "$fixture_dir/minimal.yaml" --set ports.http=70000 > /dev/null 2>&1; then
  fail 'schema accepted an invalid port'
fi
if helm template contract "$chart_dir" -f "$fixture_dir/minimal.yaml" \
  --set-string 'receivers.netflow.allowedPeers[0]=not-a-cidr' > /dev/null 2>&1; then
  fail 'schema accepted a non-CIDR receiver peer'
fi
if helm template contract "$chart_dir" -f "$fixture_dir/minimal.yaml" \
  --set-string 'receivers.netflow.allowedPeers[0]=::::/999' > /dev/null 2>&1; then
  fail 'schema accepted an out-of-range IPv6 CIDR prefix'
fi

for forbidden_arg in \
  '--opnsense.api-key=supersecret' \
  '--opnsense.api-secret=supersecret' \
  '--opnsense.address=other-fw.example.net' \
  '--opnsense.protocol=http' \
  '--exporter.instance-label=other' \
  '--web.listen-address=:9090' \
  '--config.check' \
  '--logs.enabled' \
  '--logs.syslog.enabled' \
  '--logs.zenarmor.enabled' \
  '--flow.enabled' \
  '--flow.netflow.enabled'; do
  if helm template contract "$chart_dir" -f "$fixture_dir/minimal.yaml" \
    --set-string "extraArgs[0]=$forbidden_arg" > /dev/null 2>&1; then
    fail "extraArgs accepted chart-managed or secret flag $forbidden_arg"
  fi
done

# The settings map draws from the same reserved-flag list as extraArgs (see
# opnsense2otel.reservedFlagReason in _helpers.tpl) -- a key naming a
# chart-managed flag must fail the render rather than silently picking a winner.
for forbidden_key in \
  opnsense.api-key \
  opnsense.api-secret \
  opnsense.address \
  opnsense.protocol \
  exporter.instance-label \
  web.listen-address \
  config.check \
  logs.enabled \
  logs.syslog.enabled \
  logs.zenarmor.enabled \
  flow.enabled \
  flow.netflow.enabled; do
  # --set path segments split on "." same as settings' own dotted flag names, so an
  # unescaped dot would build a NESTED value (settings.logs.syslog.enabled=x means
  # settings: {logs: {syslog: {enabled: x}}}), which the schema already rejects for an
  # unrelated reason (an object isn't a valid settingValue) without ever reaching the
  # conflict check this loop means to exercise. Escaping every dot keeps each
  # forbidden_key a single flat settings key, matching a real values.yaml entry.
  escaped_key="${forbidden_key//./\\.}"
  output="$(helm template contract "$chart_dir" -f "$fixture_dir/minimal.yaml" \
    --set-string "settings.$escaped_key=x" 2>&1)" && \
    fail "settings accepted chart-managed or secret flag $forbidden_key"
  echo "$output" | grep -q 'conflicts with a chart-managed flag' \
    || fail "settings.$forbidden_key was rejected for the wrong reason: $output"
done

if command -v kubeconform >/dev/null 2>&1; then
  kubeconform -strict -summary "$minimal" "$all_receivers"
fi

printf 'chart contract tests passed\n'
