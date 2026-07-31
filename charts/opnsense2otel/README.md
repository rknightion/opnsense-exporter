# opnsense2otel

This Helm v3 application chart deploys one secure OPNsense exporter for one firewall. Install a separate Helm release for every additional firewall; the Deployment is deliberately fixed at one replica.

## Install

Create the API credential Secret outside Helm. By default its keys must be the canonical raw-manifest names `key` and `secret`; the chart mounts them as the internal files `api-key` and `api-secret` and never accepts or renders credential values.

```sh
kubectl -n monitoring create secret generic edge-fw-api \
  --from-literal=key='...' \
  --from-literal=secret='...'

helm upgrade --install edge-fw charts/opnsense2otel \
  --namespace monitoring --create-namespace \
  --set opnsense.address=edge-fw.example.net \
  --set opnsense.existingSecret=edge-fw-api
```

`opnsense.address` is required when the chart renders. Use a hostname or IP address without a scheme; set `opnsense.protocol` to `http` only when that is genuinely required. Set `opnsense.secretKeys.apiKey` and `opnsense.secretKeys.apiSecret` only when an existing Secret uses names other than `key` and `secret`.

After rotating an existing Secret, set `opnsense.secretRevision` to a non-secret revision string and upgrade the release. The chart adds that string to the pod template so Kubernetes rolls the exporter without reading or hashing Secret contents.

## Versions and release packages

The source chart tracks the development image with `appVersion: main`, so an empty `image.tag` renders `ghcr.io/rknightion/opnsense2otel:main`. The release publisher overrides `appVersion` with the release version when building packages. It signs and pushes each package to `oci://ghcr.io/rknightion/charts/opnsense2otel` and attaches `opnsense2otel-<version>.tgz` to the matching GitHub release.

## Optional receivers

All push receivers are disabled by default, so their Service and container ports are absent until enabled. This chart exposes the fixed non-privileged receiver ports: syslog UDP and TCP `5514`, Zenarmor TCP `9200`, and NetFlow UDP `2055`.

```yaml
receivers:
  syslog:
    enabled: true
    allowedPeers: ["10.0.0.254/32"]
  zenarmor:
    enabled: true
    allowedPeers: ["10.0.0.254/32"]
  netflow:
    enabled: true
    allowedPeers: ["10.0.0.254/32"]
```

The chart adds the corresponding exporter flags: `--logs.enabled --logs.syslog.enabled`, `--logs.enabled --logs.zenarmor.enabled`, and `--flow.enabled --flow.netflow.enabled`. Peer allowlists become receiver arguments, not Kubernetes labels. Use the `extraArgs` string array for advanced exporter flags.

Syslog and Zenarmor feed the log-shipping pipeline. Its default sink is OTLP, so configure the matching `--otlp.*` transport arguments in `extraArgs`, or select `--logs.sink=stdout`. The chart does not silently replace the exporter's sink default.

The pod runs as UID/GID `65532`, has no service-account token, drops all capabilities, disallows privilege escalation, uses a read-only root filesystem, and sets the RuntimeDefault seccomp profile. A hardened `config-check` init container validates configuration and mounted credentials before the exporter starts.

## Grafana assets

This chart does not package dashboards, alert rules, or Prometheus Operator CRDs. Manage Grafana dashboards and rules through the repository's supported Grafana artifacts.

## Validation

Run the chart-local render contracts:

```sh
bash charts/opnsense2otel/tests/test-chart.sh
```

They cover Helm linting, minimal and optional-receiver renders, schema failures, credential references, pod hardening, upgrade rendering, and kubeconform when it is installed.
