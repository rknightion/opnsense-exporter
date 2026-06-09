---
title: Upgrading
description: Breaking changes and migration notes for OPNsense Exporter releases, including v1.0 and migration from the upstream AthennaMind exporter
tags:
  - upgrading
  - migration
---

# Upgrading

This page lists breaking changes by release, plus notes for users migrating from the
upstream AthennaMind exporter. Full details for every release:
[Changelog](changelog.md).

## Upgrading to v1.0 from v0.x

- **IPsec SPI labels removed** — phase-2 metrics no longer carry `spi_in`/`spi_out`
  labels (remaining: `description`, `name`, `phase1_name`). SPIs rotate on every
  rekey, so the labels caused unbounded series churn. Update any PromQL that
  referenced them.
- **OpenVPN per-session metrics are opt-in** — the per-session
  `opnsense_openvpn_sessions` series (username and tunnel-address labels) is only
  emitted with `--exporter.enable-openvpn-details`. The aggregate
  `opnsense_openvpn_sessions_total` and `opnsense_openvpn_sessions_by_instance`
  series are always emitted. Set the flag to restore the old behaviour.
- **WireGuard handshake metric type** — `opnsense_wireguard_peer_last_handshake_seconds`
  changed from counter to gauge (it is a Unix timestamp). Replace
  `rate(opnsense_wireguard_peer_last_handshake_seconds[...])` with the purpose-built
  `opnsense_wireguard_peer_handshake_age_seconds` gauge.

## Migrating from upstream (AthennaMind/opnsense-exporter)

In addition to the items above:

- **Image and module path** — pull `ghcr.io/rknightion/opnsense-exporter`; the Go
  module is `github.com/rknightion/opnsense-exporter`.
- **`--runtime.gomaxprocs` removed** — Go now auto-detects CPUs; delete the flag from
  any unit files or manifests.
- **`/debug/pprof/*` endpoints removed** — replaced by optional authenticated push
  profiling via `--pyroscope.*` flags. See
  [Configuration](configuration.md#continuous-profiling-pyroscope).
- **Firmware metrics reworked** — version strings consolidated into
  `opnsense_firmware_info` (labels) plus numeric gauges (`needs_reboot`,
  `upgrade_needs_reboot`, `last_check_timestamp_seconds`, `new_packages_count`,
  `upgrade_packages_count`).
- **`--exporter.instance-label` now optional** — defaults to the hostname reported by
  the OPNsense API.
- **Many new collectors are enabled by default** — review the
  [collector switches](configuration.md#collector-switches) and disable what you
  don't need.
