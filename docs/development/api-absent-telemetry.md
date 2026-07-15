---
title: API-Absent Telemetry
description: Why the exporter will never ship an SSH channel, and how to cover the handful of signals only available over shell
tags:
  - OPNsense
  - development
---

# API-Absent Telemetry

A recurring request is an SSH-based channel for the small set of signals OPNsense's REST API
does not expose at all, chiefly ZFS pool health and CARP demotion state. This was spiked
end-to-end in [#225](https://github.com/rknightion/opnsense-exporter/issues/225) against a real
26.7-devel box. **Verdict: no.** This page is the permanent record of why, and the recipe to get
those two signals without the exporter ever holding a shell credential.

## Why the exporter will never dial SSH

The blocker is not parser fragility, it is OPNsense's privilege model: **there is no unprivileged
shell tier to grant a credential into.**

`/usr/local/etc/inc/auth.inc` decides a user's login shell with one line:

```php
$user_shell = $is_admin && !empty($user['shell']) ? $user['shell'] : '/usr/sbin/nologin';
```

Any account without the full `page-all` admin privilege is force-set to shell `/usr/sbin/nologin`
and group `nobody`, regardless of what shell the GUI's user editor claims to offer. There is no
separate "shell access" privilege distinct from full admin: OPNsense's privilege model does not
model that tier. On top of that, the generated `sshd_config`
(`plugins.inc.d/openssh.inc:171`) hardcodes `AllowGroups wheel` unconditionally, so even a
`nologin`-shelled account that somehow reached sshd would be refused at the group check.

The practical consequence: **every credential capable of running one SSH command against an
OPNsense box is a full-admin, effectively root-equivalent credential.** A dedicated, read-only,
non-wheel SSH user (the shape of thing a scraper credential should be) does not exist in stock
OPNsense. Building one would mean unmanaged `sshd_config.d` drop-ins and a boot-hook user
creation outside `config.xml`, which is not upgrade-safe and not something this project will ship
as a default for every install.

Given that, embedding an SSH client in the exporter would trade a scoped API-key credential for a
root-equivalent one, add a reconnect/session state machine, and add parsers with no contract-canary
safety net (see [API Landmines](api-landmines.md) for what that safety net normally buys us). All
that to unlock two metrics. Not a good trade. Closed as a documentation deliverable instead.

## Use os-node_exporter for OS-level telemetry

Most of what an SSH channel would have chased is already covered by installing the
**os-node_exporter** plugin on the firewall itself and scraping it as a second Prometheus target
(the exporter and node_exporter are complementary, not overlapping; see
[Integration & Dashboards](../integration-dashboards.md)). Its GUI collector toggles
(Services → Node Exporter) map straight onto the metrics families the spike was chasing:

| Toggle | Covers |
| --- | --- |
| `devstat` | Per-disk I/O: read/write bytes, ops, busy time (the same data `iostat -x` would give an SSH-based collector, without a fixed-column parser to keep in sync with FreeBSD releases). |
| `interrupts` | Per-CPU interrupt counters. |
| `zfs` | ZFS ARC size and hit/miss counters (`kstat.zfs.misc.arcstats.*`). |
| `cpu`, `meminfo`, `loadavg`, `filesystem`, `netdev`, `time`, `ntp` | Standard OS-level coverage; not the reason for this spike but worth enabling alongside the above. |

node_exporter does **not** cover ZFS pool health (degraded/faulted vdevs) or CARP demotion state.
Those two are the only genuinely API-absent signals the spike confirmed, and they need the recipe
below.

## Textfile-collector recipe: ZFS pool health + CARP demotion

The os-node_exporter plugin ships node_exporter's textfile collector always on, pointed at a fixed
directory, `/var/tmp/node_exporter` (owned `nobody:nobody`; confirmed against the plugin's
[startup template](https://github.com/opnsense/plugins/blob/master/sysutils/node_exporter/src/opnsense/service/templates/OPNsense/NodeExporter/node_exporter)
and reports from users who hit it). There is no GUI setting for the directory, and none is needed:
any `.prom` file dropped there on a `mtime` newer than node_exporter's scrape gets picked up on the
next scrape automatically.

A root cron job writing one file covers both signals with zero new credentials and zero exporter
code:

```sh
#!/bin/sh
# /usr/local/bin/zfs_carp_textfile.sh
# Root cron: emit ZFS pool health + CARP demotion as a node_exporter textfile metric.
set -eu
DIR=/var/tmp/node_exporter
TMP=$(mktemp "${DIR}/.zfs_carp.prom.XXXXXX")
POOLS=$(zpool list -H -o name 2>/dev/null | wc -l | tr -d ' ')
HEALTHY=0
zpool status -x 2>/dev/null | grep -qx 'all pools are healthy' && HEALTHY=1
DEMOTION=$(sysctl -n net.inet.carp.demotion 2>/dev/null || echo 0)
{
  printf '# TYPE opnsense_textfile_zpool_count gauge\nopnsense_textfile_zpool_count %s\n' "${POOLS}"
  printf '# TYPE opnsense_textfile_zpool_healthy gauge\nopnsense_textfile_zpool_healthy %s\n' "${HEALTHY}"
  printf '# TYPE opnsense_textfile_carp_demotion gauge\nopnsense_textfile_carp_demotion %s\n' "${DEMOTION}"
} > "${TMP}"
chmod 644 "${TMP}"
mv -f "${TMP}" "${DIR}/zfs_carp.prom"
```

Add it via **Services → Cron** (do not hand-edit `/etc/crontab`: OPNsense regenerates it from
`config.xml` on every boot and config write, silently discarding a manual entry) at whatever
interval matches your scrape cadence; every 5 minutes is generally enough for pool health and
CARP demotion, neither of which flaps on a healthy box.

Two things make this safe to run unattended:

- **Atomic write:** node_exporter's textfile collector rejects a file mid-write (a truncated
  `.prom` file is invalid exposition format), so the script writes to a `mktemp` sibling in the
  *same* directory and `mv`s it into place: a rename within one filesystem is atomic, so
  node_exporter only ever sees the file fully formed or not at all.
- **Zero-pools handled correctly:** `zpool list -H -o name` against a box with no pools returns
  empty stdout with exit code 0, so the `wc -l` count is then `0`, which is correct, not an
  error. This is a real gotcha to know if you build your own variant against `zpool list -j`:
  with zero pools it *also* returns empty stdout (not `{}`, nothing at all), while `zpool status
  -j` returns valid, parseable JSON even with zero pools (`{"pools":{}}`). The two `-j` forms are
  not consistent with each other on the empty case. The script above sidesteps the whole question
  by staying on the plain-text forms, which need no JSON parser on the box at all.

## Deliberately out of scope

- **`dev.cpu.N.freq`** is a real-hardware-only signal: there is no cpufreq driver under
  virtualization (confirmed absent on a KVM-hosted devel box), so it would read absent on a
  large fraction of installs and isn't worth a collector or a textfile metric either.
- **NIC driver sysctl trees** (`dev.ix.N.*`, `dev.igb.N.*`, and similar) remain out of scope. They
  are driver-specific, not part of any stable cross-driver API, and already partially duplicated
  by node_exporter's `netdev` collector for the counters that matter for dashboards.

## See also

- [API Landmines](api-landmines.md) — the same "verified against source, not guessed at" treatment
  for endpoints inside the OPNsense REST API itself.
- [Compatibility](../compatibility.md#how-drift-is-caught) — the automated canaries that keep the
  in-API surface honest; there is no equivalent canary for this page's shell commands, so treat
  the recipe as a starting point to adapt, not a pinned contract.
