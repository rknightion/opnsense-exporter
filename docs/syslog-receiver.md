---
title: Syslog receiver
description: Push OPNsense logs straight to the exporter, enriched with rule descriptions, interface names and hostnames
---

# Syslog receiver

The exporter can listen for syslog and have OPNsense **push** its logs to it, instead
of polling the API for them. It parses what it receives and enriches it from the
OPNsense API before shipping it on through the [log pipeline](log-shipping.md).

This is off by default. It needs configuration on **both** sides: the receiver on the
exporter, and a logging target on the firewall.

## Why this exists

A generic syslog collector (Alloy, Vector, rsyslog) can already receive these logs.
What it cannot do is *understand* them. A raw firewall log line looks like this:

```
16,115,,6cafbc76-9f4d-4150-949e-e3c37dd0a596,igb0,match,block,in,4,0x0,,58,0,0,none,6,tcp,40,203.0.113.9,198.51.100.4,54321,22,...
```

Nothing there tells you which rule that was, what `igb0` is called, or who owns those
addresses. The exporter already holds an authenticated OPNsense API client, so it can
resolve all of it at ingest — which is the one thing a general-purpose log collector
structurally cannot do.

## Set up the exporter

```bash
opnsense-exporter \
  --logs.enabled \
  --logs.syslog.enabled
```

The receiver listens on **port 5514** for both UDP and TCP by default. (Not 514: that
is a privileged port, and the container runs as a non-root user.)

If you run the exporter in a container, publish the port for **both** protocols —
missing one is the most common reason nothing arrives:

```yaml
ports:
  - "5514:5514/udp"
  - "5514:5514/tcp"
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--logs.syslog.enabled` | `false` | Enables the receiver. Also needs `--logs.enabled`. |
| `--logs.syslog.listen-udp` | `:5514` | Empty disables the UDP listener. |
| `--logs.syslog.listen-tcp` | `:5514` | Empty disables the TCP listener. |
| `--logs.syslog.allowed-peers` | *(any)* | CIDR allowlist of permitted senders. |
| `--logs.syslog.max-conns` | `64` | Cap on concurrent TCP connections. |
| `--logs.syslog.enrich` | `true` | Enrich records from the OPNsense API. |

## Set up the firewall

In the OPNsense UI: **System → Settings → Logging → Targets → +**

| Field | Value |
| --- | --- |
| **Transport** | `TCP(4)` — see below |
| **Applications** | *leave empty* |
| **Levels** | *leave empty* |
| **Facilities** | *leave empty* |
| **Hostname** | the exporter's address |
| **Port** | `5514` |
| **rfc5424** | **ticked** |

Then **Apply**.

Three of those deserve explanation.

**Leave Applications, Levels and Facilities empty.** Empty means *all* — that is how
OPNsense's target model works. Selecting nothing forwards everything the box logs,
which is what you want: the receiver ships unknown programs as generic records rather
than discarding them, so anything you don't explicitly model still reaches Loki.

**Prefer TCP.** UDP is OPNsense's default and it works, but datagram loss is silent
and unrecoverable — you will never know what you didn't receive. Firewall logs are
the highest-volume stream on the box and the one most worth not losing.

**Tick rfc5424.** OPNsense leaves this **off** by default, which sends the legacy BSD
format. The receiver parses both, so it will work either way — but RFC5424 carries a
proper timestamp with a UTC offset, where the legacy format has no year at all and
must be inferred.

## What you get

Firewall (`filterlog`) lines are parsed into structured fields and enriched:

| Attribute | Resolved from |
| --- | --- |
| `rule.description` | `diagnostics/firewall/list_rule_ids` |
| `interface.name` | the interface overview (`vtnet0` → `LAN`) |
| `src.hostname` / `dst.hostname` | DHCPv4/DHCPv6/Kea/dnsmasq leases |
| `src.mac` / `dst.mac` | the ARP and NDP tables |
| `src.scope` / `dst.scope` | `self`, `local` or `remote` |
| `src.service` / `dst.service` | a compiled-in well-known-port table |

So the line above arrives looking like this:

```json
{
  "body": "block in on WAN: 203.0.113.9:54321 -> 198.51.100.4:22 (tcp)",
  "attributes": {
    "action": "block", "direction": "in",
    "interface": "igb0", "interface.name": "WAN",
    "rule.description": "Default deny / state violation rule",
    "src.ip": "203.0.113.9", "src.scope": "remote",
    "dst.ip": "198.51.100.4", "dst.scope": "self", "dst.service": "ssh",
    "tcp.flags": "S", "tcp.window": "64240"
  }
}
```

Every other program OPNsense routes through syslog-ng — the auth/audit trail (SSH
logins, "action allowed X for user root"), configd, unbound, dnsmasq, kea, haproxy,
frr, ipsec, openvpn, package installs, and a catch-all for everything else — ships as
a generic record with its raw body and its envelope attributes.

Records go to Loki as **structured metadata, never as labels**. See the
[Loki label model](log-shipping.md#loki-label-model).

### The rule description is the interesting one

A filterlog rule id is *either* a rule UUID (for rules you wrote) *or* a content hash
(for the auto-generated ones: anti-lockout, default-deny, bogon blocks, DHCP-allow,
IPv6 RFC4890). The rule inventory the exporter already collects only contains the
first kind — on a stock box that is a small minority of the rules that actually match
traffic. `list_rule_ids` resolves both, which is why the receiver uses it.

Lines where the rule id is `0` (NAT and floating-rule matches) carry no rule id at
all by design. They get `rule.ref` (`rule #16.115`) instead of a description.

## What you do *not* get

The receiver is not a total replacement for the API-polling sources. Three things
have no usable syslog path, and their poll lanes remain:

- **Per-query DNS** (`--logs.unbound.enabled`) — Unbound's per-query log with
  blocklist/policy/rcode comes from OPNsense's reporting database. What arrives over
  syslog under `program("unbound")` is the resolver *daemon* log (cache maintenance,
  errors), which is a different stream entirely.
- **CrowdSec** (`--logs.crowdsec.enabled`) — CrowdSec logs to file only. Nothing it
  produces reaches syslog, and it ships no syslog notification plugin.
- **Suricata alerts** (`--logs.ids.enabled`) — the IDS lane ships full EVE alert
  records. OPNsense *can* mirror alerts to syslog (the `syslog_eve` setting), but that
  copy is alerts-only and payload-free. The receiver deliberately ships anything under
  `program("suricata")` as a generic record rather than parsing it, so that enabling
  both does not ship every alert twice.

## Security

**Syslog is unauthenticated.** Anything that can reach the port can inject arbitrary
log records into your observability stack. This is inherent to syslog, not to this
implementation.

- Bind the receiver to a trusted interface.
- On a shared network, set `--logs.syslog.allowed-peers` to the firewall's address
  (`--logs.syslog.allowed-peers=10.0.0.254/32`). Senders outside the list are dropped
  and counted in `opnsense_exporter_logs_rejected_total{reason="peer"}`.
- Messages are capped at 64KB, concurrent TCP connections at `--logs.syslog.max-conns`,
  and idle connections time out — a peer cannot exhaust memory or goroutines.

## Migrating from the poll lanes

`--logs.firewall.enabled`, `--logs.diaglog.enabled` and `--logs.scopes` are **removed**.
The exporter fails to start with an error naming the replacement if any of them (or
their environment variables) are still set.

!!! warning "`--logs.diaglog.enabled` used to default to `true`"
    If you had `--logs.enabled` set, you were shipping the audit/configd/gateway/
    portal trail **without asking for it**. That stops at upgrade and does not come
    back until you configure a syslog target on the firewall as described above. This
    is the one genuinely disruptive part of the change.

## Troubleshooting

**Nothing arrives.** Check `opnsense_exporter_logs_shipped_total{source="syslog"}` is
climbing. If it is flat: confirm the port is published for *both* UDP and TCP, confirm
the target on the firewall is **enabled** and points at the right address, and check
`opnsense_exporter_logs_rejected_total{reason="peer"}` in case an allowlist is
dropping it.

**Records arrive but aren't enriched.** Check
`opnsense_exporter_logs_enrich_refresh_errors_total` and
`opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds` — the API client may be
failing while the receiver keeps working. Enrichment failure never drops a record, so
this shows up as plainer logs rather than missing ones.

**Rules aren't labelled.** A steady
`opnsense_exporter_logs_enrich_misses_total{table="rules"}` means the rule snapshot is
behind the box. It refreshes every 60s and on a miss (rate-limited), so a persistent
rate points at an API permission problem on `diagnostics/firewall/list_rule_ids`.
