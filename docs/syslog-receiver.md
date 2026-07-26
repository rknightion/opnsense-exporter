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

If a log line from your firewall is not parsed the way you expect, the parsers are open source:
see [`internal/logship/` on GitHub](https://github.com/rknightion/opnsense-exporter/tree/main/internal/logship)
and [report the format](https://github.com/rknightion/opnsense-exporter/issues/new) with a sample line.

## Why this exists

A generic syslog collector (Alloy, Vector, rsyslog) can already receive these logs.
What it cannot do is *understand* them. A raw firewall log line looks like this:

```
16,115,,6cafbc76-9f4d-4150-949e-e3c37dd0a596,igb0,match,block,in,4,0x0,,58,0,0,none,6,tcp,40,203.0.113.9,198.51.100.4,54321,22,...
```

Nothing there tells you which rule that was, what `igb0` is called, or who owns those
addresses. The exporter already holds an authenticated OPNsense API client, so it can
resolve all of it at ingest - which is the one thing a general-purpose log collector
structurally cannot do.

## Set up the exporter

```bash
opnsense-exporter \
  --logs.enabled \
  --logs.syslog.enabled
```

The receiver listens on **port 5514** for both UDP and TCP by default. (Not 514: that
is a privileged port, and the container runs as a non-root user.)

If you run the exporter in a container, publish the port for **both** protocols -
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
| `--logs.syslog.listen-tls` | *(none)* | TLS listen address (OPNsense `tls4`/`tls6`). Empty disables it. Needs the cert/key flags below. See [TLS transport](#tls-transport-optional). |
| `--logs.syslog.tls-cert-file` | *(none)* | PEM server certificate for the TLS listener. |
| `--logs.syslog.tls-key-file` | *(none)* | PEM private key for the TLS listener. |
| `--logs.syslog.tls-client-ca-file` | *(none)* | PEM CA bundle to verify sender client certificates. When set, a sender must present a cert signed by this CA - the only real sender authentication syslog has. |
| `--logs.syslog.allowed-peers` | *(any)* | CIDR allowlist of permitted senders. |
| `--logs.syslog.max-conns` | `64` | Cap on concurrent TCP connections. |
| `--logs.syslog.enrich` | `true` | Enrich records from the OPNsense API. |
| `--logs.syslog.exclude-programs` | *(none)* | Programs to drop, e.g. `radvd,cron`. |
| `--logs.syslog.include-programs` | *(none)* | If set, ship ONLY these. Mutually exclusive with exclude. |
| `--logs.syslog.min-severity` | *(none)* | Drop below this severity, e.g. `notice` drops info and debug. |
| `--logs.syslog.sample` | `false` | Drop high-volume raw lines after deriving their metrics. See [Derived metrics and sampling](#derived-metrics-and-sampling). |
| `--logs.syslog.sampled-attribute` | `true` | While sampling, stamp `sampled="true"` on shipped lines. Only takes effect with `--logs.syslog.sample`. |

## Set up the firewall

In the OPNsense UI: **System → Settings → Logging → Targets → +**

| Field | Value |
| --- | --- |
| **Transport** | `TCP(4)` - see below |
| **Applications** | *leave empty* |
| **Levels** | *leave empty* |
| **Facilities** | *leave empty* |
| **Hostname** | the exporter's address |
| **Port** | `5514` |
| **rfc5424** | **ticked** |

Then **Apply**.

Three of those deserve explanation.

**Leave Applications, Levels and Facilities empty.** Empty means *all* - that is how
OPNsense's target model works. Selecting nothing forwards everything the box logs,
which is what you want: the receiver ships unknown programs as generic records rather
than discarding them, so anything you don't explicitly model still reaches Loki.

**Prefer TCP.** UDP is OPNsense's default and it works, but datagram loss is silent
and unrecoverable - you will never know what you didn't receive. Firewall logs are
the highest-volume stream on the box and the one most worth not losing.

**Tick rfc5424.** OPNsense leaves this **off** by default, which sends the legacy BSD
format. The receiver parses both, so it will work either way - but RFC5424 carries a
proper timestamp with a UTC offset, where the legacy format has no year at all and
must be inferred.

## Filtering (optional, off by default)

The receiver ships **everything** unless you tell it otherwise - an unknown program is
never dropped, because that is the point of a catch-all receiver and your box runs
plugins we have never heard of.

If you do pay per GB of ingest, a firewall at debug level is loud. `radvd` logs a timer
tick every two minutes and says nothing; HAProxy logs every request. So:

```bash
--logs.syslog.exclude-programs=radvd,cron     # drop the known-useless
--logs.syslog.min-severity=notice             # drop info and debug, keep notice and worse
```

Syslog severity is **inverted** (0 = emerg, 7 = debug), so `--min-severity=notice` keeps
everything *at or above* notice. Anything dropped is counted in
`opnsense_exporter_logs_rejected_total{reason="filtered"}`, so nothing is
discarded silently.

You can also filter on the firewall itself (the target's Applications/Levels/Facilities
selectors). Use that for coarse cuts you never want to see; use the exporter for tuning
you might change your mind about, since it needs no firewall config edit.

## Derived metrics and sampling

The receiver counts what it parses. Every firewall, HAProxy, sshd, DHCP, audit and IDS
line it recognises increments a Prometheus counter at `/metrics`, so you get rates and
totals without querying Loki at all:

| Metric | Labels |
| --- | --- |
| `opnsense_log_events_firewall_total` | `action`, `interface`, `rule_id`, `rule_name`, `scope` |
| `opnsense_log_events_haproxy_total` | `event`, `backend`, `server`, `state`, `status_class` |
| `opnsense_log_events_sshd_total` | `result`, `method`, `scope` |
| `opnsense_log_events_dhcp_total` | `action`, `interface`, `server` |
| `opnsense_log_events_audit_total` | `event`, `result` |
| `opnsense_log_events_ids_total` | `event_type`, `action`, `category`, `severity` |
| `opnsense_log_events_gateway_total` | `event`, `gateway` |

No IP, port, SID, hostname or signature text becomes a label. Configuration-scale
values such as gateway, interface, rule, backend and server names are protected by
the per-family `--logs.max-metric-keys` budget. This is on by default; turn it off
with `--exporter.disable-log-events`.

### Gateway monitor (`dpinger`) alarms

On OPNsense `27.1.a_40`, the recognised RFC5424 form is:

```text
<PRI>1 <timestamp> <host> dpinger <pid> - [meta sequenceId="<sequence>"] MONITOR: <gateway> (Addr: <address> Alarm: none -> down RTT: <milliseconds> ms RTTd: <milliseconds> ms Loss: <percent> %)
```

The clear form is identical except for `Alarm: down -> none`. These are the only
two transition directions currently counted: `none -> down` becomes
`event="alarm_started"`; `down -> none` becomes `event="alarm_cleared"`.
`opnsense_log_events_gateway_total` carries only `event` and `gateway` (along with
the exporter's standard `opnsense_instance` attribution). The address, RTT, RTTd,
loss, sequence ID and message text are deliberately not metric labels.

Matching lines are enriched with `gateway.event`, `gateway.name`, `gateway.address`,
`gateway.alarm.previous`, `gateway.alarm.current`, `gateway.rtt_ms`,
`gateway.rttd_ms` and `gateway.loss_percent`. A `dpinger` line that does not match
this grammar still ships as a generic record; it is not counted as an inferred
gateway transition.

Because the counters already carry the totals, you can **stop shipping the raw lines
they count** and keep only the ones worth reading. That is `--logs.syslog.sample` (off
by default):

```bash
--logs.syslog.sample     # keep firewall block/reject and HAProxy errors, drop the rest
```

With sampling on, the receiver keeps firewall `block`/`reject` lines and drops the
passes, keeps HAProxy state changes and errors and drops per-connection noise, and
keeps every low-volume program (sshd, DHCP, audit, IDS) in full. A line is only ever
dropped **after** its metric has been counted, so the counters stay complete even
though the log stream is not. Sampling requires the `log_events` collector to be on
(the exporter refuses to start otherwise), because counting first is the whole point.

Every shipped line then carries a `sampled="true"` attribute so a consumer knows the
stream is incomplete and must use the counters for totals. Turn that stamp off with
`--logs.syslog.sampled-attribute=false` if you would rather not have it.

## TLS transport (optional)

The receiver can take syslog over TLS in addition to (or instead of) plain UDP/TCP -
OPNsense's `tls4`/`tls6` transports. It matters when the firewall ships across an
untrusted segment; on a LAN-local link it is unnecessary.

```bash
opnsense-exporter \
  --logs.enabled \
  --logs.syslog.enabled \
  --logs.syslog.listen-tls=:6514 \
  --logs.syslog.tls-cert-file=/etc/exporter/syslog.pem \
  --logs.syslog.tls-key-file=/etc/exporter/syslog.key \
  --logs.syslog.tls-client-ca-file=/etc/exporter/senders-ca.pem   # optional, see below
```

Set `--logs.syslog.tls-client-ca-file` too: it's the only real sender authentication
syslog has. With it, a sender **must** present a client certificate signed by that CA -
the peer allowlist only filters by IP, it doesn't prove who's on the other end. Left
empty, the listener encrypts but accepts any TLS client. On the firewall, set the
target's Transport to `TLS(4)` and point it at the TLS port.

## What you get

**Structured parsers** run for these programs; everything else ships as a generic
record with its message body verbatim and its envelope as metadata.

| Program | Parsed into |
| --- | --- |
| `filterlog` | Firewall packet decisions - see below |
| `audit`, `configd.py` | `config_user`, `config_revision`, `config_uri` (who changed the config), plus configd authorisation and RPC events |
| `sshd`, `sshd-session` | `auth.result` (accepted/failed/invalid-user), `auth.user` (also as the semconv `user.name`), `auth.method`, key fingerprint, source address. A failed login is raised to **warning** - sshd logs a rejected login at the same severity as a successful one, and you should not have to know that to find it. |
| `dhcpd`, `dnsmasq`, `kea-dhcp4`, `kea-dhcp6` | `dhcp.action`, `dhcp.ip`, `dhcp.mac`, `dhcp.hostname`, `dhcp.lease_seconds` - **normalised across all three backends**, so you can query DHCP activity without caring which one your box runs |
| `haproxy` | Server **UP/DOWN** health transitions and "backend has no server available" (severity-mapped), plus per-connection frontend/mode. HTTP fields use OTel semconv names: `http.request.method`, `http.response.status_code`, `url.path`, `network.protocol.version`. |
| `dpinger` | Gateway monitor transitions `none -> down` and `down -> none`, with the observed address, alarm state and probe values. Nonmatching `dpinger` lines remain generic records. |

**Every record**, structured or generic, also gets:

- an `opnsense.subsystem` attribute (`opnsense_subsystem` in Loki) with a value like `firewall`, `auth`, `dhcp`, `ipsec`, `vpn`, `proxy`, `routing` or `ups`, so you can select a whole class of events without enumerating program names;
- any **IP address** mentioned anywhere in the message resolved to a hostname, MAC and scope (`self`/`local`/`remote`);
- any **interface device** resolved to its friendly name (`vtnet0` → `LAN`);
- for IPsec and OpenVPN, the **tunnel UUID resolved to its name** - `charon` logs `<5e891b0c-…|8> sending DPD request`, which is unreadable; the exporter turns it into `ipsec.connection: "site-to-site"` because it already has the API.

### Firewall lines specifically

Firewall (`filterlog`) lines are parsed into structured fields and enriched:

| Attribute | Resolved from |
| --- | --- |
| `rule.description` | `diagnostics/firewall/list_rule_ids` |
| `interface.name` | the interface overview (`vtnet0` → `LAN`) |
| `src.hostname` / `dst.hostname` | DHCPv4/DHCPv6/Kea/dnsmasq leases |
| `src.mac` / `dst.mac` | the ARP and NDP tables |
| `src.scope` / `dst.scope` | `self`, `local` or `remote` |
| `src.service` / `dst.service` | a compiled-in well-known-port table |
| `network.type` | the IP-version field (`ipv4`/`ipv6`) - OTel semconv |
| `network.transport` | the protocol, for TCP/UDP only (`tcp`/`udp`) - OTel semconv |

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

Every other program OPNsense routes through syslog-ng - the auth/audit trail (SSH
logins, "action allowed X for user root"), configd, unbound, dnsmasq, kea, haproxy,
frr, ipsec, openvpn, package installs, and a catch-all for everything else - ships as
a generic record with its raw body and its envelope attributes.

## Querying it in Loki

!!! warning "Attribute names lose their dots"
    The exporter emits OTLP attributes with dots (`rule.description`, `src.ip`) - the
    names used throughout this page. **Loki sanitises dots to underscores.** What you
    type in LogQL is `rule_description` and `src_ip`. A query written with the dotted
    name matches nothing and reports no error, which is the single easiest way to
    waste an afternoon here.

Two index labels select the stream; everything else is structured metadata, filtered
with `|` after it:

```logql
{service_name="opnsense-exporter", service_instance_id="opnsense"}
  | opnsense_subsystem="firewall" | action="block" | src_scope="remote"
```

A real record from a live box, as it lands:

```json
{
  "action": "pass", "direction": "in",
  "interface": "pppoe0", "interface_name": "AAISP",
  "rule_description": "[AAISP] Allow inbound ICMP (monitors)",
  "rule_id": "7ed3ec06-ecf8-4ca8-9a2a-bb346967850f",
  "src_ip": "3.123.217.248", "src_scope": "remote",
  "dst_ip": "81.187.237.31", "dst_scope": "self",
  "protocol": "icmp", "ip_version": "4", "network_type": "ipv4",
  "opnsense_source": "syslog", "opnsense_subsystem": "firewall"
}
```

Useful starting points:

```logql
{service_name="opnsense-exporter"} | opnsense_subsystem="audit"                    # who changed the config
{service_name="opnsense-exporter"} | opnsense_subsystem="auth" | auth_result="failed"
{service_name="opnsense-exporter"} | opnsense_subsystem="firewall" | action="block" | dst_scope="self"
{service_name="opnsense-exporter"} | program="filterlog" | src_hostname="WINSRV"
```

`opnsense.source` and `opnsense.subsystem` (namespaced so they can never collide
with a Loki-reserved key) are the two attributes worth *indexing* if you query them
often. Both ride on the OTLP resource for exactly that reason, and both can be
promoted to real Loki labels with a one-off tenant config change - see the
[Loki label model](log-shipping.md#loki-label-model). Nothing else should be
promoted: `src_ip` as a label is one stream per address.

### Multi-line messages

syslog-ng frames with newlines, not octet counts, so a message that itself contains
newlines - a configd Python traceback, a cron command spanning lines - arrives as
several frames of which only the first carries a `<PRI>` header. The receiver rejoins
them: a line that does not begin with `<` cannot start a new message, so it is
appended to the previous one. The assembled message is capped at 64KB like any other
(the overflowing tail is dropped and counted as `oversized`), and a message with no
successor to complete it is flushed after 250ms rather than waiting for the next line.
Octet-counted frames carry their own length and are passed through untouched, as are
UDP datagrams - one datagram is always exactly one message.

### Resolving rule ids

A filterlog rule id is *either* a rule UUID (for rules you wrote) *or* a content hash
(for the auto-generated ones: anti-lockout, default-deny, bogon blocks, DHCP-allow,
IPv6 RFC4890). The rule inventory the exporter already collects only contains the
first kind - on a stock box that is a small minority of the rules that actually match
traffic. `list_rule_ids` resolves both, which is why the receiver uses it.

Lines where the rule id is `0` (NAT and floating-rule matches) carry no rule id at
all by design. They get `rule.ref` (`rule #16.115`) instead of a description.

## What you do *not* get

The receiver is not a total replacement for the API-polling sources. Three things
have no usable syslog path, and their poll lanes remain:

- **Per-query DNS** (`--logs.unbound.enabled`) - Unbound's per-query log with
  blocklist/policy/rcode comes from OPNsense's reporting database. What arrives over
  syslog under `program("unbound")` is the resolver *daemon* log (cache maintenance,
  errors), which is a different stream entirely.
- **CrowdSec** (`--logs.crowdsec.enabled`) - CrowdSec logs to file only. Nothing it
  produces reaches syslog, and it ships no syslog notification plugin.
- **Suricata payloads** (`--logs.ids.enabled`) - the syslog copy of an EVE alert never
  carries the packet payload. See below.

## Suricata alerts: pick ONE path

The receiver **does** parse Suricata EVE alerts when the box forwards them (the IDS
`syslog_eve` setting, off by default). So does the `ids` poll lane, from the richer
file-based `eve.json`.

**Running both would ship every alert into Loki twice, with no dedupe** - and a
duplicated security alert is worse than a missing one, because it silently inflates
every count anyone builds on it. The exporter therefore **refuses to start** with
`--logs.syslog.enabled` and `--logs.ids.enabled` both set, rather than guessing which
you meant.

| | syslog receiver | `ids` poll lane |
|---|---|---|
| delivery | push, lossless, immediate | polled, up to one interval late |
| cost on the firewall | none | an API call per poll |
| event types | **alerts only** | alerts only |
| payload | **never** (OPNsense forces `payload: no` on the syslog copy) | available |

Take the receiver unless you need the payload. Then turn `syslog_eve` **on** in the
IDS settings and leave `--logs.ids.enabled` off.

Records from both paths carry the **same attribute names** (`alert_sid`, `signature`,
`src_ip`, …), so a dashboard or alert rule does not care which path you chose.

## Security

**Syslog is unauthenticated.** Anything that can reach the port can inject arbitrary
log records into your observability stack. This is inherent to syslog, not to this
implementation.

- Bind the receiver to a trusted interface.
- On a shared network, set `--logs.syslog.allowed-peers` to the firewall's address
  (`--logs.syslog.allowed-peers=10.0.0.254/32`). Senders outside the list are dropped
  and counted in `opnsense_exporter_logs_rejected_total{reason="peer"}`.
- Messages are capped at 64KB, concurrent TCP connections at `--logs.syslog.max-conns`,
  and idle connections time out - a peer cannot exhaust memory or goroutines.

## Migrating from the poll lanes

`--logs.firewall.enabled`, `--logs.diaglog.enabled` and `--logs.scopes` are **removed**.
The exporter fails to start with an error naming the replacement if any of them (or
their environment variables) are still set.

!!! warning "`--logs.diaglog.enabled` used to default to `true`"
    If you had `--logs.enabled` set, you were shipping the audit/configd/gateway/
    portal trail **without asking for it**. That stops at upgrade and does not come
    back until you configure a syslog target on the firewall as described above. This
    is the one disruptive part of the change.

## Troubleshooting

**Nothing arrives.** Check `opnsense_exporter_logs_shipped_total{source="syslog"}` is
climbing. If it is flat: confirm the port is published for *both* UDP and TCP, confirm
the target on the firewall is **enabled** and points at the right address, and check
`opnsense_exporter_logs_rejected_total{reason="peer"}` in case an allowlist is
dropping it.

**Records arrive but aren't enriched.** Check
`opnsense_exporter_logs_enrich_refresh_errors_total` and
`opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds` - the API client may be
failing while the receiver keeps working. Enrichment failure never drops a record, so
this shows up as plainer logs rather than missing ones.

**Rules aren't labelled.** A steady
`opnsense_exporter_logs_enrich_misses_total{table="rules"}` means the rule snapshot is
behind the box. It refreshes every 60s and on a miss (rate-limited), so a persistent
rate points at an API permission problem on `diagnostics/firewall/list_rule_ids`.
