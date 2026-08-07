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
see [`internal/logship/` on GitHub](https://github.com/rknightion/opnsense2otel/tree/main/internal/logship)
and [report the format](https://github.com/rknightion/opnsense2otel/issues/new) with a sample line.

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
opnsense2otel \
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

The receiver counts what it parses. Every firewall, HAProxy, sshd, DHCP (server and
this firewall's own WAN DHCP/DHCPv6 client), audit, IDS, gateway, CARP, UPnP, VPN
lifecycle and supported FreeRADIUS access line it recognises increments a Prometheus
counter at `/metrics`, so you get rates and totals without querying Loki at all:

| Metric | Labels |
| --- | --- |
| `opnsense_log_events_firewall_total` | `action`, `interface`, `rule_id`, `rule_name`, `scope` |
| `opnsense_log_events_haproxy_total` | `event`, `backend`, `server`, `state`, `status_class` |
| `opnsense_log_events_sshd_total` | `result`, `method`, `scope` |
| `opnsense_log_events_dhcp_total` | `action`, `interface`, `server` |
| `opnsense_log_events_dhcp_client_total` | `interface`, `type` |
| `opnsense_log_events_dhcp6c_message_total` | `interface`, `direction`, `type` |
| `opnsense_log_events_dhcp6c_event_total` | `interface`, `event`, `reason` |
| `opnsense_log_events_audit_total` | `event`, `result` |
| `opnsense_log_events_ids_total` | `event_type`, `action`, `category`, `severity` |
| `opnsense_log_events_gateway_total` | `event`, `gateway` |
| `opnsense_log_events_radius_total` | `event`, `result`, `client_scope` |
| `opnsense_log_events_vpn_total` | `backend`, `event`, `result`, `connection` |
| `opnsense_log_events_carp_total` | `event`, `from`, `to`, `interface`, `vhid` |
| `opnsense_log_events_upnp_total` | `event`, `result`, `protocol` |

No IP, port, SID, hostname, username, MAC, NAS/client identity, certificate subject or
serial, IKE identity, SPI, reply text, credential or signature text becomes a label.
Configuration-scale values such as gateway, interface, rule, backend, server and VPN
connection names are protected by the per-family `--logs.max-metric-keys` budget. This
is on by default; turn it off with `--exporter.disable-log-events`.

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

### CARP state changes and demotion (kernel)

CARP transitions come from the **FreeBSD kernel**, not from OPNsense, under the
RFC5424 APP-NAME `kernel`. They require `net.inet.carp.log=1`, which is the FreeBSD
default. On OPNsense `27.1.a_40` (FreeBSD 15) the two recognised forms are:

```text
<PRI>1 <timestamp> <host> kernel - - [meta sequenceId="<sequence>"] <<kpri>>[<kuptime>] carp: <vhid>@<device>: INIT -> BACKUP (initialization complete)
<PRI>1 <timestamp> <host> kernel - - [meta sequenceId="<sequence>"] <<kpri>>[<kuptime>] carp: demoted by <delta> to <total> (pfsync bulk start)
```

The `<6>[754] ` prefix ahead of `carp:` is the kernel's own priority and monotonic
counter. It is part of the message, both numbers vary freely, and the receiver
tolerates it being absent.

`event` is closed to three values. A `<FROM> -> <TO>` line is `state_changed`, with
`from` and `to` closed to `master`, `backup` or `init` (lowercased) and the OS device
and VHID in `interface` and `vhid`. A `demoted by` line is `demoted` when the delta is
positive and `promoted` when it is negative — FreeBSD has no separate promotion line,
so the **sign of the delta** is the whole distinction. A demotion is global to the
node and names neither an interface nor a VHID, so `from`, `to`, `interface` and
`vhid` are all **empty** on those series.

The kernel's **cause** — `initialization complete`, `master timed out`, `hardware
interface up`, `pfsync bulk start`, `pfsync bulk fail`, `service disruption`, and
whatever a future FreeBSD adds — is deliberately **not a metric label**, and is not
bucketed into a `reason_class` either: it is open-ended free text across FreeBSD
versions. It ships on the record as `carp.reason`, alongside `carp.event`,
`carp.state.previous`, `carp.state.current`, `carp.interface`, `carp.vhid`,
`carp.demotion.delta` and `carp.demotion.total`. Those last two are the numbers that
explain *why* a node demoted, which the `opnsense_carp_demotion` current-state gauge
cannot retain.

Because this parser claims `kernel`, it sees every kernel line on the box. Anything
that is not one of the two forms above — link-state changes, watchdog resets, ZFS,
USB, arp — is **not** claimed: it ships as a generic record exactly as it did before,
and is never counted as an inferred CARP transition.

OPNsense's own CARP syshook also logs transitions under APP-NAME `opnsense`, carrying
the admin's VIP description. That source is deliberately not parsed: `opnsense` is the
catch-all app-name for every `log_msg()` call on the box, so claiming it would put an
unbounded variety of unrelated lines through a CARP matcher.

### UPnP / NAT-PMP mapping events (`miniupnpd`)

The `os-upnp` plugin's daemon logs under the RFC5424 APP-NAME `miniupnpd`. Five forms
are recognised, and all five are **failures or expiries** - see the warning below about
what is *not* here:

```text
<PRI>1 <timestamp> <host> miniupnpd <pid> - [meta sequenceId="<sequence>"] remove port mapping <external_port> UDP because it has expired
<PRI>1 <timestamp> <host> miniupnpd <pid> - [meta sequenceId="<sequence>"] could not find nat rule to delete iport=<internal_port> addr=<token>
<PRI>1 <timestamp> <host> miniupnpd <pid> - [meta sequenceId="<sequence>"] could not find redirect rule to delete eport=<external_port>
<PRI>1 <timestamp> <host> miniupnpd <pid> - [meta sequenceId="<sequence>"] Unauthorized to remove PCP mapping internal port <internal_port>, protocol UDP
<PRI>1 <timestamp> <host> miniupnpd <pid> - [meta sequenceId="<sequence>"] could not open lease file: <path>
```

They map onto `opnsense_log_events_upnp_total{event,result,protocol}` (plus the standard
`opnsense_instance` label) with fully closed values:

| Attribute | Closed values |
| --- | --- |
| `upnp.event` | `expired`, `cleanup_failed`, `unauthorized`, `lease_file_error` |
| `upnp.result` | `ok` (only for `expired`), `failure` |
| `upnp.protocol` | `tcp`, `udp`, or **empty** on the three forms that name no protocol |

`expired` is a mapping reaching the end of its lease and being torn down - the
lifecycle working. `cleanup_failed` means the daemon and pf disagree about which rules
exist. `unauthorized` is a PCP client trying to remove a mapping it does not own, which
the plugin's default `secure_mode` refuses.

!!! warning "There is no active-mapping count, and no successful add or delete"

    **No gauge of currently-active mappings is exported and none can be derived from
    this family.** The plugin's own status page lists mappings by running `pfctl`
    rather than exposing them through an API; an event stream cannot see mappings that
    already existed, and it cannot survive a daemon restart. `expired` is a decrement
    with no matching increment, so anything gauge-shaped built from it would drift
    negative without bound.

    **A successful add and a successful delete are also absent.** `miniupnpd` logs
    those at a verbosity `os-upnp` does not expose a setting for, so no captured
    grammar proves one. The daemon's request lines (`AddPortMapping:`, `redirecting
    port`, `DeletePortMapping:`, `removing redirect rule port`) and its
    `Returning UPnPError <code>: <text>` responses are deliberately **not** parsed: a
    request is not an outcome, and in a live capture a real add logged
    `AddPortMapping`, then `redirecting port`, then `Returning UPnPError 501: Action
    Failed`, having created no rule at all. `shutting down MiniUPnPd` and `Listening
    for NAT-PMP/PCP traffic on port <n>` are not parsed either - daemon lifecycle, not
    mapping lifecycle. All of them still ship as generic records with the body verbatim.

Ports ship on the record as `upnp.port.external` and `upnp.port.internal` alongside
`upnp.event`, `upnp.result` and `upnp.protocol`, and are deliberately **not** metric
labels - an ephemeral client port is unbounded and would mint a series per mapping. The
raw record is therefore the only place the *specific* mapping behind a failure can be
identified. The daemon's opaque `addr=` token and the lease-file path are not even
attributes: they stay in the message body.

Recognised on OPNsense `26.7.1_1` and `27.1.a_40` with `miniupnpd 2.3.9_2,1` /
`os-upnp 1.9`.

### PPPoE link and negotiation events (`ppp`)

`ppp` is mpd5, the dialler that brings a PPPoE WAN up. Every shape below was taken
from a real capture of a single link flap; nothing here is inferred from mpd's
documentation.

```text
<PRI>1 <timestamp> <host> ppp <pid> - [meta sequenceId="<sequence>"] [<link>] Link: UP event
<PRI>1 <timestamp> <host> ppp <pid> - [meta sequenceId="<sequence>"] [<bundle>] IPCP: state change Ack-Sent --> Opened
<PRI>1 <timestamp> <host> ppp <pid> - [meta sequenceId="<sequence>"] ppp-linkup: executing on <interface> for <af>
```

Thirteen `ppp.event` values are recognised: `link_up`, `link_down`, `iface_up`,
`iface_down`, `reconnecting`, `bundle_status`, `negotiation_state_change`,
`terminate_requested`, `session_established`, `session_closed`, `session_failed`,
`auth_success` and `address_assigned`. Alongside them a matching line carries
whichever of `ppp.bundle`, `ppp.link`, `ppp.interface`, `ppp.protocol`,
`ppp.state.previous`, `ppp.state.current`, `ppp.links_up`, `ppp.bandwidth_bps`,
`ppp.retry_attempt`, `ppp.retry_delay_seconds`, `ppp.address.local`,
`ppp.address.peer`, `ppp.address_family` and `ppp.error` the line stated.

Two details of the grammar are worth knowing, because both are places a
plausible-looking parser goes wrong:

LCP is always bracketed under the **link** (`opt7_link0`) while IPCP and IPV6CP are
bracketed under the **bundle** (`opt7`). That is mpd's own architecture — LCP
negotiates per physical link, the network-layer protocols per bundle, which may stack
several links — so the scope is decided by which protocol produced the line, not by
pattern-matching the bracketed name.

The `[<bundle>]   <x> -> <y>` shape carries **either** an address assignment **or** an
IPv6 interface-identifier pair (`9ab7:85ff:fe21:aff2 -> 9e89:1eff:fe2e:0000`). The two
are told apart by whether both sides parse as IP addresses; the identifier form has
four hex groups and no `::`, so it fails to parse and ships as a generic record with
no `ppp.address.*` attributes rather than as a fabricated address.

The CHAP authname, the `MESG:` circuit identifier and the link magic number are
subscriber-identifying and are **never** captured into an attribute. Only the
`LCP: authorization successful` outcome is parsed. A test walks every attribute value
looking for the authname and fails if it appears.

No derived counter yet. A link-flap rate is the obvious follow-up, but the three
layers (Link, LCP, IPCP) each report a state change for one physical event, so a naive
counter would treble every flap.

### Alias and table maintenance (`firewall`)

The program name is misleading and the mistake it invites is worth stating plainly:
`firewall` is OPNsense's **alias and table maintenance** logger, not packet filtering.
Packet filtering logs under `filterlog` and is parsed separately.

```text
<PRI>1 <timestamp> <host> firewall <pid> - [meta sequenceId="<sequence>"] resolving <n> hostnames (<m> addresses) for <alias> took <seconds> seconds
<PRI>1 <timestamp> <host> firewall <pid> - [meta sequenceId="<sequence>"] fetch alias url <url> (bytes: <n>)
<PRI>1 <timestamp> <host> firewall <pid> - [meta sequenceId="<sequence>"] processing alias url <url> took <seconds>s
```

Five `alias.event` values are recognised: `resolved`, `fetched`, `processed`,
`geoip_updated` and `archive_detected`. Matching lines carry whichever of
`alias.name`, `alias.hostnames`, `alias.addresses`, `alias.duration_seconds`,
`alias.url`, `alias.bytes`, `alias.lines`, `geoip.files` and `geoip.lines` applies.

The `fetch` grammar reports **either** a byte count **or** a line count depending on
the payload, and only the one present is emitted — a text list reports lines, a JSON
or archive body reports bytes.

Note that the two duration forms differ: `resolving ... took 0.08 seconds` has a space
and the full word, while `processing ... took 0.14s` has neither. They come from
different subsystems and are matched by separate grammars; a test pins them apart,
because conflating them is the natural bug here. Both are emitted as the bare number
of seconds exactly as it appeared on the wire, with no unit conversion.

This is where a slow or failing alias URL becomes visible. A URL is an
operator-configured value and is kept in full as structured metadata; it is never a
metric label.

### Certificate lifecycle (`acme.sh` and the ACME plugin)

Two programs feed one parser. The OPNsense ACME plugin logs its own lifecycle under
the catch-all program `opnsense`, and the `acme.sh` client logs its progress under
`acme.sh`. Records from the two are told apart by `cert.source`, which is `plugin` or
`acme.sh`.

```text
<PRI>1 <timestamp> <host> opnsense <pid> - [meta sequenceId="<sequence>"] AcmeClient: successfully issued/renewed certificate: <domain>
<PRI>1 <timestamp> <host> acme.sh <pid> - [meta sequenceId="<sequence>"] [<client timestamp>] Cert success.
```

**`opnsense` is a catch-all**: every OPNsense PHP log line on the box arrives under
it, not just the ACME plugin's. The parser therefore refuses anything outside a
captured `AcmeClient: ` shape, exactly as the kernel grammars do, so unrelated PHP
lines still degrade to generic records. Loosening that match would relabel every PHP
log line on the box as certificate activity.

Recognised `cert.event` values are `renewal_not_required`, `renewal_required`,
`issue_started`, `issue_succeeded`, `config_wiped`, `removal_failed`,
`account_registered`, `ca_imported`, `ca_selected`, `challenge_type_selected`,
`challenge_added`, `challenge_removed`, `validation_pending`, `validation_succeeded`,
`signing_started`, `cert_downloaded`, `cert_installed`, `domain_skipped` and
`shell_command`. Alongside them a line may carry `cert.domain`, `cert.ca`,
`cert.challenge_type`, `cert.challenge_domain`, `cert.result`, `cert.exit_code`,
`cert.attempt` and `cert.attempt_max`.

There is deliberately **no `issue_failed`**: no failure has been captured from a real
box, and inventing a grammar for one would pin a shape upstream may never produce. It
should be added from a real capture when one occurs.

The `acme.sh` lines are prefixed with the client's own bracketed local timestamp. It
is stripped and never emitted — the syslog envelope already carries the record's time,
and a second, differently-formatted, differently-zoned time would only be a trap.

These lines carry secrets, and several are handled by refusing to match them at all:
the ACME account thumbprint, the `Le_OrderFinalize=` and `Le_LinkCert=` order URLs,
and every filesystem path to a private key produce no attributes whatsoever. On the
TXT challenge lines the challenge **domain** is captured but the challenge **value**
is matched non-capturing and discarded. A test asserts that the thumbprint and a TXT
value never appear in any attribute across the whole captured corpus.

### DNS blocklist and service lifecycle (`unbound`)

Beyond the local-zone query log and SERVFAIL lines documented above, the DNSBL
subsystem and unbound's own start/stop are parsed.

```text
<PRI>1 <timestamp> <host> unbound <pid> - [meta sequenceId="<sequence>"] [<pid>:<thread>] info: dnsbl_module: blocklist loaded. length is <n>
<PRI>1 <timestamp> <host> unbound <pid> - [meta sequenceId="<sequence>"] blocklist parsing done in <seconds> seconds (<n> records)
```

Seven `dnsbl.event` values are recognised: `blocklist_updating`, `blocklist_loaded`,
`blocklist_parsed`, `pipe_opening`, `pipe_opened`, `pipe_closed` and
`backend_missing`. The start/stop pair emits `dns.event` (`service_started` or
`service_stopped`) with `dns.version`.

`dnsbl.entries` is emitted for **both** the `blocklist loaded. length is <n>` and the
`blocklist parsing done ... (<n> records)` lines. They report the same quantity by two
routes, and a consumer should not have to know which line it came from.
`dnsbl.parse_duration_seconds` comes from the parsing-done line.

Note that the parsing-done line carries **no** `[<pid>:<thread>]` prefix while the
`dnsbl_module:` lines do. That asymmetry is real and is pinned by a test. Where the
prefix exists, only the thread number is kept as `unbound.thread`; the pid changes on
every restart and carries no operational meaning.

The multi-line statistics dump — `server stats for thread <n>`, the recursion
histogram, the percentile line and the `lower(secs) upper(secs) recursions` header —
is deliberately **not** parsed. Its shape varies per thread, and half-parsing a
multi-line report yields records that look complete and are not.

**These metrics answer different questions and are easy to confuse.**
`opnsense_unbound_dns_dnsbl_blocklist_size` is the number of entries currently loaded
in unbound's DNSBL module. `opnsense_unbound_dns_blocklist_enabled` reports whether
any DNSBL **policy** is enabled in OPNsense's own Unbound configuration. A box whose
blocklist is populated by a third-party plugin — Q-Feeds, for instance — will report a
large size alongside `blocklist_enabled=0`, because the plugin loads the list into the
module without going through core's blocklist configuration. That combination is not a
bug in either metric; it means core Unbound has no blocklist selected and no policy,
and what is loaded got there another way.

### FreeRADIUS access outcomes and credential handling

OPNsense `27.1.a_40` with `os-freeradius 1.10.2` emits authentication outcomes
under the RFC5424 APP-NAME `radiusd`. The captured normal-service forms are
`Login OK` and `Login incorrect`. They become:

| Attribute | Closed values |
| --- | --- |
| `radius.event` | `access` |
| `radius.result` | `accepted`, `rejected` |
| `radius.client_scope` | `configured` |

The corresponding counter is
`opnsense_log_events_radius_total{event,result,client_scope}` (plus the standard
`opnsense_instance` label). Usernames and the configured RADIUS client name are
not attributes or labels.

FreeRADIUS is a stricter confidentiality boundary than the other syslog parsers.
For every `radiusd` frame, the exporter replaces the original hostname, PID,
structured data and message before parser dispatch, generic enrichment, debug
capture, shape-key calculation, metric derivation, sampling or queue admission.
Recognised access outcomes become fixed code-defined messages. Any other
`radiusd` message becomes a fixed sanitized generic record and is not counted.
A malformed RFC5424 or RFC3164 frame with a recognizable `radiusd` program token
also fails closed to that safe generic record. This prevents an enabled
FreeRADIUS password-log option from reaching the raw generic or debug-capture
paths.

Configure the plugin and target manually on OPNsense:

1. In the FreeRADIUS general settings, select `syslog` as the log destination
   and enable authentication-request logging.
2. Leave both accepted-password (`auth_goodpass`) and rejected-password
   (`auth_badpass`) logging disabled.
3. Add an OPNsense syslog Target for program `radiusd` pointing at the exporter's
   syslog listener.

The exporter does not create that Target or write firewall rules.

Normal Accounting Start, Interim-Update and Stop requests returned
Accounting-Response in the capture but emitted no syslog records. Accounting
therefore remains unsupported and is not inferred from request traffic.

### IPsec and OpenVPN tunnel lifecycle events

The `vpn` family counts tunnel lifecycle transitions for both VPN backends, from
`charon` (IPsec) and from the per-instance `openvpn_*` programs. Its vocabularies are
closed and resolved in code:

| Label | Closed values |
| --- | --- |
| `backend` | `ipsec`, `openvpn` |
| `event` | `established`, `terminated`, `authentication_failed`, `liveness_failed`, `certificate_failed` |
| `result` | `success` (established, terminated), `failure` (the three failure events) |

`connection` is the fourth label and the only one that is not code-defined. It is the
**configured name** of the IPsec connection or OpenVPN instance, resolved from the id
in the log line against the inventory the exporter already fetches for its IPsec and
OpenVPN collectors (the same enrichment that adds `ipsec.connection` /
`openvpn.instance` to every record). It is **empty when the id could not be resolved**,
and it is never the raw UUID.

**`connection` is populated for IPsec and is ALWAYS EMPTY for OpenVPN. That is by
design, not a fault.** Read this before reporting an empty label as a bug:

- **IPsec: populated.** Every captured `charon` line carries the connection id, so the
  label resolves whenever the tunnel is still in the fetched inventory. It is empty
  only for a tunnel deleted since the last inventory refresh, or before the first
  refresh completes.
- **OpenVPN: always empty.** None of the four captured OpenVPN lines contains the
  instance id — OpenVPN prints it only on its `MANAGEMENT: Client connected from
  /var/etc/openvpn/instance-<uuid>.sock` line, which is not one of the four shapes
  this family parses. There is therefore nothing on those lines to resolve, and the
  label will never populate.
  **Operator workaround:** attribute those events using the `program` attribute on the
  raw log record (`openvpn_server40`, `openvpn_client2`), which names the instance.
  Nothing is inferred from the program-name suffix: the exporter's OpenVPN instance
  inventory has no numeric key to match `40` against, so guessing would be a
  fabrication rather than a resolution.

#### Recognised grammar

Only the grammar captured on an isolated testbed running OPNsense `27.1.a_40` with
strongSwan `6.0.7` and the OpenVPN **server** package `2.7.5` is counted. The shapes,
with every value replaced by a placeholder:

```text
charon:  <thread>[<tag>] <<connection-id>|<n>> generating IKE_AUTH response <n> [ N(AUTH_FAILED) ]
charon:  <thread>[<tag>] <<connection-id>|<n>> IKE_SA <id>[<n>] established between <local>[<local-id>]...<remote>[<remote-id>]
charon:  <thread>[<tag>] <<connection-id>|<n>> giving up after <n> retransmits
charon:  <thread>[<tag>] <<connection-id>|<n>> IKE_SA deleted

openvpn: <peer-context> [<common-name>] Peer Connection Initiated with [AF_INET]<address>:<port>
openvpn: <peer-context> SENT CONTROL [<common-name>]: 'AUTH_FAILED' (status=<n>)
openvpn: <peer-context> VERIFY ERROR: depth=<n>, error=<error text>
openvpn: <peer-context> SIGUSR1[soft,ping-restart] received, client-instance restarting
```

The strongSwan `<thread>` number and `<tag>` subsystem vary line to line and are not
anchored on. Mapping: `N(AUTH_FAILED)` in a **generated** `IKE_AUTH` response is
`authentication_failed`; `IKE_SA … established between …` is `established`; `giving up
after N retransmits` is `liveness_failed`; `IKE_SA deleted` is `terminated`. On the
OpenVPN side `Peer Connection Initiated with` is `established`, `'AUTH_FAILED'` is
`authentication_failed`, a `VERIFY ERROR:` in OpenVPN's `depth=<n>, error=<text>` form
is `certificate_failed`, and the `ping-restart` SIGUSR1 is `terminated`.

Three points of tolerance, so the recognised set is neither narrower nor wider than it
looks:

- `N(AUTH_FAILED)` is counted wherever it appears in the response's payload list, not
  only when it is the sole notify. Only **generated** responses count — the box
  rejecting a peer. The initiator-side `parsed IKE_AUTH response … N(AUTH_FAILED)`
  (the far end rejecting *our* credentials) is a different event, was not captured, and
  is deliberately not counted.
- `certificate_failed` matches OpenVPN's format string, so expired, revoked and
  depth-N rejections all count as the same event class. A line that merely mentions
  the words does not.
- `[AF_INET6]` is accepted alongside the captured `[AF_INET]`, derived from OpenVPN's
  own address-family tag rather than from a capture, so an IPv6 peer's establishment is
  not silently uncounted.

#### What is deliberately not counted

**Anything else, including every stable-release form.** A read-only search of a
production OPNsense `26.7.1_1`'s retained logs found zero usable lifecycle or failure
records, so no stable-release grammar exists to parse and none is inferred from the
development formats. Unmatched and version-new lines still **ship in full as generic
records with the body verbatim**, and still appear in the debug capture as unmodelled
signal — they are simply not counted as a transition the exporter did not witness.

These lines were captured for real and are deliberately left generic:

| Line | Why it is not an event |
| --- | --- |
| `SIGUSR1[soft,tls-error] received, client-instance restarting` | A control-channel failure, often for a session that never established. Counting it as `terminated` would mint terminations with no matching `established`. |
| `SIGTERM[soft,delayed-exit] received, client-instance exiting` | The instance being shut down by an administrator, not the peer going away. |
| `TLS Error: TLS handshake failed` / `TLS Error: TLS object -> incoming plaintext read error` | Companions to the rejection `VERIFY ERROR:` already counts; counting them too would report three failures for one rejected client. |
| `Inactivity timeout (--ping-restart), restarting` | The first of the two lines OpenVPN logs for one ping-restart. The SIGUSR1 line is the second, and exactly one of the pair may be counted. |
| IPsec CHILD_SA establishment, rekeys, DPD probes, individual retransmits, `deleting IKE_SA` | Not part of the captured lifecycle vocabulary; rekey and daemon shutdown were explicitly excluded from it. |

#### Identity handling

The captured lines carry usernames, certificate subjects and serials, IKE identities,
peer addresses and ports. The parsers extract **none** of them: the only attributes
they add are `vpn.backend`, `vpn.event` and `vpn.result`. Those values stay in the
record **body**, which ships verbatim exactly as it did before this family existed, so
an investigation still has the detail while the metric stays bounded and non-identifying.

A matched line keeps everything it had while it was generic: the `peer.*` address
resolution, the interface resolution, the tunnel-id resolution and the verbatim body
are all still there, with the VPN attributes added on top. Structured parsers normally
skip the address scan — a parser that reports its own source and destination would
otherwise report them twice — but these two extract no address at all, so the scan
still runs for them and no existing query on `peer.*` for `charon` or `openvpn_*` lines
changes behaviour.

Because the counters already carry the totals, you can **stop shipping the raw lines
they count** and keep only the ones worth reading. That is `--logs.syslog.sample` (off
by default):

```bash
--logs.syslog.sample     # keep firewall block/reject and HAProxy errors, drop the rest
```

With sampling on, the receiver keeps firewall `block`/`reject` lines and drops the
passes, keeps HAProxy state changes and errors and drops per-connection noise, and
keeps every low-volume program (sshd, DHCP, audit, IDS, gateway, RADIUS and the VPN
lifecycle events) in full.
A line is only ever dropped **after** its metric has been counted, so the counters
stay complete even though the log stream is not. Sampling requires the `log_events`
collector to be on (the exporter refuses to start otherwise), because counting first
is the whole point.

Every shipped line then carries a `sampled="true"` attribute so a consumer knows the
stream is incomplete and must use the counters for totals. Turn that stamp off with
`--logs.syslog.sampled-attribute=false` if you would rather not have it.

### WireGuard, Tailscale and NetBird tunnel lifecycle attributes

`wireguard`, `tailscaled` and `/usr/local/bin/netbird` lines also carry `vpn.backend`,
`vpn.event` and `vpn.result`, so the dashboard's **Tunnel lifecycle** annotation layer
marks them the same way it marks IPsec and OpenVPN. They are **not counted into
`opnsense_log_events_vpn_total`**: that counter's `backend` label stays `ipsec` or
`openvpn`, and its `connection` label is resolved from an IPsec or OpenVPN id that
these lines do not contain. The records are unaffected, and because they are not
counted, sampling never drops them.

The granularity is different and it matters when you read a marker: these are
**service-level** events for a tunnel instance or for the whole node, never per peer.

| Program | Line | `vpn.event` |
| --- | --- | --- |
| `wireguard` | `wireguard instance <name> (<dev>) started` | `established` |
| `wireguard` | `wireguard instance <name> (<dev>) stopped` | `terminated` |
| `wireguard` | `wireguard instance <name> (<dev>) switching to UP` (CARP promotion) | `established` |
| `wireguard` | `wireguard instance <name> (<dev>) switching to DOWN` (CARP demotion) | `terminated` |
| `tailscaled` | `Switching ipn state <from> -> Running (WantRunning=…, nm=…)` | `established` |
| `tailscaled` | `Switching ipn state Running -> <to> (WantRunning=…, nm=…)` | `terminated` |
| `tailscaled` | `Destroying <dev> adapter` (the rc script's service-stop teardown) | `terminated` |
| `/usr/local/bin/netbird` | `Netbird engine started, the IP is: <addr>` | `established` |
| `/usr/local/bin/netbird` | `stopped NetBird client` | `terminated` |

`vpn.result` is always `success`: none of these app-names states an authentication,
certificate or liveness verdict.

Four things to know before expecting these to appear:

- **WireGuard's per-peer handshakes are not events, and they are not even here.** They
  come from the FreeBSD kernel driver, so they arrive under program `kernel`, and they
  are behind the per-instance **Debug Log** flag, which is off by default. They also
  repeat roughly every two minutes for a *healthy* peer, and there is no
  "handshake completed" line at all — so the tunnel-up edge is not expressible from
  them, and treating them as one would paint the dashboard with markers. The exporter's
  WireGuard **peer** handshake data comes from the API poll lane instead.
- **Tailscale's own log is not routed to syslog on a stock box.** The FreeBSD rc script
  runs `tailscaled` under `daemon(8)` and only forwards its output to syslog when
  `tailscaled_syslog_output_enable="YES"`, which defaults to NO and which the OPNsense
  plugin does not set. Until you set it (in `/etc/rc.conf.local`, which survives
  OPNsense's config regeneration), the only line you will see is the service-stop
  teardown. The two never double-count one event: a `service tailscaled stop` produces
  no ipn state line, and `tailscale down` produces no teardown line.
- **NetBird's app-name is a PATH, not a program name, and that is not a typo above.**
  The daemon passes an empty syslog tag, Go's `log/syslog` substitutes `argv[0]`, and
  the rc script starts it as `/usr/local/bin/netbird` — so that is what arrives on the
  wire, confirmed against an enrolled box. If you filter your own log pipeline by
  program name, `netbird` matches only the rc script's service-start notice; the
  daemon's several thousand lines a day are under the path.
- **NetBird's markers are the ENGINE, and its per-peer lines are deliberately not
  events.** `client/internal/lazyconn` closes and reopens an idle peer on a 15-minute
  inactivity threshold, and whether it does so at all is decided by a **server-side
  management feature flag** the firewall cannot see, so `peer connection closed` means
  different things on different tenants and the log cannot tell them apart. The engine
  pair above is immune to that: both lines come from one function, and the terminated
  line sits strictly downstream of the established one, so a teardown marker can never
  appear without a matching bring-up. Note also that `starting`/`stopped NetBird
  service` are the **daemon process**, not the overlay — an unenrolled box logs those
  all day and never establishes a tunnel — and `stopped Netbird Engine` is logged
  **twice** per teardown from two call sites upstream. Neither is an event here.

## TLS transport (optional)

The receiver can take syslog over TLS in addition to (or instead of) plain UDP/TCP -
OPNsense's `tls4`/`tls6` transports. It matters when the firewall ships across an
untrusted segment; on a LAN-local link it is unnecessary.

```bash
opnsense2otel \
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
| `audit`, `configd.py`, `config` | `config_user`, `config_revision`, `config_uri` (who changed the config), plus configd authorisation and RPC events. `config` adds the config-apply event itself: `config.event`, `config.backup_path`, `config.version`. **`configctl` is deliberately NOT parsed** - it re-emits the same line inside a second envelope, so structuring it too would double-count every config change. `configd.py` template-regeneration chatter stays generic. |
| `sshd`, `sshd-session` | `auth.result` (accepted/failed/invalid-user), `auth.user` (also as the semconv `user.name`), `auth.method`, key fingerprint, source address. A failed login is raised to **warning** - sshd logs a rejected login at the same severity as a successful one, and you should not have to know that to find it. |
| `dhcpd`, `dnsmasq`, `dnsmasq-dhcp`, `kea-dhcp4`, `kea-dhcp6`, `dhcrelay` | `dhcp.action`, `dhcp.ip`, `dhcp.mac`, `dhcp.hostname`, `dhcp.lease_seconds` - **normalised across every backend**, so you can query DHCP activity without caring which one your box runs |
| `dhclient` | This firewall's **own WAN DHCP client** lease lifecycle (#541) - not the LAN DHCP servers above: `dhcp_client.type`, `dhcp_client.interface`, `dhcp_client.server`, `dhcp_client.address`, `dhcp_client.lease.*` timestamps, `dhcp_client.script.reason`. |
| `dhcp6c` | This firewall's **own WAN DHCPv6 client and delegated-prefix** lifecycle (#546): `dhcp6c.event`, `dhcp6c.type`, `dhcp6c.direction`, `dhcp6c.interface`, `dhcp6c.prefix`, `dhcp6c.prefix_length`, `dhcp6c.address`, plus prefix/address lease timestamps. |
| `haproxy` | Server **UP/DOWN** health transitions and "backend has no server available" (severity-mapped), plus per-connection frontend/mode. HTTP fields use OTel semconv names: `http.request.method`, `http.response.status_code`, `url.path`, `network.protocol.version`. |
| `dpinger` | Gateway monitor transitions `none -> down` and `down -> none`, with the observed address, alarm state and probe values. Plus **watcher lifecycle**: `watcher_started` (carrying the configured `gateway.latency_alarm_ms` / `gateway.loss_alarm_percent` thresholds), `watcher_stopped` and `watcher_reloaded`. Those matter because a dpinger restart clears the alarm state - without them an apparent recovery is indistinguishable from a real one. Reading the thresholds back also shows when they are `0`, which means a latency alarm **cannot fire on that box at all**. Nonmatching `dpinger` lines remain generic records. |
| `radiusd` | FreeRADIUS access accepted/rejected with closed non-PII attributes. Every unsupported or malformed recognizable `radiusd` form is sanitized before it becomes a generic record or debug capture. |
| `unbound` | Local-zone query log, only when Unbound's `log-local-actions: yes` is set: `dns.query_name`, `dns.query_type`, `dns.query_class`, `dns.local_zone`, `dns.local_action`, resolved `src.*`; plus SERVFAIL failures as `dns.error`/`dns.upstream`/`dns.error_zone`. **No blocklist match, policy, resolution source or DNSSEC status** - that stays poll-lane-only, see [Unbound](log-shipping.md#unbound-per-query-dns-log). Cache maintenance and DNSBL/plugin chatter stay generic records. |
| `kernel` | FreeBSD CARP transitions: `carp.event`, `carp.state.previous`, `carp.state.current`, `carp.interface`, `carp.vhid`, `carp.reason`, `carp.demotion.delta`, `carp.demotion.total`. Plus **promiscuous-mode toggles**: `kernel.event` (`promiscuous_enabled`/`promiscuous_disabled`) and `interface.device` - an interface entering promiscuous mode is what packet capture looks like from the outside, and it was previously invisible. **Every other kernel line stays a generic record** - link state, watchdogs, ZFS, USB and the rest are not claimed. |
| `miniupnpd` | UPnP/NAT-PMP mapping expiries and failures: `upnp.event`, `upnp.result`, `upnp.protocol`, `upnp.port.external`, `upnp.port.internal`. **No successful add or delete, and no active-mapping count** - see above. Request, response and daemon-lifecycle lines stay generic records. |
| `charon`, `openvpn_*` | IPsec and OpenVPN tunnel lifecycle: `vpn.backend`, `vpn.event`, `vpn.result` and nothing else - no username, certificate subject, IKE identity, address or port is extracted. `openvpn_*` is matched by PREFIX because OPNsense names one program per configured instance. Only the captured grammar above is parsed; everything else stays a generic record. |
| `wireguard`, `tailscaled`, `/usr/local/bin/netbird` | The same three `vpn.*` attributes, at **service** granularity rather than per peer: a WireGuard instance started/stopped/switched by CARP, this node's own Tailscale ipn state entering or leaving `Running`, and the NetBird engine coming up with an overlay address or its connect loop finishing teardown. NetBird's app-name is `argv[0]`, not `netbird` - see below. **Not counted** into `opnsense_log_events_vpn_total` - see [WireGuard, Tailscale and NetBird tunnel lifecycle attributes](#wireguard-tailscale-and-netbird-tunnel-lifecycle-attributes). No instance name, device, node key, peer or overlay address is extracted. |
| `suricata` | Suricata EVE **alerts only**, when the `syslog_eve` setting is forwarding them: `event_type`, `signature`, `alert_sid`, `alert_action`, `alert_category`, `alert_severity`, resolved `src`/`dest` endpoints. See [Suricata alerts](#suricata-alerts-pick-one-path) below. Non-JSON `suricata` lines (engine text) stay generic. |
| `cron`, `/usr/sbin/cron` | `cron.user`, `cron.action` (`cmd`/`mail`), `cron.command` (CMD lines only, never set for MAIL). |
| `radvd` | `radvd.event` (`polling`/`timer`), `interface`, `interface.name`, `radvd.interval_seconds` (polling lines only). |
| `syslog-ng` | The firewall's own log daemon, which is how the box reports that **our feed dropped**: `syslogng.event` (`connection_established`/`connection_closed`/`connection_broken`/`eof`/`child_exited`/`read_error`/`statistics`), `syslogng.fd`, `dst.ip`/`dst.port`, and from the statistics line only `syslogng.dropped_total` and `syslogng.truncated_total`. Deliberately narrow: the statistics line carries dozens of per-destination counters and none of them are fanned out. Configuration-reload lines stay generic. |
| `DhcpLFC`, plus Kea LFC lines from `kea-dhcp6` | Kea's lease-file cleanup: `kea.msg_id`, `kea.component`, and on the read/write stats lines `kea.lfc_leases`, `kea.lfc_attempts`, `kea.lfc_errors`, `kea.lfc_phase`. This was the single largest source of unattributed syslog volume on a live box. Note `DhcpLFC` is CamelCase, so the `kea-` prefix rule does not reach it. |
| `rule-updater.py` | Suricata **ruleset freshness**, which no metric exposes: `ids.event` (`ruleset_downloaded`, `ruleset_version`, `ruleset_skipped`, and the failure verbs), `ids.ruleset_url`, `ids.ruleset_version`, `ids.http_status`. The ruleset URL is operator-supplied and unbounded, so it is structured metadata only and never a label. |
| `sudo` | Privilege escalation: `auth.result` (`allowed`/`failed`), `auth.user`, `auth.target_user`, `auth.command`, `auth.pwd`, `auth.tty`. **`auth.command` is the command line verbatim, arguments included** - a password typed as an argument is logged by sudo itself and ships either way, so structuring it changes how you query it, not who can see it. Like every attribute here it is structured metadata and never a metric label. |

**Every record**, structured or generic, also gets:

- an `opnsense.subsystem` attribute (`opnsense_subsystem` in Loki) with a value like `firewall`, `auth`, `dhcp`, `ipsec`, `vpn`, `upnp`, `proxy`, `routing` or `ups`, so you can select a whole class of events without enumerating program names;
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

Every other program OPNsense routes through syslog-ng - the bare `configd` daemon (as
opposed to `configd.py`'s authorisation/RPC lines, parsed above), routing daemons
(`bgpd`, `ospfd`, `zebra`), `netbird` (the rc script's app-name, which carries only a
service-start notice; the daemon's own lines are parsed under `argv[0]` as above),
package installs, `su`, `sudo`, and a catch-all for everything else - ships as a generic
record with its raw body and its envelope attributes.

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
{service_name="opnsense2otel", service_instance_id="opnsense"}
  | opnsense_subsystem="firewall" | action="block" | src_scope="remote"
```

A record, as it lands:

```json
{
  "action": "pass", "direction": "in",
  "interface": "pppoe0", "interface_name": "WAN2",
  "rule_description": "[WAN2] Allow inbound ICMP (monitors)",
  "rule_id": "7ed3ec06-ecf8-4ca8-9a2a-bb346967850f",
  "src_ip": "203.0.113.55", "src_scope": "remote",
  "dst_ip": "198.51.100.23", "dst_scope": "self",
  "protocol": "icmp", "ip_version": "4", "network_type": "ipv4",
  "opnsense_source": "syslog", "opnsense_subsystem": "firewall"
}
```

Useful starting points:

```logql
{service_name="opnsense2otel"} | opnsense_subsystem="audit"                    # who changed the config
{service_name="opnsense2otel"} | opnsense_subsystem="auth" | auth_result="failed"
{service_name="opnsense2otel"} | opnsense_subsystem="firewall" | action="block" | dst_scope="self"
{service_name="opnsense2otel"} | program="filterlog" | src_hostname="WINSRV"
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

- **Blocklist/policy/DNSSEC DNS detail** (`--logs.unbound.enabled`) - the syslog
  `unbound` parser structures Unbound's local-zone query log (query name/type/class,
  matched local-zone, resolved client) and SERVFAIL failures, but blocklist match,
  policy, resolution source and DNSSEC status come only from OPNsense's reporting
  database, which only the poll lane reads. See [What you get](#what-you-get) above.
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
