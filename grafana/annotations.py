"""Generated event-annotation contract for the operational dashboard (#421).

An operational graph shows a discontinuity; it does not say why. This module is the
shared timeline that answers that: a reboot, a config change, an interface counter
reset, a CARP failover, a gateway alarm, a threat-feed update. The motivating case
is the cheapest one to get wrong by hand — a new firewall rule starts dropping
traffic, every rate panel steps down, and nothing on the dashboard connects the two.

## How the marker gets placed at the right instant

Two mechanisms, deliberately not one:

* **Prometheus, value-as-time.** For a metric whose VALUE is an instant
  (`opnsense_system_config_last_change`), Grafana's `useValueForTime` places the
  marker at the value rather than at the sample. `* 1000` because Grafana reads the
  value as epoch milliseconds, and `> $__from < $__to` because without it every
  historical event of a months-old metric renders on a six-hour window. The idiom
  is lifted from Grafana's own node_exporter integration dashboard as deployed on
  the live stack, not from documentation.

  This is why `opnsense_system_boot_timestamp_seconds` was added rather than
  reusing `time() - opnsense_system_uptime_seconds`: a derived instant is
  recomputed on every evaluation, and a live one-hour query produced two inferred
  epochs a second apart, so the reboot marker would shuffle between refreshes.

* **Loki, real record timestamp.** For an event that was logged, the shipped record
  already carries the RFC5424 timestamp of the event itself, which beats any
  observation of its after-effects. Used where the log also carries detail no
  metric can (which admin, which API endpoint, which gateway).

## Why `step` is left to Grafana's default

A fixed coarse `step` is the obvious way to stop one long-lived gauge value
producing a marker per sample. It is rejected here because it silently drops
events: the live box emitted two `config_change` records inside the same second,
and any step above that resolution keeps one and loses the other. Duplicate
markers at one instant collapse visually; a missing config change is a wrong
answer to the question the annotation exists to answer.

## Degradation

There is no `conditionalRendering` for annotations, and none is needed: a disabled
collector or an unshipped log source produces no series, and a query with no series
produces no annotation. Absent, not noisy — which is the acceptance criterion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from builder import loki_sel, sel


@dataclass(frozen=True)
class Annotation:
    """One annotation layer. `why` is part of the contract, not a comment: the
    catalogue is a set of judgement calls about what is worth interrupting a graph
    for, and tests/test_annotations.py fails an entry that does not state its."""

    name: str
    group: str                      # prometheus | loki | grafana
    title: str
    expr: str
    why: str
    color: str
    enable: bool = True
    tag_keys: tuple = ()
    text: str = ""
    value_as_time: bool = False
    metrics: tuple = field(default=())
    # Where this layer's toggle renders (#470). False puts it in the v2 controls
    # menu; True spends a slot on the always-visible toolbar, which sixteen layers
    # cannot all have — see TOOLBAR_LAYERS.
    on_toolbar: bool = False


# Observation-time Prometheus annotations — an entry here says "the marker is
# placed where the change was OBSERVED, not when it happened", which on the cold
# poll tier can be fifteen minutes late. Empty by design: every current Prometheus
# annotation is value-as-time. A future entry needs the delay named in its reason.
OBSERVATION_TIME_ANNOTATIONS: dict = {}


def observation_time_is_deliberate(name: str) -> bool:
    return name in OBSERVATION_TIME_ANNOTATIONS


# ---- toolbar vs controls menu (#470) -------------------------------------
# Sixteen annotation toggles plus two dashboard links pushed the controls area to
# THREE rows above the tab bar, on every tab, before any data — caught by rendering
# the published dashboard, not by reading the manifest. Schema v2 has
# `placement: "inControlsMenu"` for this, and Grafana 13 / v2 is the only supported
# target, so it is used unconditionally.
#
# The toolbar is for layers an operator toggles WHILE reading a graph, and these
# three are the reason the feature exists: a rate panel steps because the box
# rebooted, because the configuration changed, or because one interface's counters
# reset. Everything else is context you want on by default and rarely switch, or is
# default-off — and a layer nobody has enabled is the last thing worth a toolbar slot.
TOOLBAR_LAYERS = {"Reboot", "Config change", "Interface counter reset"}


# ---- the catalogue -------------------------------------------------------

_IFACE_RESET = (
    # boottime is one series per appliance and the reset marker is one per
    # interface, so the join is many-to-one with the interfaces on the many side;
    # group_right() keeps interface/device on the result so they can be tagged.
    f'({sel("opnsense_system_boot_timestamp_seconds")} + on(opnsense_instance) group_right() '
    f'{sel("opnsense_interfaces_attach_or_statistics_reset_uptime_seconds")})'
)

ANNOTATIONS: list = [
    Annotation(
        name="Reboot",
        group="prometheus",
        on_toolbar=True,
        title="Firewall rebooted",
        expr=f'{sel("opnsense_system_boot_timestamp_seconds")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="light-yellow",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_system_boot_timestamp_seconds",),
        why="A reboot resets every counter on the box at once, so it is the single "
            "most common cause of a whole-dashboard discontinuity being read as an "
            "outage. Taken from the API's boottime rather than derived from uptime.",
    ),
    Annotation(
        name="Config change",
        group="prometheus",
        on_toolbar=True,
        title="Configuration changed",
        expr=f'{sel("opnsense_system_config_last_change")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="light-blue",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_system_config_last_change",),
        why="The headline case: a rule or interface change lands, traffic shifts, and "
            "the graph alone cannot distinguish 'someone changed something' from 'the "
            "network broke'. Available with no log shipping, which is why this rather "
            "than the richer audit-log layer is the default-on one.",
    ),
    Annotation(
        name="Interface counter reset",
        group="prometheus",
        on_toolbar=True,
        title="Interface attached or counters reset",
        expr=f"{_IFACE_RESET} * 1000 > $__from < $__to",
        value_as_time=True,
        color="light-orange",
        tag_keys=("opnsense_instance", "interface", "device"),
        metrics=("opnsense_system_boot_timestamp_seconds",
                 "opnsense_interfaces_attach_or_statistics_reset_uptime_seconds"),
        why="A per-interface counter reset makes one interface's rate panels drop to "
            "zero and climb again while every other interface looks fine — the "
            "hardest discontinuity on the dashboard to attribute without a marker. "
            "The kernel does not distinguish an attach from an explicit reset.",
    ),
    Annotation(
        name="Boot environment created",
        group="prometheus",
        title="Boot environment created (upgrade)",
        expr=f'{sel("opnsense_snapshots_active_created_timestamp_seconds")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="purple",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_snapshots_active_created_timestamp_seconds",),
        why="An OPNsense upgrade creates the boot environment it then boots into, so "
            "this marks the upgrade itself rather than the reboot that followed it. "
            "It is the annotation that explains behaviour changing across a version.",
    ),
    Annotation(
        name="Certificate renewed",
        group="prometheus",
        title="ACME certificate issued or renewed",
        expr=f'{sel("opnsense_acme_certificate_last_update_timestamp_seconds")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="green",
        tag_keys=("opnsense_instance", "name"),
        metrics=("opnsense_acme_certificate_last_update_timestamp_seconds",),
        why="A renewal reloads the services presenting the certificate, so HAProxy, "
            "nginx and captive-portal metrics can step at exactly this instant for a "
            "reason that has nothing to do with traffic.",
    ),
    Annotation(
        name="GeoIP database updated",
        group="prometheus",
        title="GeoIP database updated",
        expr=f'{sel("opnsense_firewall_geoip_last_update_timestamp_seconds")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="dark-blue",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_firewall_geoip_last_update_timestamp_seconds",),
        why="Country-based rules change what they match the moment the database "
            "changes, with no configuration change to point at. A block-rate step "
            "here is the update, not an attack.",
    ),
    Annotation(
        name="nginx config reloaded",
        group="prometheus",
        title="nginx configuration reloaded",
        expr=f'{sel("opnsense_nginx_config_load_timestamp_seconds")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="dark-green",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_nginx_config_load_timestamp_seconds",),
        why="A reload zeroes nginx's vts counters, so its request-rate panels restart "
            "from nothing. Without the marker that reads as the web front end having "
            "stopped serving.",
    ),
    Annotation(
        name="Public IP updated",
        group="prometheus",
        title="DynDNS updated the public address",
        expr=f'{sel("opnsense_dyndns_account_last_update_timestamp_seconds")} * 1000 > $__from < $__to',
        value_as_time=True,
        color="yellow",
        tag_keys=("opnsense_instance", "service"),
        metrics=("opnsense_dyndns_account_last_update_timestamp_seconds",),
        why="A successful DynDNS update means the WAN address changed, which drops "
            "inbound sessions and every tunnel anchored to the old address. The "
            "account description is deliberately not tagged: it is operator free text.",
    ),
    Annotation(
        name="IDS ruleset updated",
        group="prometheus",
        title="IDS ruleset updated",
        expr=f'max by (opnsense_instance) ({sel("opnsense_ids_ruleset_last_updated_timestamp_seconds")}) '
             "* 1000 > $__from < $__to",
        value_as_time=True,
        color="dark-orange",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_ids_ruleset_last_updated_timestamp_seconds",),
        why="An alert-rate step after a ruleset update is the ruleset, not the "
            "traffic — and IDS alert rate is a panel operators read constantly, so the "
            "marker earns its place on the timeline. Aggregated to the newest update "
            "per appliance, which is what keeps a box tracking many rulesets to one "
            "marker per update cycle. Default-ON by owner decision 2026-07-29 (#523), "
            "reversing the earlier default-off cadence call.",
    ),
    Annotation(
        name="Threat feed updated",
        group="prometheus",
        title="Q-Feeds threat feed updated",
        expr=f'max by (opnsense_instance) ({sel("opnsense_qfeeds_feed_last_update_timestamp_seconds")}) '
             "* 1000 > $__from < $__to",
        value_as_time=True,
        enable=False,
        color="orange",
        tag_keys=("opnsense_instance",),
        metrics=("opnsense_qfeeds_feed_last_update_timestamp_seconds",),
        why="Same shape as the IDS ruleset: the blocklist contents changed under a "
            "static configuration. The ONE layer the owner kept default-off in the "
            "2026-07-29 default set (#523) — Q-Feeds refreshes on a much tighter "
            "schedule than an IDS ruleset, so its markers are the ones that would bury "
            "the rest of the timeline. Turn it on when investigating block-rate steps.",
    ),
    Annotation(
        name="Config change detail",
        group="loki",
        title="Configuration changed (audit)",
        expr=f'{loki_sel("""opnsense_subsystem="audit\"""")} | event="config_change"',
        color="blue",
        tag_keys=("service_instance_id", "config_uri"),
        why="The same event as the Config change layer, at the same instant, but "
            "carrying which API endpoint was called — so a traffic step can be traced "
            "to /api/firewall/filter/addRule specifically. Default-ON by owner "
            "decision 2026-07-29 (#523): it lands on the same timestamps as the Config "
            "change layer rather than adding new marks, so the duplication that argued "
            "for default-off costs nothing on the timeline while the endpoint detail is "
            "worth having without a toggle. It needs log shipping, so it is simply "
            "absent where the Config change layer is the only one available. Its record "
            "body names the admin and their source address, which is why neither is a tag.",
    ),
    Annotation(
        name="Gateway alarm",
        group="loki",
        title="Gateway alarm",
        expr=f'{loki_sel("""opnsense_subsystem="gateways\"""")} '
             '| gateway_event=~"alarm_started|alarm_cleared"',
        color="red",
        tag_keys=("service_instance_id", "gateway_event"),
        why="dpinger's own transition record, so the marker sits at the instant the "
            "gateway went down rather than at the scrape that noticed. The closed "
            "alarm_started/alarm_cleared vocabulary makes it safe to tag.",
    ),
    Annotation(
        name="CARP transition",
        group="loki",
        title="CARP state change",
        expr=f'{loki_sel("""opnsense_subsystem="kernel\"""")} '
             '| carp_event=~"state_changed|demoted|promoted"',
        color="dark-red",
        tag_keys=("service_instance_id", "carp_event"),
        why="A failover moves every service between nodes, so both appliances' graphs "
            "step at once. The kernel logs the transition with its cause; the cause "
            "is in the record body rather than a tag because it is free text.",
    ),
    Annotation(
        name="Tunnel lifecycle",
        group="loki",
        title="VPN tunnel established or terminated",
        expr=f'{loki_sel("""opnsense_subsystem=~"vpn|ipsec\"""")} '
             '| vpn_event=~"established|terminated"',
        color="light-purple",
        tag_keys=("service_instance_id", "vpn_event"),
        why="Explains a tunnel's traffic series starting or stopping. Default-ON by "
            "owner decision 2026-07-29 (#523). The volume objection that made it "
            "default-off is real on a box with many road-warrior peers — turn it off "
            "there — but it is the wrong default for a site-to-site box, where a "
            "tunnel establishing or terminating is precisely the event explaining the "
            "graph. It is a toolbar-menu toggle, not a permanent cost.",
    ),
    Annotation(
        name="Exporter-pushed events",
        group="grafana",
        title="",
        expr="",
        color="rgba(255, 145, 0, 1)",
        why="Reads Grafana's OWN annotation store rather than a datasource, so it "
            "shows the events the exporter pushed there with --annotations.enabled. "
            "The same events the metric layers above derive, but written once and "
            "therefore visible on every other dashboard, in Explore, and to alert "
            "annotations — and carrying text a query cannot produce.",
    ),
    Annotation(
        name="External change events",
        group="grafana",
        title="",
        expr="",
        color="rgba(255, 145, 0, 1)",
        enable=True,
        why="A deployment-local overlay: annotations written into Grafana's store by "
            "automation OUTSIDE this repository (see EXTERNAL_CHANGE_TAGS). Generated "
            "so that publishing generated output cannot delete a layer the live "
            "dashboard has carried since before the generator existed — which is "
            "exactly what copying the artifact over it would otherwise have done.",
    ),
]

# The tag every annotation the exporter writes carries (internal/annotations
# BaseTag). One string, and the Go and Python sides must agree on it or the pushed
# events land somewhere the dashboard never looks.
EXPORTER_TAG = "opnsense-exporter"

# Tags for the deployment-local overlay layer. Both matter and neither is
# guessable, which is why they are data here rather than a comment: the second
# scopes the query to THIS dashboard, without which every change event in the
# estate lands on it.
EXTERNAL_CHANGE_TAGS = ("n8n-change", "dashboard:opnsense-exporter")

# Which tag set each built-in-store layer queries, keyed by layer name.
TAG_QUERIES = {
    "Exporter-pushed events": (EXPORTER_TAG,),
    "External change events": EXTERNAL_CHANGE_TAGS,
}


# ---- the exclusion ledger ------------------------------------------------
# Every instant-valued metric in the catalogue that is deliberately NOT a marker,
# and why. tests/test_annotations.py fails on an instant-valued metric that is
# neither annotated nor listed here, so a new one is a decision rather than an
# oversight.
NOT_ANNOTATED: dict = {
    "opnsense_acme_certificate_status_last_update_timestamp_seconds":
        "The last time the ACME CLIENT RAN, which is a scheduled no-op on most runs. "
        "The renewal itself is annotated from the certificate's own update timestamp.",
    "opnsense_backup_last_timestamp_seconds":
        "OPNsense writes a config backup as part of applying a config change, so this "
        "would place a second marker within a second of every Config change one.",
    "opnsense_clamav_signature_db_built_timestamp_seconds":
        "Upstream's BUILD time from freshclam metadata, not the instant this box "
        "fetched it, so the marker would sit at an event that happened elsewhere.",
    "opnsense_flow_geoip_database_build_timestamp_seconds":
        "MaxMind's BUILD time for the database, not the instant this box downloaded "
        "it, so the marker would sit at an event that happened elsewhere - the same "
        "reason clamav_signature_db_built is excluded. Its value is as a STALENESS "
        "reading, which is what OPNsenseFlowGeoIPDatabaseStale alerts on.",
    "opnsense_crowdsec_bouncer_last_pull_timestamp_seconds":
        "A heartbeat: it advances on every successful pull, so under value-as-time it "
        "produces a continuous smear of markers rather than events.",
    "opnsense_crowdsec_machine_last_heartbeat_timestamp_seconds":
        "A heartbeat by name and by behaviour — same continuous-smear problem.",
    "opnsense_exporter_annotations_last_success_timestamp_seconds":
        "Advances on every annotation the exporter successfully writes, so it is a "
        "freshness reading of the writer rather than an event. Annotating it would also "
        "be circular: a marker on the timeline saying a marker was placed on the "
        "timeline. It is read as an age on Diagnostics instead (#428).",
    "opnsense_exporter_collector_last_poll_timestamp_seconds":
        "Exporter scheduler liveness, advancing every poll interval. Belongs on the "
        "self-observability dashboard as a freshness panel, never as a marker.",
    "opnsense_exporter_collector_last_success_timestamp_seconds":
        "Same: advances on every successful poll. A freshness reading, not an event.",
    "opnsense_exporter_collector_next_poll_timestamp_seconds":
        "Future-dated by construction, so any marker would sit ahead of now.",
    "opnsense_exporter_collector_snapshot_timestamp_seconds":
        "Advances whenever a collector's buffer is replaced — a per-poll heartbeat.",
    "opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds":
        "Advances every time an enrichment table refreshes — rules every 60s, interfaces "
        "every 5m — so under value-as-time it is a continuous smear, not events. Its "
        "value is as a STALENESS reading, which is how the Log Shipping tab plots it.",
    "opnsense_exporter_logs_last_exported_timestamp_seconds":
        "A pipeline-stage cursor that advances with every batch the sink acknowledges. "
        "The whole point of the pair with logs_last_received is the LAG between them; a "
        "marker per shipped batch would be one per second on a busy box.",
    "opnsense_exporter_logs_last_received_timestamp_seconds":
        "Same: advances on every record admitted to the queue. Cursor, not event.",
    "opnsense_exporter_otlp_last_success_timestamp_seconds":
        "Advances on every OTLP export the backend accepts, i.e. once per export "
        "interval while delivery is healthy — a heartbeat. What an operator needs from "
        "it is the AGE since the last acceptance, which Diagnostics already stats.",
    "opnsense_firmware_last_check_timestamp_seconds":
        "The last UPDATE CHECK, which changes nothing on the box. The upgrade that "
        "does is annotated from the boot environment it creates.",
    "opnsense_netbird_peer_last_handshake_timestamp_seconds":
        "Per-peer WireGuard keepalive handshakes, refreshing every couple of minutes "
        "per peer. Cardinality times cadence makes it unusable as a timeline.",
    "opnsense_nginx_ban_last_timestamp_seconds":
        "Advances on every autoblock ban, which is exactly the high-frequency "
        "security event a panel counts and a timeline cannot show.",
    "opnsense_openvpn_session_connected_since_timestamp_seconds":
        "One series per live session, each retained for the session's whole life; the "
        "same lifecycle is available as discrete events in the Tunnel lifecycle layer.",
    "opnsense_qfeeds_feed_next_update_timestamp_seconds":
        "Future-dated by construction.",
    "opnsense_qfeeds_license_expiry_timestamp_seconds":
        "Future-dated by construction, and an expiry deadline rather than an event.",
    "opnsense_tailscale_peer_last_handshake_timestamp_seconds":
        "Per-peer keepalive handshakes, as for NetBird.",
    "opnsense_trafficshaper_rule_last_match_timestamp_seconds":
        "Advances every time a shaper rule matches traffic, so on a busy box it "
        "advances continuously per rule.",
}


# ---- rendering -----------------------------------------------------------
def _legacy_options(entry: Annotation) -> dict:
    opts = {"expr": entry.expr, "titleFormat": entry.title}
    if entry.text:
        opts["textFormat"] = entry.text
    if entry.tag_keys:
        opts["tagKeys"] = ",".join(entry.tag_keys)
    if entry.value_as_time:
        # Grafana's own spelling for this option is the string "on", not a bool.
        opts["useValueForTime"] = "on"
    return opts


def render(entry: Annotation) -> dict:
    """Return the v2 AnnotationQuery envelope for one catalogue entry."""
    spec = {
        "builtIn": False,
        "enable": entry.enable,
        "hide": False,
        "iconColor": entry.color,
        "name": entry.name,
    }
    if not entry.on_toolbar:
        spec["placement"] = "inControlsMenu"
    if entry.group == "grafana":
        spec["query"] = {
            "datasource": {"name": "-- Grafana --"},
            "group": "grafana",
            "kind": "DataQuery",
            "spec": {"limit": 100, "matchAny": False,
                     "tags": list(TAG_QUERIES[entry.name]), "type": "tags"},
            "version": "v0",
        }
        return {"kind": "AnnotationQuery", "spec": spec}

    datasource = "${datasource}" if entry.group == "prometheus" else "${loki_datasource}"
    spec["legacyOptions"] = _legacy_options(entry)
    spec["query"] = {
        "datasource": {"name": datasource},
        "group": entry.group,
        "kind": "DataQuery",
        "spec": {},
        "version": "v0",
    }
    return {"kind": "AnnotationQuery", "spec": spec}


def add_annotations(b) -> None:
    """Register every catalogue entry on the builder.

    Each query is also recorded on the builder's expression lists, so the existing
    gates cover annotations with no extra wiring: `promqlcheck` parses the PromQL,
    the coverage gate counts the metrics as referenced, and the instance-identity
    and Loki-scoping guards see the queries.
    """
    for entry in ANNOTATIONS:
        if entry.group == "prometheus":
            b.record_expr(entry.expr)
        elif entry.group == "loki":
            b.record_loki_expr(entry.expr)
        b.annotations.append(render(entry))
