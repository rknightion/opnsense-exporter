"""Config snapshots shipped by the family-specific config snapshot flags."""

from builder import Builder, loki_grp, loki_sel


# The selector uses only the two deliberately indexable stream labels. Family,
# sequence and entity identity remain structured metadata, then the body parser
# exposes the v1 JSON envelope as table fields.
CONFIG_STREAM = loki_sel('opnsense_source="configstate", opnsense_subsystem="config"')
FIREWALL_SNAPSHOTS = f'{CONFIG_STREAM} | snapshot_family="firewall" | json'
DEVICE_SNAPSHOTS = f'{CONFIG_STREAM} | snapshot_family="device_inventory" | json'
SECURITY_POSTURE = f'{CONFIG_STREAM} | snapshot_family="security_posture" | json'


def firewall_snapshot_table(b: Builder) -> str:
    """Build the per-batch/entity firewall snapshot table with sequence order intact."""
    # Snapshot sequence repeats in every batch, so counting it over the selected
    # range collapsed unrelated records into accumulated totals. The composite key
    # preserves BOTH opaque batch and entity identity while fitting Builder's
    # cardinality-safe Loki table contract. ``last_over_time`` returns the source
    # sequence, not an event count.
    snapshot_rows = (
        f'sum {loki_grp("snapshot_entity")} '
        f'(last_over_time({FIREWALL_SNAPSHOTS} '
        '| label_format snapshot_entity="{{.snapshot_id}} / {{.snapshot_entity_id}}" '
        '| unwrap snapshot_seq [$__range]))'
    )
    name = b.loki_table(
        "Firewall & NAT Configuration Snapshots",
        [snapshot_rows],
        field_title="Snapshot / Entity",
        sort_by="Total",
        sort_desc=False,
        desc=(
            "One firewall or NAT configuration entity per configstate record. The first column "
            "keeps the opaque Snapshot ID paired with Entity ID; Total is that entity's numeric "
            "Sequence, ordered ascending to reconstruct the source's stable entity-id order. "
            "The family ships only when its canonical content changes, plus a six-hour heartbeat."
        )
    )
    b.size[name] = (24, 12)
    return name


def build(b: Builder):
    b.loki_sentinel(
        "has_config_snapshot_logs",
        matchers='opnsense_source="configstate", opnsense_subsystem="config"',
        label="opnsense_source",
    )
    firewall = firewall_snapshot_table(b)
    devices = b.loki_table(
        "Device Inventory Snapshots",
        [f'topk {loki_grp()} (200, sum {loki_grp("device")} '
         f'(last_over_time({DEVICE_SNAPSHOTS} '
         '| label_format device="{{.entity_hostname}} / {{.entity_mac}} / {{.entity_ips}}" '
         '| unwrap snapshot_seq [$__range])))'],
        field_title="Hostname / MAC / IPs",
        sort_by="Total",
        sort_desc=False,
        desc=(
            "One row per device-inventory snapshot record, showing the bounded fused identity "
            "projection from ARP, NDP, DHCP, hostdiscovery and LLDP. Total is the record's "
            "snapshot sequence, not an event count. The family is default-off because these "
            "records contain device addresses and hostnames."
        ),
    )
    posture = b.logs(
        "Security Posture Snapshots",
        SECURITY_POSTURE,
        desc=(
            "The latest default-off security-posture records: OPNsense's update verdict and "
            "pending packages, certificate-expiry roll-up and API-key owners. Unchanged posture "
            "repeats only on its deliberate seven-day heartbeat. Listening-socket detail is not "
            "claimed because the current API exposes active-socket counts, not listener state."
        ),
        w=24,
    )
    b.tab("Config", [
        b.row("Firewall & NAT", [firewall], present="has_config_snapshot_logs", collapse=True),
        b.row("Device Inventory", [devices], present="has_config_snapshot_logs", collapse=True),
        b.row("Security Posture", [posture], present="has_config_snapshot_logs", collapse=True),
    ], present="has_config_snapshot_logs")
