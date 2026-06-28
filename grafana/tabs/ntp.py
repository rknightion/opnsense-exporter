"""
NTP tab for the OPNsense Exporter dashboard.

Covers all 9 opnsense_ntp_* metrics across two rows:
  1. Peers   — info table, stratum table, reach gauge (0-255) + % stat, peers_total
  2. Timing  — delay/offset/jitter timeseries, when/poll stats
"""

from builder import Builder, sel


def build(b: Builder):
    b.sentinel("has_ntp", "label_values(opnsense_ntp_peer_info, __name__)")

    # =====================================================================
    # Row 1: Peers
    # =====================================================================

    # Info table: server, refid, type, status labels (info metric, value always 1)
    peer_info = b.table(
        "NTP Peer Info",
        [sel("opnsense_ntp_peer_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "server": "Server",
            "refid": "Ref ID",
            "type": "Type",
            "status": "Status",
            "opnsense_instance": "Instance",
        },
        sort_by="Server",
        desc="NTP peer information: server address, reference ID, type and status (info metric).",
    )

    # Stratum table: one row per server
    peer_stratum = b.table(
        "Peer Stratum",
        [sel("opnsense_ntp_peer_stratum")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "server": "Server",
            "Value": "Stratum",
            "opnsense_instance": "Instance",
        },
        sort_by="Stratum",
        desc="NTP stratum level per peer (1 = primary reference, higher = further from source).",
    )

    # Reachability register gauge 0-255 (8-bit shift register; 255 = all 8 polls answered)
    reach_gauge = b.gauge(
        "Peer Reachability Register",
        f"max({sel('opnsense_ntp_peer_reach')})",
        unit="short",
        mn=0,
        mx=255,
        w=4, h=8,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "yellow", "value": 127},
            {"color": "green", "value": 255},
        ],
        desc=(
            "NTP reachability shift-register (0–255). 255 = all 8 recent polls answered. "
            "Shows the maximum across all peers."
        ),
    )

    # Derived reachability percentage stat: 100 * reach / 255
    reach_pct = b.stat(
        "Peer Reachability %",
        f"100 * max({sel('opnsense_ntp_peer_reach')}) / 255",
        unit="percent",
        w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "yellow", "value": 50},
            {"color": "green", "value": 99},
        ],
        color_mode="value",
        instant=True,
        desc=(
            "Derived reachability percentage: 100 × max(reach) / 255. "
            "100 % means every recent poll was answered."
        ),
    )

    # Total peers stat (instantaneous gauge named _total — show RAW per AUTHORING.md)
    peers_total = b.stat(
        "Peers Total",
        sel("opnsense_ntp_peers_total"),
        unit="short",
        w=4, h=4,
        thresholds=[{"color": "blue", "value": None}],
        desc="Total number of configured NTP peers.",
    )

    row_peers = b.row(
        "Peers",
        [peer_info, peer_stratum, reach_gauge, reach_pct, peers_total],
    )

    # =====================================================================
    # Row 2: Timing
    # =====================================================================

    # Delay / offset / jitter timeseries (unit ms)
    timing_ts = b.ts(
        "Peer Timing (delay / offset / jitter)",
        [
            (sel("opnsense_ntp_peer_delay_milliseconds"), "{{server}} delay"),
            (sel("opnsense_ntp_peer_offset_milliseconds"), "{{server}} offset"),
            (sel("opnsense_ntp_peer_jitter_milliseconds"), "{{server}} jitter"),
        ],
        unit="ms",
        w=16, h=8,
        min0=False,
        desc="Per-peer round-trip delay, clock offset, and dispersion jitter in milliseconds.",
    )

    # Seconds since last response (when)
    when_stat = b.stat(
        "Last Response (max)",
        f"max({sel('opnsense_ntp_peer_when_seconds')})",
        unit="s",
        w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 60},
            {"color": "red", "value": 300},
        ],
        color_mode="value",
        instant=True,
        desc="Seconds since the most-recent NTP peer last responded (worst peer shown).",
    )

    # Poll interval stat
    poll_stat = b.stat(
        "Poll Interval (max)",
        f"max({sel('opnsense_ntp_peer_poll_seconds')})",
        unit="s",
        w=4, h=4,
        thresholds=[{"color": "blue", "value": None}],
        color_mode="value",
        instant=True,
        desc="Maximum poll interval in seconds across all peers.",
    )

    row_timing = b.row(
        "Timing",
        [timing_ts, when_stat, poll_stat],
    )

    # =====================================================================
    # Assemble the tab
    # =====================================================================
    b.tab(
        "NTP",
        [row_peers, row_timing],
        present="has_ntp",
    )
