"""
Traffic Shaper tab — covers all opnsense_trafficshaper_* metrics.

Gated on `query_result(opnsense_trafficshaper_pipes_total > 0)` so the tab
only appears when dummynet pipes are actually configured.

Rows:
  1. Summary        — pipes_total, queues_total stats
  2. Pipes          — per-pipe active_flows, bytes, drop gauges (timeseries)
  3. Queues         — per-queue active_flows, bytes, drop gauges (timeseries)
  4. Rules          — rule packet/byte counters table (rate)
"""

from builder import Builder, sel, RATE, epoch_ms


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_trafficshaper",
               "query_result(opnsense_trafficshaper_pipes_total > 0)")

    # ================================================================
    # Row 1: Summary
    # ================================================================
    pipes_total = b.stat(
        "Configured Pipes",
        sel("opnsense_trafficshaper_pipes_total"),
        unit="short", w=6, h=4,
        desc="Number of configured dummynet pipes (gauge — instantaneous count).",
    )
    queues_total = b.stat(
        "Configured Queues",
        sel("opnsense_trafficshaper_queues_total"),
        unit="short", w=6, h=4,
        desc="Number of configured dummynet queues (gauge — instantaneous count).",
    )

    # ================================================================
    # Row 2: Pipes
    # ================================================================
    pipe_flows = b.ts(
        "Pipe Active Flows",
        [(sel("opnsense_trafficshaper_pipe_active_flows"),
          "{{pipe}} {{description}}")],
        unit="short", w=12, h=8,
        desc="Current number of active flows per dummynet pipe (gauge).",
    )
    pipe_bytes = b.ts(
        "Pipe Bytes",
        [(sel("opnsense_trafficshaper_pipe_bytes"),
          "{{pipe}} bytes"),
         (sel("opnsense_trafficshaper_pipe_drop_bytes"),
          "{{pipe}} drop_bytes")],
        unit="bytes", w=12, h=8,
        desc=(
            "Current byte counts per pipe (gauge — dummynet flow buckets "
            "can decrease when idle flows expire)."
        ),
    )
    pipe_pkts = b.ts(
        "Pipe Packets",
        [(sel("opnsense_trafficshaper_pipe_packets"),
          "{{pipe}} pkts"),
         (sel("opnsense_trafficshaper_pipe_drop_packets"),
          "{{pipe}} drop_pkts")],
        unit="pps", w=12, h=8,
        desc="Current packet counts per pipe (gauge).",
    )

    # ================================================================
    # Row 3: Queues
    # ================================================================
    queue_flows = b.ts(
        "Queue Active Flows",
        [(sel("opnsense_trafficshaper_queue_active_flows"),
          "{{queue}} {{description}}")],
        unit="short", w=12, h=8,
        desc="Current number of active flows per dummynet queue (gauge).",
    )
    queue_bytes = b.ts(
        "Queue Bytes",
        [(sel("opnsense_trafficshaper_queue_bytes"),
          "{{queue}} bytes"),
         (sel("opnsense_trafficshaper_queue_drop_bytes"),
          "{{queue}} drop_bytes")],
        unit="bytes", w=12, h=8,
        desc="Current byte counts per queue (gauge).",
    )
    queue_pkts = b.ts(
        "Queue Packets",
        [(sel("opnsense_trafficshaper_queue_packets"),
          "{{queue}} pkts"),
         (sel("opnsense_trafficshaper_queue_drop_packets"),
          "{{queue}} drop_pkts")],
        unit="pps", w=12, h=8,
        desc="Current packet counts per queue (gauge).",
    )

    # ================================================================
    # Row 4: Rules (ipfw rule counters — cumulative, use rate)
    # ================================================================
    rule_bytes = b.ts(
        "Rule Throughput (rate)",
        [(f'rate({sel("opnsense_trafficshaper_rule_bytes_total")}[{RATE}])',
          "{{rule}} {{description}}")],
        unit="Bps", w=12, h=8,
        desc="Bytes per second matched by each traffic shaper rule.",
    )
    rule_pkts = b.ts(
        "Rule Packets (rate)",
        [(f'rate({sel("opnsense_trafficshaper_rule_packets_total")}[{RATE}])',
          "{{rule}} (→{{target_type}}:{{attached_to}}) {{description}}")],
        unit="pps", w=12, h=8,
        desc="Packets per second matched by each traffic shaper rule.",
    )
    rule_last_match = b.table(
        "Rule Last Match",
        [epoch_ms(sel("opnsense_trafficshaper_rule_last_match_timestamp_seconds"))],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "rule": "Rule",
            "attached_to": "Attached To",
            "target_type": "Target Type",
            "description": "Description",
            "Value": "Last Match",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Last Match": "dateTimeAsIso"},
        sort_by="Last Match",
        sort_desc=True,
        desc=(
            "Timestamp each traffic shaper rule last matched traffic. A rule that has "
            "never matched is absent from this table (rider, #224)."
        ),
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("Traffic Shaper", [
        b.row("Summary",
              [pipes_total, queues_total],
              present="has_trafficshaper"),
        b.row("Pipes",
              [pipe_flows, pipe_bytes, pipe_pkts],
              present="has_trafficshaper"),
        b.row("Queues",
              [queue_flows, queue_bytes, queue_pkts],
              present="has_trafficshaper"),
        b.row("Rules",
              [rule_bytes, rule_pkts, rule_last_match],
              present="has_trafficshaper"),
    ])
