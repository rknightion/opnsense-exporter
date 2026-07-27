"""
Tor tab — circuit and stream telemetry from the os-tor plugin's control port
(opnsense_tor_*, opt-in via --exporter.enable-tor, #206).

AGGREGATE ONLY: circuits/streams are always counts grouped by a closed,
validated status/purpose vocabulary (an unrecognised value from a plugin
parsing regression is bucketed as "other" server-side, never a raw/garbage
label) — there is intentionally no per-circuit or per-stream panel, and no
destination/host panel of any kind. Hidden-service panels show only the
configured service name and a 0/1 hostname-availability flag; the .onion
hostname itself is never collected, so there is nothing to display.

Gauges (never rate): control_port_up, circuits, circuits_by_purpose,
streams, hidden_services, hidden_service_hostname_available.
"""

from builder import Builder, sel, grp, RUNSTOP


def build(b: Builder):
    b.sentinel("has_tor", metric="opnsense_tor_control_port_up")

    def t(metric, extra=""):
        return sel(f"opnsense_tor_{metric}", extra)

    # ------------------------------------------------------------------ #
    # Row 1: Overview                                                     #
    # ------------------------------------------------------------------ #
    control_port_up = b.stat(
        "Control Port",
        t("control_port_up"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Whether the Tor control port answered the last circuit/stream "
             "query (1 = up, 0 = unreachable or misconfigured). This is the "
             "primary health signal — a wedged Tor still reports its OPNsense "
             "service as running.",
    )
    built_expr = t("circuits", 'status="BUILT"')
    circuits_built = b.stat(
        "Built Circuits",
        f'sum({built_expr}) or vector(0)',
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "green", "value": 1},
        ],
        color_mode="background",
        desc=("Number of fully-built (3-hop, BUILT) circuits. Zero while the "
             "control port is up is the actual wedged-Tor signal — a running "
             "service with no usable circuits."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    circuits_total = b.stat(
        "Total Circuits",
        f'sum({t("circuits")}) or vector(0)',
        unit="short", w=4, h=4,
        desc=("Total circuits across every build status (LAUNCHED/BUILT/"
             "GUARD_WAIT/EXTENDED/FAILED/CLOSED/other)."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    streams_total = b.stat(
        "Total Streams",
        f'sum({t("streams")}) or vector(0)',
        unit="short", w=4, h=4,
        desc=("Total streams across every status (NEW/SUCCEEDED/FAILED/"
             "CLOSED/other). Never labeled by destination."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    hidden_services_total = b.stat(
        "Hidden Services",
        f'{t("hidden_services")} or vector(0)',
        unit="short", w=4, h=4,
        desc="Number of configured Tor hidden services. Hostnames are never "
             "collected or displayed.",
    )

    # ------------------------------------------------------------------ #
    # Row 2: Circuits                                                     #
    # ------------------------------------------------------------------ #
    circuits_by_status = b.bargauge(
        "Circuits by Status",
        [(f'sum {grp("status")} ({t("circuits")})', "{{status}}")],
        unit="short", w=12, h=8,
        orient="horizontal",
        desc="opnsense_tor_circuits: circuit counts by build status. An "
             "unrecognised status value from a plugin parsing regression is "
             "bucketed as \"other\", never shown verbatim.",
    )
    circuits_by_purpose = b.bargauge(
        "Circuits by Purpose",
        [(f'sum {grp("purpose")} ({t("circuits_by_purpose")})', "{{purpose}}")],
        unit="short", w=12, h=8,
        orient="horizontal",
        desc="opnsense_tor_circuits_by_purpose: circuit counts by purpose "
             "(GENERAL, HS_CLIENT_INTRO, HS_VANGUARDS, TESTING, ...). An "
             "unrecognised purpose is bucketed as \"other\".",
    )

    # ------------------------------------------------------------------ #
    # Row 3: Streams                                                       #
    # ------------------------------------------------------------------ #
    streams_by_status = b.bargauge(
        "Streams by Status",
        [(f'sum {grp("status")} ({t("streams")})', "{{status}}")],
        unit="short", w=24, h=8,
        orient="horizontal",
        desc="opnsense_tor_streams: stream counts by status (NEW/SUCCEEDED/"
             "FAILED/CLOSED/DETACHED/...). Never labeled by destination host "
             "or port. A row whose fields the plugin's GETINFO parser shifted "
             "into the wrong columns lands in \"other\" rather than leaking "
             "the raw (potentially relay-descriptor-shaped) value as a label.",
    )

    # ------------------------------------------------------------------ #
    # Row 4: Hidden Services                                               #
    # ------------------------------------------------------------------ #
    hidden_service_table = b.table(
        "Hidden Service Availability",
        [t("hidden_service_hostname_available")],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"service": "Service", "Value": "Hostname Available"},
        desc="Per configured hidden service: whether a .onion hostname has "
             "been provisioned (1 = available, 0 = not available). The "
             "hostname itself is never collected or shown.",
    )

    b.tab("Tor", [
        b.row("Tor Overview",
              [control_port_up, circuits_built, circuits_total, streams_total, hidden_services_total],
              present="has_tor"),
        b.row("Circuits",
              [circuits_by_status, circuits_by_purpose],
              present="has_tor"),
        b.row("Streams",
              [streams_by_status],
              present="has_tor"),
        b.row("Hidden Services",
              [hidden_service_table],
              present="has_tor"),
    ])
