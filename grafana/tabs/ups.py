"""
UPS tab — NUT and apcupsd UPS metrics (opnsense_nut_* and opnsense_apcupsd_*).

Two plugin-gated rows, one per UPS plugin (D2: separate subsystems, shared
metric suffixes). Both rows live in one tab so the operator sees a unified
UPS view regardless of which plugin they use.

Sentinels:
  has_nut     — gates the NUT row
  has_apcupsd — gates the apcupsd row

Gauge metrics (never rate):
  service_running, ups_info, battery_charge_percent, battery_runtime_seconds,
  battery_voltage_volts, input/output_voltage_volts, load_percent,
  temperature_celsius, input_frequency_hertz,
  status_online/on_battery/low_battery/charging/replace_battery (NUT)
  status_online/on_battery/low_battery (apcupsd)
  time_on_battery_seconds (apcupsd), nominal_power_watts (apcupsd)

Counter (apcupsd):
  transfers_total — cumulative mains-transfer count -> rate()
"""

from builder import Builder, sel, RATE, RUNSTOP


def build(b: Builder):
    b.sentinel("has_nut",
               "label_values(opnsense_nut_ups_info, __name__)")
    b.sentinel("has_apcupsd",
               "label_values(opnsense_apcupsd_ups_info, __name__)")

    # ================================================================== #
    # NUT row                                                              #
    # ================================================================== #
    nut_svc = b.stat(
        "NUT Service",
        sel("opnsense_nut_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="NUT (Network UPS Tools) service state (1 = running, 0 = stopped).",
    )
    nut_charge = b.gauge(
        "NUT Battery Charge",
        sel("opnsense_nut_battery_charge_percent"),
        unit="percent", mn=0, mx=100,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "orange", "value": 20},
            {"color": "green", "value": 50},
        ],
        w=4, h=6,
    )
    nut_load = b.gauge(
        "NUT Load",
        sel("opnsense_nut_load_percent"),
        unit="percent", mn=0, mx=100,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 70},
            {"color": "red", "value": 90},
        ],
        w=4, h=6,
    )
    nut_runtime = b.stat(
        "NUT Battery Runtime",
        sel("opnsense_nut_battery_runtime_seconds"),
        unit="s", w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "orange", "value": 300},
            {"color": "green", "value": 900},
        ],
        color_mode="value",
        desc="Estimated battery runtime remaining in seconds.",
    )
    nut_temp = b.stat(
        "NUT Temperature",
        sel("opnsense_nut_temperature_celsius"),
        unit="celsius", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 40},
            {"color": "red", "value": 50},
        ],
        color_mode="value",
        desc="UPS temperature in Celsius (omitted when variable absent).",
    )
    nut_voltage_ts = b.ts(
        "NUT Voltage",
        [
            (sel("opnsense_nut_battery_voltage_volts"), "battery"),
            (sel("opnsense_nut_input_voltage_volts"), "input"),
            (sel("opnsense_nut_output_voltage_volts"), "output"),
        ],
        unit="volt", w=12, h=8,
        desc="NUT battery, input, and output voltages.",
    )
    nut_freq_ts = b.ts(
        "NUT Input Frequency",
        [(sel("opnsense_nut_input_frequency_hertz"), "input freq")],
        unit="hertz", w=12, h=8,
        desc="NUT input AC frequency in Hz.",
    )
    nut_status_ts = b.statetimeline(
        "NUT Status Flags",
        [
            (sel("opnsense_nut_status_online"), "online"),
            (sel("opnsense_nut_status_on_battery"), "on battery"),
            (sel("opnsense_nut_status_low_battery"), "low battery"),
            (sel("opnsense_nut_status_charging"), "charging"),
            (sel("opnsense_nut_status_replace_battery"), "replace battery"),
        ],
        {"0": ("No", "green"), "1": ("Yes", "orange")},
        w=24, h=8,
        desc="NUT UPS status flags over time.",
    )
    nut_info_table = b.table(
        "NUT UPS Info",
        [sel("opnsense_nut_ups_info")],
        w=24, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"model": "Model", "status": "Status"},
        desc="NUT UPS identity labels (ups_info is always 1; labels carry the data).",
    )

    # ================================================================== #
    # apcupsd row                                                          #
    # ================================================================== #
    apc_svc = b.stat(
        "apcupsd Service",
        sel("opnsense_apcupsd_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="apcupsd service state (1 = running, 0 = stopped).",
    )
    apc_charge = b.gauge(
        "APC Battery Charge",
        sel("opnsense_apcupsd_battery_charge_percent"),
        unit="percent", mn=0, mx=100,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "orange", "value": 20},
            {"color": "green", "value": 50},
        ],
        w=4, h=6,
    )
    apc_load = b.gauge(
        "APC Load",
        sel("opnsense_apcupsd_load_percent"),
        unit="percent", mn=0, mx=100,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 70},
            {"color": "red", "value": 90},
        ],
        w=4, h=6,
    )
    apc_runtime = b.stat(
        "APC Battery Runtime",
        sel("opnsense_apcupsd_battery_runtime_seconds"),
        unit="s", w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "orange", "value": 300},
            {"color": "green", "value": 900},
        ],
        color_mode="value",
        desc="Estimated battery runtime remaining in seconds (TIMELEFT × 60).",
    )
    apc_nominal_watts = b.stat(
        "APC Nominal Power",
        sel("opnsense_apcupsd_nominal_power_watts"),
        unit="watt", w=4, h=4,
        desc="Nominal UPS power output in watts.",
    )
    apc_time_on_battery = b.stat(
        "APC Time on Battery",
        sel("opnsense_apcupsd_time_on_battery_seconds"),
        unit="s", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 30},
            {"color": "red", "value": 120},
        ],
        color_mode="value",
        desc="Cumulative seconds on battery power since last mains transfer.",
    )
    apc_voltage_ts = b.ts(
        "APC Voltage",
        [
            (sel("opnsense_apcupsd_battery_voltage_volts"), "battery"),
            (sel("opnsense_apcupsd_input_voltage_volts"), "input"),
            (sel("opnsense_apcupsd_output_voltage_volts"), "output"),
        ],
        unit="volt", w=12, h=8,
        desc="apcupsd battery, input, and output voltages.",
    )
    apc_transfers_ts = b.ts(
        "APC Mains Transfer Rate",
        [(f'rate({sel("opnsense_apcupsd_transfers_total")}[{RATE}])', "transfers/s")],
        unit="short", w=12, h=8,
        desc="Rate of mains-to-battery transfers (counter, use rate()).",
    )
    apc_status_ts = b.statetimeline(
        "APC Status Flags",
        [
            (sel("opnsense_apcupsd_status_online"), "online"),
            (sel("opnsense_apcupsd_status_on_battery"), "on battery"),
            (sel("opnsense_apcupsd_status_low_battery"), "low battery"),
        ],
        {"0": ("No", "green"), "1": ("Yes", "orange")},
        w=24, h=8,
        desc="apcupsd UPS status flags over time.",
    )
    apc_info_table = b.table(
        "APC UPS Info",
        [sel("opnsense_apcupsd_ups_info")],
        w=24, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"model": "Model", "status": "Status"},
        desc="apcupsd UPS identity labels (ups_info is always 1; labels carry the data).",
    )

    b.tab("UPS", [
        b.row("NUT (Network UPS Tools)",
              [nut_svc, nut_charge, nut_load, nut_runtime, nut_temp,
               nut_voltage_ts, nut_freq_ts,
               nut_status_ts, nut_info_table],
              present="has_nut"),
        b.row("APC UPS (apcupsd)",
              [apc_svc, apc_charge, apc_load, apc_runtime, apc_nominal_watts,
               apc_time_on_battery, apc_voltage_ts, apc_transfers_ts,
               apc_status_ts, apc_info_table],
              present="has_apcupsd"),
    ])
