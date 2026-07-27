#!/usr/bin/env python3
"""
Single-source builder for OPNsense exporter alert + recording rules.

Rules are defined once (RULES / RECORDING below) and emitted as Grafana-managed manifests:

  * `grafana-managed/*.json`         — Grafana-managed `rules.alerting.grafana.app/v0alpha1`
                                       AlertRule / RecordingRule manifests (+ a folder),
                                       pushable with `gcx resources push`. Use `--stack` to add
                                       an IRM label contract (domain/page) for routed alerting.

Grafana-managed alerting is the only supported format: it carries `noDataState` (so the
exporter-down/NoData case actually fires) and Grafana templating (`$values`), neither of which
a portable Prometheus rule-group file can express. A previously-shipped portable
`opnsense.rules.yaml` was dropped for this reason.

Usage:
    python3 build_rules.py                       # generic labels
    python3 build_rules.py --stack               # add domain=infra (+page on critical)
    python3 build_rules.py --datasource <uid>    # datasource UID (default grafanacloud-prom)
    python3 build_rules.py --folder <name>       # grafana folder (default opnsense-alerts)

Alerts are defined as a value-producing query `A` plus a threshold condition, rendered to the
Grafana A→C query/threshold node pipeline.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# The runbook URL is shared with the dashboard's own "Alert runbooks" link (#419):
# one registry, so an alert notification and the dashboard can never point at two
# different pages.
sys.path.insert(0, os.path.dirname(HERE))
from uids import RUNBOOK_URL  # noqa: E402

# Each alert: name(slug), title, A (value query), cond (op, params), for_min, severity,
# summary, description. op in {gt, lt, within_range, outside_range}.
RULES = [
    dict(name="opnsense-exporter-down", title="OPNsenseExporterDown",
         A="opnsense_up", op="lt", params=[1, 0], for_min=15, severity="critical",
         nodata="Alerting",
         summary="OPNsense exporter/box down ({{ $labels.opnsense_instance }})",
         description="opnsense_up has been 0 (the OPNsense API was unreachable / the scrape failed) "
                     "or the target produced NoData for 15m. opnsense_up reflects API reachability ONLY - "
                     "a reachable box reporting a degraded subsystem (e.g. a crash report) stays up=1 and is "
                     "covered by the lower-severity OPNsenseCrashReports / OPNsenseFirewallUnhealthy alerts, "
                     "so this critical/page fires on genuine unreachability only. The 15m window tolerates a "
                     "router reboot (typically <10m) without paging."),
    # #427. The rule above cannot detect a PARTIAL fleet loss, and the reason is a
    # Grafana distinction that is easy to miss:
    #
    #   No Data      - the query returns no series AT ALL. noDataState governs it,
    #                  which is why the rule above sets Alerting: total loss pages.
    #   MissingSeries - the query still returns series, but one dimension has gone.
    #                  Grafana retains that alert instance briefly, then EVICTS it as
    #                  stale. It never passes through noDataState.
    #
    # So with edge-a and edge-b, losing edge-a entirely leaves opnsense_up{edge-b}
    # returning happily; the edge-a instance is quietly evicted and nothing pages.
    # A bare `opnsense_up` cannot detect its own absence — a series that does not
    # exist cannot match a selector. Something has to assert what SHOULD be there.
    #
    # present_over_time gives one series per instance that reported at any point in
    # the lookback; `unless` removes the ones still reporting. What survives is
    # exactly the set that has vanished, still labelled with opnsense_instance so the
    # page can name the box.
    #
    # The baseline is HISTORICAL, not a configured inventory. That is a deliberate
    # trade: it is self-contained (nothing to maintain, a new exporter protects
    # itself the moment it has been up an hour) at the cost of alerting for up to the
    # lookback after a planned decommission. One hour is short enough to wait out and
    # long enough to survive a slow reboot, a Prometheus restart, or a brief scrape
    # outage without a false page. A configured expected-instance list would avoid
    # the decommission noise but silently protects nothing when someone forgets to
    # add a box — failing open on the exact event this rule exists to catch.
    #
    # noDataState stays Ok on purpose: when the whole fleet disappears THIS query
    # returns nothing too, and OPNsenseExporterDown already pages for that. Alerting
    # here would double-page one event.
    #
    # The `max by (opnsense_instance)` is load-bearing, not tidiness. present_over_time
    # yields one series per distinct LABEL SET, not per instance, so any label churn
    # inside the lookback — a version label changing, a relabel, a scrape-config edit —
    # leaves several historical series for one box. Without the aggregation a single
    # missing exporter would raise one alert instance per historical label set, paging
    # repeatedly for one event. Verified live 2026-07-27: the raw form returned two
    # series for the one real instance, differing only by a service_version label that
    # had been removed earlier that day (#472).
    dict(name="opnsense-exporter-instance-missing", title="OPNsenseExporterInstanceMissing",
         A="max by (opnsense_instance) (present_over_time(opnsense_up[1h])) "
           "unless on(opnsense_instance) opnsense_up",
         op="gt", params=[0, 0], for_min=10, severity="critical",
         summary="OPNsense exporter {{ $labels.opnsense_instance }} has stopped reporting",
         description="opnsense_up reported for {{ $labels.opnsense_instance }} at some point in the last "
                     "1h and is now absent entirely, while at least one other exporter is still "
                     "reporting. That is Grafana's MissingSeries case, NOT NoData: the vanished alert "
                     "instance is evicted as stale rather than passing through noDataState, so "
                     "OPNsenseExporterDown cannot see it. Causes: the exporter process died, its host "
                     "went away, or Prometheus stopped scraping that target — note this fires when the "
                     "series is GONE, whereas OPNsenseExporterDown fires when the exporter is alive and "
                     "reporting opnsense_up=0. Check the scrape target's health first, then the "
                     "exporter process. If the instance was decommissioned deliberately, this "
                     "self-resolves once it has been absent for 1h; silence it until then."),
    dict(name="opnsense-firewall-unhealthy", title="OPNsenseFirewallUnhealthy",
         A="opnsense_firewall_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense firewall health check failing ({{ $labels.opnsense_instance }})",
         description="opnsense_firewall_status has reported 0 (errors) for 10m."),
    dict(name="opnsense-crash-reports", title="OPNsenseCrashReports",
         A="opnsense_crash_reporter_status", op="lt", params=[1, 0], for_min=5, severity="warning",
         summary="OPNsense crash reports present ({{ $labels.opnsense_instance }})",
         description="opnsense_crash_reporter_status is 0 — one or more crash reports are present."),
    # #218: the root filesystem "diskspace" health-check subsystem, surfaced by the generic
    # opnsense_system_subsystem_status_code gauge (no dedicated gauge for this one). OPNsense
    # omits a healthy subsystem from the payload entirely, so the series is ABSENT (not 0/OK)
    # on a healthy box — noDataState is deliberately left at the default "Ok" (see nodata=
    # default below) rather than "Alerting", unlike opnsense-exporter-down.
    dict(name="opnsense-disk-space-low", title="OPNsenseDiskSpaceLow",
         A='opnsense_system_subsystem_status_code{subsystem="diskspace"}', op="lt", params=[2, 0],
         for_min=10, severity="warning",
         summary="OPNsense root filesystem disk space low ({{ $labels.opnsense_instance }})",
         description="opnsense_system_subsystem_status_code{subsystem=\"diskspace\"} has reported below OK "
                     "(2 = OK, 1 = NOTICE, 0 = WARNING nearly full, -1 = ERROR critically full) for 10m. "
                     "Absent means healthy — OPNsense omits an OK subsystem from the health-check payload."),
    # The alert-condition window MUST be short (2m) so the long for:15m actually measures how long
    # errors PERSIST. If the window equals for (both 15m), increase()>0 stays true for 15m after the
    # last error, so for:15m is satisfied by any burst spanning >1 eval interval and the alert fires
    # ~15m AFTER recovery (#94). With a 2m window, an 8m error burst keeps the condition true only
    # ~t=0..10m (<15m) → for:15m never elapses → no false page; genuinely sustained errors keep every
    # rolling 2m window non-empty, so the condition stays true past 15m and the alert fires.
    dict(name="opnsense-endpoint-errors", title="OPNsenseEndpointErrors",
         A="sum by (opnsense_instance, endpoint) (increase(opnsense_exporter_endpoint_errors_total[2m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense exporter endpoint errors ({{ $labels.endpoint }})",
         description="The {{ $labels.endpoint }} API endpoint has produced errors sustained for 15m "
                     "(at least one error in every rolling 2m window for the full 15m). A brief router "
                     "reboot / WAN blip empties the 2m window well before 15m elapses, so it does not fire. "
                     "One alert per endpoint. SCOPE (#382): this rule is the FAST/MEDIUM-tier signal and "
                     "the one that names the failing endpoint. It structurally cannot fire for a collector "
                     "on the slow (5m) or cold (15m) poll tier, because such a collector increments the "
                     "counter only once per tier and the 2m window is empty in between, resetting the 15m "
                     "pending clock every eval. Widening the window to cover those tiers would reintroduce "
                     "the #94 false page (a window as long as `for` keeps the condition true for a full "
                     "window after recovery), so the window is deliberately left at 2m and every tier is "
                     "covered instead by OPNsenseCollectorDataStale, which is driven by the data clock and "
                     "scales its tolerance with each collector's own interval."),
    # ---- tier-aware collector staleness (#382) -------------------------------------
    # Error-aware retention (#336 D8) keeps a collector's last-good metrics when a poll
    # fails with nothing to emit. That is deliberate and stays. What was missing was any
    # alertable expression of how OLD the retained data is: last_poll_timestamp advances
    # on every failed attempt, so it can never express staleness.
    #
    # Shape, shared by the two rules below:
    #
    #   (time() - <data clock> - 120) / opnsense_exporter_collector_poll_interval_seconds
    #
    # i.e. staleness measured in MISSED POLL INTERVALS, not a fixed window — the whole
    # point, since the tiers span 15s to 15m. Vector matching is left at the default
    # (all labels bar __name__): both series are emitted from the same collector with an
    # identical {collector, opnsense_instance} label set, so the pairing is exactly 1:1
    # and stays correct with several exporters scraped for one opnsense_instance, which
    # an explicit on(...) would turn into a many-to-many error.
    #
    # The 120s subtracted is SCRAPE-LAG ALLOWANCE and is load-bearing on the fast tier.
    # The gauge is read from the most recent scrape sample, so at eval time the computed
    # age already includes up to one scrape interval of sample staleness on top of one
    # poll interval. Without the allowance a perfectly healthy 15s-tier collector reads
    # (15 + 60) / 15 = 5 missed intervals on a 60s scrape and would fire constantly.
    #
    # Worked tolerance at threshold 3, with a 60s scrape:
    #
    #   tier          healthy peak   one transient failure   persistent failure fires at
    #   fast   15s    ~0.0           ~0.0                    age 165s   (+5m for → ~8m)
    #   medium 60s    0.0            1.0                     age 300s   (+5m for → ~10m)
    #   slow    5m    0.8            1.8                     age 1020s  (+5m for → ~22m)
    #   cold   15m    0.9            1.9                     age 2820s  (+5m for → ~52m)
    #
    # So a persistent slow-tier AND a persistent cold-tier failure both fire (which
    # OPNsenseEndpointErrors cannot do), while a single failed poll followed by recovery
    # peaks at ~2 missed intervals on every tier and never reaches the threshold.
    # Unlike an increase()-window rule this expression is monotone while the fault
    # persists, so the pending clock never resets between two once-per-tier attempts.
    dict(name="opnsense-collector-data-stale", title="OPNsenseCollectorDataStale",
         A="(time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds",
         op="gt", params=[3, 0], for_min=5, severity="warning",
         summary="OPNsense collector {{ $labels.collector }} is serving stale data",
         description="Collector {{ $labels.collector }} has not replaced its stored metric buffer for more "
                     "than 3 of its own poll intervals ({{ $values.A.Value | printf \"%.1f\" }} missed "
                     "intervals and counting), so every scrape and every OTLP export is replaying retained "
                     "last-good values of that age. Tolerance is expressed in MISSED INTERVALS, so it "
                     "scales with the collector's tier (fast 15s / medium 60s / slow 5m / cold 15m, or a "
                     "--collector.poll-interval-override): 3 missed intervals plus a 120s scrape-lag "
                     "allowance plus the 5m pending period, which is ~8m on the fast tier and ~52m on the "
                     "cold tier. One failed poll followed by recovery peaks at ~2 missed intervals and "
                     "cannot fire. The data is NOT blanked — retention is deliberate (#336 D8) — so the "
                     "dashboard still shows values; they are just old. Check "
                     "opnsense_exporter_scrape_collector_success and the endpoint-error panels for the "
                     "cause. NOTE the last-poll clock is useless here: it advances on every failed attempt "
                     "too (#382)."),
    # Second clock: fully-clean success. A collector whose primary endpoint works and
    # whose secondary endpoint errors every time keeps REPLACING its buffer with partial
    # data, so snapshot age stays low and the rule above correctly stays silent — but
    # part of its metric set has been silently missing the whole time. The `unless`
    # suppresses this rule for anything already alerting as fully stale, so a total
    # outage pages once rather than twice; set-operator matching is pinned explicitly to
    # (opnsense_instance, collector) since both sides are arithmetic results.
    # Tolerance is looser (6 missed intervals) and severity lower: data IS still
    # refreshing, so this is a degradation, not a freeze.
    dict(name="opnsense-collector-degraded", title="OPNsenseCollectorDegraded",
         A="((time() - opnsense_exporter_collector_last_success_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds) "
           "unless on(opnsense_instance, collector) "
           "(((time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds) > 3)",
         op="gt", params=[6, 0], for_min=10, severity="info",
         summary="OPNsense collector {{ $labels.collector }} has not fully succeeded",
         description="Collector {{ $labels.collector }} is still refreshing its stored metrics, but no "
                     "poll has completed CLEANLY for more than 6 of its own poll intervals "
                     "({{ $values.A.Value | printf \"%.1f\" }} missed intervals). That is the "
                     "persistent-partial-failure signature: one endpoint of a multi-endpoint collector "
                     "erroring every poll while the rest keep updating, so part of its metric set is "
                     "silently absent or frozen while everything looks fresh. Tolerance is in MISSED "
                     "INTERVALS so it scales with the collector's tier, and the rule deliberately excludes "
                     "collectors already covered by OPNsenseCollectorDataStale (fully frozen data), which "
                     "would otherwise fire both. Severity is info, not warning: data is still flowing, and "
                     "the endpoint-error panels name the failing endpoint (#382)."),
    # The two rules above are absent-tolerant by construction — both new gauges are
    # absent until first set, so a collector that has NEVER stored data produces no
    # series and cannot alert on staleness. That is the one blind spot they leave and
    # this rule closes it: a collector that has completed at least one attempt (the
    # last-poll clock exists) but has never once stored a buffer has failed every poll
    # since the exporter started, which is the wrong-credential / plugin-missing /
    # broken-endpoint-from-boot case. The scheduler polls each collector immediately at
    # startup (after up to 5s jitter), so last_poll appears within seconds on every
    # tier, making a fixed 30m pending period safe here rather than tier-scaled.
    dict(name="opnsense-collector-never-stored", title="OPNsenseCollectorNeverStoredData",
         A="opnsense_exporter_collector_last_poll_timestamp_seconds "
           "unless on(opnsense_instance, collector) "
           "opnsense_exporter_collector_snapshot_timestamp_seconds",
         op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense collector {{ $labels.collector }} has never returned data",
         description="Collector {{ $labels.collector }} has been polling for 30m and has never once stored "
                     "a metric buffer — every poll since the exporter started has failed with nothing to "
                     "emit, so it exports no domain metrics at all. A clean poll that legitimately finds "
                     "nothing still counts as stored, so this is a real failure, not an empty subsystem. "
                     "OPNsenseCollectorDataStale cannot cover this: the snapshot-timestamp gauge is absent "
                     "until the first successful store (deliberately, so it never renders as a 1970 "
                     "epoch), leaving no series to measure staleness against. Usual causes are a missing "
                     "plugin, an API key without permission for that endpoint, or a collector enabled "
                     "against a firewall that does not run the subsystem (#382)."),
    # Split primary vs failover: the default (primary) WAN reconverges in <1m after a reboot, so it
    # keeps a tight for=5m + critical/page. A secondary/failover WAN can take ~7-10m to re-establish
    # (DHCP + dpinger convergence) after a reboot, so it gets for=15m + warning (no page) to avoid
    # false pages during reboots. Requires the default_gateway label (opnsense-exporter >=0.x).
    dict(name="opnsense-gateway-down", title="OPNsenseGatewayDown",
         A='opnsense_gateways_status{default_gateway="true"}', op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense PRIMARY gateway {{ $labels.name }} is offline",
         description="Primary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 5m."),
    dict(name="opnsense-gw-down-failover", title="OPNsenseGatewayDownFailover",
         A='opnsense_gateways_status{default_gateway="false"}', op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense FAILOVER gateway {{ $labels.name }} is offline",
         description="Failover/secondary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 15m. "
                     "Lower urgency — primary WAN unaffected. The 15m window tolerates a router reboot / slow secondary-WAN re-establish."),
    # #405: a dpinger alarm is a transition event, not a replacement for the
    # current-state gateway collector. Count the starts per gateway; a strict >2
    # threshold is three or more starts in this fixed 15-minute observation window.
    dict(name="opnsense-gateway-alarm-flapping", title="OPNsenseGatewayAlarmFlapping",
         A='sum by (opnsense_instance, gateway) '
           '(increase(opnsense_log_events_gateway_total{event="alarm_started"}[15m]))',
         op="gt", params=[2, 0], for_min=0, severity="warning",
         summary="OPNsense gateway {{ $labels.gateway }} alarm is flapping ({{ $labels.opnsense_instance }})",
         description="dpinger emitted three or more alarm_started transitions for gateway {{ $labels.gateway }} in 15m. "
                     "This is transition evidence from syslog, not an assertion that the gateway is currently down; check OPNsenseGatewayDown and the Gateway Status panel for current state."),
    dict(name="opnsense-gateway-high-loss", title="OPNsenseGatewayHighLoss",
         A="opnsense_gateways_loss_percentage", op="gt", params=[20, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} high packet loss",
         description="Gateway {{ $labels.name }} packet loss > 20% for 10m (current {{ $values.A.Value | printf \"%.1f\" }}%)."),
    dict(name="opnsense-gateway-high-rtt", title="OPNsenseGatewayHighRTT",
         A="opnsense_gateways_rtt_milliseconds / (opnsense_gateways_rtt_high_milliseconds > 0)",
         op="gt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} RTT over its high threshold",
         description="Gateway {{ $labels.name }} mean RTT has exceeded its configured high-latency threshold for 10m."),
    dict(name="opnsense-pf-states-near-limit", title="OPNsensePFStateTableNearLimit",
         A="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)",
         op="gt", params=[0.9, 0], for_min=10, severity="warning",
         summary="OPNsense PF state table near its limit",
         description="PF state table is over 90% of its configured limit for 10m."),
    dict(name="opnsense-memory-high", title="OPNsenseMemoryHigh",
         A="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)",
         op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense memory usage high ({{ $labels.opnsense_instance }})",
         description="Physical memory usage has been above 90% for 15m."),
    dict(name="opnsense-disk-usage-high", title="OPNsenseDiskUsageHigh",
         A="opnsense_system_disk_usage_ratio", op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense disk {{ $labels.mountpoint }} almost full",
         description="Filesystem {{ $labels.mountpoint }} ({{ $labels.device }}) usage above 90% for 15m."),
    dict(name="opnsense-high-temperature", title="OPNsenseHighTemperature",
         A="opnsense_temperature_celsius", op="gt", params=[85, 0], for_min=10, severity="warning",
         summary="OPNsense sensor {{ $labels.device }} hot",
         description="Temperature sensor {{ $labels.device }} above 85°C for 10m."),
    dict(name="opnsense-smart-failed", title="OPNsenseSmartHealthFailed",
         A="opnsense_smart_device_health", op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense SMART health failed on {{ $labels.device }}",
         description="SMART overall-health for {{ $labels.device }} ({{ $labels.model }}) reports FAILED."),
    dict(name="opnsense-firmware-needs-reboot", title="OPNsenseFirmwareNeedsReboot",
         A="opnsense_firmware_needs_reboot", op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense needs a reboot ({{ $labels.opnsense_instance }})",
         description="A firmware update flagged that OPNsense needs a reboot."),
    # #373: the stored update check RAN AND FAILED (mirror unreachable, expired
    # subscription, revoked fingerprint, unavailable release train). The series
    # exists only once a check has been stored, so a box that has never checked
    # produces NoData and stays at the default "Ok" state instead of firing —
    # that presence gate is the guard, exactly like opnsense-disk-space-low.
    dict(name="opnsense-update-check-failing", title="OPNsenseUpdateCheckFailing",
         A="opnsense_firmware_update_check_success", op="lt", params=[1, 0],
         for_min=60, severity="warning",
         summary="OPNsense update check failing ({{ $labels.opnsense_instance }})",
         description="opnsense_firmware_update_check_success is 0: the firewall's stored update "
                     "check RAN AND FAILED, so the box cannot currently see security updates. "
                     "opnsense_firmware_update_check_state says which half broke - component "
                     "connection (DNS/proxy/credentials) or component repository "
                     "(fingerprint/subscription/release train). This is NOT real-time mirror "
                     "monitoring: it is the STORED result of a check OPNsense runs roughly daily, "
                     "read through the exporter's firmware response cache, so a failure can take "
                     "up to --exporter.firmware-cache-ttl (default 12h) to appear here and just "
                     "as long to clear after it is fixed. The value is therefore constant across "
                     "that window, so the 1h pending period filters scrape gaps and restarts, "
                     "not mirror flapping."),
    dict(name="opnsense-cert-expiring", title="OPNsenseCertificateExpiringSoon",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 14], for_min=0, severity="warning",
         summary="OPNsense certificate expiring soon: {{ $labels.commonname }}",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 14 days."),
    dict(name="opnsense-cert-expiring-critical", title="OPNsenseCertificateExpiringCritical",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 3], for_min=0, severity="critical",
         summary="OPNsense certificate expiring imminently: {{ $labels.commonname }}",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 3 days."),
    # Exclude on-demand services that are expected to be stopped (e.g. iperf, which only runs during
    # an explicit performance test). Add other expected-down service names to the exclusion as needed.
    dict(name="opnsense-service-down", title="OPNsenseServiceDown",
         A='opnsense_services_status{name!="iperf"}', op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense service {{ $labels.name }} stopped",
         description="Service {{ $labels.name }} ({{ $labels.description }}) has been stopped for 10m. "
                     "On-demand services (e.g. iperf) are excluded. One alert per service."),
    dict(name="opnsense-ntp-unsynced", title="OPNsenseNTPPeerUnreachable",
         A="opnsense_ntp_peer_reach", op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense NTP peer {{ $labels.server }} unreachable",
         description="NTP peer {{ $labels.server }} reachability register has been 0 for 15m."),
    # Unlike opnsense-endpoint-errors, this is a genuine count-in-window threshold (>5 bogus answers
    # per rolling 15m) with for:0 — it fires immediately when the count is exceeded, so there is no
    # for-duration whose meaning the 15m window could distort. The #94 defect (long for paired with an
    # equally-long increase window) does not apply here, so the 15m window is intentional and kept.
    dict(name="opnsense-unbound-dnssec-bogus", title="OPNsenseUnboundDNSSECBogus",
         A="sum by (opnsense_instance) (increase(opnsense_unbound_dns_answers_bogus_total[15m]))",
         op="gt", params=[5, 0], for_min=0, severity="info",
         summary="OPNsense Unbound DNSSEC bogus answers ({{ $labels.opnsense_instance }})",
         description="More than 5 DNSSEC-bogus answers in 15m — possible misconfiguration or tampering."),
    # The syslog/Zenarmor push-based log receiver (#248-#261) had no alert coverage yet — these four
    # close that gap for the log-shipping pipeline itself (sink health, backpressure, label loss,
    # source liveness).
    dict(name="opnsense-logship-sink-errors", title="OPNsenseLogShipSinkErrors",
         A="sum by (opnsense_instance) (rate(opnsense_exporter_logs_ship_errors_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense log-shipping sink retrying ({{ $labels.opnsense_instance }})",
         description="The log-shipping sink (OTLP/Loki) has had failed Emit attempts for 10m. The "
                     "unacknowledged remainder is in retry/degradation, not "
                     "proof of counted record loss. Check OPNsenseLogShipCountedLoss separately."),
    dict(name="opnsense-logship-queue-near-capacity", title="OPNsenseLogShipQueueNearCapacity",
         A="max by (opnsense_instance) ("
           "label_replace(opnsense_exporter_logs_queue_length / "
           "(opnsense_exporter_logs_queue_capacity > 0), \"bound\", \"count\", \"__name__\", \".*\") "
           "or label_replace(opnsense_exporter_logs_queue_bytes / "
           "(opnsense_exporter_logs_queue_max_bytes > 0), \"bound\", \"bytes\", \"__name__\", \".*\"))",
         op="gt", params=[0.9, 0], for_min=5, severity="warning",
         summary="OPNsense log-shipping queue near capacity ({{ $labels.opnsense_instance }})",
         description="The log-shipping backpressure queue has been above 90% of either its record-count "
                     "capacity or its enabled byte budget for 5m — overflow drops are imminent."),
    dict(name="opnsense-logship-counted-loss", title="OPNsenseLogShipCountedLoss",
         A="sum by (opnsense_instance, source, reason) "
           "(increase(opnsense_exporter_logs_dropped_total[15m]))",
         op="gt", params=[0, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping counted record loss ({{ $labels.reason }}) on "
                 "{{ $labels.source }} ({{ $labels.opnsense_instance }})",
         description="Log records were counted as lost in the last 15m, grouped by the exact source and "
                     "reason. overflow means either queue bound evicted the oldest record; "
                     "record_too_large was rejected at ingest; rejected was terminally refused by the "
                     "destination; ship_failed_permanent exhausted the configured retry bound; and "
                     "ship_failed was abandoned during shutdown. Retry attempts alone increment "
                     "logs_ship_errors_total, not this alert."),
    dict(name="opnsense-logship-resource-capped", title="OPNsenseLogShipResourceCapped",
         A="sum by (opnsense_instance) (increase(opnsense_exporter_logs_resource_capped_total[15m]))",
         op="gt", params=[0, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping records had labels dropped ({{ $labels.opnsense_instance }})",
         description="Records were shipped with their opnsense.* resource labels dropped in the last "
                     "15m, so label-scoped queries against them silently under-report."),
    # Scoped to syslog|zenarmor: both are continuously-active push sources, so 15m of silence is a
    # genuine stall. A source that is legitimately quiet or not configured would false-fire if
    # included, so it is deliberately excluded rather than covered here.
    dict(name="opnsense-logship-cursor-stalled", title="OPNsenseLogShipCursorStalled",
         A='time() - max by (opnsense_instance, source) (opnsense_exporter_logs_last_exported_timestamp_seconds{source=~"syslog|zenarmor"})',
         op="gt", params=[900, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping source {{ $labels.source }} stalled ({{ $labels.opnsense_instance }})",
         description="Push source {{ $labels.source }} has shipped no events for 15m despite being "
                     "continuously active. Scoped to syslog|zenarmor only, so a quiet or unconfigured "
                     "source cannot false-fire."),
    # OTLP metric delivery (#388). consecutive_failures is the right signal rather than
    # a rate() on otlp_exports_total{result="error"}: it resets to 0 on the next success,
    # so ">0 sustained" means an ONGOING outage, and it counts from the very first
    # attempt — which covers the never-worked-since-boot case (wrong endpoint, expired
    # credential) that a last-success-staleness rule cannot see, because
    # otlp_last_success_timestamp_seconds is 0 until something lands and time()-0 is a
    # meaningless 56-year age. At the default --otlp.export-interval=60s the 15m pending
    # period is ~15 consecutive failed exports, so a single backend blip or a rolling
    # restart of the collector endpoint does not fire.
    dict(name="opnsense-otlp-delivery-failing", title="OPNsenseOTLPDeliveryFailing",
         A="opnsense_exporter_otlp_consecutive_failures", op="gt", params=[0, 0],
         for_min=15, severity="warning",
         summary="OPNsense exporter OTLP metric delivery failing",
         description="Every OTLP metric export has failed back-to-back for 15m "
                     "({{ $values.A.Value | printf \"%.0f\" }} consecutive failures) — no metrics are "
                     "reaching the OTLP backend. READ THIS BEFORE RELYING ON IT: an exporter cannot ship "
                     "its own failure metric through the path that is failing, so this signal CANNOT REACH "
                     "A PURE-OTLP BACKEND DURING THE OUTAGE. It is for /metrics scrapers, for the operator "
                     "console (which reads it passively), and as post-recovery forensics once delivery "
                     "resumes and the backfilled series shows how long it was broken. On a pure-OTLP "
                     "backend the in-band signal for this failure mode is staleness of the exporter's data "
                     "itself, not this rule. opnsense_exporter_otlp_last_success_timestamp_seconds gives "
                     "the recovery timeline; 0 there means no export has EVER succeeded since startup, "
                     "which points at a wrong endpoint or a bad credential rather than a backend outage — "
                     "the exporter connects lazily, so a clean start proves nothing about delivery (#388)."),
    dict(name="opnsense-ipsec-tunnel-down", title="OPNsenseIPsecTunnelDown",
         A="opnsense_ipsec_phase1_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense IPsec tunnel {{ $labels.name }} down",
         description="IPsec phase1 tunnel {{ $labels.name }} ({{ $labels.description }}) has reported "
                     "status 0 (down; connected=1) for 10m. Catches a tunnel dropping while the daemon "
                     "itself keeps running, which opnsense-service-down misses."),
    # Verified semantics: 1=up, 0=down, 2=unknown, 3=stale. lt 1 fires on 0 only — 2/3 are
    # deliberately NOT alerted, since unknown/stale is not the same claim as confirmed down.
    dict(name="opnsense-wireguard-peer-down", title="OPNsenseWireGuardPeerDown",
         A="opnsense_wireguard_peer_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense WireGuard peer {{ $labels.peer_name }} down",
         description="WireGuard peer {{ $labels.peer_name }} on {{ $labels.device_name }} has reported "
                     "status 0 (down) for 10m. Status values are 1=up, 0=down, 2=unknown, 3=stale — "
                     "this alert deliberately fires on 0 only, not on unknown/stale."),
    # remote_services_total>0 is load-bearing: reachable=0 also means "HA sync isn't configured at
    # all", so the guard restricts firing to boxes where HA sync is actually set up.
    dict(name="opnsense-hasync-unreachable", title="OPNsenseHASyncUnreachable",
         A="opnsense_hasync_remote_reachable == 0 and on(opnsense_instance) "
           "(opnsense_hasync_remote_services_total > 0)",
         op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense HA sync peer unreachable ({{ $labels.opnsense_instance }})",
         description="opnsense_hasync_remote_reachable has been 0 for 10m on a box where HA sync is "
                     "configured (remote_services_total > 0). The guard excludes boxes with HA sync "
                     "unconfigured, where reachable=0 is the normal, expected reading."),
    # carp_vip_status: 1=MASTER, 0=BACKUP (both normal — inside the [0,1] range), 2=INIT, -1=unknown
    # (faults — outside the range). The `unless` clause suppresses alerts during deliberate maintenance
    # mode.
    dict(name="opnsense-carp-vip-fault", title="OPNsenseCARPVIPFault",
         A="opnsense_carp_vip_status unless on(opnsense_instance) (opnsense_carp_maintenance_mode == 1)",
         op="outside_range", params=[0, 1], for_min=5, severity="warning",
         summary="OPNsense CARP VIP {{ $labels.vip }} fault on {{ $labels.interface }}",
         description="CARP VIP {{ $labels.vip }} on {{ $labels.interface }} has been outside the normal "
                     "MASTER(1)/BACKUP(0) range for 5m — status 2 (INIT) or -1 (unknown). BACKUP is a "
                     "normal, healthy state and does not fire; this only fires on INIT/unknown. "
                     "Suppressed while opnsense_carp_maintenance_mode is 1."),
    # #405: kernel CARP transitions are EVENTS, and these two rules complement
    # OPNsenseCARPVIPFault above rather than replacing it — that one reads the
    # current-state gauge, these read the transitions the gauge cannot retain.
    # Grouped by interface AND vhid because a vhid is only unique within an interface.
    #
    # THRESHOLD: strict >3, i.e. four or more changes in the window. A boot/init
    # sequence is INIT -> BACKUP -> MASTER (two changes) and a single failover is one,
    # so four-or-more sits above one planned event with margin.
    #
    # This DELIBERATELY DIVERGES from the dpinger sibling OPNsenseGatewayAlarmFlapping
    # below, which uses >2 — do not "fix" the two to match. They are different event
    # shapes: dpinger emits alarm/clear PAIRS for one gateway, so >2 there is calibrated
    # against a pair count, whereas CARP emits one record per state edge and a normal
    # boot already spends two of them. Matching the numbers for symmetry would make this
    # rule page on every planned failover.
    dict(name="opnsense-carp-state-flapping", title="OPNsenseCARPStateFlapping",
         A='sum by (opnsense_instance, interface, vhid) '
           '(increase(opnsense_log_events_carp_total{event="state_changed"}[15m]))',
         op="gt", params=[3, 0], for_min=0, severity="warning",
         summary="OPNsense CARP vhid {{ $labels.vhid }} is flapping on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="Four or more CARP state changes for vhid {{ $labels.vhid }} on interface "
                     "{{ $labels.interface }} in 15m. A boot sequence is two changes "
                     "(INIT -> BACKUP -> MASTER) and a single failover is one, so neither fires. "
                     "This is transition evidence from "
                     "syslog, not an assertion about the current state; read the kernel's cause from "
                     "the carp.reason field on the shipped log records, and check OPNsenseCARPVIPFault "
                     "and the CARP VIP Status panel for where the VIP actually sits now."),
    # Demotion is how a node steps back from being master: pfsync bulk transfer, a
    # service disruption, or an interface being taken down.
    #
    # THRESHOLD: strict >3, i.e. four or more demotions in the window. DO NOT "tighten"
    # this to >0 for sensitivity — that is the trap, and the #405 capture proves it.
    # The evidence window recorded 11 `demoted by 240 (pfsync bulk start)` and 11
    # `demoted by -240 (pfsync bulk fail)` records: demotion during pfsync bulk transfer
    # is ROUTINE OPERATION, so >0 pages on a healthy cluster doing exactly what it is
    # supposed to do, and an alert that fires on normal behaviour trains people to
    # ignore it. One bulk cycle is one `demoted` plus one `promoted`, so this is
    # effectively a bulk-cycle counter; four or more in fifteen minutes is churn rather
    # than routine sync.
    #
    # increase(), NOT rate(): the threshold is a COUNT OVER THE WINDOW. rate() is
    # per-second, so four events in 15m is 0.0044/s and any threshold >=1 on a rate()
    # could never fire — a silently dead alert. increase() is still rate-derived rather
    # than a bare cumulative total, which is what matters here.
    dict(name="opnsense-carp-unexpected-demotion", title="OPNsenseCARPUnexpectedDemotion",
         A='sum by (opnsense_instance) '
           '(increase(opnsense_log_events_carp_total{event="demoted"}[15m]))',
         op="gt", params=[3, 0], for_min=0, severity="warning",
         summary="OPNsense CARP node is demoting itself ({{ $labels.opnsense_instance }})",
         description="Four or more positive CARP demotion adjustments in 15m — this node keeps making "
                     "itself less willing to be master. A single pfsync bulk transfer demotes and then "
                     "promotes once and does NOT fire; this threshold sits above routine sync so it "
                     "means churn. Common causes are repeated pfsync bulk "
                     "transfers, a service disruption, or an interface flapping; the kernel states "
                     "which on the shipped log record as carp.reason, with the signed adjustment in "
                     "carp.demotion.delta and the resulting level in carp.demotion.total. Neither the "
                     "cause nor those numbers is a metric label. Compare opnsense_carp_demotion for the "
                     "current level, and note the matching promoted event when the demotion is released."),
    # Threshold and lookback are deployment-specific: tune --exporter.ids-alert-lookback and the 50
    # threshold per site, same tone as opnsense-unbound-dnssec-bogus above. Verified: action is only
    # ever allowed/blocked — no drop/reject values exist.
    dict(name="opnsense-ids-alert-spike", title="OPNsenseIDSAlertSpike",
         A='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})',
         op="gt", params=[50, 0], for_min=5, severity="info",
         summary="OPNsense IDS blocked-alert spike ({{ $labels.opnsense_instance }})",
         description="More than 50 blocked IDS alerts held in the recent-alerts window for 5m. The "
                     "threshold and --exporter.ids-alert-lookback window are deployment-specific — tune "
                     "both per site. action is only ever allowed/blocked (no drop/reject)."),
    # No bytes are lost on eviction (the oldest is force-emitted, not dropped), so this is a warning,
    # not a page: the correlate window can no longer be held under current flow volume.
    dict(name="opnsense-flow-correlator-evicting", title="OPNsenseFlowCorrelatorEvicting",
         A="sum by (opnsense_instance) (rate(opnsense_flow_correlator_evicted_total[5m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense flow correlator evicting entries ({{ $labels.opnsense_instance }})",
         description="The flow correlator has force-emitted entries for 15m because "
                     "--flow.correlate.max-entries is binding under current flow volume. No bytes are "
                     "lost, but the cap should be raised so the accumulator can hold a full correlate "
                     "window; sustained eviction shortens the effective join window and lowers the "
                     "merged hit-rate."),
    # Metrics are never truncated, only per-flow logs, so this is a warning about log completeness and a
    # possible flood on the unauthenticated NetFlow ingress rather than a data-integrity page.
    dict(name="opnsense-flow-logs-truncated", title="OPNsenseFlowLogsTruncated",
         A="sum by (opnsense_instance) (rate(opnsense_flow_logs_truncated_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense flow logs truncated by budget ({{ $labels.opnsense_instance }})",
         description="Flow log records have been dropped by the --flow.max-logs-per-window budget for "
                     "10m. Metrics are unaffected, but per-flow logs are incomplete. Raise the budget if "
                     "this is expected volume, or restrict the unauthenticated NetFlow ingress with "
                     "--flow.netflow.allowed-peers if it is a flood."),
    # #402: managed alert for the #368 dead-hook detector. Query is copied VERBATIM from
    # docs/flow.md ("Joining the two label spaces") - do not simplify it, each clause kills
    # a specific false positive. Clause 1 restricts to interfaces actually configured for
    # capture. Clause 2 is the only signal a dead hook cannot hide from: ng_netflow fills one
    # side of every flow from a FIB lookup, so merged flow records can still name a dead
    # interface via a peer's route - only the interface's OWN cache node proves it silent.
    # Clause 3 is what tells a dead hook from a legitimately idle interface (a quiet guest
    # VLAN's cache node is flat too; pf confirms bytes actually crossed the device). Clause 4
    # is the honesty guard: it withdraws the whole query once the box's own NetFlow active
    # timeout is at least the 45m observation window, rather than letting a shorter box-side
    # timeout make "45m of silence" a lie. Do NOT read NetFlow source_id=0 as loss elsewhere -
    # it is not a sequence counter. Live-verified 2026-07-25 against the reference box: exactly
    # one row, {interface="AAISP", device="pppoe0"} - the hook whose death took a packet
    # capture to find.
    dict(name="opnsense-netflow-hook-dead", title="OPNsenseNetFlowHookDead",
         A="max by (opnsense_instance, interface, device) (\n"
           "  (opnsense_netflow_capture_expected == 1)\n"
           "    * on (opnsense_instance, interface) group_left (device) opnsense_flow_interface_info\n"
           ")\n"
           "and on (opnsense_instance, device) max by (opnsense_instance, device) (\n"
           "  label_join(increase(opnsense_netflow_cache_packets_total[45m]), \"device\", \"\", "
           "\"interface\") == 0\n"
           ")\n"
           "and on (opnsense_instance, device) max by (opnsense_instance, device) (\n"
           "  label_join(increase(opnsense_firewall_in_ipv4_pass_bytes_total[45m]), \"device\", \"\", "
           "\"interface\") > 0\n"
           ")\n"
           "and on (opnsense_instance) (opnsense_netflow_capture_active_timeout_seconds < 2700)",
         op="gt", params=[0, 0], for_min=5, severity="warning",
         summary="OPNsense NetFlow hook dead on {{ $labels.interface }} ({{ $labels.device }})",
         description="The NetFlow hook configured for interface {{ $labels.interface }} (kernel device "
                     "{{ $labels.device }}) on {{ $labels.opnsense_instance }} has recorded zero packets "
                     "on its own ng_netflow node (opnsense_netflow_cache_packets_total) for 45m while pf "
                     "keeps passing traffic on the same device (opnsense_firewall_in_ipv4_pass_bytes_total "
                     "> 0) - the #368 pppoe0 failure mode, where ng_netflow accepted a bogus hook on a "
                     "PPPoE interface and silently captured nothing, because ng_netflow attaches to mpd's "
                     "framing node rather than the ng_iface node ng_pppoe exposes. The alert withdraws "
                     "itself if the box's own configured NetFlow active timeout is 45m (2700s) or more, "
                     "rather than call a shorter window dead on an honesty guard it cannot clear - check "
                     "opnsense_netflow_capture_active_timeout_seconds first if this never fires on a box "
                     "you know has a dead hook. On firing: open the operator console's NetFlow / ifIndex "
                     "tab, confirm {{ $labels.device }} is a real ng_netflow node with `ngctl list` on the "
                     "box, then rebind the capture to the correct kernel device. See docs/flow.md "
                     "('Joining the two label spaces') for the full derivation. Resolves automatically "
                     "once opnsense_netflow_cache_packets_total resumes counting on the device."),
]

# Recording rules: metric name (level:metric:operation) + value query.
RECORDING = [
    dict(metric="instance:opnsense_interface_rx_bits:rate5m",
         expr="sum by (opnsense_instance, interface) (rate(opnsense_interfaces_received_bytes_total[5m])) * 8"),
    dict(metric="instance:opnsense_interface_tx_bits:rate5m",
         expr="sum by (opnsense_instance, interface) (rate(opnsense_interfaces_transmitted_bytes_total[5m])) * 8"),
    dict(metric="instance:opnsense_firewall_block_packets:rate5m",
         expr="sum by (opnsense_instance, interface) ("
              "rate(opnsense_firewall_in_ipv4_block_packets_total[5m]) + rate(opnsense_firewall_out_ipv4_block_packets_total[5m]) + "
              "rate(opnsense_firewall_in_ipv6_block_packets_total[5m]) + rate(opnsense_firewall_out_ipv6_block_packets_total[5m]))"),
    dict(metric="instance:opnsense_pf_state:utilization",
         expr="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)"),
    dict(metric="instance:opnsense_unbound_cache:hit_ratio",
         expr="rate(opnsense_unbound_dns_cache_hits_total[5m]) / "
              "(rate(opnsense_unbound_dns_cache_hits_total[5m]) + rate(opnsense_unbound_dns_cache_miss_total[5m]) > 0)"),
    dict(metric="instance:opnsense_unbound_queries:rate5m",
         expr="rate(opnsense_unbound_dns_queries_total[5m])"),
    dict(metric="instance:opnsense_gateway_loss:ratio",
         expr="opnsense_gateways_loss_percentage / 100"),
    dict(metric="instance:opnsense_system_mem:utilization",
         expr="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)"),
    dict(metric="instance:opnsense_zenarmor_block:ratio5m",
         expr='sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total{action="block"}[5m])) / '
              '(sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total[5m])) > 0)'),
    dict(metric="instance:opnsense_haproxy_5xx:ratio5m",
         expr='sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total{status_class="5xx"}[5m])) / '
              '(sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total[5m])) > 0)'),
    dict(metric="instance:opnsense_ipsec_tunnels_down:count",
         expr="sum by (opnsense_instance) (opnsense_ipsec_phase1_status == bool 0)"),
    dict(metric="instance:opnsense_wireguard_peers_down:count",
         expr="sum by (opnsense_instance) (opnsense_wireguard_peer_status == bool 0)"),
    dict(metric="instance:opnsense_ids_alerts:active",
         expr='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})'),
    # Pins source="netflow" deliberately. The flow family carries TWO independent measurements of the
    # same traffic (Zenarmor and NetFlow) and #346 decision 3 forbids summing them; NetFlow post-repair
    # is authoritative for volume, so pinning it here gives a double-count-safe per-WAN byte rate that
    # dashboards and alerts can build on without every query having to remember the source filter.
    dict(metric="instance:opnsense_flow_bytes:rate5m",
         expr='sum by (opnsense_instance, interface, direction) '
              '(rate(opnsense_flow_bytes_total{source="netflow"}[5m]))'),
]

def grafana_for(for_min: int) -> str:
    return "0s" if not for_min else f"{for_min}m0s"


def emit_grafana_managed(ds: str, folder: str, stack: bool):
    outdir = os.path.join(HERE, "grafana-managed")
    os.makedirs(outdir, exist_ok=True)
    for stale in os.listdir(outdir):  # clear stale manifests so renames don't linger
        if stale.endswith(".json"):
            os.remove(os.path.join(outdir, stale))
    written = []
    # Folder manifest (named so its UID == folder); pushed first so the rules resolve.
    folder_manifest = {
        "apiVersion": "folder.grafana.app/v1beta1", "kind": "Folder",
        "metadata": {"name": folder},
        "spec": {"title": "OPNsense Exporter Alerts"},
    }
    fp = os.path.join(outdir, "_folder.json")
    with open(fp, "w") as f:
        json.dump(folder_manifest, f, indent=2)
        f.write("\n")
    written.append(fp)
    for r in RULES:
        labels = {"severity": r["severity"]}
        if stack:
            labels["domain"] = "infra"
            if r["severity"] == "critical":
                labels["page"] = "true"
        cond = {"evaluator": {"type": r["op"], "params": r["params"]},
                "operator": {"type": "and"}, "query": {"params": []},
                "reducer": {"type": "last", "params": []}, "type": "query"}
        manifest = {
            "apiVersion": "rules.alerting.grafana.app/v0alpha1", "kind": "AlertRule",
            "metadata": {"name": r["name"],
                         "annotations": {"grafana.app/folder": folder},
                         "labels": {"grafana.app/folder": folder}},
            "spec": {
                "title": r["title"], "noDataState": r.get("nodata", "Ok"),
                "execErrState": "Error", "for": grafana_for(r["for_min"]),
                "trigger": {"interval": "1m"}, "labels": labels,
                "annotations": {"summary": r["summary"], "description": r["description"],
                                "runbook_url": RUNBOOK_URL},
                "expressions": {
                    "A": {"datasourceUID": ds,
                          "relativeTimeRange": {"from": "15m0s", "to": "0s"},
                          "model": {"datasource": {"type": "prometheus", "uid": ds},
                                    "editorMode": "code", "expr": r["A"], "instant": True,
                                    "range": False, "intervalMs": 60000,
                                    "maxDataPoints": 43200, "refId": "A"}},
                    "C": {"model": {"datasource": {"type": "__expr__", "uid": "__expr__"},
                                    "expression": "A", "type": "threshold", "refId": "C",
                                    "intervalMs": 1000, "maxDataPoints": 43200,
                                    "conditions": [cond]},
                          "source": True},
                },
            },
        }
        p = os.path.join(outdir, f"{r['name']}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        written.append(p)
    for r in RECORDING:
        labels = {"domain": "infra"} if stack else {}
        # Grafana rule UIDs are capped at 40 chars; keep the slug compact.
        short = (r["metric"].replace("instance:opnsense_", "").replace("opnsense_", "")
                 .replace(":", "-").replace("_", "-"))
        slug = "oxrec-" + short
        manifest = {
            "apiVersion": "rules.alerting.grafana.app/v0alpha1", "kind": "RecordingRule",
            "metadata": {"name": slug,
                         "annotations": {"grafana.app/folder": folder},
                         "labels": {"grafana.app/folder": folder}},
            "spec": {"title": r["metric"], "metric": r["metric"],
                     "targetDatasourceUID": ds, "paused": False,
                     "trigger": {"interval": "1m"}, "labels": labels,
                     "expressions": {"A": {"datasourceUID": ds,
                                           "relativeTimeRange": {"from": "10m0s", "to": "0s"},
                                           "model": {"datasource": {"type": "prometheus", "uid": ds},
                                                     "editorMode": "code", "expr": r["expr"],
                                                     "format": "table", "instant": True,
                                                     "range": False,
                                                     "intervalMs": 1000, "maxDataPoints": 43200,
                                                     "refId": "A"},
                                           "source": True}}},
        }
        p = os.path.join(outdir, f"{slug}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        written.append(p)
    return outdir, written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasource", default="grafanacloud-prom")
    ap.add_argument("--folder", default="opnsense-alerts")
    ap.add_argument("--stack", action="store_true",
                    help="add IRM label contract (domain=infra; page=true on critical)")
    args = ap.parse_args()

    outdir, written = emit_grafana_managed(args.datasource, args.folder, args.stack)
    print(f"wrote {len(written)} grafana-managed manifests to {outdir}")
    print(f"alerts: {len(RULES)}  recording rules: {len(RECORDING)}  stack-labels: {args.stack}")


if __name__ == "__main__":
    main()
