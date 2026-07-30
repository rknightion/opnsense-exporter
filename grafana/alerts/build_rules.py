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
    python3 build_rules.py --health-folder <name>  # exporter self-health folder (#431)

Alerts are defined as a value-producing query `A` plus a threshold condition, rendered to the
Grafana A→C query/threshold node pipeline.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GRAFANA_DIR = os.path.dirname(HERE)
RUNBOOKS_MD_PATH = os.path.join(GRAFANA_DIR, "runbooks.md")
# The runbook URL is shared with the dashboard's own "Alert runbooks" link (#419):
# one registry, so an alert notification and the dashboard can never point at two
# different pages. `runbook_url()` builds the PER-RULE anchor into runbooks.md (#430).
sys.path.insert(0, os.path.dirname(HERE))
from uids import RUNBOOK_URL, runbook_url  # noqa: E402

# ---- panel links (#530) ---------------------------------------------------
# An alert notification says WHAT crossed a threshold. `panel=` says WHERE to look,
# so Grafana's "View panel" lands the responder on the canonical graph instead of a
# dashboard they then have to search.
#
# The two generated dashboards are read, never hand-listed: the operational rules
# link into the main dashboard and the exporter-health rules into the health one,
# which is the same split as the two alert folders.
DASHBOARD_DOCS = (
    os.path.join(GRAFANA_DIR, "dashboard.json"),
    os.path.join(GRAFANA_DIR, "dashboard-health.json"),
)
_panel_index_cache = None

# #430: every alert's summary should identify WHICH box fired when the query can carry
# opnsense_instance at all - a bare "gateway X is down" is ambiguous the moment more
# than one firewall is scraped. This is the documented exception list (style matches
# grafana/annotations.py's NOT_ANNOTATED): a rule goes here only when its own source
# metric structurally cannot carry the label, never as a shortcut to skip writing it in.
#
# EMPTY, and that is the finding. Its only entry was opnsense-otlp-delivery-failing,
# exempted because opnsense_exporter_otlp_consecutive_failures was registered bare
# against telemetry.Start's raw registry and carried no opnsense_instance to put in a
# summary. #466 fixed the registration rather than the summary, so the exemption
# became false and was removed. Keep the mechanism: the next family that genuinely
# cannot carry the label needs somewhere to say so with a reason.
SUMMARY_INSTANCE_EXEMPT: dict = {}

# Each alert: name(slug), title, A (value query), cond (op, params), for_min, severity,
# summary, description. op in {gt, lt, within_range, outside_range}.
RULES = [
    dict(name="opnsense-exporter-down", title="OPNsenseExporterDown",
         selfhealth=True,
         A="opnsense_up", op="lt", params=[1, 0], for_min=15, severity="critical",
         nodata="Alerting",
         summary="OPNsense exporter/box down ({{ $labels.opnsense_instance }})",
         description="opnsense_up has been 0 (the OPNsense API was unreachable / the scrape failed) "
                     "or the target produced NoData for 15m. opnsense_up reflects API reachability ONLY - "
                     "a reachable box reporting a degraded subsystem (e.g. a crash report) stays up=1 and is "
                     "covered by the lower-severity OPNsenseCrashReports / OPNsenseFirewallUnhealthy alerts, "
                     "so this critical/page fires on genuine unreachability only. The 15m window tolerates a "
                     "router reboot (typically <10m) without paging.",
         runbook=dict(
             measures="opnsense_up: whether the exporter's most recent poll of the OPNsense system-status API succeeded at all. It is reachability-only - a reachable box self-reporting a degraded subsystem stays at 1.",
             threshold='lt 1 for 15m. The 15m window is sized to ride out a normal reboot (typically <10m) without paging.',
             absent="noDataState is Alerting - a totally-missing series (the whole fleet gone) pages immediately here. A SINGLE instance disappearing while others keep reporting is Grafana's MissingSeries case instead, which this rule structurally cannot see; OPNsenseExporterInstanceMissing exists to catch that.",
             checks=[
                'Check the Prometheus Targets page for this scrape target before assuming the firewall itself is down - it may be a network path or scrape-config problem',
                'Read opnsense_system_status_code and the crash-reporter/firewall-status gauges for the same instance - if those are non-zero the box is reachable but sick, a different alert',
                'Reach the OPNsense box directly (console/SSH) to tell a full outage from an API-only fault',
            ],
             causes=[
                'The OPNsense box is powered off, rebooting past the 15m grace window, or unreachable over the network',
                'The OPNsense API credentials were revoked/expired or the API service crashed',
                'The exporter process itself died or lost its network path to the firewall',
            ],
             verify=[
                'opnsense_up reads 1 again on the next scrape for the named instance',
                "No further NoData gap appears on the Overview tab's Exporter/API panels for at least one full scrape interval",
            ],
         )),
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
         selfhealth=True,
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
                     "self-resolves once it has been absent for 1h; silence it until then.",
         runbook=dict(
             measures='Compares a 1h present_over_time baseline of opnsense_up against what is reporting right now, `unless`-subtracting instances still present - what survives is exactly the set that has vanished while at least one other instance keeps reporting.',
             threshold='gt 0 for 10m. The 1h lookback is a historical baseline, not a configured inventory: self-protecting for a new exporter once it has been up an hour, at the cost of alerting for up to that hour after a deliberate decommission.',
             absent='noDataState is Ok on purpose: if the WHOLE fleet disappears this query also returns nothing, and OPNsenseExporterDown already pages for that case - alerting here too would double-page one event.',
             checks=[
                'Read the firing opnsense_instance label and check whether that scrape target still exists in Prometheus service discovery',
                'Check whether that instance was deliberately decommissioned - if so, silence it rather than chase it',
                'Look for a label change on that instance in the last hour (version bump, relabel, scrape-config edit) - a changed label set can itself look like a vanished instance (#472)',
            ],
             causes=[
                'The exporter process for that instance was stopped or its host decommissioned',
                'The exporter crashed or its host went down unexpectedly',
                'Prometheus stopped scraping that target (dropped from service discovery, firewall rule, DNS failure)',
            ],
             verify=[
                "The named instance's opnsense_up series is present and back at 1 on the next scrape",
                'The instance no longer appears as a firing alert instance after one more evaluation cycle',
            ],
         )),
    dict(name="opnsense-firewall-unhealthy", title="OPNsenseFirewallUnhealthy",
         A="opnsense_firewall_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense firewall health check failing ({{ $labels.opnsense_instance }})",
         description="opnsense_firewall_status has reported 0 (errors) for 10m.",
         runbook=dict(
             measures="opnsense_firewall_status, the firewall subsystem's own entry in OPNsense's combined system-status payload (the same API call opnsense_up is derived from).",
             threshold='lt 1 (0 = errors reported) sustained for 10m.',
             absent='Default noDataState (Ok). Because this comes from the same status call as opnsense_up, a total absence here usually means the whole status API is unreachable - which OPNsenseExporterDown already covers - rather than an independent signal to alert on.',
             checks=[
                'Check opnsense_system_status_code and opnsense_crash_reporter_status for the same instance - OPNsense reports these as one combined payload',
                "Open the OPNsense UI's own Dashboard status widget for the actual subsystem error text, which this gauge cannot carry",
                'Confirm opnsense_up is still 1 - if it is 0 too, this is a symptom of full unreachability, not an independent firewall fault',
            ],
             causes=[
                'A firewall ruleset failed to apply or reload cleanly',
                'pf itself is reporting an internal error state',
                'A subsystem that rolls up into firewall health (e.g. Suricata/IDS) broke',
            ],
             verify=[
                'opnsense_firewall_status returns to 1',
                "The OPNsense UI's own status widget for this subsystem shows OK/green",
            ],
         )),
    dict(name="opnsense-crash-reports", title="OPNsenseCrashReports",
         A="opnsense_crash_reporter_status", op="lt", params=[1, 0], for_min=5, severity="warning",
         summary="OPNsense crash reports present ({{ $labels.opnsense_instance }})",
         description="opnsense_crash_reporter_status is 0 — one or more crash reports are present.",
         runbook=dict(
             measures="opnsense_crash_reporter_status: whether OPNsense's own crash-report collector has one or more unreviewed crash reports on disk.",
             threshold='lt 1 (0 = reports present) sustained for 5m.',
             absent='Default noDataState (Ok) - absence means the status API itself is down, covered by OPNsenseExporterDown, not that crash reports are clear.',
             checks=[
                "Open the OPNsense UI's crash reporter page to read the actual report(s), which the gauge cannot carry",
                'Check whether the crash coincides with a recent firmware/plugin update',
                'Confirm opnsense_up is 1 - this fires independently of reachability, on a box that is otherwise healthy',
            ],
             causes=[
                "A daemon or kernel module crashed and OPNsense's monitor captured a core/report",
                'A plugin update introduced a regression',
            ],
             verify=[
                'The crash report is reviewed and cleared in the OPNsense UI',
                'opnsense_crash_reporter_status returns to 1 and no new report appears after clearing it',
            ],
         )),
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
                     "Absent means healthy — OPNsense omits an OK subsystem from the health-check payload.",
         runbook=dict(
             measures='opnsense_system_subsystem_status_code{subsystem="diskspace"}, OPNsense\'s own root filesystem health-check subsystem (2=OK, 1=NOTICE, 0=WARNING nearly full, -1=ERROR critically full).',
             threshold='lt 2 (below OK) sustained for 10m.',
             absent='Absent means healthy on purpose - OPNsense omits an OK subsystem from the health-check payload entirely rather than emitting a 2, so noDataState is deliberately left at the default Ok.',
             checks=[
                'Check actual root filesystem usage on the box (`df -h /`) rather than relying on the coarse 4-value gauge',
                'Look for a runaway log, a stuck package cache, or a full config-backup history filling the root partition',
            ],
             causes=[
                'Log rotation is misconfigured or a service is logging excessively',
                'Firmware/package upgrade left old files uncleaned',
                'The root partition is simply undersized for the installed plugin set',
            ],
             verify=[
                'The subsystem key disappears from the payload again (return to the healthy, absent-means-OK state) or reads 2',
                '`df -h /` on the box shows headroom restored',
            ],
         )),
    # The alert-condition window MUST be short (2m) so the long for:15m actually measures how long
    # errors PERSIST. If the window equals for (both 15m), increase()>0 stays true for 15m after the
    # last error, so for:15m is satisfied by any burst spanning >1 eval interval and the alert fires
    # ~15m AFTER recovery (#94). With a 2m window, an 8m error burst keeps the condition true only
    # ~t=0..10m (<15m) → for:15m never elapses → no false page; genuinely sustained errors keep every
    # rolling 2m window non-empty, so the condition stays true past 15m and the alert fires.
    dict(name="opnsense-endpoint-errors", title="OPNsenseEndpointErrors",
         selfhealth=True,
         A="sum by (opnsense_instance, endpoint) (increase(opnsense_exporter_endpoint_errors_total[2m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense exporter endpoint errors on {{ $labels.endpoint }} ({{ $labels.opnsense_instance }})",
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
                     "scales its tolerance with each collector's own interval.",
         runbook=dict(
             measures='Per-endpoint count of opnsense_exporter_endpoint_errors_total increases in rolling 2m windows, summed by opnsense_instance and endpoint - a FAST/MEDIUM-tier signal that names which API call is failing.',
             threshold="gt 0 for 15m, with a deliberately short 2m inner window: a burst under ~10m clears the 2m window before the 15m pending period elapses, so a router reboot doesn't false-page (#94), while genuinely sustained errors keep every rolling 2m window non-empty.",
             absent='Default noDataState (Ok) - no errors means no series, which is the healthy state, not an outage signal.',
             checks=[
                'Read the endpoint label to know exactly which OPNsense API call is failing',
                "Check the exporter's own logs for the HTTP status/error body from that endpoint",
                'Confirm the API key/secret still has permission for that endpoint, and that any gating plugin is still installed',
            ],
             causes=[
                'An API key was revoked or its permissions narrowed',
                'The relevant OPNsense plugin was removed or is misbehaving',
                'OPNsense itself returned malformed or unexpected data for that endpoint',
            ],
             verify=[
                'The 2m rolling increase() for that endpoint returns to 0 and stays there',
                'opnsense_exporter_scrape_collector_success for the owning collector reads 1 again',
            ],
         )),
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
         selfhealth=True,
         A="(time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds",
         op="gt", params=[3, 0], for_min=5, severity="warning",
         summary="OPNsense collector {{ $labels.collector }} is serving stale data ({{ $labels.opnsense_instance }})",
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
                     "too (#382).",
         runbook=dict(
             measures="How many of a collector's own poll intervals have elapsed since its stored metric buffer was last replaced (time() minus the snapshot timestamp, minus a 120s scrape-lag allowance, divided by the collector's own poll interval) - staleness expressed in MISSED INTERVALS so one rule covers every tier.",
             threshold='gt 3 missed intervals for 5m, which works out to roughly 8m on the fast (15s) tier and 52m on the cold (15m) tier; one failed poll followed by recovery peaks at ~2 missed intervals on any tier and cannot fire.',
             absent='Both feeding gauges are absent until first successfully stored, so a collector that has NEVER stored data produces no series here and cannot alert on staleness - that gap is what OPNsenseCollectorNeverStoredData exists to close.',
             checks=[
                'Read the collector label and check opnsense_exporter_scrape_collector_success and the endpoint-error panels for that same collector',
                "Note the last-poll-timestamp panel is USELESS here - it advances on every failed attempt too, so don't use it to judge freshness",
                "Confirm the dashboard's stale value is old but not blanked - retained last-good data is deliberate (#336 D8), so a flat panel does not mean the outage just started",
            ],
             causes=[
                "The collector's endpoint started erroring on every attempt",
                'A plugin the collector depends on was removed or disabled',
                'The firewall itself stopped exposing that data (feature disabled, subsystem down)',
            ],
             verify=[
                'The missed-interval expression drops back under 3 and stays there for at least one poll interval',
                'opnsense_exporter_collector_snapshot_timestamp_seconds advances again on schedule',
            ],
         )),
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
         selfhealth=True,
         A="((time() - opnsense_exporter_collector_last_success_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds) "
           "unless on(opnsense_instance, collector) "
           "(((time() - opnsense_exporter_collector_snapshot_timestamp_seconds - 120) "
           "/ opnsense_exporter_collector_poll_interval_seconds) > 3)",
         op="gt", params=[6, 0], for_min=10, severity="info",
         summary="OPNsense collector {{ $labels.collector }} has not fully succeeded ({{ $labels.opnsense_instance }})",
         description="Collector {{ $labels.collector }} is still refreshing its stored metrics, but no "
                     "poll has completed CLEANLY for more than 6 of its own poll intervals "
                     "({{ $values.A.Value | printf \"%.1f\" }} missed intervals). That is the "
                     "persistent-partial-failure signature: one endpoint of a multi-endpoint collector "
                     "erroring every poll while the rest keep updating, so part of its metric set is "
                     "silently absent or frozen while everything looks fresh. Tolerance is in MISSED "
                     "INTERVALS so it scales with the collector's tier, and the rule deliberately excludes "
                     "collectors already covered by OPNsenseCollectorDataStale (fully frozen data), which "
                     "would otherwise fire both. Severity is info, not warning: data is still flowing, and "
                     "the endpoint-error panels name the failing endpoint (#382).",
         runbook=dict(
             measures='The same missed-interval-age expression as OPNsenseCollectorDataStale, but built from opnsense_exporter_collector_last_success_timestamp_seconds (last fully CLEAN poll) rather than the snapshot timestamp, with an `unless` clause suppressing anything already covered by that fully-stale rule.',
             threshold='gt 6 missed intervals for 10m - looser than the 3-interval stale threshold, because the collector IS still refreshing partial data; this is degradation, not a freeze.',
             absent='No dedicated nodata handling (default Ok) - same absent-until-first-store gap as OPNsenseCollectorDataStale.',
             checks=[
                'Read the collector label and check its endpoint-error panels - the classic shape is one endpoint of a multi-endpoint collector erroring every poll while the rest keep updating',
                'Confirm this collector is NOT also firing OPNsenseCollectorDataStale - if it is, treat that as the primary signal',
                'Check whether a specific sub-feature (not the whole collector) is missing from its metrics on the dashboard',
            ],
             causes=[
                'One endpoint of a multi-endpoint collector is failing every poll while its sibling endpoints keep succeeding',
                "A specific plugin sub-feature was disabled or lost permission while the rest of the collector's data source stayed healthy",
            ],
             verify=[
                'The missed-interval expression built from last_success drops back under 6',
                'The endpoint-error panel for the previously-failing endpoint returns to zero increase',
            ],
         )),
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
         selfhealth=True,
         A="opnsense_exporter_collector_last_poll_timestamp_seconds "
           "unless on(opnsense_instance, collector) "
           "opnsense_exporter_collector_snapshot_timestamp_seconds",
         op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense collector {{ $labels.collector }} has never returned data ({{ $labels.opnsense_instance }})",
         description="Collector {{ $labels.collector }} has been polling for 30m and has never once stored "
                     "a metric buffer — every poll since the exporter started has failed with nothing to "
                     "emit, so it exports no domain metrics at all. A clean poll that legitimately finds "
                     "nothing still counts as stored, so this is a real failure, not an empty subsystem. "
                     "OPNsenseCollectorDataStale cannot cover this: the snapshot-timestamp gauge is absent "
                     "until the first successful store (deliberately, so it never renders as a 1970 "
                     "epoch), leaving no series to measure staleness against. Usual causes are a missing "
                     "plugin, an API key without permission for that endpoint, or a collector enabled "
                     "against a firewall that does not run the subsystem (#382).",
         runbook=dict(
             measures='opnsense_exporter_collector_last_poll_timestamp_seconds present (the scheduler has attempted this collector) `unless` opnsense_exporter_collector_snapshot_timestamp_seconds present (it has ever stored a buffer) - what survives is a collector that has attempted every poll since startup and succeeded at none of them.',
             threshold="gt 0 for 30m. The scheduler polls every collector within seconds of startup (up to 5s jitter), so 30m is a fixed pending period safe on every tier, not one scaled to the collector's own interval.",
             absent='No dedicated nodata handling - a collector that has never even attempted a poll (the left-hand gauge itself absent) produces no series here, which is expected during the first seconds after startup.',
             checks=[
                'Read the collector label and check whether its required OPNsense plugin is installed',
                "Confirm the API key has permission for that collector's endpoint(s)",
                "Check whether this collector is even applicable to this firewall (e.g. a collector enabled against a box that doesn't run the subsystem)",
            ],
             causes=[
                'A missing OPNsense plugin the collector depends on',
                "An API key without permission for that collector's endpoint",
                'The collector enabled against a firewall that does not run the relevant subsystem at all',
            ],
             verify=[
                'opnsense_exporter_collector_snapshot_timestamp_seconds appears for the first time for that collector',
                "The collector's own metrics start appearing on its dashboard tab",
            ],
         )),
    # Split primary vs failover: the default (primary) WAN reconverges in <1m after a reboot, so it
    # keeps a tight for=5m + critical/page. A secondary/failover WAN can take ~7-10m to re-establish
    # (DHCP + dpinger convergence) after a reboot, so it gets for=15m + warning (no page) to avoid
    # false pages during reboots. Requires the default_gateway label (opnsense-exporter >=0.x).
    dict(name="opnsense-gateway-down", title="OPNsenseGatewayDown",
         A='opnsense_gateways_status{default_gateway="true"}', op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense PRIMARY gateway {{ $labels.name }} is offline ({{ $labels.opnsense_instance }})",
         description="Primary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 5m.",
         runbook=dict(
             measures='opnsense_gateways_status{default_gateway="true"}: the API-reported up/down state of the box\'s PRIMARY WAN gateway.',
             threshold='lt 1 (down) for 5m - tight, because the primary WAN typically reconverges in under a minute after a reboot.',
             absent='Default noDataState (Ok) - a totally-absent series means the exporter itself is down (OPNsenseExporterDown already pages for that); it does not fire for gateways with OPNsense-side monitoring disabled, which legitimately have no status series.',
             checks=[
                'Read the name/address labels to identify the specific gateway',
                "Check OPNsense's own Gateway status widget and dpinger logs for the same gateway",
                'Confirm whether the upstream ISP link itself is down vs. a local interface/dpinger fault',
            ],
             causes=[
                'The upstream ISP circuit is down',
                'A local WAN interface (physical link, PPPoE session, DHCP lease) failed',
                'dpinger itself stopped monitoring the gateway',
            ],
             verify=[
                'opnsense_gateways_status for that gateway returns to 1',
                'Traffic is observably flowing again on the interface (rx/tx byte-rate panels moving)',
            ],
         )),
    dict(name="opnsense-gw-down-failover", title="OPNsenseGatewayDownFailover",
         A='opnsense_gateways_status{default_gateway="false"}', op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense FAILOVER gateway {{ $labels.name }} is offline ({{ $labels.opnsense_instance }})",
         description="Failover/secondary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 15m. "
                     "Lower urgency — primary WAN unaffected. The 15m window tolerates a router reboot / slow secondary-WAN re-establish.",
         runbook=dict(
             measures='opnsense_gateways_status{default_gateway="false"}: the same up/down state, for a failover/secondary WAN gateway rather than the primary.',
             threshold="lt 1 (down) for 15m - looser than the primary's 5m, because a secondary WAN can legitimately take ~7-10m to re-establish (DHCP + dpinger convergence) after a reboot.",
             absent='Default noDataState (Ok), same reasoning as OPNsenseGatewayDown: absence is the gateway lacking OPNsense-side monitoring, not a fault.',
             checks=[
                'Read the name/address labels to identify the specific secondary gateway',
                'Confirm the primary gateway is still up (this is lower urgency precisely because it is)',
                "Check OPNsense's Gateway status widget for the secondary's own convergence state",
            ],
             causes=[
                'The secondary ISP circuit or interface is down',
                'The secondary WAN is still mid-convergence after a reboot (should self-clear within the 15m window if so)',
            ],
             verify=[
                'opnsense_gateways_status for that gateway returns to 1',
                'Failover routing (if in use) reports the secondary as available again',
            ],
         )),
    # #405: a dpinger alarm is a transition event, not a replacement for the
    # current-state gateway collector. Count the starts per gateway; a strict >2
    # threshold is three or more starts in this fixed 15-minute observation window.
    dict(name="opnsense-gateway-alarm-flapping", title="OPNsenseGatewayAlarmFlapping",
         A='sum by (opnsense_instance, gateway) '
           '(increase(opnsense_log_events_gateway_total{event="alarm_started"}[15m]))',
         op="gt", params=[2, 0], for_min=0, severity="warning",
         summary="OPNsense gateway {{ $labels.gateway }} alarm is flapping ({{ $labels.opnsense_instance }})",
         description="dpinger emitted three or more alarm_started transitions for gateway {{ $labels.gateway }} in 15m. "
                     "This is transition evidence from syslog, not an assertion that the gateway is currently down; check OPNsenseGatewayDown and the Gateway Status panel for current state.",
         runbook=dict(
             measures='Count of dpinger alarm_started transitions for one gateway in a 15m window, from shipped syslog events - a TRANSITION signal, not a current-state assertion.',
             threshold='gt 2 (three or more starts) in the fixed 15m observation window, for_min=0 so it fires the instant the count is exceeded.',
             absent='Default noDataState (Ok) - no alarm_started events in the window is the normal, quiet state.',
             checks=[
                "Check OPNsenseGatewayDown/OPNsenseGatewayDownFailover and the Gateway Status panel for this gateway's CURRENT state - this alert only proves instability happened, not that the gateway is down now",
                "Look at the gateway's RTT/loss panels over the same 15m window for a pattern (intermittent vs. one-off)",
            ],
             causes=[
                'An unstable upstream link (flapping DSL/cable/PPPoE session)',
                "dpinger's monitor target itself is intermittently unreachable",
                'Congestion or a misconfigured latency/loss threshold making dpinger over-sensitive',
            ],
             verify=[
                'No further alarm_started events for the gateway in the next 15m window',
                "The gateway's current status gauge stays at 1 (up) for a sustained period",
            ],
         )),
    dict(name="opnsense-gateway-high-loss", title="OPNsenseGatewayHighLoss",
         A="opnsense_gateways_loss_percentage", op="gt", params=[20, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} high packet loss ({{ $labels.opnsense_instance }})",
         description="Gateway {{ $labels.name }} packet loss > 20% for 10m (current {{ $values.A.Value | printf \"%.1f\" }}%).",
         runbook=dict(
             measures="opnsense_gateways_loss_percentage: dpinger's measured packet loss to the gateway's monitor target.",
             threshold='gt 20% sustained for 10m.',
             absent='Default noDataState (Ok) - absence means the gateway has no dpinger loss data (e.g. monitoring disabled), not that loss is zero.',
             checks=[
                "Read the name label and check the gateway's RTT panel alongside this one for a combined latency/loss picture",
                'Check whether this coincides with an OPNsenseGatewayAlarmFlapping firing for the same gateway',
                'Rule out local congestion (interface error/drop counters) before blaming the upstream link',
            ],
             causes=[
                'Upstream ISP link degradation or congestion',
                'A flapping or marginal physical/PPPoE connection',
                "Local interface saturation causing dpinger's own probes to be dropped",
            ],
             verify=[
                'opnsense_gateways_loss_percentage drops back under 20% and stays there for 10m',
            ],
         )),
    dict(name="opnsense-gateway-high-rtt", title="OPNsenseGatewayHighRTT",
         A="opnsense_gateways_rtt_milliseconds / (opnsense_gateways_rtt_high_milliseconds > 0)",
         op="gt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} RTT over its high threshold ({{ $labels.opnsense_instance }})",
         description="Gateway {{ $labels.name }} mean RTT has exceeded its configured high-latency threshold for 10m.",
         runbook=dict(
             measures="opnsense_gateways_rtt_milliseconds divided by the gateway's own configured high-latency threshold (opnsense_gateways_rtt_high_milliseconds) - a ratio over 1 means the gateway has crossed ITS OWN configured threshold, not a fixed global one.",
             threshold='gt 1 (over its own configured high-RTT threshold) sustained for 10m.',
             absent='Default noDataState (Ok) - the division guard (`> 0`) means a gateway with no configured high threshold produces no series, deliberately, rather than firing on a meaningless comparison.',
             checks=[
                "Read the name label and check the gateway's loss panel for a combined picture",
                "Check the gateway's configured high-RTT threshold value itself in OPNsense - it may need retuning rather than the link being genuinely unhealthy",
            ],
             causes=[
                'Upstream network congestion or a route change adding latency',
                "The configured high-RTT threshold is tighter than the link's normal baseline",
            ],
             verify=[
                'The ratio drops back to 1 or below and stays there for 10m',
            ],
         )),
    dict(name="opnsense-kernel-zone-alloc-failure", title="OPNsenseKernelZoneAllocationFailure",
         A="sum by (zone, opnsense_instance) (rate(opnsense_kernel_memory_zone_failures_total"
           "{zone=~\"pf states|pf state keys|pf source nodes|socket|tcp_inpcb|udp_inpcb|tcpreass\"}[5m]))",
         op="gt", params=[0, 0], for_min=5, severity="critical",
         summary="OPNsense kernel could not allocate {{ $labels.zone }} ({{ $labels.opnsense_instance }})",
         description="The FreeBSD UMA allocator has been failing to satisfy allocations in the "
                     "{{ $labels.zone }} zone for 5m. This is silent, consequential loss: no new pf "
                     "state means a dropped connection, no socket means a refused one, and neither "
                     "produces a log line.",
         runbook=dict(
             measures='rate of UMA allocation failures in the zones whose exhaustion has a direct operational consequence.',
             threshold='gt 0 for 5m, SCOPED to pf states, pf state keys, pf source nodes, socket, tcp_inpcb, udp_inpcb and tcpreass. The scoping is essential and must not be widened to all zones: UMA bucket zones, vm pgcache and vmem btag fail BY DESIGN and fall back to a slower path, and they account for all 158,488 failures on a healthy prod box. An unscoped rule would page continuously and immediately.',
             absent='Default noDataState (Ok). The zone set follows loaded kernel modules, so a zone can legitimately be absent on a box that does not use the feature.',
             checks=[
                'Check the zone occupancy panel on the Kernel Memory tab for whether this zone is at a configured ceiling or simply out of memory',
                'Remember limit=0 means NO CEILING CONFIGURED, not a ceiling of zero - a zero limit does not mean the zone is capped',
                'Check overall memory pressure on System & Resources, since a zone can fail because the machine is out of memory rather than because the zone is capped',
                'For pf states specifically, cross-check OPNsensePFStateTableNearLimit, which watches the same exhaustion from the pf side',
            ],
             causes=[
                'The zone has hit a configured limit and the workload genuinely needs more',
                'System-wide memory exhaustion, so no zone can grow',
                'A traffic flood opening connections faster than the box can allocate state for them',
            ],
             verify=[
                'The failure rate returns to zero and stays there',
                'Zone occupancy falls back below its ceiling, or the ceiling is raised deliberately',
            ],
         )),
    dict(name="opnsense-kernel-zone-near-limit", title="OPNsenseKernelZoneNearLimit",
         A="opnsense_kernel_memory_zone_used / (opnsense_kernel_memory_zone_limit > 0)",
         op="gt", params=[0.8, 0], for_min=15, severity="warning",
         summary="OPNsense kernel zone {{ $labels.zone }} over 80% of its limit ({{ $labels.opnsense_instance }})",
         description="A UMA zone has been above 80% of its configured ceiling for 15m. This is the "
                     "leading indicator for OPNsenseKernelZoneAllocationFailure - it fires while "
                     "allocations still succeed.",
         runbook=dict(
             measures='zone occupancy as a fraction of its configured ceiling, across every zone that HAS a ceiling.',
             threshold='gt 0.8 sustained for 15m. The `> 0` division guard is load-bearing: limit=0 means no ceiling configured rather than a ceiling of zero, and 113 of 242 zones on a real box report limit=0 with non-zero use, so an unguarded division would evaluate +Inf on half of them and fire permanently.',
             absent='Default noDataState (Ok). A zone with no configured limit produces no series here at all, by design.',
             checks=[
                'Identify the zone and whether its growth is a trend or a spike',
                'Check whether the workload changed - more concurrent connections, a new plugin, a traffic flood',
                'Ignore pf anchors and pf Ethernet anchors: their limit is 2147483647 (INT_MAX), so they can never approach it and never fire here',
            ],
             causes=[
                'Legitimate growth in the resource the zone backs',
                'A limit left at a default that is undersized for this box',
                'A leak in whatever allocates from the zone',
            ],
             verify=[
                'Occupancy falls back below 80% and stays there',
            ],
         )),
    dict(name="opnsense-default-route-missing", title="OPNsenseDefaultRouteMissing",
         A="opnsense_network_diag_default_route_present",
         op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense has no {{ $labels.proto }} default route ({{ $labels.opnsense_instance }})",
         description="The routing table carries no default route for {{ $labels.proto }}. For a "
                     "firewall that is a total outage for that address family - nothing off-subnet "
                     "is reachable. There was no signal for this condition before #544.",
         runbook=dict(
             measures='whether a default route exists per address family: 1 present, 0 absent.',
             threshold='lt 1 for 5m. The metric is emitted for a FIXED ipv4/ipv6 set every scrape rather than only when a route exists, precisely so the absent case is a 0 that can be alerted on rather than a missing series that cannot.',
             absent='Default noDataState (Ok). No series at all means the network diagnostics collector is off (it is opt-in), not that the route is fine.',
             checks=[
                'Check the Default Route Detail table for what the gateway and interface were before it vanished',
                'Check gateway health - a dpinger-driven failover that found no healthy member can leave no default route at all',
                'For IPv6 specifically, check whether the WAN still holds a delegated prefix and a router advertisement',
            ],
             causes=[
                'The WAN interface went down and took its default route with it',
                'Gateway failover removed the failed route and had no healthy alternative to install',
                'A DHCP or PPPoE lease expired without renewing',
                'For IPv6, the RA or prefix delegation lapsed',
            ],
             verify=[
                'The metric returns to 1 and the Default Route Detail table shows a plausible gateway',
            ],
         )),
    dict(name="opnsense-netmap-ring-full", title="OPNsenseNetmapRingFull",
         A="sum by (device, opnsense_instance) (rate(opnsense_log_events_netmap_ring_full_events_total[15m]))",
         op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense netmap host ring full on {{ $labels.device }} ({{ $labels.opnsense_instance }})",
         description="The kernel has been reporting the netmap host TX ring full on "
                     "{{ $labels.device }} for 30m - Zenarmor's packet-capture datapath is "
                     "dropping traffic. This counts OCCURRENCES, not packets: the kernel "
                     "rate-limits the underlying log line to 2 per second, so the metric "
                     "saturates under sustained load and the true drop volume is unbounded above "
                     "whatever this shows.",
         runbook=dict(
             measures='rate(opnsense_log_events_netmap_ring_full_events_total[15m]) - how often the kernel reported a full netmap host ring, derived from syslog rather than polled.',
             threshold='gt 0 sustained for 30m. The long window is deliberate: an isolated burst during a traffic spike is normal, a persistent condition is not.',
             absent='Default noDataState (Ok). Absence means no report, NOT no drops - a box with the syslog receiver disabled, or with Zenarmor not running, produces no series at all.',
             checks=[
                'Confirm Zenarmor is actually running and check its own engine health - it owns this datapath',
                'Check throughput on the named device against what the box normally carries',
                'Do NOT expect the interface drop counters to corroborate this on ixl/ixgbe/igb hardware - see causes below',
            ],
             causes=[
                'Traffic volume exceeds what the Zenarmor capture ring can absorb',
                'Zenarmor is wedged or too slow to drain the ring, so it backs up',
                'The ring is sized for a lighter load than the box now carries',
            ],
             verify=[
                'The event rate returns to zero and stays there across a full traffic peak, not just a quiet period',
            ],
         )),
    dict(name="opnsense-dhcp-client-lease-overdue", title="OPNsenseDHCPClientLeaseRenewalOverdue",
         A="opnsense_log_events_dhcp_client_lease_renewal_timestamp_seconds - time()",
         op="lt", params=[0, 0], for_min=15, severity="critical",
         summary="OPNsense WAN DHCP renewal overdue on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="dhclient's renewal deadline for {{ $labels.interface }} has passed without a "
                     "new lease being bound. The WAN address is on borrowed time: once the full "
                     "lease expires the box loses the address entirely. This fires hours before "
                     "that happens, which is the entire point of it.",
         runbook=dict(
             measures='The renewal (T1) deadline dhclient last reported, minus now. Negative means the deadline has passed and nothing has rebound since.',
             threshold='lt 0 sustained for 15m. Note this is the RENEWAL deadline, not absolute lease expiry - dhclient never logs the latter, so there is more headroom than this alert implies, not less.',
             absent='Default noDataState (Ok). No series means no bound-lease line has been seen since the exporter started - expected on a static or PPPoE WAN, which never runs dhclient at all.',
             checks=[
                'Check the WAN DHCP Client Messages panel for a request storm with no matching ack - that is the upstream refusing or ignoring renewals',
                'Check for any nak, which means the server actively rejected the current address',
                'Confirm physical link and upstream reachability on the WAN interface',
            ],
             causes=[
                'The upstream DHCP server is unreachable or not responding',
                'The ISP changed its allocation and is refusing to renew the existing address',
                'dhclient has died or is wedged on that interface',
            ],
             verify=[
                'A fresh bind appears and the countdown resets to a positive value',
                'Time since last bind drops back to near zero on the countdown panel',
            ],
         )),
    dict(name="opnsense-dhcp-client-nak", title="OPNsenseDHCPClientNak",
         A="sum by (interface, opnsense_instance) (rate(opnsense_log_events_dhcp_client_total{type=\"nak\"}[15m]))",
         op="gt", params=[0, 0], for_min=5, severity="warning",
         summary="OPNsense WAN DHCP server sent a NAK on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="The upstream DHCP server is refusing the address this box is currently "
                     "using on {{ $labels.interface }}. A NAK forces dhclient back to DISCOVER, "
                     "so the WAN address is about to change or be lost.",
         runbook=dict(
             measures='rate of DHCPNAK messages received by the WAN dhclient.',
             threshold='gt 0 for 5m. Any NAK at all is abnormal on a stable WAN.',
             absent='Default noDataState (Ok). No dhclient on this box means no series.',
             checks=[
                'Check whether the WAN address actually changed after the NAK',
                'Check whether anything downstream is pinned to the old address (NAT rules, dynamic DNS, VPN endpoints)',
            ],
             causes=[
                'The ISP moved the box to a different subnet or reclaimed the address',
                'The upstream lease database was reset and no longer recognises this client',
                'Two clients are presenting the same identifier upstream',
            ],
             verify=[
                'A new address is bound and the NAK rate returns to zero',
            ],
         )),
    dict(name="opnsense-dhcp-client-storm", title="OPNsenseDHCPClientRequestStorm",
         A="sum by (interface, opnsense_instance) (rate(opnsense_log_events_dhcp_client_total{type=\"request\"}[15m]))",
         op="gt", params=[0.1, 0], for_min=30, severity="warning",
         summary="OPNsense WAN DHCP request storm on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="dhclient has been retransmitting DHCPREQUEST far above its normal cadence "
                     "for 30m. A healthy WAN renews on the order of once per lease period; a "
                     "sustained retransmit rate means renewals are not being answered, and is a "
                     "leading indicator of losing the address hours before it happens.",
         runbook=dict(
             measures='rate of DHCPREQUEST messages sent by the WAN dhclient.',
             threshold='gt 0.1/s (360/hour) sustained for 30m. Calibrated against a real incident: the box that motivated this alert ran a ~42/hour baseline and sustained ~4,500/hour for 11-12 hours, so this threshold sits roughly 8x above normal and 12x below the observed storm.',
             absent='Default noDataState (Ok). No dhclient on this box means no series.',
             checks=[
                'Check whether acks are coming back at all - requests without acks is the storm signature',
                'Check the lease renewal countdown: if it is still positive and being refreshed, the address is not yet at risk',
                'Check upstream link quality - a lossy WAN produces retransmits without any DHCP fault',
            ],
             causes=[
                'The upstream DHCP server is not responding to renewals',
                'Packet loss on the WAN is eating the requests or the replies',
                'The upstream server is rate-limiting or blocklisting this client',
            ],
             verify=[
                'The request rate falls back to baseline and a fresh bind is recorded',
            ],
         )),
    dict(name="opnsense-dhcp-client-script-failure", title="OPNsenseDHCPClientScriptFailure",
         A="sum by (interface, reason, opnsense_instance) "
           "(rate(opnsense_log_events_dhcp_client_script_total{reason=~\"expire|fail|timeout\"}[15m]))",
         op="gt", params=[0, 0], for_min=5, severity="critical",
         summary="OPNsense WAN DHCP {{ $labels.reason }} on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="dhclient-script ran with reason {{ $labels.reason }} on "
                     "{{ $labels.interface }}. expire means the lease is gone and the interface "
                     "has lost its address; fail and timeout mean dhclient gave up trying to "
                     "obtain or renew one. Unlike the renewal-overdue alert, this is the box "
                     "reporting the outcome rather than us inferring it.",
         runbook=dict(
             measures='rate of dhclient-script invocations whose reason indicates lease loss or failure.',
             threshold='gt 0 for 5m on reason expire, fail or timeout. The healthy reasons (bound, renew, rebind, reboot) are deliberately excluded.',
             absent='Default noDataState (Ok). No dhclient on this box means no series.',
             checks=[
                'Confirm whether the WAN interface still has an address at all',
                'Check the request/ack panel for how long the renewal had been failing beforehand - OPNsenseDHCPClientRequestStorm should have fired first',
            ],
             causes=[
                'The upstream DHCP server has been unreachable long enough for the full lease to run out',
                'Physical WAN link failure',
                'dhclient could not obtain any lease on a fresh start',
            ],
             verify=[
                'A bound or renew reason follows and the interface regains an address',
            ],
         )),
    # #546: the v6 twin of the four dhcp-client rules above, adapted for prefix
    # delegation. Deliberately NOT folded into them: a v4 and a v6 uplink fail
    # independently, and a firewall can hold a perfectly healthy v4 lease while every
    # downstream v6 prefix is about to be withdrawn.
    #
    # Two deadlines rather than one, and only the VALID one pages. The preferred
    # lifetime running out deprecates the prefix (existing connections survive, new
    # ones prefer another source); the valid lifetime running out REMOVES every
    # address derived from it. Same countdown-not-gauge reasoning as #541: the
    # exporter exports absolute deadlines and the alert does the arithmetic, because
    # a countdown computed at parse time keeps counting down from a stale value and a
    # dead dhcp6c would look exactly like a healthy one.
    dict(name="opnsense-dhcp6-prefix-expiring", title="OPNsenseDHCP6PrefixExpiring",
         A="opnsense_log_events_dhcp6c_prefix_valid_expiry_timestamp_seconds - time()",
         op="lt", params=[0, 0], for_min=10, severity="critical",
         summary="OPNsense delegated IPv6 prefix expired on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="The valid lifetime of the /{{ $labels.prefix_length }} prefix delegated on "
                     "{{ $labels.interface }} has run out with no refresh. This is not just the "
                     "WAN losing its own address: every downstream address derived from this "
                     "prefix is removed, so IPv6 goes away on every LAN it was delegated to.",
         runbook=dict(
             measures='The valid-lifetime deadline dhcp6c last reported for the delegated prefix, minus now. Negative means it has passed with nothing refreshing it.',
             threshold='lt 0 sustained for 10m. The prefix is already gone at 0 - the for_min is there so a renewal landing a moment late does not page, not to add headroom.',
             absent='Default noDataState (Ok). No series means no prefix-delegation line has been seen since the exporter started, which is the normal state on a WAN with no PD or no IPv6 at all.',
             checks=[
                'Check the WAN DHCPv6 Client Messages panel for sent renew climbing with no matching received - that is the upstream having stopped answering, and it would have been visible for hours',
                'Check whether the preferred-lifetime countdown went negative first; if both crossed together the prefix was withdrawn rather than allowed to age out',
                'Confirm the v4 side is healthy - if both stopped at once this is a link or PPPoE problem, not a DHCPv6 one',
            ],
             causes=[
                'The upstream DHCPv6 server stopped answering Renew, so the delegation was never refreshed',
                'The ISP withdrew or re-delegated the prefix',
                'dhcp6c died or is wedged on the WAN interface',
            ],
             verify=[
                'A prefix_updated event appears and both lifetime countdowns reset to positive values',
                'Downstream interfaces regain their IPv6 addresses',
            ],
         )),
    dict(name="opnsense-dhcp6-prefix-not-refreshing", title="OPNsenseDHCP6PrefixNotRefreshing",
         A="time() - opnsense_log_events_dhcp6c_prefix_updated_timestamp_seconds",
         op="gt", params=[7200, 0], for_min=15, severity="warning",
         summary="OPNsense delegated IPv6 prefix has not refreshed on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="Nothing has created or refreshed the delegated prefix on "
                     "{{ $labels.interface }} for over two hours. The prefix is still valid, so "
                     "nothing has broken yet - this is the leading indicator that fires while "
                     "there is still time to act, ahead of OPNsenseDHCP6PrefixExpiring.",
         runbook=dict(
             measures='Time since the last prefix create/update line from dhcp6c for this interface.',
             threshold='gt 7200s (2h), for_min=15. Sized as roughly 2x the observed refresh interval - the reference box renews hourly (pltime=3600), so two missed refreshes. Retune if your ISP hands out a longer lifetime; the honest threshold is 2x whatever pltime the prefix actually carries.',
             absent='Default noDataState (Ok). No series means no prefix delegation on this box, which is normal on a WAN without PD.',
             checks=[
                'Check the WAN DHCPv6 Client Messages panel: sent renew with no received reply means the upstream has gone quiet',
                'Check the valid and preferred countdowns for how much time is actually left before it matters',
            ],
             causes=[
                'The upstream DHCPv6 server has stopped responding to Renew',
                'dhcp6c is wedged - it may still be sending without processing replies',
            ],
             verify=[
                'A prefix_updated event lands and the age drops back to near zero',
            ],
         )),
    # #560: the IA_NA WAN-address-lease twin of the two prefix alerts above, for a box
    # that takes its own WAN address directly by DHCPv6 rather than only a delegated
    # prefix. Same reasoning throughout: absolute deadlines exported, countdown done
    # in the alert expression, only the VALID deadline pages.
    dict(name="opnsense-dhcp6-address-expiring", title="OPNsenseDHCP6AddressExpiring",
         A="opnsense_log_events_dhcp6c_address_valid_expiry_timestamp_seconds - time()",
         op="lt", params=[0, 0], for_min=10, severity="critical",
         summary="OPNsense WAN IPv6 address lease expired on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="The valid lifetime of the IA_NA address lease on {{ $labels.interface }} "
                     "has run out with no refresh. dhcp6c has lost this firewall's own WAN IPv6 "
                     "address.",
         runbook=dict(
             measures='The valid-lifetime deadline dhcp6c last reported for the WAN address lease, minus now. Negative means it has passed with nothing refreshing it.',
             threshold='lt 0 sustained for 10m, same shape as OPNsenseDHCP6PrefixExpiring - the for_min exists so a renewal landing a moment late does not page.',
             absent='Default noDataState (Ok). No series means either no address-lease line has been seen since the exporter started (normal on a PD-only WAN), or the address was explicitly removed - ClearDHCP6CAddress deletes the series rather than freezing it, so absence here can mean a clean removal rather than an unreported expiry.',
             checks=[
                'Check the WAN DHCPv6 Client Messages panel for sent renew climbing with no matching received',
                'Check whether an address_lease_removed event landed just before the series went absent - that is a clean teardown, not a silent failure',
                'Confirm the v4 side is healthy - if both stopped at once this is a link problem, not a DHCPv6 one',
            ],
             causes=[
                'The upstream DHCPv6 server stopped answering Renew/Request, so the lease was never refreshed',
                'The ISP withdrew the address',
                'dhcp6c died or is wedged on the WAN interface',
            ],
             verify=[
                'An address_lease_created or address_lease_updated event appears and the deadline resets to a positive value',
            ],
         )),
    dict(name="opnsense-dhcp6-address-not-refreshing", title="OPNsenseDHCP6AddressNotRefreshing",
         A="time() - opnsense_log_events_dhcp6c_address_updated_timestamp_seconds",
         op="gt", params=[7200, 0], for_min=15, severity="warning",
         summary="OPNsense WAN IPv6 address lease has not refreshed on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="Nothing has created or refreshed the WAN IPv6 address lease on "
                     "{{ $labels.interface }} for over two hours. The lease is still valid, so "
                     "nothing has broken yet - this is the leading indicator that fires while "
                     "there is still time to act, ahead of OPNsenseDHCP6AddressExpiring.",
         runbook=dict(
             measures='Time since the last address-lease create/update line from dhcp6c for this interface.',
             threshold='gt 7200s (2h), for_min=15 - same 2x-observed-refresh-interval sizing as OPNsenseDHCP6PrefixNotRefreshing (pltime=1125 observed on the captured box). Retune to 2x whatever pltime your ISP actually hands out.',
             absent='Default noDataState (Ok). No series means either no IA_NA address lease on this box (normal on a PD-only WAN) or the lease was cleanly removed.',
             checks=[
                'Check the WAN DHCPv6 Client Messages panel: sent renew/request with no received reply means the upstream has gone quiet',
                'Check the valid-expiry countdown for how much time is actually left before it matters',
            ],
             causes=[
                'The upstream DHCPv6 server has stopped responding to Renew/Request',
                'dhcp6c is wedged - it may still be sending without processing replies',
            ],
             verify=[
                'An address_lease_created or address_lease_updated event lands and the age drops back to near zero',
            ],
         )),
    dict(name="opnsense-dhcp6-alloc-failures", title="OPNsenseDHCP6AllocationFailures",
         A="sum by (reason, opnsense_instance) (rate(opnsense_log_events_dhcp6_alloc_fail_total[15m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense kea-dhcp6 is refusing IPv6 leases: {{ $labels.reason }} ({{ $labels.opnsense_instance }})",
         description="This box's own DHCPv6 SERVER has been refusing lease requests for 10m. The "
                     "opposite direction from the prefix alerts: clients on the LAN are being "
                     "denied IPv6 addresses. reason=exhausted means the pool is full; "
                     "reason=no_pools means the subnet has no pool configured for that client at "
                     "all, which is a configuration fault rather than a capacity one.",
         runbook=dict(
             measures='Rate of DHCPv6 allocation failures reported by kea-dhcp6, by reason. Counted once per failed allocation - kea emits up to three lines per failure sharing a tid, and only the cause line is counted.',
             threshold='gt 0 sustained for 10m. Must be a rate: a single refusal from a client that has since been served is not worth paging on, a sustained one is.',
             absent='Default noDataState (Ok). No series means kea-dhcp6 has refused nothing, which is the normal state.',
             checks=[
                'reason=no_pools: check that the subnet the client is on actually has a v6 pool defined - this one never resolves itself',
                'reason=exhausted: check pool utilisation against the lease count on the DHCP tab, and whether the lease time is long enough to be holding addresses for departed clients',
                'Check whether the failures correlate with the delegated prefix changing - a re-delegation invalidates the pool the old subnet was carved from',
            ],
             causes=[
                'The v6 pool is genuinely full',
                'No pool is configured for the subnet or client class in question',
                'The delegated prefix changed and the configured pools still reference the old one',
            ],
             verify=[
                'The failure rate returns to zero and clients obtain leases again',
            ],
         )),
    dict(name="opnsense-netisr-queue-drops", title="OPNsenseNetisrQueueDrops",
         A="sum by (protocol, opnsense_instance) (rate(opnsense_network_diag_netisr_queue_drops_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense netisr is dropping {{ $labels.protocol }} packets ({{ $labels.opnsense_instance }})",
         description="The FreeBSD network interrupt scheduler has been dropping packets on the "
                     "{{ $labels.protocol }} queue for 10m. This is silent packet loss - it is invisible "
                     "from the OPNsense UI and degrades the affected protocol without any other symptom. "
                     "Must be a rate: the counter is cumulative since boot, so an absolute threshold would "
                     "keep alerting forever on a box that dropped packets once a year ago.",
         runbook=dict(
             measures='rate(opnsense_network_diag_netisr_queue_drops_total[5m]) - packets per second discarded by netisr because a workstream queue was full.',
             threshold='gt 0 (any sustained drop rate) for 10m.',
             absent='Default noDataState (Ok). The network diagnostics collector is opt-in (--exporter.enable-network-diagnostics), so no series at all usually means the collector is off rather than that the box is healthy.',
             checks=[
                'Read opnsense_network_diag_netisr_drop_concentration_ratio for this protocol FIRST. At or near 1.0 every drop is landing on ONE workstream, which is a CPU-affinity problem, not a queue-size problem',
                'Open the NetISR Per-CPU Distribution row and find which cpu is dropping - the per-CPU drops panel names it directly',
                'Compare opnsense_network_diag_netisr_active_workstreams against the box core count. Four active workstreams on a twelve-core box means netisr is only using a third of the machine',
                'Check the NetISR Protocol Policy table: a policy_type of "source" is single-lane by design and cannot spread, so one busy workstream there is expected',
                'Do NOT reach straight for net.isr.maxqlen. On the box that motivated this rule, ip6 dropped 683 packets entirely on cpu0 while cpu1-3 ran at roughly half their watermark and cpu4-11 were completely idle - raising the queue limit there would have masked an affinity problem rather than fixing it',
            ],
             causes=[
                'netisr work is bound to a subset of CPUs - check net.isr.maxthreads and net.isr.bindthreads',
                'The NIC RSS / queue configuration is steering all traffic into one hardware queue and so onto one workstream',
                'cpu0 additionally carries interrupt and userland work the other cores do not, so it saturates first even with fewer packets queued',
                'A genuine traffic volume increase beyond what the configured queue depth absorbs',
            ],
             verify=[
                'The drop rate returns to zero and stays there for 10m',
                'drop_concentration_ratio and queue_imbalance_ratio both fall, showing work actually spread rather than the queue merely being enlarged',
            ],
         )),
    dict(name="opnsense-netisr-queue-near-limit", title="OPNsenseNetisrQueueNearLimit",
         A="(opnsense_network_diag_netisr_queue_watermark / (opnsense_network_diag_netisr_queue_limit > 0)) "
           "and (delta(opnsense_network_diag_netisr_queue_watermark[1h]) > 0)",
         op="gt", params=[0.9, 0], for_min=10, severity="warning",
         summary="OPNsense netisr {{ $labels.protocol }} queue approaching its limit ({{ $labels.opnsense_instance }})",
         description="A netisr queue watermark is above 90% of its configured limit AND is still rising. "
                     "This is the leading indicator - it fires before drops start.",
         runbook=dict(
             measures='netisr_queue_watermark divided by netisr_queue_limit - how close the deepest queue occupancy since boot has come to the configured ceiling, evaluated only while the watermark is still climbing.',
             threshold='gt 0.9 sustained for 10m, and only while the watermark rose within the last hour. The rising-edge guard (delta over 1h) is deliberate and must not be removed: the watermark is a since-boot HIGH-WATER MARK that never decays, so a bare ratio > 0.9 would latch on the first burst and alert continuously until the next reboot whether or not anything was still wrong. This is a deviation from the rule as originally proposed in #538, made because the metric it reads does not behave like a gauge.',
             absent='Default noDataState (Ok). The division guard means a protocol reporting limit=0 produces no series rather than a divide-by-zero artifact.',
             checks=[
                'Identify the protocol and check whether its watermark is climbing steadily or jumped once during a traffic burst',
                'Check the per-CPU watermark panel: one workstream at the limit beside idle siblings is an affinity problem, all of them near the limit is genuine volume',
                'Confirm whether drops have started yet via OPNsenseNetisrQueueDrops',
            ],
             causes=[
                'Rising traffic on the affected protocol is filling the queue faster than it drains',
                'netisr work concentrated on too few workstreams, so per-lane depth grows while total capacity sits unused',
                'A queue limit left at a default that is undersized for this box',
            ],
             verify=[
                'The ratio stops rising - the rising-edge guard clears the alert on its own once the watermark stops moving',
                'Per-CPU watermarks even out across active workstreams',
            ],
             note='The rising-edge guard (delta over 1h) is deliberate and must not be removed. The watermark is a since-boot HIGH-WATER MARK that never decays, so a bare ratio > 0.9 would latch on the first burst and alert continuously until the next reboot, whether or not anything was still wrong. That is exactly the alert nobody reads. Deviation from the rule as originally proposed in #538, made because the metric it reads does not behave like a gauge.',
         )),
    dict(name="opnsense-pf-states-near-limit", title="OPNsensePFStateTableNearLimit",
         A="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)",
         op="gt", params=[0.9, 0], for_min=10, severity="warning",
         summary="OPNsense PF state table near its limit ({{ $labels.opnsense_instance }})",
         description="PF state table is over 90% of its configured limit for 10m.",
         runbook=dict(
             measures='opnsense_firewall_pf_states_current divided by opnsense_firewall_pf_states_limit - how full the pf state table is relative to its configured ceiling.',
             threshold='gt 0.9 (over 90% full) sustained for 10m.',
             absent='Default noDataState (Ok) - the division guard means a box with no configured limit produces no series rather than a divide-by-zero artifact.',
             checks=[
                'Check the Firewall & PF tab for which connection types/rules are consuming the most states',
                'Look for a sudden traffic spike (flood, misbehaving client, DDoS) versus a slow organic climb',
            ],
             causes=[
                'A legitimate traffic surge is opening more concurrent connections than usual',
                'A flood/DDoS or a misbehaving internal host opening excessive connections',
                'The configured pf state-table limit is simply undersized for normal load',
            ],
             verify=[
                'The ratio drops back under 0.9 and stays there for 10m',
                'opnsense_firewall_pf_states_current stabilises at a sustainable level',
            ],
         )),
    # The stall alert, not an "is it connected" alert (#559). The documented failure
    # mode of SSE on this box is that keepalives keep flowing after the data has
    # stopped, so the socket looks perfectly healthy while the stream is dead.
    # stream_up would still read 1 through exactly that. Frame age is the only signal
    # that separates them.
    dict(name="opnsense-cpu-stream-stalled", title="OPNsenseCPUStreamStalled",
         A="opnsense_cpu_stream_last_frame_age_seconds",
         op="gt", params=[120, 0], for_min=5, severity="warning",
         summary="OPNsense CPU usage stream stalled ({{ $labels.opnsense_instance }})",
         description="No CPU sample has arrived from the api/diagnostics/cpu_usage SSE stream for "
                     "over 2 minutes ({{ $values.A.Value | printf \"%.0f\" }}s). Frames normally arrive "
                     "about once a second. The exporter's own watchdog tears down and re-dials a stalled "
                     "connection, so this firing means recovery is ALSO failing - the firewall is "
                     "unreachable, rebooting, or refusing the stream. cpu_seconds_total has already been "
                     "withdrawn (opnsense_cpu_stream_counters_published=0), so CPU panels read absent "
                     "rather than a misleading flat zero.",
         runbook=dict(
             measures='opnsense_cpu_stream_last_frame_age_seconds: seconds since the last CPU sample arrived over the SSE stream.',
             threshold='gt 120 for 5m. Two minutes is well past the 10s stall watchdog and one full re-dial cycle, so an ordinary reconnect never fires this.',
             absent='Default noDataState (Ok) - the series is absent before the first frame ever arrives and on a box with --exporter.disable-cpu set.',
             checks=[
                'Read opnsense_cpu_stream_up for the same instance: 0 means the exporter cannot establish the connection at all, 1 means it connected and the data stopped anyway',
                'Read rate(opnsense_cpu_stream_reconnects_total[5m]): a high rate means the connection is being established and torn down repeatedly rather than never established',
                'Check opnsense_up - a firewall that is wholly unreachable explains this and much else besides',
                'On the firewall, confirm lighttpd and configd are running and that php-cgi worker capacity is not exhausted (max-procs x PHP_FCGI_CHILDREN)',
            ],
             causes=[
                'The firewall is rebooting or applying a firmware update, so there is nothing to reconnect to',
                'configd or the iostat process behind the stream has wedged',
                'php-cgi worker capacity on the firewall is exhausted, so the stream cannot be re-established',
                'The API credentials were revoked, so every re-dial is rejected',
            ],
             verify=[
                'opnsense_cpu_stream_last_frame_age_seconds drops back under a few seconds',
                'opnsense_cpu_stream_counters_published returns to 1 and the CPU Usage panel stops reading absent',
            ],
         )),
    dict(name="opnsense-memory-high", title="OPNsenseMemoryHigh",
         A="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)",
         op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense memory usage high ({{ $labels.opnsense_instance }})",
         description="Physical memory usage has been above 90% for 15m.",
         runbook=dict(
             measures='opnsense_system_memory_used_bytes divided by opnsense_system_memory_total_bytes - physical memory utilisation.',
             threshold='gt 0.9 (over 90%) sustained for 15m.',
             absent='Default noDataState (Ok) - the division guard suppresses the series if total memory is unreported, rather than alerting on a meaningless ratio.',
             checks=[
                'Check which process/service is consuming memory on the box directly (OPNsense UI System Activity, or SSH `top`)',
                'Look for a recently-added plugin or a runaway daemon rather than assuming a hardware limit',
            ],
             causes=[
                'A plugin or service leaking memory over time',
                'The box is simply under-provisioned for its configured feature set (e.g. IDS/IPS rules, many VPN tunnels)',
            ],
             verify=[
                'The ratio drops back under 0.9 and stays there for 15m',
            ],
         )),
    dict(name="opnsense-disk-usage-high", title="OPNsenseDiskUsageHigh",
         A="opnsense_system_disk_usage_ratio", op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense disk {{ $labels.mountpoint }} almost full ({{ $labels.opnsense_instance }})",
         description="Filesystem {{ $labels.mountpoint }} ({{ $labels.device }}) usage above 90% for 15m.",
         runbook=dict(
             measures='opnsense_system_disk_usage_ratio for one mounted filesystem/device.',
             threshold='gt 0.9 (over 90% full) sustained for 15m.',
             absent="Default noDataState (Ok) - absence means that mountpoint isn't reported (e.g. not present on this box), not that it's empty.",
             checks=[
                'Read the mountpoint/device labels to identify which filesystem is filling up',
                'Check for oversized logs, config-backup history, or package caches on that mount',
            ],
             causes=[
                'Log growth or a service writing excessively to that filesystem',
                'Accumulated firmware/package upgrade artifacts or config backups',
                'The mount is genuinely undersized for its role',
            ],
             verify=[
                'opnsense_system_disk_usage_ratio for that mountpoint drops back under 0.9',
            ],
         )),
    dict(name="opnsense-high-temperature", title="OPNsenseHighTemperature",
         A="opnsense_temperature_celsius", op="gt", params=[85, 0], for_min=10, severity="warning",
         summary="OPNsense sensor {{ $labels.device }} hot ({{ $labels.opnsense_instance }})",
         description="Temperature sensor {{ $labels.device }} above 85°C for 10m.",
         runbook=dict(
             measures='opnsense_temperature_celsius for one hardware sensor (CPU, chassis, drive bay, etc).',
             threshold='gt 85°C sustained for 10m.',
             absent="Default noDataState (Ok) - absence means that sensor isn't present/reported on this hardware, not that it has cooled.",
             checks=[
                'Read the device label to identify which sensor is hot',
                'Check physical airflow/fan status and ambient conditions around the appliance',
            ],
             causes=[
                'A failed or blocked chassis/CPU fan',
                'Blocked intake/exhaust airflow or high ambient temperature',
                'Sustained high CPU load driving thermal output up',
            ],
             verify=[
                'opnsense_temperature_celsius for that sensor drops back under 85°C and stays there',
            ],
         )),
    dict(name="opnsense-smart-failed", title="OPNsenseSmartHealthFailed",
         A="opnsense_smart_device_health", op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense SMART health failed on {{ $labels.device }} ({{ $labels.opnsense_instance }})",
         description="SMART overall-health for {{ $labels.device }} ({{ $labels.model }}) reports FAILED.",
         runbook=dict(
             measures="opnsense_smart_device_health: the disk's own SMART overall-health self-assessment.",
             threshold='lt 1 (FAILED) - any occurrence for 5m, since a SMART FAILED verdict is never transient noise worth waiting out.',
             absent="Default noDataState (Ok) - absence means SMART data isn't available for that device (e.g. a virtual disk), not that it passed.",
             checks=[
                'Read the device/model labels and pull the full SMART report on the box (`smartctl -a`) for the specific failing attribute',
                'Check whether a backup/replacement disk is on hand before the drive fails outright',
            ],
             causes=[
                'The physical disk is genuinely failing (reallocated sectors, pending sectors, etc.)',
                'A SMART firmware quirk on some controllers can occasionally misreport - cross-check with the raw attribute values before assuming imminent failure',
            ],
             verify=[
                'opnsense_smart_device_health returns to 1 only after replacing the drive (a genuine SMART FAILED verdict does not self-clear)',
            ],
         )),
    dict(name="opnsense-firmware-needs-reboot", title="OPNsenseFirmwareNeedsReboot",
         A="opnsense_firmware_needs_reboot", op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense needs a reboot ({{ $labels.opnsense_instance }})",
         description="A firmware update flagged that OPNsense needs a reboot.",
         runbook=dict(
             measures='opnsense_firmware_needs_reboot: whether a previously-applied firmware/package update is waiting on a reboot to take effect.',
             threshold='gt 0 sustained for 30m (a deliberately long grace period, since this is rarely urgent).',
             absent='Default noDataState (Ok) - absence means no update is pending a reboot.',
             checks=[
                "Check the OPNsense UI's firmware/updates page for exactly which update is pending",
                'Plan a maintenance window for the reboot rather than treating this as an emergency',
            ],
             causes=[
                'A kernel, base-system, or driver update was applied and needs a reboot to load',
            ],
             verify=[
                'opnsense_firmware_needs_reboot returns to 0 after the reboot completes',
            ],
         )),
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
                     "not mirror flapping.",
         runbook=dict(
             measures="opnsense_firmware_update_check_success: whether OPNsense's own STORED update check ran and succeeded (not a real-time mirror probe). opnsense_firmware_update_check_state says which half broke: connection (DNS/proxy/credentials) or repository (fingerprint/subscription/release train).",
             threshold="lt 1 for 60m. This value is read through the exporter's firmware response cache (default 12h TTL), so a failure can take up to that long to appear and just as long to clear - the value stays constant across that window, so the 1h pending period filters scrape gaps and restarts rather than genuine mirror flapping.",
             absent='The series exists only once a check has been stored; a box that has never checked produces NoData and stays at the default Ok state instead of firing.',
             checks=[
                'Read opnsense_firmware_update_check_state to know which half failed before digging further',
                'Manually trigger an update check in the OPNsense UI and read the actual error text',
                'Check DNS/proxy reachability to the OPNsense mirror, and subscription/fingerprint validity if the state points at the repository side',
            ],
             causes=[
                'The configured mirror is unreachable (DNS, proxy, or network path)',
                'An expired subscription, revoked fingerprint, or unavailable release train',
            ],
             verify=[
                'opnsense_firmware_update_check_success returns to 1 (note: can take up to the firmware cache TTL to reflect a fix)',
            ],
         )),
    dict(name="opnsense-cert-expiring", title="OPNsenseCertificateExpiringSoon",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 14], for_min=0, severity="warning",
         summary="OPNsense certificate expiring soon: {{ $labels.commonname }} ({{ $labels.opnsense_instance }})",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 14 days.",
         runbook=dict(
             measures="Days until a certificate's notAfter time ((opnsense_certificate_valid_to_seconds - time()) / 86400).",
             threshold='within_range [0, 14] - the certificate expires within the next 14 days (and has not already expired, which is covered by the critical rule below).',
             absent="Default noDataState (Ok) - absence means that certificate is no longer tracked (removed/replaced), not that it's safely far from expiry.",
             checks=[
                'Read the commonname/description labels to identify the exact certificate',
                "Check whether it's ACME-managed (should auto-renew) or a manually-imported cert needing a manual renewal",
            ],
             causes=[
                'A manually-managed certificate was never scheduled for renewal',
                "An ACME renewal is failing silently (check the ACME client's own log/status)",
            ],
             verify=[
                "The certificate's valid_to timestamp moves out past the 14-day window after renewal",
            ],
         )),
    dict(name="opnsense-cert-expiring-critical", title="OPNsenseCertificateExpiringCritical",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 3], for_min=0, severity="critical",
         summary="OPNsense certificate expiring imminently: {{ $labels.commonname }} ({{ $labels.opnsense_instance }})",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 3 days.",
         runbook=dict(
             measures='The same days-until-expiry expression as OPNsenseCertificateExpiringSoon ((opnsense_certificate_valid_to_seconds - time()) / 86400).',
             threshold='within_range [0, 3] - imminent expiry, escalated to critical severity because there is very little runway left to act.',
             absent='Default noDataState (Ok) - same reasoning as the warning-tier sibling: absence means the certificate is no longer tracked.',
             checks=[
                'Read the commonname/description labels and confirm this is the same cert already flagged by OPNsenseCertificateExpiringSoon, or a newly-discovered one',
                'Renew or replace the certificate immediately - anything consuming it (web UI, VPN, reverse proxy) will start failing TLS validation at expiry',
            ],
             causes=[
                "OPNsenseCertificateExpiringSoon's warning was missed or not actioned in time",
                'An ACME renewal has been failing for multiple cycles',
            ],
             verify=[
                "The certificate's valid_to timestamp moves out past the 3-day window",
                'Whatever service depends on the cert (UI, VPN, proxy) still presents a valid chain after renewal',
            ],
         )),
    # Exclude on-demand services that are expected to be stopped (e.g. iperf, which only runs during
    # an explicit performance test). Add other expected-down service names to the exclusion as needed.
    dict(name="opnsense-service-down", title="OPNsenseServiceDown",
         A='opnsense_services_status{name!="iperf"}', op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense service {{ $labels.name }} stopped ({{ $labels.opnsense_instance }})",
         description="Service {{ $labels.name }} ({{ $labels.description }}) has been stopped for 10m. "
                     "On-demand services (e.g. iperf) are excluded. One alert per service.",
         runbook=dict(
             measures='opnsense_services_status: whether a monitored OPNsense service is running (excludes on-demand services such as iperf, which are expected to be stopped between test runs).',
             threshold='lt 1 (stopped) sustained for 10m. One alert instance per service.',
             absent="Default noDataState (Ok) - absence means that service is no longer configured/tracked, not that it's running.",
             checks=[
                'Read the name/description labels to identify the exact service',
                "Check the OPNsense UI's Services page for the actual stop reason/crash log",
                'Try restarting it from the UI and watch whether it stays up or crash-loops',
            ],
             causes=[
                'The service crashed and did not auto-restart',
                'A configuration error is preventing the service from starting',
                'A dependency (interface, another service, a plugin) it needs is unavailable',
            ],
             verify=[
                'opnsense_services_status for that service returns to 1 and stays there (not just a one-shot restart that crashes again)',
            ],
         )),
    dict(name="opnsense-ntp-unsynced", title="OPNsenseNTPPeerUnreachable",
         A="opnsense_ntp_peer_reach", op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense NTP peer {{ $labels.server }} unreachable ({{ $labels.opnsense_instance }})",
         description="NTP peer {{ $labels.server }} reachability register has been 0 for 15m.",
         runbook=dict(
             measures='opnsense_ntp_peer_reach: whether NTP considers a specific configured time peer reachable.',
             threshold='lt 1 sustained for 15m.',
             absent="Default noDataState (Ok) - absence means that peer is no longer configured, not that it's reachable.",
             checks=[
                'Read the server label to identify the specific NTP peer',
                "Check outbound connectivity/firewall rules to that peer's address and port (UDP/123)",
                "Confirm the peer itself hasn't been decommissioned or renumbered upstream",
            ],
             causes=[
                'The configured NTP peer is down or unreachable from this network',
                'A firewall rule change blocked outbound NTP',
                "DNS resolution for the peer's hostname is failing",
            ],
             verify=[
                'opnsense_ntp_peer_reach for that peer returns to 1',
            ],
         )),
    # Unlike opnsense-endpoint-errors, this is a genuine count-in-window threshold (>5 bogus answers
    # per rolling 15m) with for:0 — it fires immediately when the count is exceeded, so there is no
    # for-duration whose meaning the 15m window could distort. The #94 defect (long for paired with an
    # equally-long increase window) does not apply here, so the 15m window is intentional and kept.
    dict(name="opnsense-unbound-dnssec-bogus", title="OPNsenseUnboundDNSSECBogus",
         A="sum by (opnsense_instance) (increase(opnsense_unbound_dns_answers_bogus_total[15m]))",
         op="gt", params=[5, 0], for_min=0, severity="info",
         summary="OPNsense Unbound DNSSEC bogus answers ({{ $labels.opnsense_instance }})",
         description="More than 5 DNSSEC-bogus answers in 15m — possible misconfiguration or tampering.",
         runbook=dict(
             measures='Count of DNSSEC-bogus DNS answers Unbound has returned in a rolling 15m window, summed by opnsense_instance.',
             threshold="gt 5 bogus answers in 15m, for_min=0 - a genuine count-in-window threshold that fires immediately once exceeded (no persistence period needed, unlike the endpoint-error rule's #94 trap).",
             absent='Default noDataState (Ok) - no bogus answers is the normal, healthy state.',
             checks=[
                "Check Unbound's own logs for which domain(s) are producing bogus DNSSEC validation",
                'Determine whether this correlates with a specific external resolver/domain misconfiguration versus active tampering on the network path',
            ],
             causes=[
                'A misconfigured authoritative zone upstream (broken DNSSEC signing)',
                'Clock skew on the box breaking signature validity windows',
                'Active DNS tampering/spoofing on the network path (the case this alert exists to surface)',
            ],
             verify=[
                'The 15m rolling count of bogus answers returns to 0 or stays under the threshold',
            ],
         )),
    # The syslog/Zenarmor push-based log receiver (#248-#261) had no alert coverage yet — these four
    # close that gap for the log-shipping pipeline itself (sink health, backpressure, label loss,
    # source liveness).
    dict(name="opnsense-logship-sink-errors", title="OPNsenseLogShipSinkErrors",
         selfhealth=True,
         A="sum by (opnsense_instance) (rate(opnsense_exporter_logs_ship_errors_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense log-shipping sink retrying ({{ $labels.opnsense_instance }})",
         description="The log-shipping sink (OTLP/Loki) has had failed Emit attempts for 10m. The "
                     "unacknowledged remainder is in retry/degradation, not "
                     "proof of counted record loss. Check OPNsenseLogShipCountedLoss separately.",
         runbook=dict(
             measures='Rate of failed Emit attempts by the log-shipping sink (OTLP/Loki) over 5m, summed by opnsense_instance - retry/degradation activity, not proof that records were actually lost.',
             threshold='gt 0 sustained for 10m.',
             absent='Default noDataState (Ok) - no errors means the sink is delivering cleanly.',
             checks=[
                "Check connectivity/auth to the configured OTLP or Loki destination from the exporter's network path",
                'Check OPNsenseLogShipCountedLoss separately - this rule only proves retrying is happening, not that anything was actually dropped',
            ],
             causes=[
                'The log-shipping destination (OTLP/Loki backend) is unreachable or rejecting requests',
                'Credentials for the destination expired or were rotated without updating the exporter',
            ],
             verify=[
                'The 5m error rate returns to 0 and stays there',
                'opnsense_exporter_logs_dropped_total stops incrementing for this instance',
            ],
         )),
    dict(name="opnsense-logship-queue-near-capacity", title="OPNsenseLogShipQueueNearCapacity",
         selfhealth=True,
         A="max by (opnsense_instance) ("
           "label_replace(avg_over_time(opnsense_exporter_logs_queue_length[5m]) / "
           "(opnsense_exporter_logs_queue_capacity > 0), \"bound\", \"count\", \"__name__\", \".*\") "
           "or label_replace(avg_over_time(opnsense_exporter_logs_queue_bytes[5m]) / "
           "(opnsense_exporter_logs_queue_max_bytes > 0), \"bound\", \"bytes\", \"__name__\", \".*\"))",
         op="gt", params=[0.75, 0], for_min=5, severity="warning",
         summary="OPNsense log-shipping queue under sustained pressure ({{ $labels.opnsense_instance }})",
         description="The log-shipping backpressure queue has averaged over 75% of either its record-count "
                     "capacity or its enabled byte budget for 5m — overflow drops are imminent.",
         runbook=dict(
             measures="The higher of two ratios for the log-shipping backpressure queue: record-count occupancy (queue_length / queue_capacity) or byte occupancy where a byte budget is enabled (queue_bytes / queue_max_bytes), max'd by opnsense_instance. The numerator is a 5m AVERAGE, not the instantaneous depth - see the threshold note.",
             threshold='gt 0.75 of whichever bound is enabled, on a 5m average, sustained for a further 5m. '
                       'The numerator is averaged deliberately. An earlier version of this rule read the '
                       'INSTANTANEOUS queue depth against a 0.9 threshold and it was structurally unable to '
                       'fire: the emitter drains a whole batch at once, so occupancy sawtooths on roughly the '
                       'batch period and almost never sits above a fixed line for 5 consecutive minutes. '
                       'Measured over one week on a live box it went Normal->Pending 148 times and reached '
                       'Alerting twice, while the queue was in fact overflowing and losing records the whole '
                       'time. Averaging reads the sawtooth as the sustained pressure it actually is.',
             absent='Default noDataState (Ok) - the `> 0` guards mean an unconfigured bound produces no series for that half rather than a meaningless ratio.',
             checks=[
                "Check the downstream sink's health first (OPNsenseLogShipSinkErrors) - a stalled destination is the most common reason the queue backs up",
                'Check the configured queue capacity/byte budget against current log volume',
            ],
             causes=[
                'The log-shipping destination has slowed or stopped accepting records, so the queue is backing up behind it',
                'A sudden spike in log volume (e.g. a flood on a push source) is outrunning the configured queue bound',
            ],
             verify=[
                'The occupancy ratio drops back under 0.9 and stays there for 5m',
                'No overflow drops appear in OPNsenseLogShipCountedLoss immediately afterward',
            ],
         )),
    dict(name="opnsense-logship-counted-loss", title="OPNsenseLogShipCountedLoss",
         selfhealth=True,
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
                     "logs_ship_errors_total, not this alert.",
         runbook=dict(
             measures='Count of log records counted as lost in a rolling 15m window, grouped by the exact source and reason (overflow, record_too_large, rejected, ship_failed_permanent, ship_failed).',
             threshold='gt 0 in 15m, for_min=0 - fires immediately, since any counted loss is worth knowing about.',
             absent='Default noDataState (Ok) - no loss events is the normal state.',
             checks=[
                'Read the reason label first - it tells you which of five distinct failure modes occurred (queue-bound eviction, oversized record, destination refusal, retry exhaustion, or shutdown abandonment)',
                'Cross-check OPNsenseLogShipQueueNearCapacity and OPNsenseLogShipSinkErrors for the same window - overflow/ship_failed reasons usually correlate with one of those',
            ],
             causes=[
                'overflow: the queue bound evicted the oldest record under sustained backpressure',
                'record_too_large: a single record exceeded the configured size limit',
                'rejected / ship_failed_permanent: the destination terminally refused it or retries were exhausted',
                'ship_failed: records were abandoned during shutdown',
            ],
             verify=[
                'The 15m rolling count for that source/reason returns to 0',
            ],
         )),
    dict(name="opnsense-logship-resource-capped", title="OPNsenseLogShipResourceCapped",
         selfhealth=True,
         A="sum by (opnsense_instance) (increase(opnsense_exporter_logs_resource_capped_total[15m]))",
         op="gt", params=[0, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping records had labels dropped ({{ $labels.opnsense_instance }})",
         description="Records were shipped with their opnsense.* resource labels dropped in the last "
                     "15m, so label-scoped queries against them silently under-report.",
         runbook=dict(
             measures='Count of records shipped with their opnsense.* resource labels dropped in a rolling 15m window, summed by opnsense_instance.',
             threshold='gt 0 in 15m, for_min=0.',
             absent='Default noDataState (Ok) - no capped records is the normal state.',
             checks=[
                'Check whether label-scoped queries against recently-shipped log records are silently under-reporting for this instance',
                'Check the configured resource-attribute budget/limit on the log-shipping pipeline',
            ],
             causes=[
                'The configured cap on resource attributes per record was hit under high label cardinality or volume',
            ],
             verify=[
                'The 15m rolling count of capped records returns to 0',
                'Newly-shipped records carry their full opnsense.* resource labels again',
            ],
         )),
    # Scoped to syslog|zenarmor: both are continuously-active push sources, so 15m of silence is a
    # genuine stall. A source that is legitimately quiet or not configured would false-fire if
    # included, so it is deliberately excluded rather than covered here.
    dict(name="opnsense-logship-cursor-stalled", title="OPNsenseLogShipCursorStalled",
         selfhealth=True,
         A='time() - max by (opnsense_instance, source) (opnsense_exporter_logs_last_exported_timestamp_seconds{source=~"syslog|zenarmor"})',
         op="gt", params=[900, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping source {{ $labels.source }} stalled ({{ $labels.opnsense_instance }})",
         description="Push source {{ $labels.source }} has shipped no events for 15m despite being "
                     "continuously active. Scoped to syslog|zenarmor only, so a quiet or unconfigured "
                     "source cannot false-fire.",
         runbook=dict(
             measures='Seconds since the last exported event timestamp for a continuously-active push source, restricted to source=~"syslog|zenarmor" - both are always-on push feeds, so silence from either is itself the anomaly.',
             threshold='gt 900s (15m) of silence, for_min=0.',
             absent='Default noDataState (Ok) - deliberately scoped to only the two always-active sources, so a legitimately quiet or unconfigured source (excluded from the query) cannot false-fire.',
             checks=[
                'Confirm the source (syslog sender or Zenarmor) is still actually configured to push to the exporter',
                "Check the exporter's log-shipping receiver logs for connection resets or parse errors from that source",
                "Confirm the firewall/network path between the source and the exporter's receiver port hasn't changed",
            ],
             causes=[
                'The syslog sender or Zenarmor was reconfigured/pointed elsewhere',
                'A network path or firewall rule change blocked the push',
                'The receiver itself hit an unhandled error and stopped accepting from that source',
            ],
             verify=[
                'opnsense_exporter_logs_last_exported_timestamp_seconds for that source starts advancing again',
            ],
         )),
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
         selfhealth=True,
         A="opnsense_exporter_otlp_consecutive_failures", op="gt", params=[0, 0],
         for_min=15, severity="warning",
         summary="OPNsense exporter OTLP metric delivery failing ({{ $labels.opnsense_instance }})",
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
                     "the exporter connects lazily, so a clean start proves nothing about delivery (#388).",
         runbook=dict(
             measures='opnsense_exporter_otlp_consecutive_failures: how many OTLP metric export attempts have failed back-to-back, resetting to 0 on the next success - so ">0 sustained" means an ONGOING outage, including the never-worked-since-boot case a staleness rule can\'t see.',
             threshold="gt 0 for 15m. At the default 60s export interval that's ~15 consecutive failed exports, so a single blip or a rolling restart of the collector endpoint does not fire.",
             absent='No dedicated nodata handling - this metric simply does not exist on a box with OTLP export disabled.',
             checks=[
                'READ THIS FIRST: an exporter cannot ship its own failure metric through the path that is failing, so this signal CANNOT reach a pure-OTLP backend during the outage itself - it is for /metrics scrapers, the passive operator console, and post-recovery forensics only',
                'Read opnsense_exporter_otlp_last_success_timestamp_seconds: 0 means no export has EVER succeeded since startup (wrong endpoint or bad credential), a non-zero value gives the recovery timeline',
                "On a pure-OTLP backend, look for STALENESS of this exporter's own data at the backend as the in-band symptom instead of this rule",
            ],
             causes=[
                'The configured OTLP endpoint is wrong or unreachable',
                'The OTLP credential/token is invalid or expired',
                'The OTLP collector/backend itself is down or rejecting exports',
            ],
             verify=[
                'opnsense_exporter_otlp_consecutive_failures returns to 0',
                'opnsense_exporter_otlp_last_success_timestamp_seconds advances to a recent time',
            ],
         )),
    dict(name="opnsense-ipsec-tunnel-down", title="OPNsenseIPsecTunnelDown",
         A="opnsense_ipsec_phase1_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense IPsec tunnel {{ $labels.name }} down ({{ $labels.opnsense_instance }})",
         description="IPsec phase1 tunnel {{ $labels.name }} ({{ $labels.description }}) has reported "
                     "status 0 (down; connected=1) for 10m. Catches a tunnel dropping while the daemon "
                     "itself keeps running, which opnsense-service-down misses.",
         runbook=dict(
             measures='opnsense_ipsec_phase1_status: whether a specific IPsec phase1 tunnel is connected. Catches a tunnel dropping while the strongSwan/racoon daemon itself keeps running, which OPNsenseServiceDown cannot see.',
             threshold='lt 1 (down; connected=1) sustained for 10m.',
             absent="Default noDataState (Ok) - absence means that tunnel is no longer configured, not that it's connected.",
             checks=[
                'Read the name/description labels to identify the specific tunnel',
                "Check the OPNsense UI's IPsec status page and the daemon's own log for the negotiation failure reason",
                "Confirm the remote peer's public IP/credentials haven't changed",
            ],
             causes=[
                'The remote peer is unreachable or its public IP changed',
                'A pre-shared key or certificate mismatch after a credential rotation',
                'A phase1/phase2 proposal mismatch introduced by a config change on either side',
            ],
             verify=[
                'opnsense_ipsec_phase1_status for that tunnel returns to 1 (connected)',
                'Traffic is observably flowing across the tunnel again',
            ],
         )),
    # Verified semantics: 1=up, 0=down, 2=unknown, 3=stale. lt 1 fires on 0 only — 2/3 are
    # deliberately NOT alerted, since unknown/stale is not the same claim as confirmed down.
    dict(name="opnsense-wireguard-peer-down", title="OPNsenseWireGuardPeerDown",
         A="opnsense_wireguard_peer_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense WireGuard peer {{ $labels.peer_name }} down ({{ $labels.opnsense_instance }})",
         description="WireGuard peer {{ $labels.peer_name }} on {{ $labels.device_name }} has reported "
                     "status 0 (down) for 10m. Status values are 1=up, 0=down, 2=unknown, 3=stale — "
                     "this alert deliberately fires on 0 only, not on unknown/stale.",
         runbook=dict(
             measures='opnsense_wireguard_peer_status for one peer. Values are 1=up, 0=down, 2=unknown, 3=stale; this alert deliberately fires on 0 only.',
             threshold='lt 1 sustained for 10m - matches 0 (down) only; 2 (unknown) and 3 (stale) are deliberately not alerted, since neither is the same claim as confirmed down.',
             absent='Default noDataState (Ok) - absence means that peer is no longer configured.',
             checks=[
                'Read the peer_name/device_name labels to identify the specific peer and interface',
                "Check the peer's last-handshake time in the OPNsense UI - a peer stuck at 0 rather than cycling through 2/3 usually means the endpoint address is simply wrong or unreachable",
                "Confirm the peer's allowed-IPs and endpoint configuration haven't drifted from the remote side",
            ],
             causes=[
                "The remote peer's network endpoint changed or became unreachable",
                'A key mismatch after a credential rotation on either side',
                'A firewall rule blocking the WireGuard UDP port',
            ],
             verify=[
                'opnsense_wireguard_peer_status for that peer returns to 1 (up)',
                "The peer's last-handshake timestamp is recent",
            ],
         )),
    # remote_services_total>0 is load-bearing: reachable=0 also means "HA sync isn't configured at
    # all", so the guard restricts firing to boxes where HA sync is actually set up.
    dict(name="opnsense-hasync-unreachable", title="OPNsenseHASyncUnreachable",
         A="opnsense_hasync_remote_reachable == 0 and on(opnsense_instance) "
           "(opnsense_hasync_remote_services_total > 0)",
         op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense HA sync peer unreachable ({{ $labels.opnsense_instance }})",
         description="opnsense_hasync_remote_reachable has been 0 for 10m on a box where HA sync is "
                     "configured (remote_services_total > 0). The guard excludes boxes with HA sync "
                     "unconfigured, where reachable=0 is the normal, expected reading.",
         runbook=dict(
             measures='opnsense_hasync_remote_reachable, guarded to only fire on boxes where HA sync is actually configured (opnsense_hasync_remote_services_total > 0) - reachable=0 on an unconfigured box is the normal, expected reading and is deliberately excluded.',
             threshold='lt 1 sustained for 10m, on a box where HA sync is configured.',
             absent="Default noDataState (Ok) - absence means HA sync isn't configured on this box at all, which the guard already treats as non-alertable.",
             checks=[
                'Confirm the HA peer box is actually up and reachable on the network from this instance',
                'Check the configured HA sync IP/interface for a recent change on either side',
                "Check the OPNsense UI's HA Sync status page for the specific connection error",
            ],
             causes=[
                'The HA peer firewall is down or unreachable',
                'A network path change (interface, VLAN, firewall rule) broke the sync link',
                'HA sync credentials were rotated on one box but not the other',
            ],
             verify=[
                'opnsense_hasync_remote_reachable returns to 1',
                'Config changes on the primary are observed to sync to the peer again',
            ],
         )),
    # carp_vip_status: 1=MASTER, 0=BACKUP (both normal — inside the [0,1] range), 2=INIT, -1=unknown
    # (faults — outside the range). The `unless` clause suppresses alerts during deliberate maintenance
    # mode. The `!= 3` drops administratively DISABLED VIPs before the threshold sees them (#503):
    # DISABLED is also outside [0,1], so without it disabling a VIP pages someone five minutes later.
    dict(name="opnsense-carp-vip-fault", title="OPNsenseCARPVIPFault",
         A="(opnsense_carp_vip_status != 3) unless on(opnsense_instance) (opnsense_carp_maintenance_mode == 1)",
         op="outside_range", params=[0, 1], for_min=5, severity="warning",
         summary="OPNsense CARP VIP {{ $labels.vip }} fault on {{ $labels.interface }} ({{ $labels.opnsense_instance }})",
         description="CARP VIP {{ $labels.vip }} on {{ $labels.interface }} has been outside the normal "
                     "MASTER(1)/BACKUP(0) range for 5m — status 2 (INIT) or -1 (unknown). BACKUP is a "
                     "normal, healthy state and does not fire; this only fires on INIT/unknown. "
                     "Suppressed while opnsense_carp_maintenance_mode is 1, and DISABLED(3) VIPs are "
                     "excluded outright.",
         runbook=dict(
             measures='opnsense_carp_vip_status for one VIP/interface. Values: 1=MASTER, 0=BACKUP (both normal, inside [0,1]), 2=INIT, 3=DISABLED, -1=unknown. Suppressed while opnsense_carp_maintenance_mode is 1 (deliberate maintenance).',
             threshold='outside_range [0, 1] sustained for 5m - fires on INIT(2)/unknown(-1) only. BACKUP is healthy and never fires; DISABLED(3) is administrative and is filtered out of the series before the threshold is applied.',
             absent='Default noDataState (Ok) - absence means that VIP/interface is no longer configured.',
             checks=[
                'Read the vip/interface labels to identify the exact VIP in fault',
                "Check opnsense_carp_maintenance_mode for this instance - if it's 1, this is intentional and won't fire (if you're seeing this alert, maintenance mode is NOT the cause)",
                'Check OPNsenseCARPStateFlapping for recent transition history on the same interface/vhid',
            ],
             causes=[
                'The CARP peer relationship is broken (pfsync misconfigured, network partition between nodes)',
                'The interface the VIP is bound to went down',
                'A VHID/advertising-frequency conflict with another device on the same broadcast domain',
            ],
             verify=[
                'opnsense_carp_vip_status for that VIP returns to 0 or 1 (BACKUP or MASTER)',
            ],
         )),
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
                     "and the CARP VIP Status panel for where the VIP actually sits now.",
         runbook=dict(
             measures="Count of CARP state_changed transitions for one interface+vhid pair in a rolling 15m window, from shipped syslog events - a TRANSITION signal complementing OPNsenseCARPVIPFault's current-state gauge, grouped by vhid AND interface since a vhid is only unique within an interface.",
             threshold="gt 3 (four or more changes) in 15m, for_min=0. A boot sequence is two changes (INIT->BACKUP->MASTER) and a single failover is one, so this threshold sits above one planned event with margin. Deliberately DIFFERENT from the dpinger sibling's >2 threshold - the two event shapes aren't comparable, don't tune them to match.",
             absent='Default noDataState (Ok) - no state_changed events in the window is the normal, quiet state.',
             checks=[
                "Read carp.reason on the shipped log records for the kernel's own stated cause",
                'Check OPNsenseCARPVIPFault and the CARP VIP Status panel for where the VIP actually sits now - this alert is transition evidence, not a current-state claim',
            ],
             causes=[
                'An unstable network path between HA peers causing repeated MASTER/BACKUP transitions',
                'A pfsync/CARP advertisement misconfiguration',
                'Genuine repeated hardware/service disruptions on one node',
            ],
             verify=[
                'No further state_changed events for that vhid/interface in the next 15m window',
                'opnsense_carp_vip_status for the VIP settles at a stable value',
            ],
         )),
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
                     "current level, and note the matching promoted event when the demotion is released.",
         runbook=dict(
             measures='Count of positive CARP demotion adjustments (event="demoted") for the instance in a rolling 15m window, from shipped syslog events - a node stepping back from its willingness to be master.',
             threshold='gt 3 (four or more) in 15m, for_min=0. DO NOT tighten to >0: one pfsync bulk-transfer cycle is one demoted plus one promoted event, ROUTINE operation (the #405 capture recorded 11 pairs on a healthy cluster) - a threshold of >0 would page on normal behaviour and train people to ignore the alert.',
             absent='Default noDataState (Ok) - no demoted events in the window is the normal, quiet state.',
             checks=[
                "Read carp.reason, carp.demotion.delta, and carp.demotion.total on the shipped log records for the kernel's own stated cause and the resulting demotion level - none of these are metric labels",
                'Compare opnsense_carp_demotion for the current level, and look for the matching promoted event that releases the demotion',
                'Check for repeated pfsync bulk transfers, a flapping interface, or an actual service disruption on this node',
            ],
             causes=[
                'Repeated pfsync bulk transfers (each one demotes and promotes once - only churn, four or more cycles in 15m, is the actual signal)',
                'A service disruption on this node',
                'A flapping interface causing repeated CARP re-evaluation',
            ],
             verify=[
                'No further demoted events in the next 15m window',
                'opnsense_carp_demotion returns to its baseline level',
            ],
         )),
    # Threshold and lookback are deployment-specific: tune --exporter.ids-alert-lookback and the 50
    # threshold per site, same tone as opnsense-unbound-dnssec-bogus above. Verified: action is only
    # ever allowed/blocked — no drop/reject values exist.
    dict(name="opnsense-ids-alert-spike", title="OPNsenseIDSAlertSpike",
         A='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})',
         op="gt", params=[50, 0], for_min=5, severity="info",
         summary="OPNsense IDS blocked-alert spike ({{ $labels.opnsense_instance }})",
         description="More than 50 blocked IDS alerts held in the recent-alerts window for 5m. The "
                     "threshold and --exporter.ids-alert-lookback window are deployment-specific — tune "
                     "both per site. action is only ever allowed/blocked (no drop/reject).",
         runbook=dict(
             measures='Count of currently-held blocked-action IDS alerts in the recent-alerts window, summed by opnsense_instance. action is only ever allowed/blocked (no drop/reject values exist).',
             threshold='gt 50 for 5m. Both the threshold and --exporter.ids-alert-lookback window are deployment-specific - tune per site.',
             absent='Default noDataState (Ok) - a quiet IDS is the normal state.',
             checks=[
                'Open the IDS/IPS tab to see which signature(s)/source IPs are driving the spike',
                'Check whether this correlates with a known scan, a new malicious campaign, or a misbehaving internal host being flagged repeatedly',
            ],
             causes=[
                "An active scan or attack against the firewall's public-facing services",
                'A misconfigured or compromised internal host triggering repeated egress alerts',
                'A signature update introducing a burst of (possibly false-positive) matches',
            ],
             verify=[
                'The blocked-alert count in the lookback window drops back under 50',
            ],
         )),
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
                     "merged hit-rate.",
         runbook=dict(
             measures='Rate of forced-eviction of flow-correlator entries over 5m, summed by opnsense_instance - the correlate window can no longer be held under current flow volume. No bytes are lost (the oldest entry is force-emitted, not dropped).',
             threshold='gt 0 sustained for 15m.',
             absent='Default noDataState (Ok) - no eviction is the normal state.',
             checks=[
                'Check current flow volume/cardinality (Flow Volume tab on the operational dashboard, Flow Pipeline tab on the health dashboard) against --flow.correlate.max-entries',
                'Confirm nothing is generating an unusual number of concurrent flows (scan, flood, a chatty new service)',
            ],
             causes=[
                '--flow.correlate.max-entries is set too low for current flow volume',
                'A traffic pattern change (more concurrent connections) increased pressure on the correlate accumulator',
            ],
             verify=[
                'The eviction rate returns to 0 and stays there for 15m',
                'Raising --flow.correlate.max-entries (if that was the cause) removes the eviction pressure',
            ],
         )),
    # Metrics are never truncated, only per-flow logs, so this is a warning about log completeness and a
    # possible flood on the unauthenticated NetFlow ingress rather than a data-integrity page.
    dict(name="opnsense-flow-logs-truncated", title="OPNsenseFlowLogsTruncated",
         A="sum by (opnsense_instance) (rate(opnsense_flow_logs_truncated_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense flow logs truncated by budget ({{ $labels.opnsense_instance }})",
         description="Flow log records have been dropped by the --flow.max-logs-per-window budget for "
                     "10m. Metrics are unaffected, but per-flow logs are incomplete. Raise the budget if "
                     "this is expected volume, or restrict the unauthenticated NetFlow ingress with "
                     "--flow.netflow.allowed-peers if it is a flood.",
         runbook=dict(
             measures='Rate of flow log records dropped by the --flow.max-logs-per-window budget over 5m, summed by opnsense_instance. Metrics themselves are never truncated, only per-flow LOGS.',
             threshold='gt 0 sustained for 10m.',
             absent='Default noDataState (Ok) - no truncation is the normal state.',
             checks=[
                'Check whether this is expected volume (raise --flow.max-logs-per-window) or a flood on the unauthenticated NetFlow ingress',
                'Check --flow.netflow.allowed-peers if a flood from an unexpected source looks likely',
            ],
             causes=[
                'Genuinely high flow volume exceeding the configured per-window log budget',
                'A flood on the unauthenticated NetFlow ingress from an unexpected/unrestricted peer',
            ],
             verify=[
                'The truncation rate returns to 0',
                "Per-flow log completeness is restored (no further gaps on the health dashboard's Flow Pipeline tab)",
            ],
         )),
    # #520: GeoIP enrichment is FAIL-OPEN by construction — a failed download, an expired
    # MaxMind license key or a geoipupdate cron that stopped running degrades the data and
    # nothing else, so there is no error to notice and no metric that stops moving. Lookups
    # keep succeeding against an ever-older database. The BUILD timestamp is the only signal
    # that separates "current" from "quietly frozen", which is why it is a metric at all and
    # why this alert exists. The gauge is ABSENT (never zero) for a database that is not
    # loaded, so a box with geo off cannot false-fire.
    #
    # 45d, RAISED FROM 14d BY #549 — do not put it back without re-reading this. 14d was
    # correct while GeoLite2 was the only database anyone could load: it rebuilds twice a
    # week, so two weeks was four missed builds. Since #549 the image SHIPS DB-IP Lite and
    # geo is on by default, and DB-IP republishes MONTHLY. At 14d every stock deployment
    # would sit firing for roughly half of every month, and the alert would be describing a
    # working updater. Worst case for the bundled path is ~31d of publish interval plus the
    # refresh workflow's own lag, so 45d clears it with headroom.
    #
    # The cost is real and accepted: a MaxMind deployment whose updater dies now takes 45d
    # to page instead of 14d. That is tolerable because this is a warning about data DRIFT,
    # not an outage — country-level answers are barely different at 6 weeks — and because
    # the downloads/reloads counters in the runbook below catch a broken updater far sooner
    # for anyone actually watching. A per-provider threshold was considered and rejected:
    # the gauge carries no provider label, and adding one to split a warning-severity drift
    # alert into two rules is more machinery than the difference is worth.
    dict(name="opnsense-flow-geoip-database-stale", title="OPNsenseFlowGeoIPDatabaseStale",
         A="max by (opnsense_instance, database) "
           "(time() - opnsense_flow_geoip_database_build_timestamp_seconds)",
         op="gt", params=[3888000, 0], for_min=60, severity="warning",
         summary="OPNsense GeoIP {{ $labels.database }} database is stale ({{ $labels.opnsense_instance }})",
         description="The loaded {{ $labels.database }} database was built more than 45 days ago, which "
                     "is past the publish interval of every database this exporter can load - GeoLite2 "
                     "rebuilds twice a week, the bundled DB-IP Lite monthly - so whatever refreshes it "
                     "has stopped. With --geoip.download.enabled that is a failed fetch (expired "
                     "license key, blocked egress, exhausted download quota); with an operator-managed "
                     "file it is a geoipupdate cron, sidecar or mounted volume that is no longer "
                     "refreshing it; and on a stock deployment running the database baked into the "
                     "image it means the image itself is old. Enrichment is fail-open, so nothing has "
                     "broken and no attribute has disappeared - the countries and ASNs on flow records "
                     "are simply drifting out of date, which is exactly why this needs an alert rather "
                     "than being noticed.",
         runbook=dict(
             measures="Age in seconds of the loaded GeoIP database, per database (country, asn), against MaxMind's own BUILD date rather than the download time - a re-download of the same build correctly does NOT reset it.",
             threshold='gt 3888000s (45d), for_min=60. Raised from 14d by #549: the image now ships DB-IP Lite, which republishes MONTHLY, so 14d would fire on a healthy stock deployment for half of every month. 45d clears a ~31d publish interval plus refresh lag for every database the exporter can load.',
             absent='Default noDataState (Ok). The gauge is omitted entirely for a database that is not loaded (a zero would read as "built in 1970" and fire permanently), so a deployment with --geoip.enabled off has no series here and cannot false-fire.',
             checks=[
                'Check opnsense_flow_geoip_downloads_total: a rising result="failure" rate is a fetch problem, while a flat counter with --geoip.download.enabled set means the updater goroutine is not running at all',
                'With the built-in downloader: verify the MaxMind license key has not expired and that the exporter has egress to download.maxmind.com',
                'With operator-managed files: confirm the geoipupdate cron / sidecar is still running and writing to the configured --geoip.country-database and --geoip.asn-database paths',
                'On a stock deployment using the database bundled in the image, no updater exists to fix - the image is what is old, so pull a current one',
                'Check opnsense_flow_geoip_reloads_total for result="failure" - a corrupt replacement leaves the OLD database serving, which looks exactly like no update at all',
                'Confirm the download directory is persistent: a volume lost on restart re-downloads every start and can exhaust the daily limit',
            ],
             causes=[
                'MaxMind license key expired or the account was disabled',
                'Egress to download.maxmind.com blocked, or the daily download limit exhausted',
                'A geoipupdate cron / sidecar stopped running, or its output path no longer matches the exporter configuration',
                'A corrupt or truncated replacement file that fails to parse, leaving the previous database serving indefinitely',
                'A stock deployment running an image that has not been pulled for over 45 days, so the bundled DB-IP Lite copy is simply as old as the image',
            ],
             verify=[
                'opnsense_flow_geoip_database_build_timestamp_seconds advances to a recent build',
                'opnsense_flow_geoip_downloads_total{result="updated"} increments once, then settles back to result="unmodified"',
            ],
         )),
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
           "and on (opnsense_instance) (opnsense_netflow_capture_active_timeout_seconds < 2700)\n"
           "unless on (opnsense_instance, interface) "
           "(opnsense_flow_interface_capture_unsupported == 1)",
         op="gt", params=[0, 0], for_min=5, severity="warning",
         summary="OPNsense NetFlow hook dead on {{ $labels.interface }} ({{ $labels.device }}, {{ $labels.opnsense_instance }})",
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
                     "you know has a dead hook. A device that can NEVER capture is excluded rather than "
                     "reported here - opnsense_flow_interface_capture_unsupported marks those, and every "
                     "PPPoE interface is one, so this firing means a hook that SHOULD work does not. "
                     "On firing: open the operator console's NetFlow / ifIndex tab and confirm "
                     "{{ $labels.device }} is a real ng_netflow node with `ngctl list` on the box. If the "
                     "node is missing, the capture selection no longer matches the box's interfaces - "
                     "re-save Reporting/NetFlow to reattach. If it exists and still counts zero, capture "
                     "on that device is not working at the netgraph layer and the interface should be "
                     "unticked until it is. See docs/flow.md "
                     "('Joining the two label spaces') for the full derivation. Resolves automatically "
                     "once opnsense_netflow_cache_packets_total resumes counting on the device.",
         runbook=dict(
             measures="A five-clause join proving a specific NetFlow capture hook has gone silent while pf still passes traffic on the same kernel device - the #368 dead-hook failure mode, where ng_netflow accepted a bogus hook and silently captured nothing. PPPoE interfaces, where that is permanent and unfixable (ng_netflow attaches to mpd's framing node, not the ng_iface node ng_pppoe exposes), are excluded by clause 5 rather than reported forever.",
             threshold="gt 0 for 5m. Clause 1 restricts to interfaces actually configured for capture; clause 2 checks the interface's OWN ng_netflow cache node recorded zero packets in 45m; clause 3 confirms pf actually passed bytes on the same device in that window (telling a dead hook from a legitimately idle interface); clause 4 withdraws the whole query unless the box's own configured NetFlow active timeout is at least the 45m observation window; clause 5 drops any interface whose device can never capture at all (opnsense_flow_interface_capture_unsupported), which is every PPPoE WAN.",
             absent="Default noDataState (Ok) - a healthy hook, an interface not configured for capture, a PPPoE interface (clause 5, permanently incapable), or a box whose active timeout is shorter than 45m (clause 4's honesty guard) all produce no series here, which is the intended quiet state.",
             checks=[
                'Check opnsense_netflow_capture_active_timeout_seconds FIRST if you believe a hook is dead but this never fires - a box with a shorter active timeout is structurally excluded by clause 4',
                "Open the operator console's NetFlow/ifIndex tab and confirm the device label is a real ng_netflow node with `ngctl list` on the box",
                "Read docs/flow.md ('Joining the two label spaces') for the full query derivation before changing this rule",
            ],
             causes=[
                "The capture hook was bound to the wrong kernel device (e.g. a PPPoE interface's framing node rather than its actual ng_iface) - the #368 pattern",
                'The ng_netflow hook was silently dropped by a reconfiguration and never rebound',
            ],
             verify=[
                'opnsense_netflow_cache_packets_total for the device resumes counting - the alert resolves automatically once it does',
            ],
         )),
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


# ---- self-health routing (#431 step 4) ------------------------------------
# Exporter-health alerts land in their own Grafana folder so they cannot be
# mistaken for firewall-operational ones. The difference matters at 3am: an
# OPNsenseFirewallUnhealthy page means go look at the firewall, an
# OPNsenseLogShipSinkErrors page means the firewall is probably fine and the
# monitoring is not, and mixing them in one folder makes the responder read every
# title to tell which they have.
#
# Membership is DECLARED per rule (`selfhealth=True`), not inferred, because two
# members cannot be inferred: OPNsenseExporterDown and
# OPNsenseExporterInstanceMissing both fire on `opnsense_up`, which is not an
# `opnsense_exporter_*` metric but is entirely a statement about the exporter's
# ability to see the box. `is_self_health_expr` below is the mechanical
# cross-check — a rule built purely from self-metrics that FORGETS the flag fails
# the tests, so the declaration cannot silently fall behind the expressions.
SELF_METRIC_RE = re.compile(
    r"\b(opnsense_exporter_[a-z0-9_]+|go_[a-z0-9_]+|process_[a-z0-9_]+)")
# `opnsense_instance` is excluded explicitly: it is the LABEL every rule groups by,
# not a firewall metric, and matching it would classify every self-health rule as
# mixed.
FIREWALL_METRIC_RE = re.compile(r"\bopnsense_(?!exporter_|instance\b)[a-z0-9_]+")


def is_self_health_expr(expr: str) -> bool:
    """True iff `expr` reads ONLY exporter self-metrics. Sufficient for membership,
    not necessary — see the note above about `opnsense_up`."""
    return bool(SELF_METRIC_RE.search(expr)) and not FIREWALL_METRIC_RE.search(expr)


# ---- panel links (#530) ---------------------------------------------------
def _walk_layout(node, tabs: tuple, out: dict):
    """Collect element name -> tuple of enclosing tab titles.

    The tab is needed because a handful of titles legitimately appear twice: once as
    an Overview summary tile and once as the canonical panel on its domain tab.
    Walking the layout is what lets an alert name which of the two it means without
    renaming either panel.
    """
    if isinstance(node, dict):
        kind = node.get("kind")
        if kind == "TabsLayoutTab":
            tabs = tabs + (node.get("spec", {}).get("title"),)
        elif kind == "ElementReference":
            out.setdefault(node["name"], tabs)
            return
        for value in node.values():
            _walk_layout(value, tabs, out)
    elif isinstance(node, list):
        for value in node:
            _walk_layout(value, tabs, out)


def _panel_index():
    """[(dashboard uid, {title: [(panel id, tab titles), ...]}), ...] over the
    GENERATED dashboards.

    Resolution is by TITLE, never by a hard-coded id: ids come from a counter in the
    dashboard builder and renumber whenever a panel is inserted, so a literal id here
    would rot silently into a link to whatever panel inherited the number.
    """
    global _panel_index_cache
    if _panel_index_cache is not None:
        return _panel_index_cache
    indexed = []
    for path in DASHBOARD_DOCS:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as err:
            # `make rules` alone can be run against a dashboard that has not been
            # rebuilt yet. Say which target fixes it rather than emitting a rule with
            # a link into a stale panel id.
            raise ValueError(
                f"cannot read the generated dashboard {path}: {err}. "
                "Run `make dashboard` before `make rules`.") from err
        where: dict = {}
        _walk_layout(doc["spec"].get("layout", {}), (), where)
        titles: dict = {}
        for key, element in doc["spec"]["elements"].items():
            if element.get("kind") != "Panel":
                continue
            spec = element["spec"]
            titles.setdefault(spec["title"], []).append((spec["id"], where.get(key, ())))
        if not titles:
            raise ValueError(f"{path} contains no panels")
        indexed.append((doc["metadata"]["name"], titles))
    _panel_index_cache = indexed
    return indexed


def panel_ref(title: str, selfhealth: bool, tab: "str | None" = None):
    """(dashboardUid, panelId) for exactly one panel titled `title`.

    A title present on BOTH dashboards resolves to the one matching the rule's own
    folder — an exporter-health rule means the health dashboard's copy, and an
    operational rule whose only panel lives on the health dashboard still resolves,
    because the other dashboard is tried second.

    Ambiguity within a dashboard is an ERROR, not a pick-first: silently linking the
    first match sends an on-call engineer to the wrong tab. Pass `panel_tab` to say
    which copy is canonical — that is a statement of intent, and cheaper than renaming
    a panel an operator already recognises.
    """
    indexed = _panel_index()
    # Index order is (main, health); the rule's own dashboard is tried first.
    ordered = list(reversed(indexed)) if selfhealth else list(indexed)
    for uid, titles in ordered:
        found = titles.get(title)
        if not found:
            continue
        if tab is not None:
            found = [(pid, tabs) for pid, tabs in found if tab in tabs]
            if not found:
                raise ValueError(
                    f"no panel titled {title!r} on tab {tab!r} of {uid}. Check the tab "
                    "title, or drop panel_tab if the panel title is already unique.")
        if len(found) > 1:
            detail = "; ".join(f"id {pid} on {' / '.join(t for t in tabs if t)}"
                               for pid, tabs in found)
            raise ValueError(
                f"panel title {title!r} is used by {len(found)} panels on {uid} ({detail}). "
                "Add panel_tab= to name the canonical one.")
        return uid, found[0][0]
    known = ", ".join(uid for uid, _ in indexed)
    raise ValueError(
        f"no panel titled {title!r} on either generated dashboard ({known}). Panel titles "
        "are the link key, so a retitled panel must be updated here too.")


# Alert title -> the canonical panel to open from the notification. Either a panel
# title, or (panel title, tab) for the handful of titles that appear twice — once as an
# Overview summary tile and once on the domain tab.
#
# A table rather than a per-rule kwarg because completeness is the property worth
# gating: `test_every_alert_declares_a_panel_or_is_exempt` requires every alert to
# appear HERE or in PANEL_LINK_EXEMPT with a reason, so a new alert cannot quietly ship
# without someone deciding where it points.
PANEL_LINKS = {
    # --- exporter health -------------------------------------------------------
    "OPNsenseExporterDown": "Firewall Reachable",
    "OPNsenseExporterInstanceMissing": "Scrape Success (opnsense_up)",
    "OPNsenseEndpointErrors": "Endpoint Errors (rate)",
    "OPNsenseCollectorDataStale": "Collector Retained Data Age (true data age)",
    "OPNsenseCollectorDegraded": "Collector Time Since Last Full Success",
    "OPNsenseCollectorNeverStoredData": "Collector Last Attempt Age (scheduler liveness)",
    "OPNsenseLogShipSinkErrors": "Sink Errors (rate)",
    "OPNsenseLogShipQueueNearCapacity": "Queue Depth",
    "OPNsenseLogShipCountedLoss": "Records Dropped (rate)",
    "OPNsenseLogShipResourceCapped": "Resource Label Cap Hit (rate)",
    "OPNsenseLogShipCursorStalled": "Delivery Lag",
    "OPNsenseOTLPDeliveryFailing": ("OTLP Consecutive Failures", "Delivery"),
    # --- firewall health -------------------------------------------------------
    "OPNsenseFirewallUnhealthy": "Health History",
    "OPNsenseCrashReports": "Crash reports",
    "OPNsenseDiskSpaceLow": "Subsystem Status",
    # --- gateways --------------------------------------------------------------
    "OPNsenseGatewayDown": ("Gateway Status", "Gateways & WAN"),
    "OPNsenseGatewayDownFailover": ("Gateway Status", "Gateways & WAN"),
    "OPNsenseGatewayAlarmFlapping": "Gateway Alarm Events",
    "OPNsenseGatewayHighLoss": "Packet Loss %",
    "OPNsenseGatewayHighRTT": ("Gateway RTT", "Gateways & WAN"),
    # --- system resources ------------------------------------------------------
    "OPNsenseKernelZoneAllocationFailure": "Allocation Failures — zones that matter (rate)",
    "OPNsenseKernelZoneNearLimit": "Zone Saturation (used / limit)",
    "OPNsenseDefaultRouteMissing": "Default Route Present",
    "OPNsenseNetmapRingFull": "Netmap Host Ring Full Events (rate)",
    "OPNsenseDHCPClientLeaseRenewalOverdue": "WAN DHCP Lease Renewal Countdown",
    "OPNsenseDHCPClientNak": "WAN DHCP Client Messages (rate)",
    "OPNsenseDHCPClientRequestStorm": "WAN DHCP Client Messages (rate)",
    "OPNsenseDHCPClientScriptFailure": "WAN DHCP Client Script Events (rate)",
    "OPNsenseDHCP6PrefixExpiring": "Delegated IPv6 Prefix Lifetimes",
    "OPNsenseDHCP6PrefixNotRefreshing": "Delegated IPv6 Prefix Lifetimes",
    "OPNsenseDHCP6AddressExpiring": "WAN IPv6 Address Lease Lifetimes",
    "OPNsenseDHCP6AddressNotRefreshing": "WAN IPv6 Address Lease Lifetimes",
    "OPNsenseDHCP6AllocationFailures": "DHCPv6 Server Allocation Failures (rate)",
    "OPNsenseNetisrQueueDrops": "NetISR Per-CPU Queue Drops (rate)",
    "OPNsenseNetisrQueueNearLimit": "NetISR Queue Length / Watermark / Limit",
    "OPNsensePFStateTableNearLimit": "PF States Used %",
    # Points at the AGE panel, not "CPU Stream" (up/down): the failure this alert
    # exists for is a stall with the socket still up, so stream_up is exactly the
    # panel that will look fine while the alert is firing.
    "OPNsenseCPUStreamStalled": "CPU Stream Last Frame Age",
    "OPNsenseMemoryHigh": "Memory Used %",
    "OPNsenseDiskUsageHigh": "Disk Usage % by Mountpoint",
    "OPNsenseHighTemperature": "Temperature",
    "OPNsenseSmartHealthFailed": "Drive Health",
    # --- firmware and certificates --------------------------------------------
    "OPNsenseFirmwareNeedsReboot": "Needs Reboot",
    "OPNsenseUpdateCheckFailing": "Update Check",
    "OPNsenseCertificateExpiringSoon": "Certificate Expiry (days left)",
    "OPNsenseCertificateExpiringCritical": "Certificate Expiry (days left)",
    # --- services --------------------------------------------------------------
    "OPNsenseServiceDown": "Service Status (current)",
    "OPNsenseNTPPeerUnreachable": "Peer Reachability Register",
    "OPNsenseUnboundDNSSECBogus": "DNSSEC Answers / s",
    # --- VPN and HA ------------------------------------------------------------
    "OPNsenseIPsecTunnelDown": "IPsec Phase 1 Status",
    "OPNsenseWireGuardPeerDown": "WireGuard Peer Status",
    "OPNsenseHASyncUnreachable": "Remote Reachable",
    "OPNsenseCARPVIPFault": "CARP VIP Status",
    "OPNsenseCARPStateFlapping": "CARP Transition Events",
    "OPNsenseCARPUnexpectedDemotion": "CARP Transition Events",
    # --- IDS -------------------------------------------------------------------
    "OPNsenseIDSAlertSpike": "Recent Alerts by Action",
    # --- flow pipeline ---------------------------------------------------------
    # These are operational rules whose panels live on the HEALTH dashboard: the flow
    # correlator and the GeoIP databases are exporter-side machinery, so that is where
    # they are graphed. The resolver falls through to the other dashboard for exactly
    # this case.
    "OPNsenseFlowCorrelatorEvicting": "Flow Correlator",
    "OPNsenseFlowLogsTruncated": "Flow Log Emission",
    "OPNsenseFlowGeoIPDatabaseStale": "GeoIP Database Age & Updates",
    "OPNsenseNetFlowHookDead": "Dead Capture Hooks (configured, own node frozen)",
}

# Alerts that deliberately carry NO panel link, with the reason. Empty today — every
# alert has a panel worth opening. Kept because the next alert whose only useful
# destination is a log stream or a runbook needs somewhere to say so with a reason,
# rather than being silently absent from PANEL_LINKS.
PANEL_LINK_EXEMPT: dict = {}


def panel_annotations(rule, selfhealth: bool) -> dict:
    """The paired panel-link annotations for one rule, or {} when it has no panel.

    This API has no top-level dashboardUid/panelId — those are the `apiVersion: 1`
    provisioning form and `additionalProperties: false` rejects them outright. The
    paired __dashboardUid__/__panelId__ annotations are the mechanism, and
    __panelId__ must be a STRING: annotation values are typed as strings, so an int
    is dropped silently and the rule looks linked while not being.
    """
    link = PANEL_LINKS.get(rule["title"])
    if not link:
        return {}
    title, tab = link if isinstance(link, tuple) else (link, None)
    uid, panel_id = panel_ref(title, selfhealth, tab)
    return {"__dashboardUid__": uid, "__panelId__": str(panel_id)}


def rule_folder(rule, folder: str, health_folder: str) -> str:
    """Which Grafana folder one alert or recording rule belongs in.

    Recording rules carry no `selfhealth` flag and are sorted by expression alone:
    all 14 bundled ones derive from firewall metrics, so the health folder holds no
    recording rules today. That is the owner's per-rule sort, applied here rather
    than assumed."""
    if rule.get("selfhealth") or is_self_health_expr(rule.get("A") or rule.get("expr", "")):
        return health_folder
    return folder


def emit_grafana_managed(ds: str, ops_folder: str, stack: bool, health_folder: str):
    outdir = os.path.join(HERE, "grafana-managed")
    os.makedirs(outdir, exist_ok=True)
    for stale in os.listdir(outdir):  # clear stale manifests so renames don't linger
        if stale.endswith(".json"):
            os.remove(os.path.join(outdir, stale))
    written = []
    # Folder manifests (named so each UID == its folder); pushed first so the rules
    # resolve. Two folders since #431: firewall-operational and exporter-health.
    for slug, title, fname in (
            (ops_folder, "OPNsense Exporter Alerts", "_folder.json"),
            (health_folder, "OPNsense Exporter Health Alerts", "_folder-health.json")):
        fp = os.path.join(outdir, fname)
        with open(fp, "w") as f:
            json.dump({"apiVersion": "folder.grafana.app/v1beta1", "kind": "Folder",
                       "metadata": {"name": slug}, "spec": {"title": title}},
                      f, indent=2)
            f.write("\n")
        written.append(fp)
    for r in RULES:
        folder = rule_folder(r, ops_folder, health_folder)
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
                                "runbook_url": runbook_url(r["title"]),
                                **panel_annotations(r, folder == health_folder)},
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
        folder = rule_folder(r, ops_folder, health_folder)
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


# #430: the top-level heading whose slug RUNBOOK_URL's anchor names (grafana/uids.py).
# Kept as one literal, asserted against RUNBOOK_URL below, so the two can never drift -
# a renamed heading here without updating uids.py fails the build instead of shipping a
# dead index link.
RUNBOOKS_MD_TITLE = "Alerts & Recording Rules"


RUNBOOK_KEYS = ("measures", "threshold", "absent", "checks", "causes", "verify")


def require_complete_runbook(name: str, rb: dict) -> None:
    """Every rule's runbook=dict(...) must carry all six keys, each non-empty. Raises
    ValueError (a hard build failure, not a silent skip) otherwise - called from
    `_runbook_section` so a missing/incomplete runbook fails `make rules` itself, not
    just a test that happens to be run."""
    for key in RUNBOOK_KEYS:
        if key not in rb:
            raise ValueError(f"{name}: runbook is missing required key {key!r}")
        value = rb[key]
        if isinstance(value, list):
            if not value or any(not str(item).strip() for item in value):
                raise ValueError(f"{name}: runbook[{key!r}] is empty or has a blank entry")
        elif not str(value).strip():
            raise ValueError(f"{name}: runbook[{key!r}] is empty")


def _runbook_section(r: dict) -> str:
    rb = r["runbook"]
    require_complete_runbook(r["name"], rb)

    def bullets(items):
        return "\n".join(f"- {item}" for item in items)

    exempt_note = ""
    if r["name"] in SUMMARY_INSTANCE_EXEMPT:
        exempt_note = (
            "\n**Instance identity:** this alert's summary does not carry "
            "`opnsense_instance` - "
            f"{SUMMARY_INSTANCE_EXEMPT[r['name']]}\n"
        )

    return (
        f"## {r['title']}\n\n"
        f"**Severity:** {r['severity']}  \n"
        f"**Pending window:** {grafana_for(r['for_min'])}  \n"
        f"**Rule name:** `{r['name']}`\n\n"
        "**Expression:**\n"
        "```promql\n"
        f"{r['A']}\n"
        "```\n\n"
        f"**What it measures:** {rb['measures']}\n\n"
        f"**Threshold & window:** {rb['threshold']}\n\n"
        f"**Absent / no-data semantics:** {rb['absent']}\n\n"
        f"**First checks:**\n{bullets(rb['checks'])}\n\n"
        f"**Likely causes:**\n{bullets(rb['causes'])}\n\n"
        f"**Verify recovery:**\n{bullets(rb['verify'])}\n"
        f"{exempt_note}"
    )


def _recording_section(r: dict) -> str:
    return (
        f"### {r['metric']}\n\n"
        "```promql\n"
        f"{r['expr']}\n"
        "```\n"
    )


def generate_runbooks_md() -> str:
    """Render `grafana/runbooks.md` (#430): one `## <Title>` section per alert in RULES
    order (exact 1:1 with the manifests `emit_grafana_managed` writes, from the same
    source list), followed by a recording-rule section covering all of RECORDING.
    `runbook_url()` in uids.py builds the per-alert anchor into this same document, and
    `grafana/alerts/validate_manifests.py` checks it actually resolves here."""
    title_slug = None
    try:
        from uids import github_heading_slug
        title_slug = github_heading_slug(RUNBOOKS_MD_TITLE)
    except ImportError:  # pragma: no cover - uids.py is always on sys.path in this repo
        pass
    expected_anchor = RUNBOOK_URL.rsplit("#", 1)[1]
    if title_slug != expected_anchor:
        raise RuntimeError(
            f"RUNBOOKS_MD_TITLE {RUNBOOKS_MD_TITLE!r} slugs to {title_slug!r}, which does "
            f"not match RUNBOOK_URL's anchor {expected_anchor!r} (grafana/uids.py) - keep "
            "them in sync or the dashboard's 'Alert runbooks' link 404s"
        )

    parts = [
        "<!-- GENERATED FILE. Do not hand-edit; run `make rules` "
        "(grafana/alerts/build_rules.py). -->",
        "",
        f"# {RUNBOOKS_MD_TITLE}",
        "",
        "One section per alert rule in `grafana/alerts/build_rules.py`'s `RULES`, in "
        "source order, followed by every recording rule in `RECORDING`. Each alert "
        "section states what its expression measures, its threshold and window, what "
        "absent/no-data means for that specific rule, first checks, likely causes, and "
        "how to confirm it has genuinely recovered - mined from the same source comments "
        "and descriptions that drive the generated manifests, so this document and the "
        "alert's own annotations can never contradict each other.",
        "",
        f"Total: **{len(RULES)} alert rules** and **{len(RECORDING)} recording rules**.",
        "",
    ]
    for r in RULES:
        parts.append(_runbook_section(r))
    parts.append("## Recording rules")
    parts.append("")
    parts.append(
        "Precomputed PromQL expressions following the "
        "`instance:opnsense_<subsystem>_<measurement>:<op>` naming convention. These are "
        "plain recording rules with no alerting semantics of their own - they exist to "
        "keep a common aggregation/ratio computed once for dashboards and other rules to "
        "reuse."
    )
    parts.append("")
    for r in RECORDING:
        parts.append(_recording_section(r))
    return "\n".join(parts).rstrip() + "\n"


def write_runbooks_md() -> str:
    content = generate_runbooks_md()
    with open(RUNBOOKS_MD_PATH, "w") as f:
        f.write(content)
    return RUNBOOKS_MD_PATH


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasource", default="grafanacloud-prom")
    ap.add_argument("--folder", default="opnsense-alerts",
                    help="grafana folder for firewall-operational rules")
    ap.add_argument("--health-folder", default="opnsense-exporter-health-alerts",
                    help="grafana folder for exporter self-health rules (#431)")
    ap.add_argument("--stack", action="store_true",
                    help="add IRM label contract (domain=infra; page=true on critical)")
    args = ap.parse_args()

    outdir, written = emit_grafana_managed(args.datasource, args.folder, args.stack,
                                          args.health_folder)
    print(f"wrote {len(written)} grafana-managed manifests to {outdir}")
    self_health = sum(1 for r in RULES
                      if rule_folder(r, args.folder, args.health_folder) == args.health_folder)
    print(f"alerts: {len(RULES)} ({self_health} exporter-health)  "
          f"recording rules: {len(RECORDING)}  stack-labels: {args.stack}")

    runbooks_path = write_runbooks_md()
    print(f"wrote runbooks to {runbooks_path}")


if __name__ == "__main__":
    main()
